// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Local in-process task route store for A2A task-ownership routing.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use serde_json::Value;

use super::config::TaskRoutingConfig;
use crate::builtins::http::value_safety::contains_control_chars;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum length for stored IDs, matching the existing A2A dynamic-value bound.
const MAX_ID_LEN: usize = 256;

/// Maximum number of task route entries before inserts are rejected.
const MAX_TASK_ROUTES: usize = 50_000;

/// Minimum interval between proactive eviction sweeps.
const EVICTION_INTERVAL: Duration = Duration::from_secs(30);

// -----------------------------------------------------------------------------
// TaskRoute
// -----------------------------------------------------------------------------

/// A stored mapping from a task (or context) ID to the cluster that owns it.
#[derive(Debug, Clone)]
struct TaskRoute {
    /// Cluster name selected when the task was created.
    cluster: Arc<str>,

    /// When this entry expires and should be treated as a miss.
    expires_at: Instant,
}

// -----------------------------------------------------------------------------
// ExtractedTaskRoute
// -----------------------------------------------------------------------------

/// Task route information extracted from a JSON-RPC response body.
#[derive(Debug, Clone)]
pub(crate) struct ExtractedTaskRoute {
    /// Whether the task is in a terminal state.
    pub terminal: bool,

    /// Task ID from the response.
    pub task_id: String,
}

// -----------------------------------------------------------------------------
// LocalTaskRouteStore
// -----------------------------------------------------------------------------

/// In-process task route store backed by `RwLock<HashMap>`.
///
/// Holds locks only for short synchronous map operations.
/// Never held across `.await` boundaries.
pub(crate) struct LocalTaskRouteStore {
    /// Task ID → cluster mappings.
    tasks: RwLock<HashMap<String, TaskRoute>>,

    /// Timestamp of the last proactive eviction sweep.
    last_eviction: Mutex<Instant>,
}

impl LocalTaskRouteStore {
    /// Create an empty store.
    pub(crate) fn new() -> Self {
        Self {
            tasks: RwLock::new(HashMap::new()),
            last_eviction: Mutex::new(Instant::now()),
        }
    }

    /// Look up a cluster by task ID. Returns `None` if absent or expired.
    /// Lazily removes expired entries on miss.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned lock is unrecoverable")]
    pub(crate) fn get_by_task_id(&self, task_id: &str) -> Option<Arc<str>> {
        let expired = {
            let tasks = self.tasks.read().expect("task route store lock poisoned");
            match tasks.get(task_id) {
                Some(r) if Instant::now() < r.expires_at => return Some(Arc::clone(&r.cluster)),
                Some(_) => true,
                None => false,
            }
        };

        if expired {
            let mut tasks = self.tasks.write().expect("task route store lock poisoned");
            // Re-check under write lock: another request may have
            // refreshed this task between the read and write locks.
            if tasks.get(task_id).is_some_and(|r| Instant::now() >= r.expires_at) {
                tasks.remove(task_id);
            }
        }
        None
    }

    /// Store a task route mapping with the given TTL.
    ///
    /// Silently ignores task IDs that fail validation (control chars,
    /// too long) and rejects new inserts when the store is at
    /// [`MAX_TASK_ROUTES`] capacity. Overwrites of existing keys are
    /// always allowed regardless of capacity.
    ///
    /// Periodically sweeps expired entries (at most once per
    /// [`EVICTION_INTERVAL`]) to bound memory growth.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned lock is unrecoverable")]
    pub(crate) fn put(&self, task_id: &str, cluster: &str, ttl: Duration) {
        if !validate_id(task_id) {
            return;
        }

        let route = TaskRoute {
            cluster: Arc::from(cluster),
            expires_at: Instant::now() + ttl,
        };

        let mut tasks = self.tasks.write().expect("task route store lock poisoned");
        self.maybe_evict(&mut tasks);

        if tasks.len() >= MAX_TASK_ROUTES && !tasks.contains_key(task_id) {
            tracing::warn!(
                limit = MAX_TASK_ROUTES,
                "task route store: capacity reached, insert rejected"
            );
            return;
        }

        tasks.insert(task_id.to_owned(), route);
    }

    /// Remove a task route immediately (for `terminal_ttl_seconds` == 0).
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned lock is unrecoverable")]
    pub(crate) fn remove(&self, task_id: &str) {
        self.tasks
            .write()
            .expect("task route store lock poisoned")
            .remove(task_id);
    }

    /// Sweep expired entries if [`EVICTION_INTERVAL`] has elapsed.
    fn maybe_evict(&self, tasks: &mut HashMap<String, TaskRoute>) {
        if let Ok(mut last) = self.last_eviction.try_lock() {
            if last.elapsed() < EVICTION_INTERVAL {
                return;
            }
            let before = tasks.len();
            let now = Instant::now();
            tasks.retain(|_, r| now < r.expires_at);
            let evicted = before.saturating_sub(tasks.len());
            if evicted > 0 {
                tracing::debug!(
                    evicted,
                    remaining = tasks.len(),
                    "task route store: evicted expired entries"
                );
            }
            *last = Instant::now();
        }
    }
}

// -----------------------------------------------------------------------------
// Response Extraction
// -----------------------------------------------------------------------------

/// Extract task route information from a parsed JSON-RPC response.
///
/// Supports these [A2A core object] response/stream shapes:
/// - `result.task.id` — full `Task` nested under result
/// - `result.id` with `result.status` — direct `Task` object in result
/// - `result.statusUpdate.taskId` — `TaskStatusUpdateEvent` (carries terminal state)
/// - `result.artifactUpdate.taskId` — `TaskArtifactUpdateEvent` (never terminal)
///
/// Returns `None` for message-only responses or malformed JSON.
///
/// [A2A core object]: https://a2a-protocol.org/latest/specification/#5-core-objects
pub(crate) fn extract_task_route(value: &Value) -> Option<ExtractedTaskRoute> {
    let result = value.get("result")?;

    if let Some(task_obj) = result.get("task") {
        return extract_from_task_object(task_obj);
    }

    if result.get("id").is_some() && result.get("status").is_some() {
        return extract_from_task_object(result);
    }

    if let Some(status_update) = result.get("statusUpdate") {
        return extract_from_status_update(status_update);
    }

    if let Some(artifact_update) = result.get("artifactUpdate") {
        return extract_from_artifact_update(artifact_update);
    }

    None
}

/// Extract route info from a task object (either `result.task` or `result` itself).
fn extract_from_task_object(task: &Value) -> Option<ExtractedTaskRoute> {
    let task_id = task.get("id")?.as_str()?;

    if !validate_id(task_id) {
        return None;
    }

    let terminal = task
        .get("status")
        .and_then(|s| s.get("state"))
        .and_then(Value::as_str)
        .is_some_and(is_terminal_state);

    Some(ExtractedTaskRoute {
        task_id: task_id.to_owned(),
        terminal,
    })
}

/// Extract route info from a `TaskStatusUpdateEvent` (`result.statusUpdate`).
fn extract_from_status_update(update: &Value) -> Option<ExtractedTaskRoute> {
    let task_id = update.get("taskId")?.as_str()?;

    if !validate_id(task_id) {
        return None;
    }

    let terminal = update
        .get("status")
        .and_then(|s| s.get("state"))
        .and_then(Value::as_str)
        .is_some_and(is_terminal_state);

    Some(ExtractedTaskRoute {
        task_id: task_id.to_owned(),
        terminal,
    })
}

/// Extract route info from a `TaskArtifactUpdateEvent` (`result.artifactUpdate`).
///
/// Artifact updates carry no status, so they are never terminal.
fn extract_from_artifact_update(update: &Value) -> Option<ExtractedTaskRoute> {
    let task_id = update.get("taskId")?.as_str()?;

    if !validate_id(task_id) {
        return None;
    }

    Some(ExtractedTaskRoute {
        task_id: task_id.to_owned(),
        terminal: false,
    })
}

/// Compute the TTL to use for a task route entry.
pub(crate) fn route_ttl(terminal: bool, config: &TaskRoutingConfig) -> Duration {
    if terminal {
        Duration::from_secs(config.terminal_ttl_seconds)
    } else {
        Duration::from_secs(config.ttl_seconds)
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Whether the given state string represents a terminal task state.
fn is_terminal_state(state: &str) -> bool {
    matches!(
        state,
        "TASK_STATE_COMPLETED"
            | "TASK_STATE_FAILED"
            | "TASK_STATE_CANCELED"
            | "TASK_STATE_REJECTED"
            | "completed"
            | "failed"
            | "canceled"
            | "cancelled"
            | "rejected"
    )
}

/// Whether an ID is safe for storage: no control characters, bounded length.
fn validate_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_LEN && !contains_control_chars(id)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::thread::sleep;

    use super::*;

    // ---- Store Tests ----

    #[test]
    fn local_store_put_then_get_task_route() {
        let store = LocalTaskRouteStore::new();
        store.put("task-1", "agent-a", Duration::from_secs(60));

        let cluster = store.get_by_task_id("task-1");
        assert_eq!(
            cluster.as_deref(),
            Some("agent-a"),
            "stored task route should be retrievable"
        );
    }

    #[test]
    fn local_store_expired_task_route_misses_and_removes_entry() {
        let store = LocalTaskRouteStore::new();
        store.put("task-1", "agent-a", Duration::from_millis(50));

        sleep(Duration::from_millis(200));

        let cluster = store.get_by_task_id("task-1");
        assert!(cluster.is_none(), "expired task route should miss");

        let still_present = store.tasks.read().unwrap().contains_key("task-1");
        assert!(!still_present, "expired entry should be lazily removed from the map");
    }

    #[test]
    fn local_store_terminal_zero_ttl_removes_route() {
        let store = LocalTaskRouteStore::new();
        store.put("task-1", "agent-a", Duration::from_secs(60));
        store.remove("task-1");

        assert!(
            store.get_by_task_id("task-1").is_none(),
            "removed task route should miss"
        );
    }

    #[test]
    fn local_store_rejects_control_char_task_id() {
        let store = LocalTaskRouteStore::new();
        let bad_id = "task\n-1";
        store.put(bad_id, "agent-a", Duration::from_secs(60));

        assert!(
            store.get_by_task_id(bad_id).is_none(),
            "task ID with control chars should not be stored"
        );
    }

    #[test]
    fn local_store_rejects_too_long_task_id() {
        let store = LocalTaskRouteStore::new();
        let long_id = "x".repeat(257);
        store.put(&long_id, "agent-a", Duration::from_secs(60));

        assert!(
            store.get_by_task_id(&long_id).is_none(),
            "task ID exceeding 256 bytes should not be stored"
        );
    }

    #[test]
    fn local_store_rejects_insert_at_capacity() {
        let store = LocalTaskRouteStore::new();
        for i in 0..MAX_TASK_ROUTES {
            store.put(&format!("task-{i}"), "agent-a", Duration::from_secs(3600));
        }

        store.put("overflow", "agent-a", Duration::from_secs(3600));
        assert!(
            store.get_by_task_id("overflow").is_none(),
            "insert should be rejected when store is at capacity"
        );
        assert_eq!(
            store.tasks.read().unwrap().len(),
            MAX_TASK_ROUTES,
            "store size should not exceed MAX_TASK_ROUTES"
        );
    }

    #[test]
    fn local_store_allows_overwrite_at_capacity() {
        let store = LocalTaskRouteStore::new();
        for i in 0..MAX_TASK_ROUTES {
            store.put(&format!("task-{i}"), "agent-a", Duration::from_secs(3600));
        }

        store.put("task-0", "agent-b", Duration::from_secs(3600));
        assert_eq!(
            store.get_by_task_id("task-0").as_deref(),
            Some("agent-b"),
            "overwrite of existing key should succeed at capacity"
        );
    }

    #[test]
    fn local_store_eviction_reclaims_expired_entries() {
        let store = LocalTaskRouteStore::new();
        for i in 0..100 {
            store.put(&format!("task-{i}"), "agent-a", Duration::from_millis(50));
        }
        assert_eq!(store.tasks.read().unwrap().len(), 100, "should have 100 entries");

        sleep(Duration::from_millis(200));

        // Force eviction by setting last_eviction far in the past.
        *store.last_eviction.lock().unwrap() = Instant::now() - EVICTION_INTERVAL - Duration::from_secs(1);
        store.put("fresh", "agent-b", Duration::from_secs(3600));

        let remaining = store.tasks.read().unwrap().len();
        assert_eq!(
            remaining, 1,
            "eviction should have removed all 100 expired entries, leaving only 'fresh'"
        );
        assert_eq!(
            store.get_by_task_id("fresh").as_deref(),
            Some("agent-b"),
            "fresh entry should be retrievable after eviction"
        );
    }

    #[test]
    fn local_store_replaces_existing_task_route() {
        let store = LocalTaskRouteStore::new();
        store.put("task-1", "agent-a", Duration::from_secs(60));
        store.put("task-1", "agent-b", Duration::from_secs(60));

        let cluster = store.get_by_task_id("task-1");
        assert_eq!(
            cluster.as_deref(),
            Some("agent-b"),
            "later put should replace earlier route"
        );
    }

    // ---- Response Extraction Tests ----

    #[test]
    fn extract_task_route_from_result_task() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "task": {
                    "id": "task-123",
                    "contextId": "ctx-123",
                    "status": {"state": "TASK_STATE_WORKING"}
                }
            }
        });

        let route = extract_task_route(&json).expect("should extract route");
        assert_eq!(route.task_id, "task-123");
        assert!(!route.terminal, "TASK_STATE_WORKING is not terminal");
    }

    #[test]
    fn extract_task_route_from_direct_result_task() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "id": "task-456",
                "contextId": "ctx-456",
                "status": {"state": "TASK_STATE_COMPLETED"}
            }
        });

        let route = extract_task_route(&json).expect("should extract route");
        assert_eq!(route.task_id, "task-456");
        assert!(route.terminal, "TASK_STATE_COMPLETED is terminal");
    }

    #[test]
    fn message_only_response_does_not_create_route() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "message": {
                    "messageId": "msg-1",
                    "role": "ROLE_AGENT",
                    "parts": [{"text": "done"}]
                }
            }
        });

        assert!(
            extract_task_route(&json).is_none(),
            "message-only response should not produce a route"
        );
    }

    #[test]
    fn invalid_json_response_does_not_error() {
        let json = serde_json::json!({"not": "a valid response"});
        assert!(
            extract_task_route(&json).is_none(),
            "malformed response should return None, not error"
        );
    }

    #[test]
    fn missing_cluster_does_not_store_route() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "task": {
                    "contextId": "ctx-1",
                    "status": {"state": "TASK_STATE_WORKING"}
                }
            }
        });

        assert!(
            extract_task_route(&json).is_none(),
            "task without id should not produce a route"
        );
    }

    #[test]
    fn terminal_state_uses_terminal_ttl() {
        let config = TaskRoutingConfig {
            ttl_seconds: 3600,
            terminal_ttl_seconds: 300,
            ..TaskRoutingConfig::default()
        };

        let ttl = route_ttl(true, &config);
        assert_eq!(ttl, Duration::from_secs(300), "terminal tasks should use terminal TTL");
    }

    #[test]
    fn input_required_state_keeps_normal_route_ttl() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "task": {
                    "id": "task-1",
                    "status": {"state": "TASK_STATE_INPUT_REQUIRED"}
                }
            }
        });

        let route = extract_task_route(&json).expect("should extract route");
        assert!(!route.terminal, "TASK_STATE_INPUT_REQUIRED should not be terminal");
    }

    // ---- Streaming Event Extraction Tests ----

    #[test]
    fn extract_from_status_update_event() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "statusUpdate": {
                    "taskId": "task-su-1",
                    "contextId": "ctx-1",
                    "status": {"state": "TASK_STATE_WORKING"}
                }
            }
        });

        let route = extract_task_route(&json).expect("should extract from statusUpdate");
        assert_eq!(route.task_id, "task-su-1");
        assert!(!route.terminal, "TASK_STATE_WORKING is not terminal");
    }

    #[test]
    fn extract_terminal_status_update_event() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "statusUpdate": {
                    "taskId": "task-su-2",
                    "status": {"state": "TASK_STATE_COMPLETED"}
                }
            }
        });

        let route = extract_task_route(&json).expect("should extract from terminal statusUpdate");
        assert_eq!(route.task_id, "task-su-2");
        assert!(
            route.terminal,
            "TASK_STATE_COMPLETED from statusUpdate should be terminal"
        );
    }

    #[test]
    fn extract_from_artifact_update_event() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "artifactUpdate": {
                    "taskId": "task-au-1",
                    "contextId": "ctx-1",
                    "artifact": {
                        "artifactId": "art-1",
                        "parts": [{"text": "chunk"}]
                    }
                }
            }
        });

        let route = extract_task_route(&json).expect("should extract from artifactUpdate");
        assert_eq!(route.task_id, "task-au-1");
        assert!(!route.terminal, "artifactUpdate is never terminal");
    }

    #[test]
    fn status_update_without_task_id_returns_none() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "statusUpdate": {
                    "status": {"state": "TASK_STATE_WORKING"}
                }
            }
        });

        assert!(
            extract_task_route(&json).is_none(),
            "statusUpdate without taskId should return None"
        );
    }

    #[test]
    fn artifact_update_without_task_id_returns_none() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "artifactUpdate": {
                    "artifact": {"parts": []}
                }
            }
        });

        assert!(
            extract_task_route(&json).is_none(),
            "artifactUpdate without taskId should return None"
        );
    }

    #[test]
    fn all_terminal_states_detected() {
        let terminal_states = [
            "TASK_STATE_COMPLETED",
            "TASK_STATE_FAILED",
            "TASK_STATE_CANCELED",
            "TASK_STATE_REJECTED",
            "completed",
            "failed",
            "canceled",
            "cancelled",
            "rejected",
        ];

        for state in terminal_states {
            assert!(is_terminal_state(state), "{state} should be terminal");
        }
    }

    #[test]
    fn non_terminal_states_not_detected() {
        let non_terminal = [
            "TASK_STATE_WORKING",
            "TASK_STATE_INPUT_REQUIRED",
            "TASK_STATE_AUTH_REQUIRED",
            "TASK_STATE_SUBMITTED",
            "working",
            "submitted",
        ];

        for state in non_terminal {
            assert!(!is_terminal_state(state), "{state} should not be terminal");
        }
    }
}
