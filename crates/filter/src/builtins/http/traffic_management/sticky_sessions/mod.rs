// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Sticky sessions filter: cookie-based, header-based, and learn-mode session persistence.
//!
//! Pins clients to specific upstream endpoints across requests using
//! a shared session-to-endpoint mapping. Supports graceful failover
//! when pinned endpoints become unhealthy.
//!
//! # YAML configuration
//!
//! ```yaml
//! filter: sticky_sessions
//! clusters:
//!   - name: app_backend
//!     type: cookie
//!     cookie_name: "_praxis_route"
//!     ttl_secs: 3600
//!     cookie_attributes:
//!       path: "/"
//!       http_only: true
//!       secure: true
//!       same_site: Lax
//!     failover: true
//!     max_entries: 100000
//!     eviction: lru
//! ```

pub(crate) mod config;
mod cookie;
mod store;

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use tracing::{debug, warn};

use self::config::{ClusterSessionConfig, CookieAttributes, PersistenceConfig, StickySessionsConfig};
pub use self::store::{SessionStore, SessionStoreRegistry};
use crate::{
    FilterError,
    actions::FilterAction,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

/// Metadata key for the session identifier extracted from the request.
const META_SESSION_KEY: &str = "sticky_sessions.session_key";
/// Maximum allowed session key length (bytes) to prevent memory exhaustion.
const MAX_SESSION_KEY_LEN: usize = 256;

// -----------------------------------------------------------------------------
// StickySessionsFilter
// -----------------------------------------------------------------------------

/// Sticky sessions HTTP filter.
///
/// On request: looks up session store for pinned endpoint, sets `ctx.pinned_endpoint_address`.
/// On response: injects session cookie or learns session ID from upstream.
pub struct StickySessionsFilter {
    /// Per-cluster session persistence configurations keyed by cluster name.
    configs: HashMap<Arc<str>, Arc<ClusterSessionConfig>>,
    /// Filter-owned session stores (used as fallback when pipeline stores are not set).
    stores: Arc<SessionStoreRegistry>,
}

impl StickySessionsFilter {
    /// Factory method called by the filter registry.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML configuration is malformed or
    /// fails validation.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let config: StickySessionsConfig = parse_filter_config("sticky_sessions", value)?;
        for cluster_config in &config.clusters {
            cluster_config.validate().map_err(|e| FilterError::from(e.as_str()))?;
        }

        let configs: HashMap<Arc<str>, Arc<ClusterSessionConfig>> = config
            .clusters
            .into_iter()
            .map(|c| (Arc::<str>::from(c.name.as_str()), Arc::new(c)))
            .collect();

        let stores = Arc::new(Self::build_stores(&configs));

        Ok(Box::new(Self { configs, stores }))
    }

    /// The session store registry owned by this filter instance.
    ///
    /// The server layer should call this after pipeline construction to
    /// extract the stores and inject them into the pipeline via
    /// `FilterPipeline::set_session_stores`, preserving them across reloads.
    pub fn session_stores(&self) -> &Arc<SessionStoreRegistry> {
        &self.stores
    }

    /// Build session stores for all configured clusters.
    fn build_stores(configs: &HashMap<Arc<str>, Arc<ClusterSessionConfig>>) -> SessionStoreRegistry {
        let registry = SessionStoreRegistry::new();
        for (name, cfg) in configs {
            let store = Arc::new(SessionStore::new(
                cfg.max_entries.get(),
                Duration::from_secs(cfg.ttl_secs),
                cfg.eviction,
            ));
            registry.insert(Arc::clone(name), store);
        }
        registry
    }

    /// Get the cluster config for the current request's cluster.
    fn cluster_config<'a>(&'a self, ctx: &HttpFilterContext<'_>) -> Option<&'a Arc<ClusterSessionConfig>> {
        let cluster_name = ctx.cluster.as_deref()?;
        self.configs.get(cluster_name)
    }

    /// Find a cookie's value across all `Cookie` request headers.
    ///
    /// HTTP/2 permits multiple `cookie` header fields (RFC 9113 §8.2.3), so
    /// examining only the first would make sessions flap for H2 clients.
    fn find_request_cookie(ctx: &HttpFilterContext<'_>, cookie_name: &str) -> Option<String> {
        ctx.request
            .headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|h| cookie::extract_cookie_value(h, cookie_name).map(String::from))
    }

    /// Extract session key from the request based on persistence type.
    fn extract_session_key(cfg: &ClusterSessionConfig, ctx: &HttpFilterContext<'_>) -> Option<String> {
        let key = match &cfg.persistence {
            PersistenceConfig::Cookie { cookie_name, .. } | PersistenceConfig::Learn { cookie_name } => {
                Self::find_request_cookie(ctx, cookie_name)
            },
            PersistenceConfig::Header { header_name } => ctx
                .request
                .headers
                .get(header_name.as_str())?
                .to_str()
                .ok()
                .map(String::from),
        }?;

        if key.len() > MAX_SESSION_KEY_LEN {
            warn!(
                len = key.len(),
                max = MAX_SESSION_KEY_LEN,
                "session key too long, ignoring"
            );
            return None;
        }

        Some(key)
    }

    /// Check if an endpoint is healthy via the health registry.
    fn is_endpoint_healthy(ctx: &HttpFilterContext<'_>, cluster: &str, endpoint: &str) -> bool {
        ctx.health_registry
            .and_then(|r| r.get(cluster))
            .and_then(|state| {
                let idx = state.endpoint_index(endpoint)?;
                Some(state.endpoints().get(idx)?.is_healthy())
            })
            .unwrap_or(true)
    }

    /// Try to route to an existing pinned endpoint for the given session.
    ///
    /// Returns `true` if the request was routed (caller should short-circuit),
    /// `false` if no usable binding exists.
    fn apply_pinned_route(
        cfg: &ClusterSessionConfig,
        ctx: &mut HttpFilterContext<'_>,
        store: &SessionStore,
        cluster_name: &str,
        session_key: &str,
    ) -> bool {
        let Some(endpoint) = store.get(session_key) else {
            return false;
        };
        if Self::is_endpoint_healthy(ctx, cluster_name, &endpoint) {
            debug!(cluster = %cluster_name, session = %session_key, endpoint = %endpoint, "session affinity hit: routing to pinned endpoint");
            ctx.pinned_endpoint_address = Some(endpoint);
            return true;
        }
        if cfg.failover {
            // Keep the stale binding: the response phase re-pins this key to
            // the endpoint the load balancer actually served, and only keys
            // already present in the store are ever re-pinned.
            debug!(cluster = %cluster_name, session = %session_key, endpoint = %endpoint, "pinned endpoint unhealthy, failing over");
            false
        } else {
            debug!(cluster = %cluster_name, session = %session_key, endpoint = %endpoint, "pinned endpoint unhealthy, failover disabled — routing anyway");
            ctx.pinned_endpoint_address = Some(endpoint);
            true
        }
    }

    /// Handle response for cookie-type persistence.
    fn handle_cookie_response(
        cfg: &ClusterSessionConfig,
        ctx: &mut HttpFilterContext<'_>,
        store: &SessionStore,
        endpoint: &Arc<str>,
    ) {
        // Skip binding work entirely when the exchange failed before response
        // headers: a Set-Cookie could never reach the client, so the binding
        // would be unreachable garbage.
        if ctx.response_header.is_none() {
            return;
        }

        let cookie_name = cfg.persistence.cookie_name().unwrap_or("_praxis_route");
        // A client-supplied cookie value is adopted only when it is already
        // bound in the store (an established session, possibly failing over);
        // any unknown value gets a fresh server-minted ID. Adopting unknown
        // client values would let an attacker flood the store with arbitrary
        // keys and evict legitimate sessions.
        let session_key = ctx
            .get_metadata(META_SESSION_KEY)
            .map(String::from)
            .or_else(|| Self::find_request_cookie(ctx, cookie_name))
            .filter(|key| store.get(key).is_some())
            .unwrap_or_else(|| generate_session_id(endpoint));

        store.put(&session_key, Arc::clone(endpoint));

        let default_attrs;
        let cookie_attrs = if let Some(attrs) = cfg.persistence.cookie_attributes() {
            attrs
        } else {
            default_attrs = CookieAttributes::default();
            &default_attrs
        };
        let set_cookie = cookie::build_set_cookie(cookie_name, &session_key, cookie_attrs, cfg.ttl_secs);

        if let Some(resp) = ctx.response_header.as_mut()
            && let Ok(val) = http::header::HeaderValue::from_str(&set_cookie)
        {
            resp.headers.append(http::header::SET_COOKIE, val);
            ctx.response_headers_modified = true;
        }
    }

    /// Handle response for learn-mode persistence.
    #[expect(clippy::too_many_lines, reason = "ownership guard adds necessary validation lines")]
    fn handle_learn_response(
        cfg: &ClusterSessionConfig,
        ctx: &HttpFilterContext<'_>,
        store: &SessionStore,
        endpoint: &Arc<str>,
    ) {
        let cookie_name = cfg.persistence.cookie_name().unwrap_or_default();
        if cookie_name.is_empty() {
            return;
        }

        let Some(resp) = ctx.response_header.as_ref() else {
            return;
        };

        for value in resp.headers.get_all(http::header::SET_COOKIE) {
            let Ok(header_str) = value.to_str() else {
                continue;
            };
            if let Some(session_id) = cookie::extract_set_cookie_value(header_str, cookie_name) {
                if session_id.len() > MAX_SESSION_KEY_LEN {
                    warn!(
                        len = session_id.len(),
                        max = MAX_SESSION_KEY_LEN,
                        "learned session ID too long, ignoring"
                    );
                    continue;
                }
                if let Some(existing_owner) = store.get(session_id)
                    && *existing_owner != **endpoint
                {
                    warn!(
                        session_id = %session_id,
                        existing_endpoint = %existing_owner,
                        claiming_endpoint = %endpoint,
                        "rejecting learn-mode overwrite from different endpoint"
                    );
                    continue;
                }
                debug!(
                    cookie_name = %cookie_name,
                    session_id = %session_id,
                    endpoint = %endpoint,
                    "learned session binding from upstream"
                );
                store.put(session_id, Arc::clone(endpoint));
                return;
            }
        }

        // Nothing learned from this response. If the client presented a key
        // that is already bound (e.g. its pinned endpoint just failed over),
        // re-pin that existing binding to the endpoint that actually served —
        // backends set their session cookie once, so failed-over sessions
        // would otherwise bounce on every request. Only keys already in the
        // store are re-pinned; unknown client values are never adopted.
        if let Some(session_key) = ctx.get_metadata(META_SESSION_KEY)
            && let Some(current) = store.get(session_key)
            && current != *endpoint
        {
            debug!(
                session_id = %session_key,
                endpoint = %endpoint,
                "re-pinning existing session to serving endpoint after failover"
            );
            store.put(session_key, Arc::clone(endpoint));
        }
    }

    /// Handle response for header-type persistence.
    fn handle_header_response(ctx: &HttpFilterContext<'_>, store: &SessionStore, endpoint: &Arc<str>) {
        let Some(session_key) = ctx.get_metadata(META_SESSION_KEY) else {
            return;
        };
        store.put(session_key, Arc::clone(endpoint));
    }
}

#[async_trait]
impl HttpFilter for StickySessionsFilter {
    fn name(&self) -> &'static str {
        "sticky_sessions"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(cfg) = self.cluster_config(ctx) else {
            return Ok(FilterAction::Continue);
        };

        // Clone the Arc, not the string: releases the ctx borrow for free.
        let Some(cluster_name) = ctx.cluster.clone() else {
            return Ok(FilterAction::Continue);
        };
        let registry = ctx.session_stores.unwrap_or(&self.stores);
        let store = registry.get_or_create(
            &cluster_name,
            cfg.max_entries.get(),
            Duration::from_secs(cfg.ttl_secs),
            cfg.eviction,
        );

        let Some(session_key) = Self::extract_session_key(cfg, ctx) else {
            return Ok(FilterAction::Continue);
        };

        if Self::apply_pinned_route(cfg, ctx, &store, &cluster_name, &session_key) {
            return Ok(FilterAction::Continue);
        }

        ctx.set_metadata(META_SESSION_KEY, &session_key);

        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(cfg) = self.cluster_config(ctx) else {
            return Ok(FilterAction::Continue);
        };

        // Clone the Arc, not the string: releases the ctx borrow for free.
        let Some(cluster_name) = ctx.cluster.clone() else {
            return Ok(FilterAction::Continue);
        };
        let registry = ctx.session_stores.unwrap_or(&self.stores);
        let store = registry.get_or_create(
            &cluster_name,
            cfg.max_entries.get(),
            Duration::from_secs(cfg.ttl_secs),
            cfg.eviction,
        );

        let endpoint = match ctx.upstream.as_ref() {
            Some(u) => Arc::clone(&u.address),
            None => return Ok(FilterAction::Continue),
        };

        match &cfg.persistence {
            PersistenceConfig::Cookie { .. } => Self::handle_cookie_response(cfg, ctx, &store, &endpoint),
            PersistenceConfig::Learn { .. } => Self::handle_learn_response(cfg, ctx, &store, &endpoint),
            PersistenceConfig::Header { .. } => Self::handle_header_response(ctx, &store, &endpoint),
        }

        Ok(FilterAction::Continue)
    }
}

/// Generate a stable, opaque session identifier from an endpoint address.
///
/// Uses the standard library's `DefaultHasher` (`SipHash`) — not cryptographic,
/// but sufficient for routing identifiers.
fn generate_session_id(endpoint: &str) -> String {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    endpoint.hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests;
