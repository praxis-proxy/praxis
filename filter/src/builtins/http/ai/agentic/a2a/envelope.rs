// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! A2A-specific extraction from parsed JSON-RPC values and A2A request headers.

use std::collections::BTreeMap;

use serde_json::Value;

// -----------------------------------------------------------------------------
// A2aMethod
// -----------------------------------------------------------------------------

/// A2A method classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum A2aMethod {
    /// `SendMessage` message delivery method.
    SendMessage,

    /// `SendStreamingMessage` streaming message method.
    SendStreamingMessage,

    /// `GetTask` task retrieval method.
    GetTask,

    /// `ListTasks` task listing method.
    ListTasks,

    /// `CancelTask` task cancellation method.
    CancelTask,

    /// `SubscribeToTask` task subscription method.
    SubscribeToTask,

    /// `CreateTaskPushNotificationConfig` push notification config creation.
    CreateTaskPushNotificationConfig,

    /// `GetTaskPushNotificationConfig` push notification config retrieval.
    GetTaskPushNotificationConfig,

    /// `ListTaskPushNotificationConfigs` push notification config listing.
    ListTaskPushNotificationConfigs,

    /// `DeleteTaskPushNotificationConfig` push notification config deletion.
    DeleteTaskPushNotificationConfig,

    /// `GetExtendedAgentCard` agent card retrieval.
    GetExtendedAgentCard,

    /// Any other method string not in the known set.
    Unknown(String),
}

/// A2A method family classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum A2aFamily {
    /// Message methods: `SendMessage`, `SendStreamingMessage`.
    Message,

    /// Task methods: `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`.
    Task,

    /// Push notification methods: Create/Get/List/DeleteTaskPushNotificationConfig.
    PushNotification,

    /// Agent card methods: `GetExtendedAgentCard`.
    AgentCard,

    /// Unknown methods.
    Unknown,
}

impl A2aMethod {
    /// Parse an A2A method from the JSON-RPC method string, with alias support.
    ///
    /// A2A JSON-RPC method strings are matched exactly. Legacy slash-delimited
    /// names are accepted only when configured explicitly in `method_aliases`.
    pub(crate) fn from_method_str(s: &str, aliases: &BTreeMap<String, String>) -> Self {
        // First check if this is an alias
        let canonical_method = aliases.get(s).map_or(s, String::as_str);

        match canonical_method {
            "SendMessage" => Self::SendMessage,
            "SendStreamingMessage" => Self::SendStreamingMessage,
            "GetTask" => Self::GetTask,
            "ListTasks" => Self::ListTasks,
            "CancelTask" => Self::CancelTask,
            "SubscribeToTask" => Self::SubscribeToTask,
            "CreateTaskPushNotificationConfig" => Self::CreateTaskPushNotificationConfig,
            "GetTaskPushNotificationConfig" => Self::GetTaskPushNotificationConfig,
            "ListTaskPushNotificationConfigs" => Self::ListTaskPushNotificationConfigs,
            "DeleteTaskPushNotificationConfig" => Self::DeleteTaskPushNotificationConfig,
            "GetExtendedAgentCard" => Self::GetExtendedAgentCard,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// String representation for headers and metadata (canonical form).
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::SendMessage => "SendMessage",
            Self::SendStreamingMessage => "SendStreamingMessage",
            Self::GetTask => "GetTask",
            Self::ListTasks => "ListTasks",
            Self::CancelTask => "CancelTask",
            Self::SubscribeToTask => "SubscribeToTask",
            Self::CreateTaskPushNotificationConfig => "CreateTaskPushNotificationConfig",
            Self::GetTaskPushNotificationConfig => "GetTaskPushNotificationConfig",
            Self::ListTaskPushNotificationConfigs => "ListTaskPushNotificationConfigs",
            Self::DeleteTaskPushNotificationConfig => "DeleteTaskPushNotificationConfig",
            Self::GetExtendedAgentCard => "GetExtendedAgentCard",
            Self::Unknown(s) => s,
        }
    }

    /// Get the family classification for this method.
    pub(crate) fn family(&self) -> A2aFamily {
        match self {
            Self::SendMessage | Self::SendStreamingMessage => A2aFamily::Message,
            Self::GetTask | Self::ListTasks | Self::CancelTask | Self::SubscribeToTask => A2aFamily::Task,
            Self::CreateTaskPushNotificationConfig
            | Self::GetTaskPushNotificationConfig
            | Self::ListTaskPushNotificationConfigs
            | Self::DeleteTaskPushNotificationConfig => A2aFamily::PushNotification,
            Self::GetExtendedAgentCard => A2aFamily::AgentCard,
            Self::Unknown(_) => A2aFamily::Unknown,
        }
    }

    /// Whether this method supports streaming responses.
    pub(crate) fn is_streaming(&self) -> bool {
        matches!(self, Self::SendStreamingMessage | Self::SubscribeToTask)
    }

    /// Whether this method should extract task ID from `params.id`.
    pub(crate) fn extracts_task_id(&self) -> bool {
        matches!(self, Self::GetTask | Self::CancelTask | Self::SubscribeToTask)
    }

    /// Whether this method should extract task ID from `params.taskId`.
    pub(crate) fn extracts_task_id_from_params(&self) -> bool {
        matches!(
            self,
            Self::CreateTaskPushNotificationConfig
                | Self::GetTaskPushNotificationConfig
                | Self::ListTaskPushNotificationConfigs
                | Self::DeleteTaskPushNotificationConfig
        )
    }
}

impl A2aFamily {
    /// String representation for headers and metadata.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Task => "task",
            Self::PushNotification => "push_notification",
            Self::AgentCard => "agent_card",
            Self::Unknown => "unknown",
        }
    }
}

// -----------------------------------------------------------------------------
// A2aEnvelope
// -----------------------------------------------------------------------------

/// Extracted A2A envelope metadata.
#[derive(Debug, Clone)]
pub(crate) struct A2aEnvelope {
    /// Classified A2A method (canonical after alias resolution).
    pub method: A2aMethod,
    /// Original method string before alias resolution (if different).
    pub original_method: Option<String>,
    /// Method family classification.
    pub family: A2aFamily,
    /// Whether the method supports streaming.
    pub streaming: bool,
    /// Task ID extracted from params, when present.
    pub task_id: Option<String>,
    /// A2A version from `A2A-Version` header, when present.
    pub version: Option<String>,
}

// -----------------------------------------------------------------------------
// Extraction
// -----------------------------------------------------------------------------

/// Extract A2A-specific metadata from a pre-parsed JSON value and request headers.
pub(crate) fn extract_a2a_envelope(
    value: &Value,
    method_str: &str,
    aliases: &BTreeMap<String, String>,
    request_headers: &http::HeaderMap,
) -> A2aEnvelope {
    let method = A2aMethod::from_method_str(method_str, aliases);

    // Track if alias resolution changed the method
    let original_method = aliases.get(method_str).map(|_| method_str.to_owned());

    let family = method.family();
    let streaming = method.is_streaming();
    let task_id = extract_task_id(value, &method);
    let version = extract_version(request_headers);

    A2aEnvelope {
        method,
        original_method,
        family,
        streaming,
        task_id,
        version,
    }
}

/// Extract task ID from params based on method requirements.
fn extract_task_id(value: &Value, method: &A2aMethod) -> Option<String> {
    let params = value.get("params")?;

    if method.extracts_task_id() {
        // Extract from params.id for task methods
        params.get("id").and_then(|v| v.as_str()).map(str::to_owned)
    } else if method.extracts_task_id_from_params() {
        // Extract from params.taskId for push notification config methods
        params.get("taskId").and_then(|v| v.as_str()).map(str::to_owned)
    } else {
        // No task ID extraction for other methods
        None
    }
}

/// Extract A2A version from `A2A-Version` request header.
fn extract_version(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("a2a-version")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}
