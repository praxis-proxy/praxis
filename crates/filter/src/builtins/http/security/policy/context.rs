// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Host context and plugin output for metadata-only response policy.

use std::{collections::HashMap, sync::Arc};

use ppe::praxis_policy_core::error::PluginViolation;

/// Host-provided values for a metadata-only inference response invocation.
#[derive(Clone, Debug, Default)]
pub struct PolicyResponseContext {
    /// Values exposed to PPE under `custom.*`.
    custom: Arc<HashMap<String, serde_json::Value>>,
}

impl PolicyResponseContext {
    /// Build response context from trusted host values.
    #[must_use]
    pub fn new(custom: HashMap<String, serde_json::Value>) -> Self {
        Self {
            custom: Arc::new(custom),
        }
    }

    /// Return the values exposed to response policy.
    #[must_use]
    pub(crate) fn custom(&self) -> Arc<HashMap<String, serde_json::Value>> {
        Arc::clone(&self.custom)
    }
}

/// Custom extension values returned by metadata-only response policy.
#[derive(Clone, Debug, Default)]
pub struct PolicyResponseOutput {
    /// Final custom extension namespace.
    custom: Arc<HashMap<String, serde_json::Value>>,
    /// Policy denial, when the response-phase policy rejected the context.
    violation: Option<PluginViolation>,
}

impl PolicyResponseOutput {
    /// Return one top-level custom value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.custom.get(key)
    }

    /// Return the response-phase denial, when policy rejected the context.
    #[must_use]
    pub fn violation(&self) -> Option<&PluginViolation> {
        self.violation.as_ref()
    }

    /// Build output from the policy engine's final custom namespace.
    pub(crate) fn new(custom: Arc<HashMap<String, serde_json::Value>>, violation: Option<PluginViolation>) -> Self {
        Self { custom, violation }
    }
}
