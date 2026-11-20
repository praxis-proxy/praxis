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

    /// Merge trusted host values into the response context.
    ///
    /// New values replace existing values with the same key while preserving
    /// every other producer's custom values.
    pub fn extend(&mut self, custom: impl IntoIterator<Item = (String, serde_json::Value)>) {
        Arc::make_mut(&mut self.custom).extend(custom);
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

    /// Return the complete custom namespace for policy-instance composition.
    pub(crate) fn custom(&self) -> Arc<HashMap<String, serde_json::Value>> {
        Arc::clone(&self.custom)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extending_context_preserves_other_producers_and_clones() {
        let mut context = PolicyResponseContext::new(HashMap::from([("existing".to_owned(), serde_json::json!(1))]));
        let earlier = context.clone();

        context.extend([("quota".to_owned(), serde_json::json!(2))]);

        assert_eq!(context.custom().get("existing"), Some(&serde_json::json!(1)));
        assert_eq!(context.custom().get("quota"), Some(&serde_json::json!(2)));
        assert!(earlier.custom().get("quota").is_none(), "clones must remain snapshots");
    }
}
