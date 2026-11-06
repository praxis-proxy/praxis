// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Route owner for startup/reload capability-gate tests; never served.

#![expect(clippy::unwrap_used, reason = "startup/reload contract test setup")]

use async_trait::async_trait;
use praxis_filter::{
    FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
    local_http::{LocalBodyOwnership, LocalCompatibility, LocalMethods, LocalPath, LocalRoute},
};

/// Install an owner using only framework interfaces.
pub(crate) fn register(registry: &mut FilterRegistry) {
    registry
        .register(
            "local_test",
            FilterFactory::Http(std::sync::Arc::new(|_| {
                Ok(Box::new(Owner(vec![LocalRoute {
                    id: "test".into(),
                    methods: LocalMethods::All,
                    path: LocalPath::Exact("/local".into()),
                    body: LocalBodyOwnership::Exclusive,
                    request_limit: 536_870_912,
                    response_limit: 536_870_912,
                }])))
            })),
        )
        .unwrap();
}

/// Stable local declarations ensure validation precedes adapter installation.
struct Owner(Vec<LocalRoute>);
#[async_trait]
impl HttpFilter for Owner {
    fn name(&self) -> &'static str {
        "local_test"
    }

    fn local_http_routes(&self) -> &[LocalRoute] {
        &self.0
    }

    fn local_http_compatibility(&self) -> LocalCompatibility {
        LocalCompatibility::Policy
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// Skip flags cannot opt out of local validation or adapter capability checks.
pub(crate) fn config(open: bool) -> praxis_core::config::Config {
    praxis_core::config::Config::from_yaml(&format!(
        r#"
insecure_options:
  skip_pipeline_validation: true
  allow_open_security_filters: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: local_test
        failure_mode: {}
"#,
        if open { "open" } else { "closed" }
    ))
    .unwrap()
}
