// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! [`CredentialInjectionFilter`] implementation and `HttpFilter` trait impl.

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use async_trait::async_trait;

use super::config::{ClusterCredentialConfig, CredentialInjectionConfig};
use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// ClusterCredential
// -----------------------------------------------------------------------------

/// Resolved credential for a single cluster.
struct ClusterCredential {
    /// Header name to inject.
    header: String,

    /// Full header value (prefix + credential).
    header_value: String,

    /// Whether to strip existing client values for this header.
    strip: bool,
}

// -----------------------------------------------------------------------------
// CredentialInjectionFilter
// -----------------------------------------------------------------------------

/// Injects per-cluster API credentials into upstream requests.
///
/// For each configured cluster, injects a header (e.g.
/// `Authorization: Bearer sk-...`) and optionally strips
/// client-provided values for that header to prevent
/// credential forwarding.
///
/// Credentials are resolved at construction time (inline
/// values or environment variables). The filter matches on
/// the cluster name selected by the router filter earlier
/// in the pipeline.
///
/// # YAML configuration
///
/// ```yaml
/// filter: credential_injection
/// clusters:
///   - name: openai
///     header: Authorization
///     env_var: OPENAI_API_KEY
///     header_prefix: "Bearer "
///     strip_client_credential: true
///   - name: internal
///     header: x-api-key
///     value: "internal-secret"
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::CredentialInjectionFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// clusters:
///   - name: backend
///     header: x-api-key
///     value: "secret-123"
///     strip_client_credential: true
/// "#,
/// )
/// .unwrap();
/// let filter = CredentialInjectionFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "credential_injection");
/// ```
pub struct CredentialInjectionFilter {
    /// Cluster name -> resolved credential.
    credentials: HashMap<Arc<str>, ClusterCredential>,
}

impl CredentialInjectionFilter {
    /// Create from YAML config.
    ///
    /// Resolves all credentials (inline or from environment
    /// variables) at construction time so that per-request
    /// processing is a simple map lookup.
    ///
    /// ```
    /// use praxis_filter::CredentialInjectionFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// clusters:
    ///   - name: my-cluster
    ///     header: Authorization
    ///     value: "token-abc"
    ///     header_prefix: "Bearer "
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = CredentialInjectionFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "credential_injection");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if:
    /// - `clusters` is empty
    /// - Both `value` and `env_var` are set (or neither)
    /// - An `env_var` is not set in the environment
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CredentialInjectionConfig = parse_filter_config("credential_injection", config)?;

        if cfg.clusters.is_empty() {
            return Err("credential_injection: 'clusters' must not be empty".into());
        }

        let mut credentials = HashMap::with_capacity(cfg.clusters.len());

        for cluster_cfg in &cfg.clusters {
            let credential = resolve_credential(cluster_cfg)?;
            credentials.insert(Arc::<str>::from(cluster_cfg.name.as_str()), credential);
        }

        Ok(Box::new(Self { credentials }))
    }
}

#[async_trait]
impl HttpFilter for CredentialInjectionFilter {
    fn name(&self) -> &'static str {
        "credential_injection"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(ref cluster) = ctx.cluster else {
            tracing::debug!("no cluster selected, skipping credential injection");
            return Ok(FilterAction::Continue);
        };

        let Some(cred) = self.credentials.get(cluster) else {
            tracing::debug!(cluster = %cluster, "no credentials configured for cluster");
            return Ok(FilterAction::Continue);
        };

        if cred.strip {
            tracing::debug!(
                cluster = %cluster,
                header = %cred.header,
                "stripping client-provided credential header"
            );
            ctx.extra_request_headers
                .push((Cow::Owned(cred.header.clone()), String::new()));
        }

        tracing::debug!(
            cluster = %cluster,
            header = %cred.header,
            "injecting credential header"
        );
        ctx.extra_request_headers
            .push((Cow::Owned(cred.header.clone()), cred.header_value.clone()));

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Credential Resolution
// -----------------------------------------------------------------------------

/// Resolve a cluster credential config into a ready-to-inject value.
fn resolve_credential(cfg: &ClusterCredentialConfig) -> Result<ClusterCredential, FilterError> {
    let raw_value = resolve_raw_value(cfg)?;

    let header_value = match &cfg.header_prefix {
        Some(prefix) => format!("{prefix}{raw_value}"),
        None => raw_value,
    };

    Ok(ClusterCredential {
        header: cfg.header.clone(),
        header_value,
        strip: cfg.strip_client_credential,
    })
}

/// Extract the raw credential string from config (inline or env var).
fn resolve_raw_value(cfg: &ClusterCredentialConfig) -> Result<String, FilterError> {
    match (&cfg.value, &cfg.env_var) {
        (Some(val), None) => Ok(val.clone()),
        (None, Some(var)) => std::env::var(var).map_err(|e| -> FilterError {
            format!(
                "credential_injection: environment variable '{var}' not set for cluster '{}': {e}",
                cfg.name
            )
            .into()
        }),
        (Some(_), Some(_)) => Err(format!(
            "credential_injection: cluster '{}' has both 'value' and 'env_var' set (use exactly one)",
            cfg.name
        )
        .into()),
        (None, None) => Err(format!(
            "credential_injection: cluster '{}' must have either 'value' or 'env_var'",
            cfg.name
        )
        .into()),
    }
}
