// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Construction-time refusals for the `policy` filter: `DPoP` issuers without
//! a fixed external URL, and crypto backend failures.

use ppe::praxis_policy_core::{
    CRYPTO_FAILED_CODE,
    config::{PolicyConfig, PolicyGroup},
    error::PluginError,
    identity::RouteIdentityConfig,
};

use crate::FilterError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The plugin kind whose trusted issuers can enable `DPoP`.
const JWT_KIND: &str = "identity/jwt";

// -----------------------------------------------------------------------------
// Crypto failures
// -----------------------------------------------------------------------------

/// Map an engine load or initialization error to a construction error.
///
/// A crypto backend failure names the stable failure code and the remedy;
/// PPE has already raised the `policy_crypto_failure` alarm. Any other
/// error keeps its message.
pub(super) fn engine_error(stage: &str, config_path: &str, error: &PluginError) -> FilterError {
    match error {
        PluginError::Crypto { source } => format!(
            "policy: {stage} failed for {config_path}: the Policy crypto backend is unavailable \
             ({CRYPTO_FAILED_CODE}: {source}); configure the OpenSSL provider, and for FIPS JWT \
             `default_properties = fips=yes`, before praxis starts"
        )
        .into(),
        other => format!("policy: {stage} failed for {config_path}: {other}").into(),
    }
}

// -----------------------------------------------------------------------------
// DPoP issuers
// -----------------------------------------------------------------------------

/// Refuse a JWT trusted issuer that enables `DPoP` without
/// `dpop.external_base_url`.
///
/// Without it the proof's `htu` is compared against a URL rebuilt from the
/// client-sent `Host` header. Checks each JWT plugin's `config:` and every
/// `authentication:` step override naming one, since an override replaces
/// `trusted_issuers` wholesale.
///
/// # Errors
///
/// Returns a [`FilterError`] naming the plugin and the issuer.
pub(super) fn require_dpop_external_base_url(policy: &PolicyConfig) -> Result<(), FilterError> {
    let jwt_plugins: Vec<&str> = policy
        .plugins
        .iter()
        .filter(|plugin| plugin.kind == JWT_KIND)
        .map(|plugin| plugin.name.as_str())
        .collect();
    for plugin in policy.plugins.iter().filter(|plugin| plugin.kind == JWT_KIND) {
        check_issuers(&plugin.name, plugin.config.as_ref())?;
    }
    for step in authentication_blocks(policy).flat_map(|block| block.steps.iter()) {
        if jwt_plugins.contains(&step.name.as_str()) {
            check_issuers(&step.name, step.config_override.as_ref())?;
        }
    }
    Ok(())
}

/// Every `authentication:` block in the document: global, entity defaults,
/// groups and routes.
fn authentication_blocks(policy: &PolicyConfig) -> impl Iterator<Item = &RouteIdentityConfig> {
    let global = &policy.global;
    let groups = global
        .bundles
        .values()
        .chain(global.defaults.values())
        .chain(policy.groups.values())
        .filter_map(|group: &PolicyGroup| group.authentication.as_ref());
    global
        .authentication
        .iter()
        .chain(groups)
        .chain(policy.routes.iter().filter_map(|route| route.authentication.as_ref()))
}

/// Check the `trusted_issuers` of one JWT plugin config, if it has any.
fn check_issuers(plugin: &str, config: Option<&serde_json::Value>) -> Result<(), FilterError> {
    let issuers = config
        .and_then(|config| config.get("trusted_issuers"))
        .and_then(serde_json::Value::as_array);
    for issuer in issuers.into_iter().flatten() {
        if dpop_enabled(issuer) && !has_external_base_url(issuer) {
            let name = issuer
                .get("issuer")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unnamed>");
            return Err(format!(
                "policy: plugin '{plugin}' trusted_issuer '{name}' enables DPoP without \
                 dpop.external_base_url; set it to the URL clients address (for example \
                 `https://api.example.com`) so the proof's `htu` does not depend on the \
                 client-sent Host header"
            )
            .into());
        }
    }
    Ok(())
}

/// Whether the issuer's `dpop.mode` is anything but absent or `off`.
fn dpop_enabled(issuer: &serde_json::Value) -> bool {
    issuer
        .get("dpop")
        .and_then(|dpop| dpop.get("mode"))
        .is_some_and(|mode| mode.as_str() != Some("off"))
}

/// Whether the issuer sets a non-empty `dpop.external_base_url`.
fn has_external_base_url(issuer: &serde_json::Value) -> bool {
    issuer
        .get("dpop")
        .and_then(|dpop| dpop.get("external_base_url"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|base| !base.is_empty())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use super::{
        super::{
            feature_tests::{filter_config, write_policy},
            filter::PolicyFilter,
            register_policy_plugin_factory,
        },
        require_dpop_external_base_url,
    };

    /// A JWT plugin whose one issuer carries `dpop`.
    fn policy(dpop: &str, extra: &str) -> String {
        format!(
            "plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      trusted_issuers:
        - issuer: https://idp.test.local
          audiences: [api]
          algorithms: [RS256]
          decoding_key: {{ kind: pem_file, path: /unused.pem }}
          {dpop}
{extra}"
        )
    }

    /// The refusal for `yaml`, if any.
    fn refusal(yaml: &str) -> Option<String> {
        let parsed = ppe::praxis_policy_core::config::parse_config(yaml).expect("the fixture parses");
        require_dpop_external_base_url(&parsed)
            .err()
            .map(|error| error.to_string())
    }

    #[test]
    fn a_dpop_issuer_without_an_external_base_url_is_refused_by_name() {
        for mode in ["optional", "required"] {
            let error = refusal(&policy(&format!("dpop: {{ mode: {mode} }}"), ""))
                .expect("a DPoP issuer without external_base_url must be refused");
            assert!(
                error.contains("'jwt-user'")
                    && error.contains("'https://idp.test.local'")
                    && error.contains("dpop.external_base_url"),
                "the refusal must name the plugin, the issuer and the setting: {error}"
            );
        }
    }

    #[test]
    fn a_dpop_issuer_with_an_external_base_url_is_accepted() {
        let yaml = policy(
            "dpop: { mode: required, external_base_url: \"https://api.example.com\" }",
            "",
        );
        assert_eq!(refusal(&yaml), None, "a DPoP issuer with a base URL must load");
    }

    #[test]
    fn issuers_without_dpop_are_accepted() {
        assert_eq!(refusal(&policy("", "")), None, "an issuer without dpop must load");
        assert_eq!(
            refusal(&policy("dpop: { mode: off }", "")),
            None,
            "an issuer with dpop off must load"
        );
    }

    #[test]
    fn a_route_override_enabling_dpop_without_a_base_url_is_refused() {
        let route = "routes:
  - tool: echo
    authentication:
      - name: jwt-user
        config:
          trusted_issuers:
            - issuer: https://route.test.local
              audiences: [api]
              algorithms: [RS256]
              decoding_key: { kind: pem_file, path: /unused.pem }
              dpop: { mode: required }
";
        let error = refusal(&policy("", route)).expect("an override enabling DPoP must be checked");
        assert!(
            error.contains("'https://route.test.local'"),
            "the refusal must name the override's issuer: {error}"
        );
    }

    #[test]
    fn construction_refuses_a_dpop_issuer_without_an_external_base_url() {
        let (_dir, path) = write_policy(&policy("dpop: { mode: required }", ""));
        let Err(error) = PolicyFilter::new(filter_config(path), None) else {
            panic!("a DPoP issuer without external_base_url must fail construction");
        };
        let error = error.to_string();
        assert!(
            error.contains("'jwt-user'") && error.contains("dpop.external_base_url"),
            "construction must refuse before any plugin is built and name the plugin: {error}"
        );
    }

    #[test]
    fn a_crypto_failure_while_loading_fails_construction_with_the_crypto_code() {
        register_policy_plugin_factory(
            "test/crypto-create-failing",
            Arc::new(|| -> Box<dyn ppe::PluginFactory> { Box::new(CryptoFailingFactory) }),
        );
        let yaml =
            "plugins:\n  - name: failing\n    kind: test/crypto-create-failing\n    hooks: [cmf.tool_pre_invoke]\n";
        let (_dir, path) = write_policy(yaml);
        let Err(error) = PolicyFilter::new(filter_config(path), None) else {
            panic!("a crypto failure while building plugins must fail construction");
        };
        let error = error.to_string();
        assert!(
            error.contains(ppe::CRYPTO_FAILED_CODE) && error.contains("OpenSSL provider"),
            "a crypto failure must name the failure code and the remedy: {error}"
        );
    }

    /// A host factory whose construction fails the way a missing crypto
    /// provider does.
    struct CryptoFailingFactory;

    impl ppe::PluginFactory for CryptoFailingFactory {
        fn create(
            &self,
            _config: &ppe::prelude::PluginConfig,
        ) -> Result<ppe::PluginInstance, Box<ppe::prelude::PluginError>> {
            Err(Box::new(ppe::prelude::PluginError::Crypto {
                source: ppe::CryptoError::DigestLength,
            }))
        }
    }
}
