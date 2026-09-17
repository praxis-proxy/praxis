// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Per-request compression levels and upstream response eligibility.

use pingora_core::{
    modules::http::{HttpModuleCtx, compression::ResponseCompression},
    protocols::http::compression::Algorithm,
};
use pingora_proxy::Session;
use praxis_filter::CompressionConfig;
use tracing::debug;

/// Configure before Pingora parses Accept-Encoding or writes a synthetic response.
pub(super) fn configure_compression(modules: &mut HttpModuleCtx, compression: Option<&CompressionConfig>) {
    let Some(module) = modules.get_mut::<ResponseCompression>() else {
        return;
    };

    // A reload may remove compression; never inherit startup levels. Algorithms
    // not configured by Praxis also stay disabled.
    module.adjust_level(0);
    if let Some(cfg) = compression {
        for (algorithm, level) in effective_levels(cfg) {
            module.adjust_algorithm_level(algorithm, level);
        }
    }
}

/// Disable compression for upstream responses outside the configured policy.
pub(super) fn adjust_compression(
    session: &mut Session,
    upstream_response: &pingora_http::ResponseHeader,
    compression: Option<&CompressionConfig>,
) {
    // Informational headers do not describe the final body. Pingora keeps its
    // compression context in the header phase until the final response arrives.
    if upstream_response.status.is_informational() {
        return;
    }
    if compression.is_some_and(|cfg| cfg.should_compress(&upstream_response.headers)) {
        return;
    }
    if let Some(module) = session.downstream_modules_ctx.get_mut::<ResponseCompression>() {
        debug!("disabling compression: response does not qualify");
        module.adjust_level(0);
    }
}

/// Clamp at the encoder boundary, including configs built through the Rust API.
fn effective_levels(cfg: &CompressionConfig) -> [(Algorithm, u32); 3] {
    [
        (Algorithm::Gzip, cfg.gzip_enabled, cfg.gzip_level, 9),
        (Algorithm::Brotli, cfg.brotli_enabled, cfg.brotli_level, 11),
        (Algorithm::Zstd, cfg.zstd_enabled, cfg.zstd_level, 22),
    ]
    .map(|(algorithm, enabled, level, maximum)| {
        (
            algorithm,
            if enabled {
                level.unwrap_or(cfg.default_level).min(maximum)
            } else {
                0
            },
        )
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use bytes::Bytes;
    use pingora_core::modules::http::{HttpModules, compression::ResponseCompressionBuilder};
    use pingora_http::{RequestHeader, ResponseHeader};

    use super::*;

    #[test]
    fn shared_levels_are_clamped_independently_for_every_algorithm() {
        for default_level in (0..=22).chain([u32::MAX]) {
            let cfg = CompressionConfig {
                default_level,
                ..Default::default()
            };
            assert_eq!(
                effective_levels(&cfg),
                [
                    (Algorithm::Gzip, default_level.min(9)),
                    (Algorithm::Brotli, default_level.min(11)),
                    (Algorithm::Zstd, default_level.min(22)),
                ],
                "shared level {default_level} must respect each encoder's own range"
            );
        }
    }

    #[test]
    fn overrides_zero_and_disablement_take_precedence_over_shared_level() {
        for default_level in [0, 6, 22] {
            let mut cfg = CompressionConfig {
                default_level,
                gzip_level: Some(1),
                brotli_level: Some(4),
                zstd_level: Some(3),
                ..Default::default()
            };
            assert_eq!(
                effective_levels(&cfg),
                [(Algorithm::Gzip, 1), (Algorithm::Brotli, 4), (Algorithm::Zstd, 3)]
            );
            cfg.gzip_level = Some(0);
            cfg.brotli_level = Some(0);
            cfg.zstd_level = Some(0);
            assert!(
                effective_levels(&cfg).iter().all(|(_, level)| *level == 0),
                "explicit zero must disable compression"
            );
            cfg.gzip_level = Some(1);
            cfg.brotli_level = Some(4);
            cfg.zstd_level = Some(3);
            cfg.gzip_enabled = false;
            cfg.brotli_enabled = false;
            cfg.zstd_enabled = false;
            assert!(
                effective_levels(&cfg).iter().all(|(_, level)| *level == 0),
                "disablement must win over explicit levels"
            );
        }
    }

    #[test]
    fn rust_api_overrides_cannot_exceed_encoder_limits() {
        let cfg = CompressionConfig {
            gzip_level: Some(u32::MAX),
            brotli_level: Some(u32::MAX),
            zstd_level: Some(u32::MAX),
            ..Default::default()
        };
        assert_eq!(
            effective_levels(&cfg),
            [(Algorithm::Gzip, 9), (Algorithm::Brotli, 11), (Algorithm::Zstd, 22)]
        );
    }

    #[test]
    fn configured_module_uses_each_algorithms_clamped_encoder() {
        let body = Bytes::from("compression regression: full payload integrity\n".repeat(32));
        let cfg = CompressionConfig {
            default_level: 22,
            ..Default::default()
        };
        for (algorithm, level) in [(Algorithm::Gzip, 9), (Algorithm::Brotli, 11), (Algorithm::Zstd, 22)] {
            let mut modules = HttpModules::new();
            modules.add_module(ResponseCompressionBuilder::enable(0));
            let mut modules = modules.build_ctx();
            configure_compression(&mut modules, Some(&cfg));
            let module = modules.get_mut::<ResponseCompression>().unwrap();
            let mut request = RequestHeader::build("GET", b"/", None).unwrap();
            request.insert_header("accept-encoding", algorithm.as_str()).unwrap();
            module.request_filter(&request);
            let mut response = ResponseHeader::build(200, None).unwrap();
            response.insert_header("content-type", "text/plain").unwrap();
            module.response_header_filter(&mut response, false);
            assert_eq!(response.headers.get("content-encoding").unwrap(), algorithm.as_str());
            let encoded = module.response_body_filter(Some(&body), true).unwrap();
            let expected = algorithm.compressor(level).unwrap().encode(&body, true).unwrap();
            assert_eq!(encoded, expected, "{algorithm:?} must use level {level}");
        }
    }

    #[test]
    fn removed_configuration_disables_all_startup_algorithms() {
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(22));
        let mut modules = modules.build_ctx();
        configure_compression(&mut modules, None);
        assert!(!modules.get_mut::<ResponseCompression>().unwrap().is_enabled());
    }
}
