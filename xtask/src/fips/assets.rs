// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Data the FIPS tasks carry with them, compiled in from `xtask/assets/fips/`.

/// Red Hat, Inc. (release key 2), the key Red Hat signs its container images
/// with, as published at <https://access.redhat.com/security/team/key>.
pub(crate) const REDHAT_RELEASE_KEY_2: &str = include_str!("../../assets/fips/redhat-release-key-2.asc");

/// The fingerprint Red Hat publishes for that key.
pub(crate) const REDHAT_RELEASE_KEY_2_FINGERPRINT: &str = "567E347AD0044ADE55BA8A5F199E2F91FD431D51";

/// Red Hat's public registry, the only one the FIPS tasks take images from.
pub(crate) const REDHAT_REGISTRY: &str = "registry.access.redhat.com";

/// The `registries.d` entry that tells podman where Red Hat's detached
/// ("simple signing") container signatures live, Red Hat's public signature
/// store at <https://access.redhat.com/webassets/docker/content/sigstore>.
/// containers-common installs the same entry; `verify-image` checks the host
/// has one and prints this to install when it does not.
pub(crate) const REDHAT_REGISTRIES_D: &str = include_str!("../../assets/fips/registry.access.redhat.com.yaml");

/// OpenSSL configuration that activates the FIPS provider for a single
/// process. Test infrastructure only: on a FIPS-enabled host the provider
/// activates by itself, and an application must never do this.
pub(crate) const FIPS_PROVIDER_CNF: &str = include_str!("../../assets/fips/fips-provider.cnf");
