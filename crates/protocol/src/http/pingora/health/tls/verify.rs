// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The cluster verify:false exception, preserving handshake signature checks.

use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, Error, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// Skip server identity checks only, matching the upstream connector's opt-out.
#[derive(Debug)]
pub(super) struct SkipServerIdentity {
    /// Standard signature verification and provider-supported algorithms.
    delegate: Arc<WebPkiServerVerifier>,
}

impl SkipServerIdentity {
    /// Wrap the normal verifier for a cluster that explicitly disables verification.
    pub(super) fn new(delegate: Arc<WebPkiServerVerifier>) -> Self {
        Self { delegate }
    }
}

impl ServerCertVerifier for SkipServerIdentity {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}
