// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pre-read error classification and client disconnect handling.
//!
//! Maps downstream body-read errors to appropriate client-facing status
//! codes, distinguishing client disconnects (408, 499) from server
//! faults (500).

use pingora_core::{ErrorType, Result};
use pingora_proxy::Session;
use praxis_filter::Rejection;
use tracing::debug;

use super::super::super::{context::PingoraRequestCtx, convert::send_rejection_for};

/// Handle an I/O error raised while pre-reading the request body for
/// `StreamBuffer` inspection.
///
/// Reading the request body pulls bytes from the downstream client, so a
/// reset, premature close, or stalled upload is client-driven, not a proxy
/// fault. Those cases return a client-closed (499) or request-timeout (408)
/// status logged at reduced severity, keeping them out of the server-error
/// rate. Any other I/O error is propagated so `fail_to_proxy` maps it to 500.
pub(super) async fn handle_pre_read_io_error(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    e: Box<pingora_core::Error>,
) -> Result<bool> {
    let Some(status) = client_disconnect_status(e.etype()) else {
        return Err(e);
    };

    debug!(error = %e, status, "client disconnected during request body pre-read");
    ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_DOWNSTREAM);
    send_rejection_for(session, Rejection::status(status), ctx).await;
    Ok(true)
}

/// Map a downstream body-read error to a client-facing status, or `None` when
/// the error is not a client disconnect and should surface as 500.
///
/// A stalled upload ([`ReadTimedout`]) becomes 408 Request Timeout; a reset or
/// premature close ([`ReadError`], [`ConnectionClosed`]) becomes 499 Client
/// Closed Request, the nginx convention for a client that vanished before the
/// response.
///
/// [`ReadTimedout`]: pingora_core::ErrorType::ReadTimedout
/// [`ReadError`]: pingora_core::ErrorType::ReadError
/// [`ConnectionClosed`]: pingora_core::ErrorType::ConnectionClosed
fn client_disconnect_status(etype: &ErrorType) -> Option<u16> {
    if matches!(etype, ErrorType::ReadTimedout) {
        return Some(408); // client stalled mid-upload
    }
    if matches!(etype, ErrorType::ReadError | ErrorType::ConnectionClosed) {
        return Some(499); // client reset or closed the connection
    }
    None
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn client_disconnect_maps_connection_closed_to_499() {
        assert_eq!(
            client_disconnect_status(&ErrorType::ConnectionClosed),
            Some(499),
            "a premature client close should map to 499 Client Closed Request"
        );
    }

    #[test]
    fn client_disconnect_maps_read_error_to_499() {
        assert_eq!(
            client_disconnect_status(&ErrorType::ReadError),
            Some(499),
            "a client connection reset should map to 499 Client Closed Request"
        );
    }

    #[test]
    fn client_disconnect_maps_read_timeout_to_408() {
        assert_eq!(
            client_disconnect_status(&ErrorType::ReadTimedout),
            Some(408),
            "a stalled upload should map to 408 Request Timeout"
        );
    }

    #[test]
    fn client_disconnect_leaves_server_faults_unclassified() {
        for etype in [
            ErrorType::InternalError,
            ErrorType::ConnectRefused,
            ErrorType::WriteError,
            ErrorType::H2Error,
        ] {
            assert_eq!(
                client_disconnect_status(&etype),
                None,
                "{etype:?} is not a downstream read disconnect and must surface as 500"
            );
        }
    }
}
