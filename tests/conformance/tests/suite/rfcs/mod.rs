// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! RFC conformance tests.
//!
//! Verifies proxy behavior against specific RFC
//! requirements. Tests are organized by RFC number and
//! section.
//!
//! - [RFC 9110]: HTTP Semantics
//! - [RFC 9112]: HTTP/1.1
//! - [RFC 9113]: HTTP/2
//! - [RFC 6265]: HTTP State Management (Cookies)
//! - [RFC 7239]: Forwarded Header
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112
//! [RFC 9113]: https://datatracker.ietf.org/doc/html/rfc9113
//! [RFC 6265]: https://datatracker.ietf.org/doc/html/rfc6265
//! [RFC 7239]: https://datatracker.ietf.org/doc/html/rfc7239

mod rfc6265;
mod rfc7239;
mod rfc9110;
mod rfc9112;
mod rfc9113;
mod test_utils;
