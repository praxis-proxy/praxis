//! Protobuf and gRPC definitions for the Envoy external processing protocol.
//!
//! This crate compiles vendored `.proto` files from the Envoy project into
//! Rust types with [`tonic`] gRPC client and server stubs.

#![deny(unsafe_code)]

#[allow(
    warnings,
    missing_docs,
    unreachable_pub,
    trivial_casts,
    unused_qualifications,
    clippy::all,
    clippy::pedantic
)]
pub mod envoy {
    pub mod service {
        pub mod common {
            pub mod v3 {
                tonic::include_proto!("envoy.service.common.v3");
            }
        }

        pub mod ext_proc {
            pub mod v3 {
                tonic::include_proto!("envoy.service.ext_proc.v3");
            }
        }
    }
}
