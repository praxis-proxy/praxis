//! Protobuf and gRPC definitions for the Envoy external processing protocol.
//!
//! This crate compiles vendored `.proto` files from the Envoy project into
//! Rust types with [`tonic`] gRPC client and server stubs.

pub mod envoy {
    pub mod service {
        pub mod common {
            #[allow(
                missing_docs,
                unreachable_pub,
                trivial_casts,
                unused_qualifications,
                clippy::doc_markdown,
                clippy::derive_partial_eq_without_eq,
                clippy::doc_lazy_continuation,
                clippy::enum_variant_names,
                clippy::needless_borrows_for_generic_args,
                clippy::default_trait_access,
                reason = "generated protobuf code"
            )]
            pub mod v3 {
                tonic::include_proto!("envoy.service.common.v3");
            }
        }

        pub mod ext_proc {
            #[allow(
                missing_docs,
                unreachable_pub,
                trivial_casts,
                unused_qualifications,
                clippy::doc_markdown,
                clippy::derive_partial_eq_without_eq,
                clippy::doc_lazy_continuation,
                clippy::enum_variant_names,
                clippy::needless_borrows_for_generic_args,
                clippy::default_trait_access,
                reason = "generated protobuf code"
            )]
            pub mod v3 {
                tonic::include_proto!("envoy.service.ext_proc.v3");
            }
        }
    }
}
