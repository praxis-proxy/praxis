// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Build script for the Praxis server.
//!
//! Discovers external filter crates via `cargo metadata` and generates
//! a registration function that calls each crate's `register_filters()`
//! at startup.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "build script: panics are the only error path; println is cargo directives"
)]

use std::{collections::HashMap, fmt::Write as _};

use cargo_metadata::{CargoOpt, DependencyKind, Metadata, NodeDep, Package, PackageId, Resolve};

/// Active Cargo feature selection for this build script invocation.
struct ActiveFeatures {
    /// Whether Cargo enabled the package's default feature set.
    default_enabled: bool,

    /// Explicit active non-default feature names.
    names: Vec<String>,
}

fn main() {
    let metadata = load_metadata();
    let crates = discover_external_filter_crates(&metadata);
    let code = generate_registration_code(&crates);
    write_generated_file(&code);
    emit_rerun_directives(&metadata);
}

/// Scan dependencies for `[package.metadata.praxis-filters]`.
fn discover_external_filter_crates(metadata: &Metadata) -> Vec<String> {
    let packages = packages_by_id(&metadata.packages);
    let resolve = metadata.resolve.as_ref().expect("no resolve graph");

    let mut crates: Vec<String> = collect_server_deps(&metadata.packages, resolve)
        .into_iter()
        .filter(|dep| is_runtime_dependency(dep))
        .filter_map(|dep| packages.get(&dep.pkg).map(|pkg| (dep, *pkg)))
        .filter(|(_, pkg)| has_praxis_filter_marker(pkg))
        // NodeDep::name is the Rust import path, including Cargo aliases and custom lib names.
        .map(|(dep, _)| dep.name.clone())
        .collect();

    crates.sort();
    crates.dedup();
    crates
}

/// Load cargo metadata, narrowed to dependencies available for the current
/// target when Cargo provides one.
fn load_metadata() -> Metadata {
    let active_features = active_features();
    let mut command = cargo_metadata::MetadataCommand::new();
    apply_active_features(&mut command, active_features);
    if let Ok(target) = std::env::var("TARGET") {
        command.other_options(vec!["--filter-platform".to_owned(), target]);
    }

    command.exec().expect("failed to run cargo metadata")
}

/// Resolve active package features from Cargo's build-script environment.
fn active_features() -> ActiveFeatures {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("failed to read package feature metadata");
    let package = metadata
        .packages
        .iter()
        .find(|pkg| pkg.name == "praxis")
        .expect("praxis package not found in metadata");

    let feature_names_by_env: HashMap<String, String> = package
        .features
        .keys()
        .map(|name| (feature_env_name(name), name.clone()))
        .collect();

    let mut names: Vec<String> = std::env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(str::to_owned))
        .filter(|name| name != "DEFAULT")
        .filter_map(|name| feature_names_by_env.get(&name).cloned())
        .collect();
    names.sort();
    names.dedup();

    ActiveFeatures {
        default_enabled: std::env::var_os("CARGO_FEATURE_DEFAULT").is_some(),
        names,
    }
}

/// Convert a Cargo feature name to the corresponding build-script env suffix.
fn feature_env_name(name: &str) -> String {
    name.replace('-', "_").to_ascii_uppercase()
}

/// Apply the current build's active feature set to a `cargo metadata` command.
fn apply_active_features(command: &mut cargo_metadata::MetadataCommand, active_features: ActiveFeatures) {
    if !active_features.default_enabled {
        command.features(CargoOpt::NoDefaultFeatures);
    }
    if !active_features.names.is_empty() {
        command.features(CargoOpt::SomeFeatures(active_features.names));
    }
}

/// Build a package lookup by package ID.
fn packages_by_id(packages: &[Package]) -> HashMap<&PackageId, &Package> {
    packages.iter().map(|pkg| (&pkg.id, pkg)).collect()
}

/// Collect dependency edges of the server crate.
fn collect_server_deps<'a>(packages: &'a [Package], resolve: &'a Resolve) -> Vec<&'a NodeDep> {
    resolve
        .nodes
        .iter()
        .find(|node| packages.iter().any(|p| p.id == node.id && p.name == "praxis"))
        .map(|node| node.deps.iter().collect())
        .unwrap_or_default()
}

/// Check whether a dependency edge is available to normal runtime code.
fn is_runtime_dependency(dep: &NodeDep) -> bool {
    dep.dep_kinds.iter().any(|kind| kind.kind == DependencyKind::Normal)
}

/// Check whether a package carries `[package.metadata.praxis-filters]`.
fn has_praxis_filter_marker(pkg: &Package) -> bool {
    pkg.metadata
        .as_object()
        .is_some_and(|obj| obj.contains_key("praxis-filters"))
}

/// Generate the `register_external_filters` function body.
fn generate_registration_code(crates: &[String]) -> String {
    let mut code = String::from(
        "/// Register all auto-discovered external filter crates.\n\
         ///\n\
         /// Generated by `build.rs` from dependencies carrying\n\
         /// `[package.metadata.praxis-filters]` in their `Cargo.toml`.\n\
         ///\n\
         /// # Panics\n\
         ///\n\
         /// Panics if any external filter name conflicts with a\n\
         /// built-in or previously registered filter.\n",
    );

    if crates.is_empty() {
        code.push_str(
            "#[expect(\n    \
             unused_variables,\n    \
             clippy::needless_pass_by_ref_mut,\n    \
             reason = \"generated: no external filters discovered\"\n\
             )]\n",
        );
    }

    code.push_str("fn register_external_filters(registry: &mut praxis_filter::FilterRegistry) {\n");

    for crate_name in crates {
        writeln!(code, "    {crate_name}::register_filters(registry);").expect("writing to String should not fail");
    }

    code.push_str("}\n");
    code
}

/// Write the generated registration code to `$OUT_DIR/external_filters.rs`.
fn write_generated_file(code: &str) {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = std::path::Path::new(&out_dir).join("external_filters.rs");
    std::fs::write(&dest, code).expect("failed to write external_filters.rs");
}

/// Tell Cargo when to re-run this build script.
fn emit_rerun_directives(metadata: &Metadata) {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");

    for manifest_path in direct_runtime_dependency_manifest_paths(metadata) {
        println!("cargo:rerun-if-changed={manifest_path}");
    }
}

/// Return manifest paths for direct runtime dependencies scanned for
/// auto-discovery.
fn direct_runtime_dependency_manifest_paths(metadata: &Metadata) -> Vec<String> {
    let packages = packages_by_id(&metadata.packages);
    let resolve = metadata.resolve.as_ref().expect("no resolve graph");

    let mut paths: Vec<String> = collect_server_deps(&metadata.packages, resolve)
        .into_iter()
        .filter(|dep| is_runtime_dependency(dep))
        .filter_map(|dep| packages.get(&dep.pkg).map(|pkg| pkg.manifest_path.to_string()))
        .collect();

    paths.sort();
    paths.dedup();
    paths
}
