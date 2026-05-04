fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let proto_files = ["proto/envoy_common.proto", "proto/ext_proc.proto"]
        .iter()
        .map(|name| cwd.join(name))
        .collect::<Vec<_>>();
    let include_dirs = [cwd.join("proto")];

    let config = {
        let mut c = prost_build::Config::new();
        c.extern_path(".google.protobuf.Value", "::prost_wkt_types::Value");
        c.extern_path(".google.protobuf.Struct", "::prost_wkt_types::Struct");
        c
    };

    let fds = protox::compile(&proto_files, &include_dirs)?;
    tonic_prost_build::configure()
        .build_server(true)
        .compile_fds_with_config(fds, config)?;

    println!("cargo:rerun-if-changed=build.rs");
    for entry in walkdir(&cwd.join("proto"))? {
        println!(
            "cargo:rerun-if-changed={}",
            entry.to_str().expect("proto path is valid UTF-8")
        );
    }

    Ok(())
}

/// Recursively collect all `.proto` files under `dir`.
fn walkdir(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut protos = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            protos.extend(walkdir(&path)?);
        } else if path.extension().is_some_and(|ext| ext == "proto") {
            protos.push(path);
        }
    }
    Ok(protos)
}
