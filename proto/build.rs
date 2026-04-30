fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let proto_files = ["proto/envoy_common.proto", "proto/ext_proc.proto"]
        .iter()
        .map(|name| cwd.join(name))
        .collect::<Vec<_>>();
    let include_dirs = [cwd.join("proto")];

    let config = {
        let mut c = prost_build::Config::new();
        c.disable_comments(Some("."));
        c.extern_path(".google.protobuf.Value", "::prost_wkt_types::Value");
        c.extern_path(".google.protobuf.Struct", "::prost_wkt_types::Struct");
        c
    };

    let fds = protox::compile(&proto_files, &include_dirs)?;
    tonic_prost_build::configure()
        .build_server(true)
        .compile_fds_with_config(fds, config)?;

    for path in [proto_files, include_dirs.to_vec()].concat() {
        println!(
            "cargo:rerun-if-changed={}",
            path.to_str().expect("proto path is valid UTF-8")
        );
    }

    Ok(())
}
