use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn all_example_configs_parse() {
    let root = format!("{}/../../examples/configs", env!("CARGO_MANIFEST_DIR"));
    let mut count = 0;
    for entry in walkdir(&root) {
        Config::from_file(&entry).unwrap_or_else(|e| panic!("{}: {e}", entry.display()));
        count += 1;
    }
    assert!(count > 0, "no YAML files found in {root}");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Recursively collect all `.yaml` files under `root`.
fn walkdir(root: &str) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "yaml") {
                files.push(path);
            }
        }
    }
    files
}
