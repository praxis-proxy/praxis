// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips signature-store`: where podman looks for Red Hat's
//! container image signatures, and how to point it there on hosts whose
//! podman packaging never did.
//!
//! podman fetches Red Hat's detached ("simple signing") signatures from the
//! store its registries.d (containers-registries.d(5)) names for the
//! registry. Without an entry every Red Hat image looks unsigned, and a
//! policy that requires Red Hat's signature rejects all of them. Fedora and
//! RHEL ship the entry in `/etc/containers/registries.d`; Debian and Ubuntu,
//! GitHub's ubuntu runners included, ship no registries.d at all.
//!
//! The entry is compiled in (`assets::REDHAT_REGISTRIES_D`). `--install`
//! writes it to the user's `~/.config/containers/registries.d`, which podman
//! reads for the current user without root, and only when the directory
//! podman reads names no store already.

use std::path::{Path, PathBuf};

use clap::Parser;

use super::assets::{self, REDHAT_REGISTRY as REGISTRY};

/// The file name containers-common uses for this entry.
const FILE_NAME: &str = "registry.access.redhat.com.yaml";

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask fips signature-store`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Install the bundled entry for the current user when the registries.d
    /// podman reads names no signature store for Red Hat's registry.
    #[arg(long)]
    install: bool,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Report whether podman can find Red Hat's signatures, installing the entry
/// on request; exit 1 when it cannot and nothing was installed.
pub(crate) fn run(args: &Args) {
    let dirs = Dirs::host();
    let result = if args.install {
        install(&dirs)
    } else {
        check(dirs.selected())
    };
    if let Err(reason) = result {
        eprintln!("fips-signature-store: FAIL: {reason}");
        std::process::exit(1);
    }
}

// -----------------------------------------------------------------------------
// Directories
// -----------------------------------------------------------------------------

/// The two registries.d directories containers-registries.d(5) knows. podman
/// reads the user's when it exists, else the system's, never both.
struct Dirs {
    /// `~/.config/containers/registries.d`; `None` without a home directory.
    user: Option<PathBuf>,
    /// `/etc/containers/registries.d`.
    system: PathBuf,
}

impl Dirs {
    /// The host's directories.
    fn host() -> Self {
        Self {
            user: std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/containers/registries.d")),
            system: PathBuf::from("/etc/containers/registries.d"),
        }
    }

    /// The directory podman reads.
    fn selected(&self) -> &Path {
        self.user.as_deref().filter(|dir| dir.is_dir()).unwrap_or(&self.system)
    }
}

/// The registries.d podman reads on this host.
pub(super) fn registries_d() -> PathBuf {
    Dirs::host().selected().to_path_buf()
}

// -----------------------------------------------------------------------------
// Checks
// -----------------------------------------------------------------------------

/// Whether `dir` names a signature store for Red Hat's registry. A directory
/// that does not exist names none; any other failure to read it is an error.
pub(super) fn configured(dir: &Path) -> Result<bool, String> {
    Ok(yaml_files(dir)?
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .any(|text| names_signature_store(&text)))
}

/// Why podman cannot find Red Hat's signatures with this `dir`, and what to
/// do about it.
pub(super) fn missing(dir: &Path) -> String {
    let state = if dir.is_dir() {
        format!("names no signature store for {REGISTRY}")
    } else {
        "does not exist".to_owned()
    };
    format!(
        "{} {state}, so podman cannot find Red Hat's image signatures; run `make fips-signature-store` (cargo xtask \
         fips signature-store --install) to install the bundled entry for the current user, or install it \
         system-wide as /etc/containers/registries.d/{FILE_NAME}:\n{}",
        dir.display(),
        assets::REDHAT_REGISTRIES_D
    )
}

/// Pass when `dir` names the store, fail with the instructions when not.
fn check(dir: &Path) -> Result<(), String> {
    if !configured(dir)? {
        return Err(missing(dir));
    }
    println!(
        "fips-signature-store: ok: {} names a signature store for {REGISTRY}",
        dir.display()
    );
    Ok(())
}

/// The `.yaml` files in a registries.d, none for a directory that does not
/// exist.
fn yaml_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("cannot read {}: {err}", dir.display())),
    };
    Ok(entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yaml"))
        .collect())
}

/// Whether a registries.d file gives Red Hat's registry a signature store.
fn names_signature_store(text: &str) -> bool {
    text.contains(&format!("{REGISTRY}:")) && (text.contains("lookaside:") || text.contains("sigstore:"))
}

// -----------------------------------------------------------------------------
// Install
// -----------------------------------------------------------------------------

/// Install the bundled entry for the current user, unless the directory
/// podman reads names a store already.
fn install(dirs: &Dirs) -> Result<(), String> {
    let selected = dirs.selected();
    if configured(selected)? {
        println!(
            "fips-signature-store: ok: {} already names a signature store for {REGISTRY}, nothing to install",
            selected.display()
        );
        return Ok(());
    }
    let user = dirs.user.as_deref().ok_or_else(|| no_home(&dirs.system))?;
    conflicts(user)?;
    let shadows = !user.is_dir() && dirs.system.is_dir();
    let file = write_entry(user)?;
    println!("fips-signature-store: installed {}", file.display());
    if shadows {
        println!(
            "fips-signature-store: note: podman reads {} instead of {} from now on (containers-registries.d(5)); copy \
             over any entry from there that you still need",
            user.display(),
            dirs.system.display()
        );
    }
    Ok(())
}

/// Without a home directory there is no per-user registries.d, so the entry
/// has to go into the system one by hand.
fn no_home(system: &Path) -> String {
    format!(
        "HOME is not set, so there is no per-user registries.d to install into; install the entry system-wide as \
         {}/{FILE_NAME}:\n{}",
        system.display(),
        assets::REDHAT_REGISTRIES_D
    )
}

/// Create the user's registries.d and write the entry into it.
fn write_entry(user: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(user).map_err(|err| format!("cannot create {}: {err}", user.display()))?;
    let file = user.join(FILE_NAME);
    std::fs::write(&file, assets::REDHAT_REGISTRIES_D)
        .map_err(|err| format!("cannot write {}: {err}", file.display()))?;
    Ok(file)
}

/// A file in `dir` that already configures Red Hat's registry, just without
/// a store, has to be fixed by hand: podman refuses two files configuring
/// the same registry, so installing a second one would break it.
fn conflicts(dir: &Path) -> Result<(), String> {
    let registry = format!("{REGISTRY}:");
    let configures = |path: &PathBuf| std::fs::read_to_string(path).is_ok_and(|text| text.contains(&registry));
    yaml_files(dir)?.into_iter().find(configures).map_or(Ok(()), |path| {
        Err(format!(
            "{} already configures {REGISTRY} without a signature store; podman allows one configuration per \
                 registry, so add the store there instead:\n{}",
            path.display(),
            assets::REDHAT_REGISTRIES_D
        ))
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A user and a system directory under one temporary root, neither
    /// created yet.
    fn dirs(root: &Path) -> Dirs {
        Dirs {
            user: Some(root.join("user")),
            system: root.join("system"),
        }
    }

    #[test]
    fn podman_reads_the_user_directory_only_when_it_exists() {
        let root = tempfile::tempdir().expect("temp dir");
        let dirs = dirs(root.path());
        assert_eq!(
            dirs.selected(),
            root.path().join("system"),
            "no user directory: the system one"
        );
        std::fs::create_dir_all(root.path().join("user")).expect("create");
        assert_eq!(
            dirs.selected(),
            root.path().join("user"),
            "the user directory replaces it"
        );
    }

    #[test]
    fn a_store_is_configured_only_by_an_entry_for_red_hats_registry() {
        let root = tempfile::tempdir().expect("temp dir");
        let dir = root.path().join("registries.d");
        assert_eq!(configured(&dir), Ok(false), "a missing directory configures nothing");
        assert!(missing(&dir).contains("does not exist"), "and the reason says so");
        std::fs::create_dir(&dir).expect("create");
        assert_eq!(configured(&dir), Ok(false), "an empty directory configures nothing");
        assert!(
            missing(&dir).contains("names no signature store"),
            "and the reason says so"
        );
        std::fs::write(
            dir.join("other.yaml"),
            "docker:\n  registry.redhat.io:\n    lookaside: x\n",
        )
        .expect("write");
        assert_eq!(configured(&dir), Ok(false), "another registry's entry does not count");
        std::fs::write(dir.join("any-name.yaml"), assets::REDHAT_REGISTRIES_D).expect("write");
        assert_eq!(configured(&dir), Ok(true), "the bundled entry, under any file name");
        assert!(
            missing(&dir).contains(assets::REDHAT_REGISTRIES_D),
            "the instructions carry the entry to install"
        );
    }

    #[test]
    fn install_writes_the_entry_for_the_user_when_podman_has_none() {
        let root = tempfile::tempdir().expect("temp dir");
        let dirs = dirs(root.path());
        install(&dirs).expect("install");
        let file = root.path().join("user").join(FILE_NAME);
        assert_eq!(
            std::fs::read_to_string(&file).expect("read"),
            assets::REDHAT_REGISTRIES_D,
            "the bundled entry, verbatim"
        );
        assert_eq!(
            configured(dirs.selected()),
            Ok(true),
            "podman now reads the user directory"
        );
        install(&dirs).expect("a second install has nothing to do");
    }

    #[test]
    fn install_leaves_a_host_alone_whose_system_directory_has_the_entry() {
        let root = tempfile::tempdir().expect("temp dir");
        let dirs = dirs(root.path());
        std::fs::create_dir_all(&dirs.system).expect("create");
        std::fs::write(dirs.system.join(FILE_NAME), assets::REDHAT_REGISTRIES_D).expect("write");
        install(&dirs).expect("nothing to do");
        assert!(
            !root.path().join("user").exists(),
            "no user directory is created: it would shadow the system one"
        );
    }

    #[test]
    fn install_refuses_to_add_a_second_configuration_for_the_registry() {
        let root = tempfile::tempdir().expect("temp dir");
        let dirs = dirs(root.path());
        let user = root.path().join("user");
        std::fs::create_dir_all(&user).expect("create");
        std::fs::write(
            user.join("mine.yaml"),
            "docker:\n  registry.access.redhat.com:\n    use-sigstore-attachments: true\n",
        )
        .expect("write");
        let err = install(&dirs).expect_err("podman allows one configuration per registry");
        assert!(err.contains("mine.yaml"), "names the file to fix: {err}");
        assert!(!user.join(FILE_NAME).exists(), "nothing was written");
    }

    #[test]
    fn install_needs_a_home_directory() {
        let root = tempfile::tempdir().expect("temp dir");
        let dirs = Dirs {
            user: None,
            system: root.path().join("system"),
        };
        let err = install(&dirs).expect_err("nowhere to install");
        assert!(err.contains("HOME"), "{err}");
        assert!(
            err.contains(assets::REDHAT_REGISTRIES_D),
            "the system-wide alternative is spelled out"
        );
    }
}
