// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors
//
//! Refcounted registry of hot-reloaded upstream TLS material.
//!
//! Cluster TLS material is built during pipeline construction, and pipelines
//! are rebuilt on every config reload. A watcher spawned per build would
//! therefore duplicate: one thread per rebuild, each swapping into its own
//! copy of the material. This module prevents that with a process-global
//! registry keyed by the configured file paths.
//!
//! The key is the raw configured path strings, never canonicalized: a
//! Kubernetes projected Secret swaps its `..data` symlink to a new versioned
//! directory on rotation, so resolving the symlink would change the key and
//! split one logical material into many entries.
//!
//! Entries are [`Arc`]-shared through the [`Reloadable`] views stored on
//! [`crate::CachedClusterTls`]. When the last view drops — the pipeline
//! rebuild replaced the old pipeline — the entry sends the watcher its
//! shutdown signal and removes itself from the map. Build order (new pipeline
//! constructed before the old one is dropped) keeps the watcher alive across
//! a reload that keeps the same paths.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, OnceLock, PoisonError, Weak},
};

use arc_swap::ArcSwap;

use crate::{CachedCaCerts, CachedClientCert, ClusterTls, TlsError, watcher};

/// A live client identity slot the watcher refreshes.
type ClientCertSlot = Arc<ArcSwap<CachedClientCert>>;

/// A live CA bundle slot the watcher refreshes.
type CaSlot = Arc<ArcSwap<CachedCaCerts>>;

// -----------------------------------------------------------------------------
// UpstreamPaths
// -----------------------------------------------------------------------------

/// The file paths one upstream reload entry watches.
///
/// Compares and hashes by the raw configured strings; see the module docs
/// for why the paths are never canonicalized.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamPaths {
    /// Client certificate PEM file, when the cluster has an identity.
    cert: Option<String>,

    /// Client key PEM file, always present with `cert`.
    key: Option<String>,

    /// CA bundle PEM file, when the cluster verifies against its own CA.
    ca: Option<String>,
}

impl UpstreamPaths {
    /// Extract the watched paths from a cluster TLS config.
    fn from_config(tls: &ClusterTls) -> Self {
        let (cert, key) = tls.client_cert.as_ref().map_or((None, None), |pair| {
            (Some(pair.cert_path.clone()), Some(pair.key_path.clone()))
        });
        Self {
            cert,
            key,
            ca: tls.ca.as_ref().map(|ca| ca.ca_path.clone()),
        }
    }

    /// The watched files in digest-baseline order: certificate, key, CA.
    pub(crate) fn watched(&self) -> Vec<String> {
        let mut paths = Vec::with_capacity(3);
        if let Some(cert) = &self.cert {
            paths.push(cert.clone());
        }
        if let Some(key) = &self.key {
            paths.push(key.clone());
        }
        if let Some(ca) = &self.ca {
            paths.push(ca.clone());
        }
        paths
    }

    /// The client identity paths, when the entry watches an identity.
    pub(crate) fn client_identity(&self) -> Option<(&str, &str)> {
        match (&self.cert, &self.key) {
            (Some(cert_path), Some(key_path)) => Some((cert_path.as_str(), key_path.as_str())),
            _ => None,
        }
    }

    /// The CA bundle path, when the entry watches one.
    pub(crate) fn ca_path(&self) -> Option<&str> {
        self.ca.as_deref()
    }
}

// -----------------------------------------------------------------------------
// UpstreamEntry
// -----------------------------------------------------------------------------

/// One shared watcher plus the slots it refreshes.
///
/// Held only weakly by the registry; the strong references live in the
/// [`Reloadable`] views. Dropping the last view stops the watcher and
/// removes the entry.
pub(crate) struct UpstreamEntry {
    /// Registry key this entry removes itself under on drop.
    paths: UpstreamPaths,

    /// Live client identity slot, when the cluster has one.
    client_cert: Option<Arc<ArcSwap<CachedClientCert>>>,

    /// Live CA bundle slot, when the cluster has one.
    ca: Option<Arc<ArcSwap<CachedCaCerts>>>,

    /// Sender that stops the watcher; taken and fired on drop.
    shutdown: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}

impl UpstreamEntry {
    /// Create an entry: load the initial material, snapshot the baseline, and
    /// spawn the watcher that keeps the slots current.
    fn new(paths: UpstreamPaths) -> Result<Arc<Self>, TlsError> {
        // The baseline is taken before the load, mirroring the listener
        // startup path: a rotation landing between the two stays visible to
        // the first poll instead of being recorded as already-loaded bytes.
        let baseline = baseline_digests(&paths);
        let (client_cert, ca) = initial_material(&paths)?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher::spawn_upstream(
            watcher::UpstreamReload {
                client_cert: client_cert.clone(),
                ca: ca.clone(),
                paths: paths.clone(),
            },
            shutdown_rx,
            baseline,
        );
        Ok(Arc::new(Self {
            paths,
            client_cert,
            ca,
            shutdown: Mutex::new(Some(shutdown_tx)),
        }))
    }
}

/// Fingerprint every watched file, before the initial material load.
fn baseline_digests(paths: &UpstreamPaths) -> Vec<Option<[u8; 32]>> {
    paths.watched().iter().map(|path| watcher::file_digest(path)).collect()
}

/// Load the initial material for every configured slot.
fn initial_material(paths: &UpstreamPaths) -> Result<(Option<ClientCertSlot>, Option<CaSlot>), TlsError> {
    let client_cert = match paths.client_identity() {
        Some((cert_path, key_path)) => Some(Arc::new(ArcSwap::from_pointee(CachedClientCert::from_pem_files(
            cert_path, key_path,
        )?))),
        None => None,
    };
    let ca = paths
        .ca_path()
        .map(|ca_path| CachedCaCerts::from_pem_file(ca_path).map(|ca| Arc::new(ArcSwap::from_pointee(ca))))
        .transpose()?;
    Ok((client_cert, ca))
}

impl Drop for UpstreamEntry {
    /// Stop the watcher, then remove the stale weak reference by key.
    ///
    /// The registry map holds only a [`Weak`], so removing it here cannot
    /// drop another entry and recurse.
    fn drop(&mut self) {
        let shutdown = self.shutdown.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(shutdown) = shutdown {
            let _sent = shutdown.send(true);
        }
        registry()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.paths);
    }
}

// -----------------------------------------------------------------------------
// Reloadable
// -----------------------------------------------------------------------------

/// A live view of one hot-reloaded upstream material slot.
///
/// Loading always returns the material that is current at that moment. The
/// view also holds a strong reference to its [`UpstreamEntry`], keeping the
/// watcher alive for as long as any view exists.
pub(crate) struct Reloadable<T> {
    /// The swappable slot the watcher refreshes.
    slot: Arc<ArcSwap<T>>,

    /// The shared entry that owns the watcher.
    entry: Arc<UpstreamEntry>,
}

impl<T> Reloadable<T> {
    /// Return the material that is current right now.
    pub(crate) fn load(&self) -> Arc<T> {
        self.slot.load_full()
    }
}

impl<T> Clone for Reloadable<T> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
            entry: Arc::clone(&self.entry),
        }
    }
}

impl<T> fmt::Debug for Reloadable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Reloadable")
    }
}

// -----------------------------------------------------------------------------
// Acquire
// -----------------------------------------------------------------------------

/// Live views for every material slot a cluster TLS config declares.
pub(crate) struct UpstreamMaterial {
    /// Live client identity view, when configured.
    pub(crate) client_cert: Option<Reloadable<CachedClientCert>>,

    /// Live CA bundle view, when configured.
    pub(crate) ca: Option<Reloadable<CachedCaCerts>>,
}

/// Return live views for the material `tls` names, reusing the watcher a
/// previous build already spawned for the same paths.
///
/// The registry lock is held across the initial material load and watcher
/// spawn so two concurrent first builds of the same paths cannot each spawn
/// a watcher.
///
/// # Errors
///
/// Returns [`TlsError`] when the initial material cannot be loaded; the
/// registry is left unchanged in that case.
///
/// [`TlsError`]: crate::TlsError
#[expect(
    clippy::significant_drop_tightening,
    reason = "the map guard is held across the watcher spawn to deduplicate concurrent first builds"
)]
pub(crate) fn acquire(tls: &ClusterTls) -> Result<UpstreamMaterial, TlsError> {
    let paths = UpstreamPaths::from_config(tls);
    let mut map = registry().lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(entry) = map.get(&paths).and_then(Weak::upgrade) {
        return Ok(material(&entry));
    }
    let entry = UpstreamEntry::new(paths.clone())?;
    map.insert(paths, Arc::downgrade(&entry));
    Ok(material(&entry))
}

/// Build the live views sharing one entry's slots.
fn material(entry: &Arc<UpstreamEntry>) -> UpstreamMaterial {
    UpstreamMaterial {
        client_cert: entry.client_cert.clone().map(|slot| Reloadable {
            slot,
            entry: Arc::clone(entry),
        }),
        ca: entry.ca.clone().map(|slot| Reloadable {
            slot,
            entry: Arc::clone(entry),
        }),
    }
}

/// The process-global path-to-entry map.
fn registry() -> &'static Mutex<HashMap<UpstreamPaths, Weak<UpstreamEntry>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<UpstreamPaths, Weak<UpstreamEntry>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::{gen_ca_file, gen_test_certs};

    /// A cluster config with a client cert and CA in one temp directory.
    fn hot_reload_config() -> (ClusterTls, tempfile::TempDir) {
        let certs = gen_test_certs();
        let ca = gen_ca_file();
        let dir = tempfile::TempDir::new().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::copy(&certs.cert_path, &cert_path).unwrap();
        std::fs::copy(&certs.key_path, &key_path).unwrap();
        std::fs::copy(&ca.ca_path, &ca_path).unwrap();
        let tls = ClusterTls {
            ca: Some(crate::CaConfig {
                ca_path: ca_path.to_str().unwrap().to_owned(),
                crl_paths: Vec::new(),
            }),
            client_cert: Some(crate::CertKeyPair {
                cert_path: cert_path.to_str().unwrap().to_owned(),
                default: false,
                key_path: key_path.to_str().unwrap().to_owned(),
                server_names: Vec::new(),
            }),
            sni: None,
            verify: true,
            hot_reload: Some(true),
        };
        (tls, dir)
    }

    #[test]
    fn acquire_returns_live_material() {
        let (tls, _dir) = hot_reload_config();
        let material = acquire(&tls).unwrap();
        assert!(material.client_cert.is_some(), "client cert view should exist");
        assert!(material.ca.is_some(), "CA view should exist");
        assert!(
            !material.ca.unwrap().load().der_certs().is_empty(),
            "the live CA slot should hold the loaded bundle"
        );
    }

    #[test]
    fn acquire_reuses_one_entry_for_the_same_paths() {
        let (tls, _dir) = hot_reload_config();
        let first = acquire(&tls).unwrap();
        let first_cert = first.client_cert.as_ref().unwrap().load();
        let second = acquire(&tls).unwrap();
        let second_cert = second.client_cert.as_ref().unwrap().load();
        assert!(
            Arc::ptr_eq(&first_cert, &second_cert),
            "the same paths must share one entry and one material instance"
        );
    }

    #[test]
    fn dropping_the_last_view_tears_the_entry_down() {
        let (tls, _dir) = hot_reload_config();
        let first = acquire(&tls).unwrap();
        let first_view = first.ca.as_ref().unwrap();
        let first_slot = first_view.load();
        drop(first);
        let second = acquire(&tls).unwrap();
        let second_view = second.ca.as_ref().unwrap();
        let second_slot = second_view.load();
        assert!(
            !Arc::ptr_eq(&first_slot, &second_slot),
            "after the last view drops, a fresh acquire must build a fresh entry"
        );
    }

    #[test]
    fn distinct_paths_get_distinct_entries() {
        let (first_tls, _first_dir) = hot_reload_config();
        let (second_tls, _second_dir) = hot_reload_config();
        let first = acquire(&first_tls).unwrap();
        let second = acquire(&second_tls).unwrap();
        let first_cert = first.client_cert.as_ref().unwrap().load();
        let second_cert = second.client_cert.as_ref().unwrap().load();
        assert!(
            !Arc::ptr_eq(&first_cert, &second_cert),
            "different path sets must not share an entry"
        );
    }
}
