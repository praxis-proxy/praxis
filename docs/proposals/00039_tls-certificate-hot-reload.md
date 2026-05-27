---
issue: https://github.com/praxis-proxy/praxis/issues/39
status: released
authors:
  - shaneutt
stakeholders:
  - shaneutt
  - twghu
---

# TLS Certificate Hot-Reload

## What?

Zero-downtime TLS certificate rotation without process
restart. A `ReloadableCertResolver` backed by ArcSwap
serves the latest certificate to new TLS handshakes
while a background watcher monitors cert and key files
for changes.

### Goals

- Lock-free certificate swap via ArcSwap during TLS
  handshakes
- File watcher with debounce for atomic rename patterns
  (Kubernetes, certbot, ACME)
- Graceful failure handling: reload errors preserve the
  previous valid certificate
- Exponential backoff on consecutive reload failures

## Why?

### Motivation

TLS certificates loaded at startup cannot be rotated
without a full process restart. This is untenable for
modern infrastructure automation where ACME, Vault PKI,
cert-manager, and SPIFFE produce short-lived
certificates that rotate frequently. Coordinating
proxy restarts around cert rotation introduces downtime
and operational complexity.

### User Stories

- As a platform operator using cert-manager, I want
  certificates to rotate automatically so that short-
  lived certs do not cause outages.
- As an SRE managing ACME certificates, I want certbot
  renewals to take effect immediately so that I do not
  need to schedule maintenance windows.
- As a security engineer, I want failed cert reloads
  to preserve the previous certificate so that a
  transient file system error does not break TLS.

## How?

### Requirements

- `ReloadableCertResolver` implementing rustls
  `ResolvesServerCert` with ArcSwap storage
- Background cert watcher using `notify` crate
- 500ms debounce for atomic rename patterns
- Exponential backoff on consecutive failures (500ms
  base, 60s max)
- Previous certificate preserved on reload failure
- Single-cert constraint (validated at config time)

### Design

**ReloadableCertResolver.**
`ReloadableCertResolver` in `tls/src/reload.rs` holds
an `Arc<ArcSwap<CertifiedKey>>`. It implements
`ResolvesServerCert`; the `resolve()` method calls
`self.current.load_full()` (a lock-free atomic read)
and returns the latest certificate. TLS handshakes
are never blocked by concurrent certificate swaps.

**CertWatcher.**
`CertWatcher` in `tls/src/watcher.rs` spawns a
background thread with its own tokio runtime. It
monitors the parent directories of the cert and key
files using `notify::RecommendedWatcher`. File events
are sent through an mpsc channel; a full channel
discards additional events since a reload is already
pending.

**Debounce and reload.**
On the first event, the watcher sleeps for 500ms and
drains all pending channel messages. This coalesces
rapid filesystem events from atomic rename patterns
(Kubernetes secret mounts write a symlink swap,
certbot writes to a temp file then renames). After
the debounce window, the watcher loads and validates
the new cert and key from disk. On success, it calls
`current.store(Arc::new(certified))` for an atomic
swap. On failure, it logs a warning and retains the
previous certificate.

**Exponential backoff.**
The backoff starts at 500ms (matching the debounce
window). On consecutive failures, the delay doubles
up to a 60s ceiling. A successful reload resets the
backoff to the base value. This prevents tight retry
loops when certs are temporarily invalid (e.g. a
partial write or permission error).

**Supported rotation patterns.**

- **ACME (certbot)**: atomic rename of cert and key
  files. The debounce window handles the race between
  cert and key updates.
- **Kubernetes cert-manager**: projected volume mount
  with atomic symlink replacement. Directory-level
  events trigger reload.
- **Vault PKI**: external sync tool writes certs
  atomically. File modification events trigger reload.
- **SPIFFE**: workload identity agent rotates short-
  lived certs in place. File events trigger immediate
  (post-debounce) reload.

**Single-cert constraint.**
Config validation rejects `hot_reload` with multiple
`CertKeyPair` entries. The resolver stores exactly one
certificate; SNI-based cert selection is handled
separately by the static cert resolver. This
simplifies the state machine and avoids the complexity
of a concurrent cert map.
