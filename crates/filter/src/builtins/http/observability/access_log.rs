// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Structured access log filter with configurable format, field selection,
//! sampling, header projection, and emit-time conditions.

#![allow(clippy::missing_docs_in_private_items, reason = "internal emit plan types")]

#[cfg(feature = "access-log-syslog")]
use std::net::{SocketAddr, ToSocketAddrs as _};
#[cfg(feature = "access-log-syslog")]
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    fs::OpenOptions,
    io::BufWriter,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
#[cfg(feature = "access-log-syslog")]
use chrono::Local;
use chrono::{DateTime, SecondsFormat, Utc};
use http::header::HeaderName;
use serde::Deserialize;
#[cfg(feature = "access-log-syslog")]
use syslog::{Formatter3164, LogFormat, Logger, LoggerBackend, Severity};
use tracing::info;

use crate::{
    BodyAccess, FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    path_match::path_prefix_matches,
};

// -----------------------------------------------------------------------------
// AccessLogFilter
// -----------------------------------------------------------------------------

/// Logs structured access records for each request and response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: access_log
/// sample_rate: 0.1   # optional; log ~10% of requests (default 1.0)
/// fields:            # optional; replaces default ten fields when present
///   - method
///   - path
///   - status
///   - duration_ms
///   - request_header.user-agent
///   - trace_id
/// request_headers: [user-agent]   # optional; pairs with request_header.* tokens
/// response_headers: [content-type]
/// conditions:                   # optional emit-time gates (AND across keys)
///   min_duration_ms: 1000
///   status_classes: [4xx, 5xx]  # OR within list
///   paths: ["/api"]             # OR within list; segment-boundary prefixes
/// sink:                         # optional; default emits via the subscriber
///   type: file                  # `stdout` or `file`
///   path: /var/log/praxis/access.log  # required for `file`, rejected for `stdout`
/// ```
///
/// # Template YAML
///
/// ```yaml
/// filter: access_log
/// # Mutually exclusive with `fields`; quote client-controlled tokens.
/// template: '{method} {path} [{status}] {duration_ms}ms ua="{request_header.user-agent}"'
/// request_headers: [user-agent]
/// ```
///
/// When `fields` is omitted, the default ten fields are emitted:
/// `method`, `path`, `client_ip`, `status`, `duration_ms`, `cluster`,
/// `upstream`, `request_id`, `request_body_bytes`, `response_body_bytes`.
///
/// When `template` is set, the rendered string is logged as the `line` field of
/// the `access` event; `PRAXIS_LOG_FORMAT` still decides whether the subscriber
/// writes text or JSON. Otherwise the record is a field projection. Each resolved
/// value is control-character sanitized and has `"` and `\` escaped, so quote
/// client-controlled tokens (`{request_header.*}`, `{request_id}`) in the
/// template to keep fields unambiguous.
///
/// Template tokens follow the same names as field tokens: `{method}`,
/// `{path}`, `{client_ip}`, `{status}`, `{duration_ms}`, `{cluster}`,
/// `{upstream}`, `{request_id}`, `{request_body_bytes}`,
/// `{response_body_bytes}`, `{trace_id}`, `{span_id}`,
/// `{request_header.user-agent}`, `{response_header.content-type}`.
///
/// Pipeline `conditions` / `response_conditions` on the filter entry still gate
/// whether this filter runs; access-log `conditions` are evaluated at emit time.
/// Both layers must pass when configured.
///
/// # Example
///
/// ```ignore
/// use praxis_filter::AccessLogFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
/// let filter = AccessLogFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "access_log");
/// ```
pub struct AccessLogFilter {
    /// Monotonic counter for deterministic sampling.
    counter: AtomicU64,

    /// Fraction of requests to log, in `(0.0, 1.0]`; `1.0` logs everything.
    sample_rate: f64,

    /// Selected fields, format shape, and header projections.
    emit_plan: EmitPlan,

    /// Emit-time gates evaluated after the response is known.
    emit_conditions: Option<AccessLogEmitConditions>,

    /// Whether response headers must be cached for emit.
    needs_response_headers: bool,

    /// Where emitted records are written (tracing by default).
    sink: RuntimeSink,
}

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the access log filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessLogConfig {
    /// Fraction of requests to log (0.0, 1.0]. Defaults to 1.0.
    #[serde(default = "default_sample_rate")]
    sample_rate: f64,

    /// Scalar field tokens; replaces the default ten when present.
    /// Mutually exclusive with `template`.
    fields: Option<Vec<serde_yaml::Value>>,

    /// Request header names allowed for `request_header.<name>` tokens.
    request_headers: Option<Vec<String>>,

    /// Response header names allowed for `response_header.<name>` tokens.
    response_headers: Option<Vec<String>>,

    /// Emit-time conditions (AND across keys).
    conditions: Option<AccessLogEmitConditions>,

    /// Text template with `{field}` placeholders. The rendered string is logged
    /// as the `line` field of the `access` event, and `PRAXIS_LOG_FORMAT` still
    /// decides text or JSON output. Mutually exclusive with `fields`.
    template: Option<String>,

    /// Output sink: `{type: stdout}`, `{type: file, path: ...}`, or (with the
    /// `access-log-syslog` feature) `{type: syslog, ...}`. Omitted means emit
    /// through the tracing subscriber.
    #[serde(default)]
    sink: Option<SinkConfig>,
}

/// Output sink configuration.
///
/// Deserialized via [`RawSinkConfig`] so serde rejects unknown fields and the
/// invalid `(type, path)` pairings during deserialization, leaving a resolved
/// enum whose variants carry exactly the fields valid for each sink.
#[derive(Debug, Deserialize)]
#[serde(try_from = "RawSinkConfig")]
enum SinkConfig {
    /// Write NDJSON lines to stdout, bypassing tracing.
    Stdout,
    /// Append NDJSON lines to a file (no rotation).
    File {
        /// Destination path, opened in append+create mode.
        path: String,
    },
    /// Send each line as an RFC 3164 syslog message over a local socket, UDP, or TCP.
    #[cfg(feature = "access-log-syslog")]
    Syslog {
        /// Syslog facility encoded in the message PRI header.
        facility: SyslogFacility,
        /// Resolved transport destination.
        target: SyslogDestination,
    },
}

/// Resolved syslog destination; the `(transport, address, path)` pairing is
/// validated in [`SinkConfig::try_syslog`] during deserialization.
#[cfg(feature = "access-log-syslog")]
#[derive(Clone, Debug)]
enum SyslogDestination {
    /// Local `AF_UNIX` socket; `None` path means `/dev/log`.
    Unix {
        /// Socket path override (`None` means `/dev/log`).
        path: Option<String>,
    },
    /// Remote UDP datagram target (RFC 5426).
    Udp {
        /// Collector `host:port`.
        address: String,
    },
    /// Remote TCP stream target (RFC 6587).
    Tcp {
        /// Collector `host:port`.
        address: String,
    },
}

/// Sink config exactly as written in YAML, before validation into
/// [`SinkConfig`]. Keeps `#[serde(deny_unknown_fields)]` so a stray key is still
/// rejected (an internally tagged enum would silently ignore it).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSinkConfig {
    /// Sink kind (`stdout`, `file`, or `syslog` with the `access-log-syslog`
    /// feature).
    #[serde(rename = "type")]
    kind: SinkKind,

    /// File path; required for `file`, rejected for `stdout`. Doubles as the
    /// local socket path override for `syslog` + `transport: unix`.
    #[serde(default)]
    path: Option<String>,

    /// Syslog transport. Only valid for `type: syslog`; defaults to `unix`.
    #[cfg(feature = "access-log-syslog")]
    #[serde(default)]
    transport: Option<SyslogTransport>,

    /// Remote `host:port` for `syslog` with `transport: udp`/`tcp`.
    #[cfg(feature = "access-log-syslog")]
    #[serde(default)]
    address: Option<String>,

    /// Syslog facility. Only valid for `type: syslog`; defaults to `user`.
    #[cfg(feature = "access-log-syslog")]
    #[serde(default)]
    facility: Option<SyslogFacility>,
}

/// Direct output sink kind discriminant.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SinkKind {
    /// Write NDJSON lines to stdout.
    Stdout,
    /// Append NDJSON lines to a file.
    File,
    /// Send lines as syslog messages.
    #[cfg(feature = "access-log-syslog")]
    Syslog,
}

impl TryFrom<RawSinkConfig> for SinkConfig {
    type Error = String;

    fn try_from(raw: RawSinkConfig) -> Result<Self, Self::Error> {
        match raw.kind {
            SinkKind::Stdout => {
                #[cfg(feature = "access-log-syslog")]
                raw.reject_syslog_fields("stdout")?;
                match raw.path {
                    None => Ok(Self::Stdout),
                    Some(_) => Err("access_log: sink type stdout does not accept a path".to_owned()),
                }
            },
            SinkKind::File => {
                #[cfg(feature = "access-log-syslog")]
                raw.reject_syslog_fields("file")?;
                match raw.path {
                    Some(path) => Ok(Self::File { path }),
                    None => Err("access_log: sink type file requires a path".to_owned()),
                }
            },
            #[cfg(feature = "access-log-syslog")]
            SinkKind::Syslog => Self::try_syslog(raw),
        }
    }
}

#[cfg(feature = "access-log-syslog")]
impl RawSinkConfig {
    /// Reject the syslog-only keys (`transport`, `address`, `facility`) on a
    /// non-syslog sink, so a misplaced key is a config error rather than a
    /// silently ignored one.
    fn reject_syslog_fields(&self, kind: &str) -> Result<(), String> {
        if self.transport.is_some() || self.address.is_some() || self.facility.is_some() {
            return Err(format!(
                "access_log: sink type {kind} does not accept syslog fields (transport, address, facility)"
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "access-log-syslog")]
impl SinkConfig {
    /// Resolve a `syslog` sink into a [`SyslogDestination`], rejecting fields the
    /// chosen transport ignores (`unix` takes a `path`; `udp`/`tcp` take an `address`).
    fn try_syslog(raw: RawSinkConfig) -> Result<Self, String> {
        let facility = raw.facility.unwrap_or_default();
        let target = match raw.transport.unwrap_or_default() {
            SyslogTransport::Unix => match raw.address {
                Some(_) => return Err("access_log: sink transport unix does not accept an address".to_owned()),
                None => SyslogDestination::Unix { path: raw.path },
            },
            SyslogTransport::Udp => SyslogDestination::Udp {
                address: remote_address(raw.path.is_some(), raw.address)?,
            },
            SyslogTransport::Tcp => SyslogDestination::Tcp {
                address: remote_address(raw.path.is_some(), raw.address)?,
            },
        };
        Ok(Self::Syslog { facility, target })
    }
}

/// Validate a remote (`udp`/`tcp`) syslog destination: a `host:port` `address`, no `path`.
#[cfg(feature = "access-log-syslog")]
fn remote_address(has_path: bool, address: Option<String>) -> Result<String, String> {
    if has_path {
        return Err("access_log: sink transport udp/tcp does not accept a path".to_owned());
    }
    let address = address.ok_or_else(|| "access_log: sink transport udp/tcp requires an address".to_owned())?;
    validate_host_port(&address)?;
    Ok(address)
}

/// Reject an `address` that is not `host:port` (non-zero port, non-empty host), without DNS.
#[cfg(feature = "access-log-syslog")]
fn validate_host_port(address: &str) -> Result<(), String> {
    let invalid = || format!("access_log: syslog address {address:?} is not host:port");
    let (host, port) = address.rsplit_once(':').ok_or_else(invalid)?;
    // A bracketed IPv6 host may contain colons (`[::1]`); an unbracketed host may
    // not, so `collector:514:123` is rejected rather than read as host `collector:514`.
    let host_ok = match host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')) {
        Some(inner) => !inner.is_empty(),
        None => !host.is_empty() && !host.contains(':'),
    };
    match port.parse::<u16>() {
        Ok(port) if port != 0 && host_ok => Ok(()),
        _ => Err(invalid()),
    }
}

/// Standard syslog facility codes (RFC 3164 §4.1.1).
#[cfg(feature = "access-log-syslog")]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyslogFacility {
    /// Kernel messages.
    Kern,
    /// User-level messages (default).
    #[default]
    User,
    /// Mail system.
    Mail,
    /// System daemons.
    Daemon,
    /// Security/authorization messages.
    Auth,
    /// Messages generated internally by syslogd.
    Syslog,
    /// Line printer subsystem.
    Lpr,
    /// Network news subsystem.
    News,
    /// UUCP subsystem.
    Uucp,
    /// Clock daemon.
    Cron,
    /// Security/authorization messages (private).
    Authpriv,
    /// FTP daemon.
    Ftp,
    /// Local use 0.
    Local0,
    /// Local use 1.
    Local1,
    /// Local use 2.
    Local2,
    /// Local use 3.
    Local3,
    /// Local use 4.
    Local4,
    /// Local use 5.
    Local5,
    /// Local use 6.
    Local6,
    /// Local use 7.
    Local7,
}

#[cfg(feature = "access-log-syslog")]
impl SyslogFacility {
    /// Facility contribution to PRI (`facility * 8`); literals avoid an `as` cast.
    fn priority_base(self) -> u8 {
        match self {
            SyslogFacility::Kern => 0,      //     0 * 8
            SyslogFacility::User => 8,      //     1 * 8
            SyslogFacility::Mail => 16,     //     2 * 8
            SyslogFacility::Daemon => 24,   //     3 * 8
            SyslogFacility::Auth => 32,     //     4 * 8
            SyslogFacility::Syslog => 40,   //     5 * 8
            SyslogFacility::Lpr => 48,      //     6 * 8
            SyslogFacility::News => 56,     //     7 * 8
            SyslogFacility::Uucp => 64,     //     8 * 8
            SyslogFacility::Cron => 72,     //     9 * 8
            SyslogFacility::Authpriv => 80, //    10 * 8
            SyslogFacility::Ftp => 88,      //    11 * 8
            SyslogFacility::Local0 => 128,  //    16 * 8
            SyslogFacility::Local1 => 136,  //    17 * 8
            SyslogFacility::Local2 => 144,  //    18 * 8
            SyslogFacility::Local3 => 152,  //    19 * 8
            SyslogFacility::Local4 => 160,  //    20 * 8
            SyslogFacility::Local5 => 168,  //    21 * 8
            SyslogFacility::Local6 => 176,  //    22 * 8
            SyslogFacility::Local7 => 184,  //    23 * 8
        }
    }
}

/// Syslog transport carrier.
#[cfg(feature = "access-log-syslog")]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyslogTransport {
    /// Local `AF_UNIX` socket (default `/dev/log`).
    #[default]
    Unix,
    /// Remote UDP datagram (RFC 5426).
    Udp,
    /// Remote TCP stream (RFC 6587).
    Tcp,
}

/// Emit-time access log conditions.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessLogEmitConditions {
    min_duration_ms: Option<u64>,
    status_classes: Option<Vec<StatusClass>>,
    paths: Option<Vec<String>>,
}

/// HTTP status class for emit-time conditions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum StatusClass {
    /// 100-199.
    #[serde(rename = "1xx")]
    Informational,
    /// 200-299.
    #[serde(rename = "2xx")]
    Success,
    /// 300-399.
    #[serde(rename = "3xx")]
    Redirection,
    /// 400-499.
    #[serde(rename = "4xx")]
    ClientError,
    /// 500-599.
    #[serde(rename = "5xx")]
    ServerError,
}

impl StatusClass {
    /// Whether `status` falls into this class.
    fn matches(self, status: u16) -> bool {
        let hundred = status / 100;
        matches!(
            (self, hundred),
            (Self::Informational, 1)
                | (Self::Success, 2)
                | (Self::Redirection, 3)
                | (Self::ClientError, 4)
                | (Self::ServerError, 5)
        )
    }
}

/// Default sample rate: log every request.
fn default_sample_rate() -> f64 {
    1.0
}

/// Default field tokens when `fields` is omitted.
const DEFAULT_FIELDS: &[&str] = &[
    "method",
    "path",
    "client_ip",
    "status",
    "duration_ms",
    "cluster",
    "upstream",
    "request_id",
    "request_body_bytes",
    "response_body_bytes",
];

// -----------------------------------------------------------------------------
// Field projection
// -----------------------------------------------------------------------------

/// Parsed scalar field token.
#[derive(Clone, Debug, Eq, PartialEq)]
enum FieldToken {
    Method,
    Path,
    ClientIp,
    Status,
    DurationMs,
    Cluster,
    Upstream,
    RequestId,
    RequestBodyBytes,
    ResponseBodyBytes,
    TraceId,
    SpanId,
    GrpcStatus,
    GrpcStatusName,
    GrpcMessage,
    GrpcStatusDetailsBin,
    RequestHeader(String),
    ResponseHeader(String),
    /// A filter-metadata key, such as `llm.model`.
    Metadata(String),
}

/// A segment in a parsed text template: a static string or an interpolated field.
#[derive(Clone, Debug)]
enum TemplatePart {
    Literal(String),
    Field(FieldToken),
}

/// Emit shape for a log record.
#[derive(Clone, Debug)]
enum EmitShape {
    /// Ten hardcoded default fields via `tracing::info!` flat format.
    DefaultFlat,
    /// User-selected field projection emitted as a `record` JSON field.
    JsonRecord(Vec<FieldToken>),
    /// Text line built from a parsed template, logged as the event's `line` field.
    Text(Vec<TemplatePart>),
}

/// Runtime emit plan built from config.
#[derive(Clone, Debug)]
struct EmitPlan {
    shape: EmitShape,
}

/// Runtime output sink resolved from [`SinkConfig`].
enum RuntimeSink {
    /// Emit via `tracing::info!`; the subscriber controls the format.
    Tracing,
    /// Write NDJSON lines to a background writer (stdout or a file).
    Direct(Arc<DirectSink>),
}

/// Bounded queue capacity for a direct sink's background writer. Records are
/// dropped (not blocked on) once this many are queued, so a slow or stalled
/// sink can never block a request executor thread.
const SINK_QUEUE_CAPACITY: usize = 8_192;

/// How often an idle writer wakes to observe [`SINK_SHUTDOWN`]. Bounds how long
/// `shutdown_sinks` waits for a quiescent writer (e.g. stdout, whose sender
/// never drops) to notice the flag and exit.
const SINK_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Poll interval while waiting for a writer to finish during shutdown.
const SINK_JOIN_POLL: Duration = Duration::from_millis(5);

/// Connect/write timeout for the TCP and Unix syslog transports, so a stalled
/// collector cannot block the writer thread (and its bounded queue) indefinitely.
#[cfg(feature = "access-log-syslog")]
const SYSLOG_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Set once at process shutdown so idle writers flush and exit even when their
/// sender never drops (the stdout singleton), making their handles joinable.
static SINK_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Join handles for every spawned writer thread, drained and joined by
/// [`shutdown_sinks`]. Finished handles are pruned as new writers register.
static SINK_WRITERS: OnceLock<Mutex<Vec<JoinHandle<()>>>> = OnceLock::new();

/// Handle to a background NDJSON writer shared by every filter instance that
/// targets the same destination.
///
/// Emitting hands an owned line to a bounded channel and returns immediately;
/// the blocking write and flush happen on a dedicated writer thread. A full
/// channel drops the line (counted, with a rate-limited warning) rather than
/// stalling the request path. Filters hold an `Arc<DirectSink>`; the file
/// registry keeps only a `Weak`, so the writer thread exits once the last
/// filter using a path is dropped (for example after a config reload).
struct DirectSink {
    /// Sender into the writer thread's bounded queue.
    tx: SyncSender<String>,
    /// Destination label for diagnostics (`"stdout"` or the file path).
    dest: Arc<str>,
    /// Count of lines dropped because the queue was full.
    dropped: AtomicU64,
    /// Unix-seconds timestamp of the last drop warning, for rate limiting.
    last_drop_warn: AtomicU64,
}

impl DirectSink {
    /// Build a handle around a channel sender.
    fn new(tx: SyncSender<String>, dest: Arc<str>) -> Self {
        Self {
            tx,
            dest,
            dropped: AtomicU64::new(0),
            last_drop_warn: AtomicU64::new(0),
        }
    }

    /// Queue one line for the background writer, dropping it if the queue is
    /// full so the caller never blocks.
    fn record(&self, line: String) {
        if self.tx.try_send(line).is_err() {
            let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            let now = unix_secs();
            let prev = self.last_drop_warn.load(Ordering::Relaxed);
            if now > prev
                && self
                    .last_drop_warn
                    .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                tracing::warn!(sink = %self.dest, dropped = total, "access_log sink queue full; dropping records");
            }
        }
    }
}

/// Throttles write-failure warnings on a writer thread to at most one per
/// second so a persistently failing sink cannot flood the logs.
#[derive(Default)]
struct WriteWarnThrottle {
    /// Unix-seconds timestamp of the last emitted warning.
    last_secs: u64,
}

impl WriteWarnThrottle {
    /// Warn about a write/flush failure unless one was already logged this
    /// second.
    fn warn(&mut self, dest: &str, err: &std::io::Error) {
        let now = unix_secs();
        if now != self.last_secs {
            self.last_secs = now;
            tracing::warn!(sink = %dest, error = %err, "access_log sink write failed");
        }
    }

    /// Warn about a sink failure carrying a non-`io::Error` cause (e.g. a syslog
    /// connect error), throttled identically to [`WriteWarnThrottle::warn`].
    #[cfg(feature = "access-log-syslog")]
    fn warn_display(&mut self, dest: &str, err: &dyn std::fmt::Display) {
        let now = unix_secs();
        if now != self.last_secs {
            self.last_secs = now;
            tracing::warn!(sink = %dest, error = %err, "access_log sink write failed");
        }
    }
}

/// Seconds since the Unix epoch, saturating to 0 before 1970.
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// RFC 3339 UTC timestamp (millisecond precision) for a sink record, taken from
/// the request's clock abstraction so tests can pin it, mirroring `cloud_events`.
fn sink_timestamp(ctx: &HttpFilterContext<'_>) -> String {
    let now = ctx.time_source.now();
    DateTime::<Utc>::from_timestamp(i64::try_from(now.as_secs()).unwrap_or(i64::MAX), now.subsec_nanos()).map_or_else(
        || "1970-01-01T00:00:00.000Z".to_owned(),
        |time| time.to_rfc3339_opts(SecondsFormat::Millis, true),
    )
}

/// Write `first` and any further queued lines, then flush once, reporting
/// (rate-limited) write or flush failures.
fn flush_batch<W: std::io::Write>(
    writer: &mut W,
    rx: &Receiver<String>,
    throttle: &mut WriteWarnThrottle,
    dest: &str,
    first: &str,
) {
    let mut result = writeln!(writer, "{first}");
    // Write any further queued lines before paying for a single flush.
    while result.is_ok() {
        match rx.try_recv() {
            Ok(next) => result = writeln!(writer, "{next}"),
            Err(_) => break,
        }
    }
    if let Err(e) = result.and_then(|()| writer.flush()) {
        throttle.warn(dest, &e);
    }
}

/// Drain the queue onto `writer`, batching available lines before each flush and
/// reporting (rate-limited) failures. Returns when every sender is dropped or
/// `shutdown` is set, flushing whatever is still queued first. `shutdown` is
/// injected (rather than read from [`SINK_SHUTDOWN`] directly) so the exit path
/// is unit-testable in isolation.
fn run_sink_writer<W: std::io::Write>(mut writer: W, rx: &Receiver<String>, dest: &str, shutdown: &AtomicBool) {
    let mut throttle = WriteWarnThrottle::default();
    loop {
        match rx.recv_timeout(SINK_POLL_INTERVAL) {
            Ok(line) => flush_batch(&mut writer, rx, &mut throttle, dest, &line),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) if shutdown.load(Ordering::Acquire) => break,
            Err(RecvTimeoutError::Timeout) => {},
        }
    }
    // Flush records queued between the last receive and the exit condition.
    if let Ok(line) = rx.try_recv() {
        flush_batch(&mut writer, rx, &mut throttle, dest, &line);
    }
    drop(writer.flush());
}

/// Spawn the dedicated writer thread for a destination and register its handle
/// for shutdown.
///
/// The caller must only cache the sink once this succeeds: a dropped `rx` would
/// make every send fail as "disconnected" while a dead sink lingered until
/// restart.
fn spawn_sink_writer<W: std::io::Write + Send + 'static>(
    writer: W,
    rx: Receiver<String>,
    dest: Arc<str>,
) -> std::io::Result<()> {
    let handle = std::thread::Builder::new()
        .name("access-log-sink".to_owned())
        .spawn(move || run_sink_writer(writer, &rx, &dest, &SINK_SHUTDOWN))?;
    register_sink_writer(handle);
    Ok(())
}

/// Record a writer's join handle so [`shutdown_sinks`] can drain it, pruning
/// handles whose threads already finished (e.g. writers replaced by a reload).
fn register_sink_writer(handle: JoinHandle<()>) {
    let registry = SINK_WRITERS.get_or_init(|| Mutex::new(Vec::new()));
    let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.retain(|existing| !existing.is_finished());
    guard.push(handle);
}

/// Signal every access-log sink writer to flush and exit, then wait up to
/// `timeout` (total) for them to finish before the process exits.
///
/// Writers already flush after each batch, so this only recovers records still
/// queued at shutdown. A writer that has not finished by the deadline is left to
/// the exiting process rather than blocking it, matching the drop-on-overflow
/// queue: the sink is best-effort, never the system of record.
#[expect(
    clippy::disallowed_methods,
    reason = "bounded synchronous wait during process shutdown, not on the async runtime"
)]
pub fn shutdown_sinks(timeout: Duration) {
    SINK_SHUTDOWN.store(true, Ordering::Release);
    let Some(registry) = SINK_WRITERS.get() else {
        return;
    };
    let handles: Vec<JoinHandle<()>> = {
        let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut guard)
    };
    let deadline = Instant::now().checked_add(timeout).unwrap_or_else(Instant::now);
    for handle in handles {
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(SINK_JOIN_POLL);
        }
        if handle.is_finished() {
            drop(handle.join());
        }
    }
}

/// The process-wide stdout sink, created on first use.
///
/// Returns an error if the writer thread cannot be spawned so the sink is never
/// cached without a live writer behind it.
fn stdout_sink() -> Result<Arc<DirectSink>, FilterError> {
    static STDOUT: OnceLock<Arc<DirectSink>> = OnceLock::new();
    if let Some(sink) = STDOUT.get() {
        return Ok(Arc::clone(sink));
    }
    let (tx, rx) = sync_channel(SINK_QUEUE_CAPACITY);
    let dest: Arc<str> = Arc::from("stdout");
    spawn_sink_writer(std::io::stdout(), rx, Arc::clone(&dest))
        .map_err(|e| format!("access_log: cannot start stdout sink writer: {e}"))?;
    // A concurrent first-init may have stored its sink first; keep that one and
    // let this writer thread exit when its unused sender drops. stdout lives for
    // the whole process, so this handle is intentionally never reclaimed.
    Ok(Arc::clone(STDOUT.get_or_init(|| Arc::new(DirectSink::new(tx, dest)))))
}

/// A file sink for `path`, shared across filter instances that name the same
/// destination so a single writer and queue serialize all writes and NDJSON
/// records never interleave.
fn file_sink(path: &str) -> Result<Arc<DirectSink>, FilterError> {
    static FILES: OnceLock<Mutex<HashMap<PathBuf, Weak<DirectSink>>>> = OnceLock::new();
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("access_log: cannot open log file {path:?}: {e}"))?;
    // Canonicalize so `./a.log` and `a.log` resolve to one writer; fall back to
    // the raw path if the resolve fails (it cannot, having just opened it).
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let registry = FILES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(sink) = guard.get(&key).and_then(Weak::upgrade) {
        return Ok(sink);
    }
    let (tx, rx) = sync_channel(SINK_QUEUE_CAPACITY);
    let dest: Arc<str> = Arc::from(path);
    spawn_sink_writer(BufWriter::new(file), rx, Arc::clone(&dest))
        .map_err(|e| format!("access_log: cannot start writer for log file {path:?}: {e}"))?;
    let sink = Arc::new(DirectSink::new(tx, dest));
    guard.insert(key, Arc::downgrade(&sink));
    drop(guard);
    Ok(sink)
}

// -----------------------------------------------------------------------------
// Syslog sink
// -----------------------------------------------------------------------------

/// RFC 3164 formatter for the `syslog` `Logger`, replacing `Formatter3164`: unlike
/// the crate it renders the header in local time (via `chrono::Local`, which reads
/// the zone soundly where the crate forces UTC) and wraps each TCP record in RFC
/// 6587 octet-counted framing (`LEN SP MSG`) so a collector can split records.
#[cfg(feature = "access-log-syslog")]
#[derive(Clone, Debug)]
struct Rfc3164Formatter {
    /// Facility contribution to PRI (`facility * 8`); see [`SyslogFacility`].
    priority_base: u8,
    /// Local host name for remote (`udp`/`tcp`) targets; `None` on `unix`.
    hostname: Option<String>,
    /// Syslog TAG process name (always `praxis`).
    process: String,
    /// Process id recorded in the TAG.
    pid: u32,
    /// Wrap each record in RFC 6587 octet-counted framing (TCP only).
    octet_framed: bool,
}

/// Render the RFC 3164 timestamp (`Mmm _d HH:MM:SS`) for `now` in its own zone.
#[cfg(feature = "access-log-syslog")]
fn rfc3164_timestamp<Tz: chrono::TimeZone<Offset: std::fmt::Display>>(now: &DateTime<Tz>) -> String {
    now.format("%b %e %H:%M:%S").to_string()
}

/// RFC 3164 §4.1 caps a complete syslog message (header included) at 1024 bytes;
/// a receiver may truncate or discard anything longer.
#[cfg(feature = "access-log-syslog")]
const RFC3164_MAX_BYTES: usize = 1024;

/// Truncate `record` in place to at most [`RFC3164_MAX_BYTES`], on a UTF-8 char
/// boundary so the emitted message stays valid and within the RFC 3164 §4.1 limit.
#[cfg(feature = "access-log-syslog")]
fn cap_rfc3164(record: &mut String) {
    if record.len() <= RFC3164_MAX_BYTES {
        return;
    }
    let mut end = RFC3164_MAX_BYTES;
    while end > 0 && !record.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    record.truncate(end);
}

#[cfg(feature = "access-log-syslog")]
impl<T: std::fmt::Display> LogFormat<T> for Rfc3164Formatter {
    fn format<W: std::io::Write>(&self, w: &mut W, _severity: Severity, message: T) -> syslog::Result<()> {
        // The access_log sink emits every record at info, so PRI is facility | 6.
        let pri = self.priority_base.saturating_add(6); // 6 = info
        let timestamp = rfc3164_timestamp(&Local::now());
        let host = self
            .hostname
            .as_deref()
            .map_or_else(String::new, |name| format!("{name} "));
        let mut record = format!("<{pri}>{timestamp} {host}{}[{}]: {message}", self.process, self.pid);
        cap_rfc3164(&mut record);
        if self.octet_framed {
            write!(w, "{} {record}", record.len())?;
        } else {
            write!(w, "{record}")?;
        }
        Ok(())
    }
}

/// Everything the writer needs to (re)build its `Logger`: the crate's `Logger` has
/// no reconnect method, so the writer rebuilds it from this after a write error.
#[cfg(feature = "access-log-syslog")]
struct SyslogTarget {
    /// Resolved transport destination for the connection.
    destination: SyslogDestination,
    /// Message formatter carrying the facility and process identity.
    formatter: Rfc3164Formatter,
    /// Destination label for diagnostics.
    dest: Arc<str>,
}

/// Build a syslog [`DirectSink`]: assemble the formatter, then spawn the writer
/// thread and keep its bounded-queue sender. A remote (`udp`/`tcp`) target fills in
/// the local host name for the RFC 3164 HEADER; `unix` leaves the daemon to stamp it.
#[cfg(feature = "access-log-syslog")]
fn syslog_sink(facility: SyslogFacility, destination: SyslogDestination) -> Result<Arc<DirectSink>, FilterError> {
    let dest: Arc<str> = Arc::from(syslog_dest(&destination));
    let hostname = match destination {
        SyslogDestination::Unix { .. } => None,
        // Borrow the crate's host-name detection for the remote HEADER.
        SyslogDestination::Udp { .. } | SyslogDestination::Tcp { .. } => Formatter3164::default().hostname,
    };
    let formatter = Rfc3164Formatter {
        priority_base: facility.priority_base(),
        hostname,
        process: "praxis".to_owned(),
        pid: std::process::id(),
        // RFC 6587 octet framing delimits records on a TCP stream; datagram
        // transports (udp, unix) carry one record per message already.
        octet_framed: matches!(destination, SyslogDestination::Tcp { .. }),
    };
    let target = SyslogTarget {
        destination,
        formatter,
        dest: Arc::clone(&dest),
    };
    let (tx, rx) = sync_channel(SINK_QUEUE_CAPACITY);
    spawn_syslog_writer(rx, target).map_err(|e| format!("access_log: cannot start syslog sink writer: {e}"))?;
    Ok(Arc::new(DirectSink::new(tx, dest)))
}

/// Human-readable destination label for diagnostics.
#[cfg(feature = "access-log-syslog")]
fn syslog_dest(destination: &SyslogDestination) -> String {
    match destination {
        SyslogDestination::Unix { path } => format!("syslog:unix:{}", path.as_deref().unwrap_or("/dev/log")),
        SyslogDestination::Udp { address } => format!("syslog:udp:{address}"),
        SyslogDestination::Tcp { address } => format!("syslog:tcp:{address}"),
    }
}

/// Spawn the syslog writer thread and register its handle for shutdown.
#[cfg(feature = "access-log-syslog")]
fn spawn_syslog_writer(rx: Receiver<String>, target: SyslogTarget) -> std::io::Result<()> {
    let handle = std::thread::Builder::new()
        .name("access-log-syslog".to_owned())
        .spawn(move || run_syslog_writer(&rx, &target, &SINK_SHUTDOWN))?;
    register_sink_writer(handle);
    Ok(())
}

/// Drain the queue into the syslog `Logger`, owning its connection lifecycle and
/// honouring [`SINK_SHUTDOWN`] so an idle writer still exits at shutdown.
#[cfg(feature = "access-log-syslog")]
fn run_syslog_writer(rx: &Receiver<String>, target: &SyslogTarget, shutdown: &AtomicBool) {
    let mut state = SyslogWriterState::default();
    loop {
        match rx.recv_timeout(SINK_POLL_INTERVAL) {
            Ok(line) => state.emit(target, &line),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) if shutdown.load(Ordering::Acquire) => break,
            Err(RecvTimeoutError::Timeout) => {},
        }
    }
    while let Ok(line) = rx.try_recv() {
        state.emit(target, &line);
    }
}

/// After a failed (re)connection the writer suppresses reconnects for this long,
/// dropping records meanwhile. Every connect attempt may spawn a `syslog-io` helper
/// thread (for a Unix connect or DNS resolution) that a hung syscall can leave
/// blocked, so bounding the reconnect rate bounds how fast those helpers can pile up
/// during a sustained outage.
#[cfg(feature = "access-log-syslog")]
const SYSLOG_RECONNECT_COOLDOWN: Duration = Duration::from_secs(30);

/// State the syslog writer carries across records: the lazily-built `Logger`, the
/// failure-warning throttle, and the post-failure reconnect-cooldown deadline.
#[cfg(feature = "access-log-syslog")]
#[derive(Default)]
struct SyslogWriterState {
    /// Active logger, or `None` before the first record and after a failure.
    logger: Option<Logger<LoggerBackend, Rfc3164Formatter>>,
    /// Rate-limits connect/write failure warnings.
    throttle: WriteWarnThrottle,
    /// When set, reconnect attempts are suppressed until this instant.
    cooldown_until: Option<Instant>,
}

#[cfg(feature = "access-log-syslog")]
impl SyslogWriterState {
    /// Emit one line, lazily (re)connecting the `Logger`. A failed connect *or* send
    /// starts a cooldown during which records are dropped, so a stalled peer or
    /// resolver cannot make every queued record block for the I/O timeout or spawn
    /// another blocked helper thread.
    fn emit(&mut self, target: &SyslogTarget, line: &str) {
        if self.logger.is_none() {
            if self.in_cooldown() {
                return;
            }
            match connect_logger(target) {
                Ok(active) => {
                    self.logger = Some(active);
                    self.cooldown_until = None;
                },
                Err(e) => {
                    self.throttle.warn_display(&target.dest, &e);
                    self.start_cooldown();
                    return;
                },
            }
        }
        if let Some(active) = self.logger.as_mut()
            && let Err(e) = active.info(line)
        {
            self.throttle.warn_display(&target.dest, &e);
            // A send failure forces a reconnect on the next record; cool down too so a
            // collector that stalls after connecting cannot loop one timed-out write
            // (and reconnect) per record.
            self.logger = None;
            self.start_cooldown();
        }
    }

    /// Begin the post-failure reconnect cooldown from now.
    fn start_cooldown(&mut self) {
        self.cooldown_until = Instant::now().checked_add(SYSLOG_RECONNECT_COOLDOWN);
    }

    /// Whether the post-failure reconnect cooldown is still in effect.
    fn in_cooldown(&self) -> bool {
        self.cooldown_until.is_some_and(|until| Instant::now() < until)
    }
}

/// (Re)connect the `syslog` crate `Logger` for the target's destination.
#[cfg(feature = "access-log-syslog")]
fn connect_logger(target: &SyslogTarget) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let formatter = target.formatter.clone();
    match &target.destination {
        SyslogDestination::Unix { path } => connect_unix(formatter, path.as_deref(), SYSLOG_IO_TIMEOUT),
        SyslogDestination::Udp { address } => connect_udp(formatter, address, SYSLOG_IO_TIMEOUT),
        SyslogDestination::Tcp { address } => connect_tcp(formatter, address, SYSLOG_IO_TIMEOUT),
    }
}

/// Run a blocking I/O op on a short-lived thread, returning its result or a
/// `TimedOut` error if it does not finish within `timeout`. Bounds operations std
/// offers no timeout for (unix stream connect, DNS resolution) so a stalled peer or
/// resolver cannot block the writer thread (and thus its bounded queue) forever.
#[cfg(feature = "access-log-syslog")]
fn with_timeout<T, F>(timeout: Duration, op: F) -> std::io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
{
    let (tx, rx) = sync_channel(1);
    std::thread::Builder::new()
        .name("syslog-io".to_owned())
        .spawn(move || {
            drop(tx.send(op()));
        })?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "syslog io timed out")),
    }
}

/// Resolve `address` to socket addresses within `timeout`, so a stalled resolver
/// cannot block the writer thread before the connect timeout even begins.
#[cfg(feature = "access-log-syslog")]
fn resolve_addrs(address: &str, timeout: Duration) -> std::io::Result<Vec<SocketAddr>> {
    let owned = address.to_owned();
    with_timeout(timeout, move || Ok(owned.to_socket_addrs()?.collect()))
}

/// Connect a Unix syslog logger with bounded connect and write timeouts (the crate's
/// helpers set none), trying a datagram socket first (the usual `/dev/log` shape) and
/// falling through to a `SOCK_STREAM` collector only when the datagram connect fails
/// with the socket-type mismatch, so a missing socket or denied permission surfaces as
/// itself rather than a masked stream-connect error.
#[cfg(feature = "access-log-syslog")]
fn connect_unix(
    formatter: Rfc3164Formatter,
    path: Option<&str>,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let path = path.unwrap_or("/dev/log");
    match unix_datagram(path, timeout) {
        Ok(socket) => Ok(Logger::new(LoggerBackend::Unix(socket), formatter)),
        Err(e) if is_wrong_socket_type(&e) => connect_unix_stream_logger(formatter, path, timeout),
        Err(e) => Err(e.into()),
    }
}

/// Build a stream-backed Unix syslog logger for a `SOCK_STREAM` collector, bounding
/// both the connect and subsequent writes by `timeout`.
#[cfg(feature = "access-log-syslog")]
fn connect_unix_stream_logger(
    formatter: Rfc3164Formatter,
    path: &str,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let stream = connect_unix_stream(path, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(Logger::new(
        LoggerBackend::UnixStream(BufWriter::new(stream)),
        formatter,
    ))
}

/// Raw `EPROTOTYPE` errno: a datagram connect to a `SOCK_STREAM` endpoint reports it
/// (Linux `91`). The lone datagram error that warrants the stream fallback.
#[cfg(all(feature = "access-log-syslog", target_os = "linux"))]
const EPROTOTYPE_ERRNO: i32 = 91;
/// Raw `EPROTOTYPE` errno on BSD/macOS targets (`41`).
#[cfg(all(feature = "access-log-syslog", not(target_os = "linux")))]
const EPROTOTYPE_ERRNO: i32 = 41;

/// Whether a Unix datagram connect error means the endpoint is a `SOCK_STREAM` socket
/// (retry it as a stream) rather than a real failure such as a missing socket or
/// denied permission. `EPROTOTYPE` has no std `ErrorKind`, so match its raw errno;
/// `InvalidInput` covers the same mismatch surfaced as a kind.
#[cfg(feature = "access-log-syslog")]
fn is_wrong_socket_type(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidInput || err.raw_os_error() == Some(EPROTOTYPE_ERRNO)
}

/// Connect a Unix stream within `timeout` so a full listen backlog cannot block the
/// writer; std has no bounded `UnixStream::connect`, so it runs via [`with_timeout`].
#[cfg(feature = "access-log-syslog")]
fn connect_unix_stream(path: &str, timeout: Duration) -> std::io::Result<UnixStream> {
    let owned = path.to_owned();
    with_timeout(timeout, move || UnixStream::connect(owned))
}

/// Bind an unbound `AF_UNIX` datagram socket with a write timeout and connect it
/// to `path`, so `send` on a full collector buffer times out instead of blocking.
#[cfg(feature = "access-log-syslog")]
fn unix_datagram(path: &str, write_timeout: Duration) -> std::io::Result<UnixDatagram> {
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(write_timeout))?;
    socket.connect(path)?;
    Ok(socket)
}

/// Connect a UDP syslog logger, resolving the collector within `timeout` and binding
/// the local socket in its address family so an IPv6 target (e.g. `[::1]:514`) works.
#[cfg(feature = "access-log-syslog")]
fn connect_udp(
    formatter: Rfc3164Formatter,
    address: &str,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let server = resolve_addrs(address, timeout)?
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "syslog udp address did not resolve"))?;
    // Resolved SocketAddr for both local and server keeps the crate's bind DNS-free.
    let local: SocketAddr = if server.is_ipv6() {
        ([0_u8; 16], 0).into()
    } else {
        ([0_u8; 4], 0).into()
    };
    syslog::udp(formatter, local, server)
}

/// Connect a TCP syslog logger with bounded connect and write timeouts so a stalled
/// collector cannot block the writer. `Logger::info` flushes the backend per message.
#[cfg(feature = "access-log-syslog")]
fn connect_tcp(
    formatter: Rfc3164Formatter,
    address: &str,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let stream = dial_tcp(address, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(Logger::new(LoggerBackend::Tcp(BufWriter::new(stream)), formatter))
}

/// Dial the first reachable address `address` resolves to, bounding both resolution
/// and each connect by `timeout`. `connect_timeout` takes one `SocketAddr`, so we
/// iterate the resolved set ourselves and surface the last error if none work.
#[cfg(feature = "access-log-syslog")]
fn dial_tcp(address: &str, timeout: Duration) -> std::io::Result<std::net::TcpStream> {
    let mut last_err = std::io::Error::new(std::io::ErrorKind::NotFound, "syslog tcp address did not resolve");
    for addr in resolve_addrs(address, timeout)? {
        match std::net::TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Cached response metadata for emit on the body phase.
#[derive(Clone, Debug)]
struct AccessLogState {
    status: u16,
    response_headers: Option<http::HeaderMap>,
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

impl AccessLogFilter {
    /// Create an access log filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AccessLogConfig = parse_filter_config("access_log", config)?;
        Ok(Box::new(Self::build(cfg)?))
    }

    #[expect(clippy::too_many_lines, reason = "config validation and emit plan assembly")]
    fn build(cfg: AccessLogConfig) -> Result<Self, FilterError> {
        // NaN compares false against both bounds, so a plain range check
        // lets it through and then every sampling comparison fails.
        if !cfg.sample_rate.is_finite() || cfg.sample_rate <= 0.0 || cfg.sample_rate > 1.0 {
            return Err(format!("access_log: sample_rate must be in (0.0, 1.0], got {}", cfg.sample_rate).into());
        }

        // A template names its own fields inline, so pairing it with a `fields`
        // projection is ambiguous.
        if cfg.fields.is_some() && cfg.template.is_some() {
            return Err("access_log: fields and template are mutually exclusive".into());
        }

        if let Some(fields) = &cfg.fields {
            if fields.is_empty() {
                return Err("access_log: fields must not be empty when present".into());
            }
            for value in fields {
                if !value.is_string() {
                    return Err(
                        "access_log: fields must be a list of scalar tokens; nested maps are not allowed".into(),
                    );
                }
            }
        }

        let request_headers = normalize_header_names(cfg.request_headers.as_deref())?;
        let response_headers = normalize_header_names(cfg.response_headers.as_deref())?;

        if request_headers.is_empty() && cfg.request_headers.is_some() {
            return Err("access_log: request_headers must not be empty when present".into());
        }
        if response_headers.is_empty() && cfg.response_headers.is_some() {
            return Err("access_log: response_headers must not be empty when present".into());
        }

        let shape = if let Some(template) = cfg.template {
            if template.trim().is_empty() {
                return Err("access_log: template must not be empty".into());
            }
            let parts = parse_template(&template, &request_headers, &response_headers)?;
            if !parts.iter().any(|part| matches!(part, TemplatePart::Field(_))) {
                return Err("access_log: template must contain at least one {field} token".into());
            }
            EmitShape::Text(parts)
        } else {
            let field_tokens = parse_field_tokens(
                cfg.fields
                    .as_ref()
                    .map(|values| values.iter().filter_map(serde_yaml::Value::as_str).collect::<Vec<_>>()),
                &request_headers,
                &response_headers,
            )?;
            if cfg.fields.is_none() {
                EmitShape::DefaultFlat
            } else {
                EmitShape::JsonRecord(field_tokens)
            }
        };

        let needs_response_headers = match &shape {
            EmitShape::DefaultFlat => false,
            EmitShape::JsonRecord(fields) => fields.iter().any(|t| matches!(t, FieldToken::ResponseHeader(_))),
            EmitShape::Text(parts) => parts
                .iter()
                .any(|p| matches!(p, TemplatePart::Field(FieldToken::ResponseHeader(_)))),
        };

        validate_emit_conditions(cfg.conditions.as_ref())?;

        let sink = build_runtime_sink(cfg.sink)?;

        Ok(Self {
            sample_rate: cfg.sample_rate,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan { shape },
            emit_conditions: cfg.conditions,
            needs_response_headers,
            sink,
        })
    }

    /// Returns `true` if this request should be logged (sampling check).
    ///
    /// Deterministic accumulator: of the first `n` requests exactly
    /// `floor(n × sample_rate)` are logged, so rates that are not a
    /// reciprocal integer (`0.7`, `0.4`) are honored rather than rounded to
    /// one-in-N.
    #[expect(clippy::cast_precision_loss, reason = "the counter stays far below 2^53")]
    fn should_log(&self) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        let seen = self.counter.fetch_add(1, Ordering::Relaxed) as f64;
        ((seen + 1.0) * self.sample_rate).floor() > (seen * self.sample_rate).floor()
    }

    /// Returns `true` for responses that Pingora delivers without a body phase.
    fn is_bodyless(status: http::StatusCode, req_method: &http::Method) -> bool {
        bodyless_response(status, req_method)
    }

    fn maybe_emit(&self, ctx: &mut HttpFilterContext<'_>, status: u16, response_headers: Option<&http::HeaderMap>) {
        // Emit at most once per request: the bodyless on_response path and the
        // on_response_body end-of-stream path can both reach here, and the
        // protocol-layer fallback already relies on this marker.
        if access_record_already_emitted(ctx) {
            return;
        }
        // Skip all per-request record work when the access-log level is
        // disabled: the info! callsites below would discard the output, but
        // the duration sampling, condition evaluation, and record formatting
        // run regardless unless gated here. Direct sinks (stdout/file) bypass
        // tracing entirely, so the level gate must not suppress them.
        if matches!(self.sink, RuntimeSink::Tracing) && !tracing::enabled!(tracing::Level::INFO) {
            return;
        }
        // Sample the duration once so the emit-time condition and the logged
        // value can never disagree around the min_duration_ms boundary.
        let duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis());
        if !self.passes_emit_conditions(ctx, status, duration_ms) {
            return;
        }
        if !self.should_log() {
            return;
        }
        self.emit_access_log(ctx, status, response_headers, duration_ms);
        mark_access_record_emitted(ctx);
    }

    fn passes_emit_conditions(&self, ctx: &HttpFilterContext<'_>, status: u16, duration_ms: u64) -> bool {
        let Some(conditions) = &self.emit_conditions else {
            return true;
        };

        if let Some(min_ms) = conditions.min_duration_ms
            && duration_ms < min_ms
        {
            return false;
        }

        // A gRPC call's outcome is its grpc-status, not the transport 200, so
        // match status_classes against the status the gRPC code maps to. This
        // lets an "errors only" listener (e.g. status_classes: [4xx, 5xx])
        // capture gRPC failures, which would otherwise all read as 2xx. A
        // non-canonical code (outside 0..=16) is still a failure, so it maps
        // to 500 rather than falling back to the transport 200.
        let class_status = if request_is_grpc(ctx) {
            ctx.grpc_completion.as_ref().map_or(status, |completion| {
                completion
                    .code()
                    .map_or(500, praxis_core::grpc::GrpcStatusCode::to_http_status)
            })
        } else {
            status
        };
        if let Some(classes) = &conditions.status_classes
            && !classes.iter().any(|class| class.matches(class_status))
        {
            return false;
        }

        if let Some(prefixes) = &conditions.paths {
            let path = sanitize_for_log(ctx.request.uri.path());
            if !prefixes.iter().any(|prefix| path_prefix_matches(&path, prefix)) {
                return false;
            }
        }

        true
    }

    /// Emit a structured access log entry for the current request through the
    /// tracing subscriber, shaping the record per the configured [`EmitShape`].
    fn emit_access_log(
        &self,
        ctx: &HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
        duration_ms: u64,
    ) {
        match &self.sink {
            RuntimeSink::Tracing => self.emit_via_tracing(ctx, status, response_headers, duration_ms),
            RuntimeSink::Direct(sink) => {
                let line = self.format_line_for_sink(ctx, status, response_headers, duration_ms);
                sink.record(line);
            },
        }
    }

    /// Emit through the tracing subscriber, shaping the record per the
    /// configured [`EmitShape`].
    fn emit_via_tracing(
        &self,
        ctx: &HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
        duration_ms: u64,
    ) {
        match &self.emit_plan.shape {
            EmitShape::DefaultFlat => Self::emit_default(ctx, status, duration_ms),
            EmitShape::JsonRecord(fields) => {
                let record = build_record_from_fields(fields, ctx, status, response_headers, duration_ms);
                emit_projected_record(&record);
            },
            EmitShape::Text(parts) => {
                let line = render_text_template(parts, ctx, status, response_headers, duration_ms);
                emit_projected_line(&line);
            },
        }
    }

    /// Format one line for a direct sink (stdout or file).
    ///
    /// A text template renders its own line verbatim, matching the `line` field
    /// the tracing path would log. The default and projected plans serialize a
    /// single JSON object per request, with a `timestamp` key (RFC 3339 UTC,
    /// millisecond precision) injected so a file log records when each request
    /// completed; the tracing path gets this from the subscriber instead.
    fn format_line_for_sink(
        &self,
        ctx: &HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
        duration_ms: u64,
    ) -> String {
        let fields = match &self.emit_plan.shape {
            EmitShape::Text(parts) => {
                return render_text_template(parts, ctx, status, response_headers, duration_ms);
            },
            EmitShape::JsonRecord(fields) => Cow::Borrowed(fields.as_slice()),
            EmitShape::DefaultFlat => Cow::Owned(default_field_tokens()),
        };
        let mut record = build_record_from_fields(&fields, ctx, status, response_headers, duration_ms);
        record.insert("timestamp".to_owned(), sink_timestamp(ctx));
        serde_json::to_string(&record).unwrap_or_default()
    }

    /// Default ten-field emit path.
    fn emit_default(ctx: &HttpFilterContext<'_>, status: u16, duration_ms: u64) {
        let path = sanitize_for_log(ctx.request.uri.path());
        let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
        info!(
            method = %ctx.request.method,
            path = %path,
            client_ip = %client_ip,
            status,
            duration_ms,
            cluster = ctx.cluster_name().unwrap_or("-"),
            upstream = ctx.upstream_addr().unwrap_or("-"),
            request_id = ctx.request_id().unwrap_or("-"),
            request_body_bytes = ctx.request_body_bytes,
            response_body_bytes = ctx.response_body_bytes,
            "access"
        );
    }
}

// -----------------------------------------------------------------------------
// Template parsing and rendering
// -----------------------------------------------------------------------------

/// Parse a text template string into a `Vec<TemplatePart>`.
///
/// Each `{token}` in the template is parsed as a [`FieldToken`] and becomes a
/// [`TemplatePart::Field`]. All other text becomes [`TemplatePart::Literal`].
/// Header tokens are validated against `request_headers` and `response_headers`.
///
/// # Errors
///
/// Returns [`FilterError`] for unclosed braces, unknown field tokens, or header
/// tokens that are not listed in the corresponding allowlist.
#[expect(clippy::too_many_lines, reason = "single-pass brace/token scanner")]
fn parse_template(
    template: &str,
    request_headers: &HashSet<String>,
    response_headers: &HashSet<String>,
) -> Result<Vec<TemplatePart>, FilterError> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut chars = template.chars();

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                // Flush the literal text accumulated before this token.
                if !literal.is_empty() {
                    parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
                }

                // Collect the token name up to the closing brace. A second '{'
                // (or the end of the string) before a '}' means this brace was
                // never closed.
                let mut token = String::new();
                let mut closed = false;
                for next in chars.by_ref() {
                    match next {
                        '}' => {
                            closed = true;
                            break;
                        },
                        '{' => return Err("access_log: unclosed brace in template".into()),
                        _ => token.push(next),
                    }
                }
                if !closed {
                    return Err("access_log: unclosed brace in template".into());
                }

                let field = parse_scalar_field_token(token.trim())?;
                match &field {
                    FieldToken::RequestHeader(name) if !request_headers.contains(name) => {
                        return Err(
                            format!("access_log: request_header.{name} requires {name:?} in request_headers").into(),
                        );
                    },
                    FieldToken::ResponseHeader(name) if !response_headers.contains(name) => {
                        return Err(format!(
                            "access_log: response_header.{name} requires {name:?} in response_headers"
                        )
                        .into());
                    },
                    _ => {},
                }
                parts.push(TemplatePart::Field(field));
            },
            '}' => return Err("access_log: unexpected '}' in template".into()),
            _ => literal.push(ch),
        }
    }

    if !literal.is_empty() {
        parts.push(TemplatePart::Literal(literal));
    }

    Ok(parts)
}

/// Render template parts into a log line string.
///
/// Each [`TemplatePart::Literal`] is emitted verbatim. Each
/// [`TemplatePart::Field`] is resolved to its value for this request/response
/// and passed through [`push_escaped_field`]; unknown or missing values fall
/// back to `"-"`.
fn render_text_template(
    parts: &[TemplatePart],
    ctx: &HttpFilterContext<'_>,
    status: u16,
    response_headers: Option<&http::HeaderMap>,
    duration_ms: u64,
) -> String {
    let mut result = String::new();

    for part in parts {
        match part {
            TemplatePart::Literal(literal) => {
                result.push_str(literal);
            },
            TemplatePart::Field(field) => {
                let map =
                    build_record_from_fields(std::slice::from_ref(field), ctx, status, response_headers, duration_ms);
                let value = map.into_values().next().unwrap_or_else(|| "-".to_owned());
                push_escaped_field(&mut result, &value);
            },
        }
    }
    result
}

/// Append a resolved field value to a rendered template line, defending against
/// log injection.
///
/// The value is first control-character sanitized with [`sanitize_for_log`]
/// (dropping newlines so it cannot forge a new log line), then `"` and `\` are
/// backslash-escaped nginx-style so a client-controlled value cannot break out
/// of a quoted template field (e.g. forging a status by closing an earlier
/// quote).
fn push_escaped_field(result: &mut String, value: &str) {
    for ch in sanitize_for_log(value).chars() {
        if matches!(ch, '"' | '\\') {
            result.push('\\');
        }
        result.push(ch);
    }
}

// -----------------------------------------------------------------------------
// Shared emit helpers
// -----------------------------------------------------------------------------

/// Returns `true` for responses that Pingora delivers without a body phase.
///
/// Shared by [`AccessLogFilter`] and the protocol layer's delivery
/// completion tracking: bodyless responses finish at the response
/// phase, everything else finishes at body end-of-stream.
pub fn bodyless_response(status: http::StatusCode, req_method: &http::Method) -> bool {
    status.as_u16() < 200
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
        || req_method == http::Method::HEAD
}

/// Whether the request itself is gRPC. A stray `grpc-status` on an ordinary
/// response must not make it look like a completed gRPC call.
fn request_is_grpc(ctx: &HttpFilterContext<'_>) -> bool {
    praxis_core::grpc::GrpcKind::from_headers(&ctx.request.headers).is_grpc()
}

/// Marker inserted into request extensions once an access record has been
/// emitted for this request.
///
/// The protocol-layer fallback checks for it via
/// [`access_record_already_emitted`] so a request the filter already logged
/// (e.g. a bodyless response whose `on_response` emitted before a later
/// response filter rejected) does not gain a duplicate fallback record.
struct AccessRecordEmitted;

/// Whether an access record has already been emitted for this request.
#[must_use]
pub fn access_record_already_emitted(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.extensions.get::<AccessRecordEmitted>().is_some()
}

/// Record that an access record has been emitted for this request.
pub fn mark_access_record_emitted(ctx: &mut HttpFilterContext<'_>) {
    ctx.extensions.insert(AccessRecordEmitted);
}

/// Emit a structured access log record for the current request.
///
/// When the `otel` feature is enabled and a valid `OpenTelemetry` context
/// is attached to the current tracing span, the entry includes `trace_id`
/// (32-char hex, W3C format) and `span_id` (16-char hex) fields for
/// correlation with OTLP-exported traces. The fields are omitted when
/// no `OTel` context is available.
///
/// Shared by [`AccessLogFilter`]'s completion hooks and the protocol
/// layer's fallback for requests whose lifecycle ended before those
/// hooks could run (pre-upstream rejections, upstream failures, and
/// streamed responses aborted mid-body). Fallback records bypass the
/// filter's sampling: incomplete requests are always worth a record.
#[expect(clippy::too_many_lines, reason = "dual info! paths for optional OTel trace fields")]
pub fn emit_access_record(ctx: &HttpFilterContext<'_>, status: u16) {
    let path = sanitize_for_log(ctx.request.uri.path());
    let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();

    #[cfg(feature = "otel")]
    if let Some((trace_id, span_id)) = extract_otel_ids() {
        info!(
            method = %ctx.request.method,
            path = %path,
            client_ip = %client_ip,
            cluster = ctx.cluster_name().unwrap_or("-"),
            duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis()),
            request_body_bytes = ctx.request_body_bytes,
            request_id = ctx.request_id().unwrap_or("-"),
            response_body_bytes = ctx.response_body_bytes,
            span_id = %span_id,
            status,
            trace_id = %trace_id,
            upstream = ctx.upstream_addr().unwrap_or("-"),
            "access"
        );
        return;
    }

    info!(
        method = %ctx.request.method,
        path = %path,
        client_ip = %client_ip,
        status,
        duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis()),
        cluster = ctx.cluster_name().unwrap_or("-"),
        upstream = ctx.upstream_addr().unwrap_or("-"),
        request_id = ctx.request_id().unwrap_or("-"),
        request_body_bytes = ctx.request_body_bytes,
        response_body_bytes = ctx.response_body_bytes,
        "access"
    );
}

/// Build a record from an explicit list of field tokens.
#[expect(clippy::too_many_lines, reason = "field projection match arms")]
fn build_record_from_fields(
    fields: &[FieldToken],
    ctx: &HttpFilterContext<'_>,
    status: u16,
    response_headers: Option<&http::HeaderMap>,
    duration_ms: u64,
) -> BTreeMap<String, String> {
    let path = sanitize_for_log(ctx.request.uri.path());
    let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
    let duration_ms = duration_ms.to_string();

    let mut record = BTreeMap::new();
    for token in fields {
        match token {
            FieldToken::Method => {
                record.insert("method".to_owned(), ctx.request.method.to_string());
            },
            FieldToken::Path => {
                record.insert("path".to_owned(), path.to_string());
            },
            FieldToken::ClientIp => {
                record.insert("client_ip".to_owned(), client_ip.clone());
            },
            FieldToken::Status => {
                record.insert("status".to_owned(), status.to_string());
            },
            FieldToken::DurationMs => {
                record.insert("duration_ms".to_owned(), duration_ms.clone());
            },
            FieldToken::Cluster => {
                record.insert("cluster".to_owned(), ctx.cluster_name().unwrap_or("-").to_owned());
            },
            FieldToken::Upstream => {
                record.insert("upstream".to_owned(), ctx.upstream_addr().unwrap_or("-").to_owned());
            },
            FieldToken::RequestId => {
                record.insert("request_id".to_owned(), ctx.request_id().unwrap_or("-").to_owned());
            },
            FieldToken::RequestBodyBytes => {
                record.insert("request_body_bytes".to_owned(), ctx.request_body_bytes.to_string());
            },
            FieldToken::ResponseBodyBytes => {
                record.insert("response_body_bytes".to_owned(), ctx.response_body_bytes.to_string());
            },
            FieldToken::TraceId => {
                record.insert("trace_id".to_owned(), current_trace_id());
            },
            FieldToken::SpanId => {
                record.insert("span_id".to_owned(), current_span_id());
            },
            FieldToken::GrpcStatus => {
                let value = ctx
                    .grpc_completion()
                    .map_or_else(|| "-".to_owned(), |completion| completion.raw_code().to_string());
                record.insert("grpc_status".to_owned(), value);
            },
            FieldToken::GrpcStatusName => {
                let value = ctx
                    .grpc_completion()
                    .map_or_else(|| "-".to_owned(), praxis_core::grpc::GrpcCompletion::code_name);
                record.insert("grpc_status_name".to_owned(), value);
            },
            FieldToken::GrpcMessage => {
                let value = ctx
                    .grpc_completion()
                    .and_then(|completion| completion.message())
                    .map_or_else(|| "-".to_owned(), |message| sanitize_for_log(message).into_owned());
                record.insert("grpc_message".to_owned(), value);
            },
            FieldToken::GrpcStatusDetailsBin => {
                let value = ctx
                    .grpc_completion()
                    .and_then(|completion| completion.status_details_bin())
                    .unwrap_or("-")
                    .to_owned();
                record.insert("grpc_status_details_bin".to_owned(), value);
            },
            FieldToken::RequestHeader(name) => {
                let value = first_header_value(&ctx.request.headers, name).unwrap_or_else(|| "-".to_owned());
                let key = format!("request_header.{}", header_json_key(name));
                record.insert(key, value);
            },
            FieldToken::ResponseHeader(name) => {
                let value = response_headers
                    .and_then(|headers| first_header_value(headers, name))
                    .unwrap_or_else(|| "-".to_owned());
                let key = format!("response_header.{}", header_json_key(name));
                record.insert(key, value);
            },
            FieldToken::Metadata(key) => {
                let value = ctx.get_metadata(key).unwrap_or("-").to_owned();
                record.insert(format!("metadata.{key}"), value);
            },
        }
    }
    record
}

#[async_trait]
impl HttpFilter for AccessLogFilter {
    fn name(&self) -> &'static str {
        "access_log"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    /// Emit the record for a request that never reached the completion
    /// hooks, honouring the configured `fields`.
    ///
    /// A complete gRPC call carries its outcome in trailers, so it reaches
    /// the log only through this path; it is sampled and gated like any
    /// other response. A request with no completion is genuinely incomplete
    /// (rejected before the upstream, or aborted mid-stream) and is always
    /// recorded, so no failure goes unlogged. Returns `true` once the record
    /// is claimed, including when sampling or conditions drop it, so the
    /// caller does not re-emit it through the fixed-shape fallback.
    fn emit_deferred_record(&self, ctx: &HttpFilterContext<'_>, status: u16) -> bool {
        // Direct sinks (stdout/file) bypass tracing, so the level gate must not
        // suppress them; it stays a fast path only for the tracing sink.
        if matches!(self.sink, RuntimeSink::Tracing) && !tracing::enabled!(tracing::Level::INFO) {
            return false;
        }
        let duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis());
        if ctx.grpc_completion.is_some()
            && request_is_grpc(ctx)
            && (!self.passes_emit_conditions(ctx, status, duration_ms) || !self.should_log())
        {
            return true;
        }
        let response_headers = ctx.response_header.as_ref().map(|response| &response.headers);
        self.emit_access_log(ctx, status, response_headers, duration_ms);
        true
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = &ctx.response_header else {
            return Ok(FilterAction::Continue);
        };
        let status = resp.status.as_u16();
        let bodyless = Self::is_bodyless(resp.status, &ctx.request.method);
        let response_headers = self.needs_response_headers.then(|| resp.headers.clone());

        // Emit from the captured map before storing it: re-reading the
        // freshly inserted state cloned the header map a second time on
        // every bodyless response.
        if bodyless {
            self.maybe_emit(ctx, status, response_headers.as_ref());
        }
        ctx.insert_filter_state(AccessLogState {
            status,
            response_headers,
        });
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            // The record is emitted at most once, so the stored map can
            // be moved out rather than cloned per response.
            let (status, headers) = ctx
                .get_filter_state_mut::<AccessLogState>()
                .map_or((0, None), |state| (state.status, state.response_headers.take()));
            self.maybe_emit(ctx, status, headers.as_ref());
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Config validation utilities
// -----------------------------------------------------------------------------

fn normalize_header_names(names: Option<&[String]>) -> Result<HashSet<String>, FilterError> {
    let Some(names) = names else {
        return Ok(HashSet::new());
    };

    let mut normalized = HashSet::with_capacity(names.len());
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("access_log: header names must not be empty".into());
        }
        if super::is_sensitive_header(trimmed) {
            return Err(format!("access_log: header {trimmed:?} is not allowed in v1").into());
        }
        normalized.insert(trimmed.to_ascii_lowercase());
    }
    Ok(normalized)
}

fn parse_field_tokens(
    fields: Option<Vec<&str>>,
    request_headers: &HashSet<String>,
    response_headers: &HashSet<String>,
) -> Result<Vec<FieldToken>, FilterError> {
    let tokens = match fields {
        None => DEFAULT_FIELDS
            .iter()
            .copied()
            .map(parse_scalar_field_token)
            .collect::<Result<Vec<_>, _>>()?,
        Some(values) => values
            .iter()
            .copied()
            .map(parse_scalar_field_token)
            .collect::<Result<Vec<_>, _>>()?,
    };

    for token in &tokens {
        match token {
            FieldToken::RequestHeader(name) if !request_headers.contains(name) => {
                return Err(format!("access_log: request_header.{name} requires {name:?} in request_headers").into());
            },
            FieldToken::ResponseHeader(name) if !response_headers.contains(name) => {
                return Err(format!("access_log: response_header.{name} requires {name:?} in response_headers").into());
            },
            _ => {},
        }
    }

    Ok(tokens)
}

/// Field tokens for the default flat shape.
///
/// The tracing path logs the default shape through the flat
/// [`AccessLogFilter::emit_default`] method, so it never needs these tokens; a
/// direct sink serializes a JSON
/// object instead and builds it from this list. Every name is a known-valid
/// scalar token, so parse failures are impossible and dropped.
fn default_field_tokens() -> Vec<FieldToken> {
    DEFAULT_FIELDS
        .iter()
        .copied()
        .filter_map(|name| parse_scalar_field_token(name).ok())
        .collect()
}

/// Parse a prefixed field token.
fn parse_prefixed_field_token(token: &str) -> Option<Result<FieldToken, FilterError>> {
    if let Some(name) = token.strip_prefix("request_header.") {
        return Some(if name.is_empty() {
            Err("access_log: request_header token must include a header name".into())
        } else {
            Ok(FieldToken::RequestHeader(name.to_ascii_lowercase()))
        });
    }
    if let Some(name) = token.strip_prefix("response_header.") {
        return Some(if name.is_empty() {
            Err("access_log: response_header token must include a header name".into())
        } else {
            Ok(FieldToken::ResponseHeader(name.to_ascii_lowercase()))
        });
    }
    if let Some(key) = token.strip_prefix("metadata.") {
        return Some(if key.is_empty() {
            Err("access_log: metadata token must include a key".into())
        } else {
            Ok(FieldToken::Metadata(key.to_owned()))
        });
    }
    None
}

fn parse_scalar_field_token(token: &str) -> Result<FieldToken, FilterError> {
    if let Some(prefixed) = parse_prefixed_field_token(token) {
        return prefixed;
    }
    if let Some(parsed) = parse_grpc_field_token(token) {
        return Ok(parsed);
    }

    match token {
        "method" => Ok(FieldToken::Method),
        "path" => Ok(FieldToken::Path),
        "client_ip" => Ok(FieldToken::ClientIp),
        "status" => Ok(FieldToken::Status),
        "duration_ms" => Ok(FieldToken::DurationMs),
        "cluster" => Ok(FieldToken::Cluster),
        "upstream" => Ok(FieldToken::Upstream),
        "request_id" => Ok(FieldToken::RequestId),
        "request_body_bytes" => Ok(FieldToken::RequestBodyBytes),
        "response_body_bytes" => Ok(FieldToken::ResponseBodyBytes),
        "trace_id" => Ok(FieldToken::TraceId),
        "span_id" => Ok(FieldToken::SpanId),
        "filter_results" => Err("access_log: filter_results is not supported in v1".into()),
        other => Err(format!("access_log: unknown field token {other:?}").into()),
    }
}

/// Parse the gRPC completion field tokens.
///
/// These read the `grpc-status` family of response trailers and render
/// `-` for any response that carries none.
fn parse_grpc_field_token(token: &str) -> Option<FieldToken> {
    match token {
        "grpc_status" => Some(FieldToken::GrpcStatus),
        "grpc_status_name" => Some(FieldToken::GrpcStatusName),
        "grpc_message" => Some(FieldToken::GrpcMessage),
        "grpc_status_details_bin" => Some(FieldToken::GrpcStatusDetailsBin),
        _ => None,
    }
}

fn validate_emit_conditions(conditions: Option<&AccessLogEmitConditions>) -> Result<(), FilterError> {
    let Some(conditions) = conditions else {
        return Ok(());
    };

    if conditions.min_duration_ms.is_none()
        && conditions.status_classes.as_ref().is_none_or(Vec::is_empty)
        && conditions.paths.as_ref().is_none_or(Vec::is_empty)
    {
        return Err(
            "access_log: conditions must include at least one of min_duration_ms, status_classes, or paths".into(),
        );
    }

    // Invalid class strings are rejected by serde at deserialization time
    // (StatusClass is a closed enum), so only emptiness needs checking here.
    if let Some(classes) = &conditions.status_classes
        && classes.is_empty()
    {
        return Err("access_log: status_classes must not be empty when present".into());
    }

    if let Some(paths) = &conditions.paths {
        if paths.is_empty() {
            return Err("access_log: paths must not be empty when present".into());
        }
        for path in paths {
            if path.contains('*') {
                return Err(format!("access_log: paths must be prefixes without globs, got {path:?}").into());
            }
        }
    }

    Ok(())
}

fn header_json_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn first_header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Extract `trace_id` and `span_id` from the `OpenTelemetry` context
/// attached to the current tracing span.
///
/// Returns `None` when no `OTel` layer is active or the span context
/// is invalid (e.g. tracing is not configured with OTLP export).
#[cfg(feature = "otel")]
fn extract_otel_ids() -> Option<(String, String)> {
    use opentelemetry::trace::TraceContextExt as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let span = tracing::Span::current();
    let otel_ctx = span.context();
    let span_ref = otel_ctx.span();
    let span_context = span_ref.span_context();

    span_context
        .is_valid()
        .then(|| (span_context.trace_id().to_string(), span_context.span_id().to_string()))
}

fn current_trace_id() -> String {
    #[cfg(feature = "otel")]
    if let Some((trace_id, _)) = extract_otel_ids() {
        return trace_id;
    }
    "-".to_owned()
}

fn current_span_id() -> String {
    #[cfg(feature = "otel")]
    if let Some((_, span_id)) = extract_otel_ids() {
        return span_id;
    }
    "-".to_owned()
}

/// Project selected fields into a single `tracing::info!` record.
///
/// `tracing` requires field names to be static, so a custom field set is
/// emitted as one JSON object under the `record` field. This keeps the log
/// schema stable regardless of which or how many fields are selected; the
/// default field set keeps the flat legacy shape via `emit_default`.
fn emit_projected_record(record: &BTreeMap<String, String>) {
    if record.is_empty() {
        return;
    }

    let json = serde_json::to_string(record).unwrap_or_default();
    info!(message = "access", record = %json);
}

/// Emit a rendered text-template line through the tracing subscriber.
///
/// Unlike [`emit_projected_record`], a template always renders to exactly one
/// string, so it needs no dynamic-field workaround: it fits a single static
/// tracing field regardless of what the template contains.
fn emit_projected_line(line: &str) {
    info!(message = "access", line = %line);
}

// -----------------------------------------------------------------------------
// Sink construction
// -----------------------------------------------------------------------------

/// Build a [`RuntimeSink`] from the deserialized `sink` config.
///
/// No `sink` emits through the tracing subscriber (the default). `stdout` and
/// `file` bypass tracing and write NDJSON lines directly; `file` requires a
/// `path` and `stdout` rejects one.
fn build_runtime_sink(sink_cfg: Option<SinkConfig>) -> Result<RuntimeSink, FilterError> {
    match sink_cfg {
        None => Ok(RuntimeSink::Tracing),
        Some(SinkConfig::Stdout) => Ok(RuntimeSink::Direct(stdout_sink()?)),
        Some(SinkConfig::File { path }) => Ok(RuntimeSink::Direct(file_sink(&path)?)),
        #[cfg(feature = "access-log-syslog")]
        Some(SinkConfig::Syslog { facility, target }) => Ok(RuntimeSink::Direct(syslog_sink(facility, target)?)),
    }
}

// -----------------------------------------------------------------------------
// Numeric Conversion
// -----------------------------------------------------------------------------

/// Truncate a `u128` to `u64`, saturating at `u64::MAX`.
fn truncate_u128(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

// -----------------------------------------------------------------------------
// Sanitization
// -----------------------------------------------------------------------------

/// Strip control characters (C0/C1, ANSI escapes) from a string before
/// logging. Prevents log injection via crafted request URIs.
///
/// Returns [`Cow::Borrowed`] when the input contains no control
/// characters (the common case for HTTP paths).
fn sanitize_for_log(s: &str) -> Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() {
            continue;
        }
        out.push(c);
    }
    Cow::Owned(out)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn test_filter(config: &serde_yaml::Value) -> AccessLogFilter {
        let cfg: AccessLogConfig = parse_filter_config("access_log", config).unwrap();
        AccessLogFilter::build(cfg).unwrap()
    }

    fn default_filter() -> AccessLogFilter {
        AccessLogFilter {
            sample_rate: 1.0,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                shape: EmitShape::DefaultFlat,
            },
            emit_conditions: None,
            needs_response_headers: false,
            sink: RuntimeSink::Tracing,
        }
    }

    #[test]
    fn from_config_defaults_to_log_all() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = test_filter(&config);
        assert_eq!(
            filter.name(),
            "access_log",
            "default config should produce access_log filter"
        );
        assert!(matches!(filter.emit_plan.shape, EmitShape::DefaultFlat));
    }

    #[test]
    fn from_config_parses_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
        let filter = test_filter(&yaml);
        assert_eq!(filter.name(), "access_log", "sample_rate config should parse correctly");
    }

    #[test]
    fn from_config_rejects_zero_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.0").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_negative_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: -0.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_sample_rate_above_one() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 1.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_nan_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: .nan").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "NaN passes a range check and then never samples; got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_non_numeric_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: abc").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("invalid type"),
            "serde should reject non-numeric sample_rate: {err}"
        );
    }

    #[test]
    fn from_config_rejects_unknown_field() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sampl_rate: 0.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("unknown field"),
            "typo should be rejected by deny_unknown_fields: {err}"
        );
    }

    #[test]
    fn from_config_rejects_empty_fields() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: []").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("fields must not be empty"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_unknown_field_token() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method, not_a_field]").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("unknown field token"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_filter_results_token() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [filter_results]").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("filter_results"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_nested_fields_map() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
fields:
  request_headers: [user-agent]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("scalar tokens") || err.to_string().contains("expected a sequence"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_sensitive_request_header() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
request_headers: [authorization]
fields: [request_header.authorization]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("not allowed"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_header_token_without_list() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [request_header.user-agent]").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("request_headers"), "got: {err}");
    }

    #[test]
    fn from_config_parses_custom_fields_and_headers() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
fields: [method, request_header.user-agent, trace_id]
request_headers: [user-agent]
",
        )
        .unwrap();
        let filter = test_filter(&yaml);
        assert!(matches!(filter.emit_plan.shape, EmitShape::JsonRecord(_)));
        if let EmitShape::JsonRecord(fields) = &filter.emit_plan.shape {
            assert_eq!(fields.len(), 3);
        }
    }

    #[test]
    fn from_config_parses_emit_conditions() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
conditions:
  status_classes: [5xx]
",
        )
        .unwrap();
        let filter = test_filter(&yaml);
        assert!(filter.emit_conditions.is_some());
    }

    #[test]
    fn from_config_rejects_invalid_status_class() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
conditions:
  status_classes: [6xx]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("unknown variant"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_glob_paths() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
conditions:
  paths: [/api/*]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("without globs"), "got: {err}");
    }

    // -------------------------------------------------------------------------
    // Format / template config parsing
    // -------------------------------------------------------------------------

    #[test]
    fn from_config_rejects_format_key() {
        // `format` was removed: output type is inferred from `template` presence,
        // so the key is now rejected by deny_unknown_fields.
        let yaml: serde_yaml::Value = serde_yaml::from_str("format: text\ntemplate: \"{method} {path}\"").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_fields_with_template() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method]\ntemplate: \"{method}\"").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_empty_template() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("template: \"   \"").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("template must not be empty"), "got: {err}");
    }

    #[test]
    fn from_config_template_builds_text_shape() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("template: \"{method} {path} {status}\"").unwrap();
        let filter = test_filter(&yaml);
        assert!(
            matches!(filter.emit_plan.shape, EmitShape::Text(_)),
            "template config should build a Text emit shape"
        );
    }

    // -------------------------------------------------------------------------
    // Template parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_template_extracts_literals_and_field_tokens() {
        let headers = HashSet::new();
        let parts = parse_template("{method} {path} [{status}]", &headers, &headers).unwrap();
        assert_eq!(parts.len(), 6); // Field, Literal, Field, Literal, Field, Literal
    }

    #[test]
    fn parse_template_rejects_unclosed_brace() {
        let headers = HashSet::new();
        let err = parse_template("{method {path}", &headers, &headers).unwrap_err();
        assert!(err.to_string().contains("unclosed"), "got: {err}");
    }

    #[test]
    fn parse_template_rejects_unknown_token() {
        let headers = HashSet::new();
        let err = parse_template("{not_a_field}", &headers, &headers).unwrap_err();
        assert!(err.to_string().contains("unknown field token"), "got: {err}");
    }

    #[test]
    fn parse_template_rejects_request_header_without_allowlist() {
        let headers = HashSet::new();
        let err = parse_template("{request_header.user-agent}", &headers, &headers).unwrap_err();
        assert!(err.to_string().contains("request_headers"), "got: {err}");
    }

    #[test]
    fn parse_template_accepts_allowed_header() {
        let mut req_headers = HashSet::new();
        req_headers.insert("user-agent".to_owned());
        let res_headers = HashSet::new();
        let parts = parse_template("{request_header.user-agent}", &req_headers, &res_headers).unwrap();
        assert_eq!(parts.len(), 1);
        assert!(matches!(&parts[0], TemplatePart::Field(FieldToken::RequestHeader(n)) if n == "user-agent"));
    }

    #[test]
    fn parse_template_rejects_response_header_without_allowlist() {
        let headers = HashSet::new();
        let err = parse_template("{response_header.content-type}", &headers, &headers).unwrap_err();
        assert!(err.to_string().contains("response_headers"), "got: {err}");
    }

    #[test]
    fn parse_template_rejects_unclosed_brace_at_end() {
        let headers = HashSet::new();
        let err = parse_template("{method", &headers, &headers).unwrap_err();
        assert!(err.to_string().contains("unclosed"), "got: {err}");
    }

    #[test]
    fn parse_template_rejects_stray_closing_brace() {
        let headers = HashSet::new();
        let err = parse_template("{status}}", &headers, &headers).unwrap_err();
        assert!(err.to_string().contains("unexpected '}'"), "got: {err}");
    }

    // -------------------------------------------------------------------------
    // Text rendering
    // -------------------------------------------------------------------------

    #[test]
    fn render_text_template_interpolates_method_path_status() {
        let parts = vec![
            TemplatePart::Field(FieldToken::Method),
            TemplatePart::Literal(" ".to_owned()),
            TemplatePart::Field(FieldToken::Path),
            TemplatePart::Literal(" ".to_owned()),
            TemplatePart::Field(FieldToken::Status),
        ];
        let req = crate::test_utils::make_request(http::Method::GET, "/api");
        let ctx = crate::test_utils::make_filter_context(&req);
        let line = render_text_template(&parts, &ctx, 200, None, 42);
        assert_eq!(line, "GET /api 200");
    }

    #[test]
    fn render_text_template_uses_dash_for_missing_values() {
        let parts = vec![TemplatePart::Field(FieldToken::Cluster)];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        let line = render_text_template(&parts, &ctx, 200, None, 0);
        assert_eq!(line, "-", "missing cluster should render as dash");
    }

    #[test]
    fn render_text_template_sanitizes_field_values() {
        let parts = vec![TemplatePart::Field(FieldToken::Metadata("llm.model".to_owned()))];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("llm.model", "gpt\ninjected 200");
        let line = render_text_template(&parts, &ctx, 200, None, 0);
        assert!(
            !line.contains('\n'),
            "newlines in field values must not forge log lines"
        );
    }

    // -------------------------------------------------------------------------
    // Sampling and emit conditions (unchanged)
    // -------------------------------------------------------------------------

    #[test]
    fn should_log_every_request_by_default() {
        let filter = default_filter();
        for _ in 0..5 {
            assert!(filter.should_log(), "sample_rate=1.0 should log every request");
        }
    }

    #[test]
    fn should_log_samples_at_rate() {
        let filter = AccessLogFilter {
            sample_rate: 0.25,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                shape: EmitShape::DefaultFlat,
            },
            emit_conditions: None,
            needs_response_headers: false,
            sink: RuntimeSink::Tracing,
        };
        let mut logged = 0;
        for _ in 0..8 {
            if filter.should_log() {
                logged += 1;
            }
        }
        assert_eq!(logged, 2, "1-in-4 over 8 calls = 2 logged");
    }

    #[test]
    fn should_log_honors_non_reciprocal_rates() {
        for (rate, calls, expected) in [(0.7, 10, 7), (0.4, 10, 4), (0.000_000_51, 2_000_000, 1)] {
            let filter = AccessLogFilter {
                sample_rate: rate,
                counter: AtomicU64::default(),
                emit_plan: EmitPlan {
                    shape: EmitShape::DefaultFlat,
                },
                emit_conditions: None,
                needs_response_headers: false,
                sink: RuntimeSink::Tracing,
            };
            let logged = (0..calls).filter(|_| filter.should_log()).count();
            assert_eq!(
                logged, expected,
                "rate {rate} over {calls} calls must log exactly {expected}"
            );
        }
    }

    #[test]
    fn status_class_or_matching() {
        assert!(StatusClass::ServerError.matches(500));
        assert!(StatusClass::ClientError.matches(404));
        assert!(!StatusClass::ServerError.matches(200));
    }

    #[test]
    fn passes_emit_conditions_and_sampling_order() {
        let filter = AccessLogFilter {
            sample_rate: 1.0,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                shape: EmitShape::JsonRecord(vec![FieldToken::Method]),
            },
            emit_conditions: Some(AccessLogEmitConditions {
                min_duration_ms: None,
                status_classes: Some(vec![StatusClass::ServerError]),
                paths: None,
            }),
            needs_response_headers: false,
            sink: RuntimeSink::Tracing,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            !filter.passes_emit_conditions(&ctx, 200, 0),
            "200 should not pass 5xx-only condition"
        );
        assert!(
            filter.passes_emit_conditions(&ctx, 503, 0),
            "503 should pass 5xx condition"
        );
    }

    #[test]
    fn build_record_includes_selected_fields_only() {
        let fields = [FieldToken::Method, FieldToken::Status];
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let ctx = crate::test_utils::make_filter_context(&req);
        let record = build_record_from_fields(&fields, &ctx, 201, None, 0);
        assert_eq!(record.len(), 2);
        assert_eq!(record.get("method"), Some(&"POST".to_owned()));
        assert_eq!(record.get("status"), Some(&"201".to_owned()));
        assert!(!record.contains_key("path"));
    }

    #[test]
    fn metadata_token_parses_its_key() {
        let token = parse_scalar_field_token("metadata.llm.model").unwrap();
        assert!(
            matches!(&token, FieldToken::Metadata(key) if key == "llm.model"),
            "the dotted key is taken whole; got {token:?}",
        );
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one assertion per rendered gRPC field")]
    fn build_record_renders_grpc_completion() {
        let fields = [
            FieldToken::GrpcStatus,
            FieldToken::GrpcStatusName,
            FieldToken::GrpcMessage,
            FieldToken::GrpcStatusDetailsBin,
        ];
        let req = grpc_request();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut trailers = http::HeaderMap::new();
        let _prev = trailers.insert("grpc-status", http::HeaderValue::from_static("5"));
        let _prev = trailers.insert("grpc-message", http::HeaderValue::from_static("no%20such%20user"));
        let _prev = trailers.insert("grpc-status-details-bin", http::HeaderValue::from_static("CAUSBG9vcHM"));
        ctx.grpc_completion = praxis_core::grpc::GrpcCompletion::from_headers(&trailers);

        let record = build_record_from_fields(&fields, &ctx, 200, None, 0);

        assert_eq!(
            record.get("grpc_status"),
            Some(&"5".to_owned()),
            "the numeric status should be rendered"
        );
        assert_eq!(
            record.get("grpc_status_name"),
            Some(&"NOT_FOUND".to_owned()),
            "the canonical name should be rendered"
        );
        assert_eq!(
            record.get("grpc_message"),
            Some(&"no%20such%20user".to_owned()),
            "the message should be rendered as received"
        );
        assert_eq!(
            record.get("grpc_status_details_bin"),
            Some(&"CAUSBG9vcHM".to_owned()),
            "status details should be rendered as received"
        );
    }

    #[test]
    fn metadata_token_rejects_an_empty_key() {
        let err = parse_scalar_field_token("metadata.").expect_err("should fail");
        assert!(err.to_string().contains("metadata token"), "got: {err}");
    }

    #[test]
    fn metadata_keys_are_case_sensitive_unlike_header_names() {
        // Header tokens lowercase their name; a metadata key is an exact
        // lookup into the bag, so it must survive as written.
        let token = parse_scalar_field_token("metadata.LLM.Model").unwrap();
        assert!(matches!(&token, FieldToken::Metadata(key) if key == "LLM.Model"));
    }

    #[test]
    fn build_record_emits_filter_metadata() {
        let fields = [FieldToken::Metadata("llm.model".to_owned())];
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("llm.model", "gpt-4o");

        let record = build_record_from_fields(&fields, &ctx, 200, None, 0);
        assert_eq!(record.get("metadata.llm.model"), Some(&"gpt-4o".to_owned()));
    }

    #[test]
    fn build_record_dashes_absent_metadata() {
        let fields = [FieldToken::Metadata("llm.model".to_owned())];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);

        let record = build_record_from_fields(&fields, &ctx, 200, None, 0);
        assert_eq!(
            record.get("metadata.llm.model"),
            Some(&"-".to_owned()),
            "an unset key reads as absent, matching the header tokens",
        );
    }

    #[test]
    fn build_record_grpc_fields_are_dashes_for_non_grpc_responses() {
        let fields = [
            FieldToken::GrpcStatus,
            FieldToken::GrpcStatusName,
            FieldToken::GrpcMessage,
        ];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);

        let record = build_record_from_fields(&fields, &ctx, 200, None, 0);

        assert_eq!(record.get("grpc_status"), Some(&"-".to_owned()), "no gRPC status");
        assert_eq!(record.get("grpc_status_name"), Some(&"-".to_owned()), "no gRPC name");
        assert_eq!(record.get("grpc_message"), Some(&"-".to_owned()), "no gRPC message");
    }

    #[test]
    fn grpc_field_tokens_parse() {
        for token in [
            "grpc_status",
            "grpc_status_name",
            "grpc_message",
            "grpc_status_details_bin",
        ] {
            assert!(
                parse_scalar_field_token(token).is_ok(),
                "{token} should be a valid access_log field"
            );
        }
    }

    #[test]
    fn build_record_trace_id_defaults_to_dash_without_span() {
        let fields = [FieldToken::TraceId, FieldToken::SpanId];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        let record = build_record_from_fields(&fields, &ctx, 200, None, 0);
        assert_eq!(record.get("trace_id"), Some(&"-".to_owned()));
        assert_eq!(record.get("span_id"), Some(&"-".to_owned()));
    }

    #[cfg(feature = "otel")]
    #[test]
    fn extract_otel_ids_returns_ids_with_active_otel_span() {
        use opentelemetry::trace::TracerProvider as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let tracer = provider.tracer("test");
        let layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("test_span");
        let _entered = span.enter();

        let (trace_id, span_id) = extract_otel_ids().expect("ids should be present with an active OTel span");
        assert_eq!(trace_id.len(), 32, "trace_id must be 32 hex chars, got {trace_id}");
        assert_ne!(trace_id, "0".repeat(32), "trace_id must not be all-zero");
        assert_eq!(span_id.len(), 16, "span_id must be 16 hex chars, got {span_id}");
        assert_ne!(span_id, "0".repeat(16), "span_id must not be all-zero");
    }

    // -------------------------------------------------------------------------
    // Sanitization (unchanged)
    // -------------------------------------------------------------------------

    #[test]
    fn sanitize_strips_newlines() {
        assert_eq!(
            sanitize_for_log("/path\ninjected"),
            "/pathinjected",
            "newlines should be stripped"
        );
        assert_eq!(
            sanitize_for_log("/path\r\ninjected"),
            "/pathinjected",
            "CRLF should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_ansi_escapes() {
        assert_eq!(
            sanitize_for_log("/path\x1b[31mred\x1b[0m"),
            "/pathred",
            "ANSI escapes should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_tabs_and_null() {
        assert_eq!(
            sanitize_for_log("/path\0\there"),
            "/pathhere",
            "null and tab should be stripped"
        );
    }

    #[test]
    fn sanitize_preserves_normal_paths() {
        assert_eq!(
            sanitize_for_log("/api/v1/users?q=foo"),
            "/api/v1/users?q=foo",
            "normal paths should be unchanged"
        );
    }

    #[test]
    fn sanitize_returns_borrowed_for_clean_paths() {
        let result = sanitize_for_log("/clean/path");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "clean paths should return Cow::Borrowed"
        );
    }

    #[test]
    fn sanitize_returns_owned_for_dirty_paths() {
        let result = sanitize_for_log("/path\ninjected");
        assert!(matches!(result, Cow::Owned(_)), "dirty paths should return Cow::Owned");
    }

    #[test]
    fn sanitize_strips_del_character() {
        assert_eq!(
            sanitize_for_log("/path\x7Fhere"),
            "/pathhere",
            "DEL (0x7F) should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_c1_control_characters() {
        assert_eq!(
            sanitize_for_log("/path\u{0080}injected"),
            "/pathinjected",
            "C1 control U+0080 should be stripped"
        );
        assert_eq!(
            sanitize_for_log("/path\u{009F}injected"),
            "/pathinjected",
            "C1 control U+009F should be stripped"
        );
    }

    // -------------------------------------------------------------------------
    // HttpFilter hooks (unchanged)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn on_response_continues_with_no_header() {
        let filter = default_filter();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response with no header should continue"
        );
    }

    #[tokio::test]
    async fn on_response_with_populated_context_continues() {
        use praxis_core::connectivity::{ConnectionOptions, Upstream};

        let filter = default_filter();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-request-id", "req-123".parse().unwrap());
        let req = crate::context::Request {
            method: http::Method::GET,
            uri: "/api/users".parse().unwrap(),
            headers,
        };
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        ctx.cluster = Some(Arc::from("backend"));
        ctx.upstream = Some(Upstream {
            address: Arc::from("10.0.0.2:8080"),
            authority: None,
            base_path: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        });
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response with populated context should continue"
        );
    }

    #[tokio::test]
    async fn on_response_stores_state_in_filter_state() {
        let filter = default_filter();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::NOT_FOUND,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
            Some(404),
            "on_response should store status in access log state"
        );
    }

    #[tokio::test]
    async fn on_response_no_header_skips_filter_state() {
        let filter = default_filter();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            ctx.get_filter_state::<AccessLogState>().is_none(),
            "on_response without header should not store filter state"
        );
    }

    #[test]
    fn is_bodyless_detects_1xx() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::CONTINUE, &http::Method::GET),
            "100 Continue should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_204() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::NO_CONTENT, &http::Method::DELETE),
            "204 No Content should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_304() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::NOT_MODIFIED, &http::Method::GET),
            "304 Not Modified should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_head() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::HEAD),
            "HEAD request should be bodyless regardless of status"
        );
    }

    #[test]
    fn is_bodyless_returns_false_for_normal_response() {
        assert!(
            !AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::GET),
            "normal 200 GET should not be bodyless"
        );
    }

    #[tokio::test]
    async fn on_response_stores_status_for_bodyless() {
        let filter = default_filter();
        let req = crate::test_utils::make_request(http::Method::DELETE, "/api/users/42");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::NO_CONTENT,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
            Some(204),
            "on_response should store status for bodyless responses"
        );
    }

    #[test]
    fn on_response_body_continues_before_end_of_stream() {
        let filter = default_filter();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut body = Some(Bytes::from_static(b"partial"));
        let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response_body should continue before end_of_stream"
        );
    }

    #[tokio::test]
    async fn on_response_body_uses_status_from_on_response() {
        let filter = default_filter();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);

        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        ctx.response_body_bytes = 1234;
        let mut body = None;
        let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response_body should continue at end_of_stream"
        );
        assert_eq!(
            ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
            Some(200),
            "status set by on_response should survive into on_response_body"
        );
    }

    #[test]
    fn response_body_access_is_read_only() {
        let filter = default_filter();
        assert_eq!(
            filter.response_body_access(),
            BodyAccess::ReadOnly,
            "access_log should declare ReadOnly response body access"
        );
    }

    #[test]
    fn normalized_ipv4_formats_without_mapped_prefix() {
        use std::net::IpAddr;

        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            v4.to_string(),
            "10.0.0.1",
            "normalized IPv4 should format without ::ffff: prefix"
        );

        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            mapped.to_string(),
            "::ffff:10.0.0.1",
            "un-normalized mapped address keeps ::ffff: prefix in Display"
        );
    }

    // -------------------------------------------------------------------------
    // Emission Shape (unchanged)
    // -------------------------------------------------------------------------

    /// Capture `tracing` output emitted synchronously by `f` on this thread.
    fn capture_logs<F: FnOnce()>(f: F) -> String {
        use std::io::Write;

        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buffer lock").extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buffer.0.lock().expect("buffer lock").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn no_record_work_when_info_level_disabled() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method, path, status]").unwrap();
        let filter = test_filter(&yaml);
        let req = crate::test_utils::make_request(http::Method::GET, "/api/thing");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).finish();
        tracing::subscriber::with_default(subscriber, || {
            filter.maybe_emit(&mut ctx, 200, None);
        });

        assert!(
            !access_record_already_emitted(&ctx),
            "when info is disabled, maybe_emit must skip all work (no marker set)"
        );
    }

    #[test]
    #[expect(clippy::disallowed_methods, reason = "sync sink test polls with thread::sleep")]
    fn file_sink_writes_even_when_info_level_disabled() {
        // A file sink bypasses tracing, so the INFO gate must not suppress it:
        // with RUST_LOG=warn a file sink would otherwise silently lose every
        // record, including rejections and upstream failures.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap())).unwrap();
        let filter = test_filter(&yaml);

        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).finish();
        tracing::subscriber::with_default(subscriber, || {
            for (path, status) in [("/ok", 200), ("/err", 500)] {
                let req = crate::test_utils::make_request(http::Method::GET, path);
                let mut ctx = crate::test_utils::make_filter_context(&req);
                filter.maybe_emit(&mut ctx, status, None);
            }
        });

        let mut lines = 0;
        for _ in 0..100 {
            lines = std::fs::read_to_string(&log_path).unwrap_or_default().lines().count();
            if lines == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(lines, 2, "both records must reach the file sink despite the INFO gate");
    }

    #[test]
    fn maybe_emit_gates_by_status_and_emits_stable_record() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
fields: [method, path, status, duration_ms, request_id]
conditions:
  status_classes: [5xx]
",
        )
        .unwrap();
        let filter = test_filter(&yaml);
        let req = crate::test_utils::make_request(http::Method::GET, "/api/thing");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let unmatched = capture_logs(|| filter.maybe_emit(&mut ctx, 200, None));
        assert!(
            !unmatched.contains("access"),
            "non-matching status must not emit: {unmatched:?}"
        );

        let matched = capture_logs(|| filter.maybe_emit(&mut ctx, 500, None));
        assert!(matched.contains("access"), "matching status must emit: {matched:?}");
        assert!(
            matched.contains("record="),
            "custom field sets emit one JSON record field: {matched:?}"
        );
        for key in ["method", "path", "status", "duration_ms", "request_id"] {
            assert!(matched.contains(key), "record should include {key}: {matched:?}");
        }
    }

    #[test]
    fn small_custom_field_sets_also_emit_record_shape() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method, path]").unwrap();
        let filter = test_filter(&yaml);
        let req = crate::test_utils::make_request(http::Method::GET, "/x");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let out = capture_logs(|| filter.maybe_emit(&mut ctx, 200, None));
        assert!(
            out.contains("record="),
            "small field sets must use the same record shape as large ones: {out:?}"
        );
    }

    #[test]
    fn template_emit_renders_response_header_through_maybe_emit() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
template: \"{status} {response_header.content-type}\"
response_headers: [content-type]
",
        )
        .unwrap();
        let filter = test_filter(&yaml);
        let req = crate::test_utils::make_request(http::Method::GET, "/api/thing");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut response_headers = http::HeaderMap::new();
        response_headers.insert("content-type", "text/plain".parse().unwrap());

        let out = capture_logs(|| filter.maybe_emit(&mut ctx, 200, Some(&response_headers)));
        assert!(
            out.contains("line=200 text/plain"),
            "template emit should render the status and response header into the line field: {out:?}"
        );
    }

    #[test]
    fn deferred_record_samples_complete_grpc_calls() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
        let filter = test_filter(&yaml);
        let req = grpc_request();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.grpc_completion = grpc_completion("0");

        let mut logged = 0;
        for _ in 0..8 {
            if capture_logs(|| {
                let _claimed = filter.emit_deferred_record(&ctx, 200);
            })
            .contains("access")
            {
                logged += 1;
            }
        }
        assert_eq!(logged, 4, "sample_rate 0.5 should log half of the complete gRPC calls");
    }

    #[test]
    fn deferred_record_gates_complete_grpc_by_conditions() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("conditions:\n  paths: [\"/allowed\"]").unwrap();
        let filter = test_filter(&yaml);
        let req = grpc_request();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.grpc_completion = grpc_completion("0");

        let dropped = capture_logs(|| {
            let _claimed = filter.emit_deferred_record(&ctx, 200);
        });
        assert!(
            !dropped.contains("access"),
            "a complete gRPC call outside the configured paths must not log: {dropped:?}"
        );
    }

    #[test]
    fn deferred_record_always_logs_incomplete_requests() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("sample_rate: 0.5\nconditions:\n  paths: [\"/allowed\"]").unwrap();
        let filter = test_filter(&yaml);
        let req = grpc_request();
        let ctx = crate::test_utils::make_filter_context(&req);

        for _ in 0..4 {
            let logged = capture_logs(|| {
                let _claimed = filter.emit_deferred_record(&ctx, 502);
            });
            assert!(
                logged.contains("access"),
                "an incomplete request must always log, bypassing sampling and conditions: {logged:?}"
            );
        }
    }

    #[test]
    fn deferred_record_gates_grpc_by_mapped_status_class() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("conditions:\n  status_classes: [5xx]").unwrap();
        let filter = test_filter(&yaml);
        let req = grpc_request();
        let mut ctx = crate::test_utils::make_filter_context(&req);

        ctx.grpc_completion = grpc_completion("13");
        let logged_error = capture_logs(|| {
            let _claimed = filter.emit_deferred_record(&ctx, 200);
        });
        assert!(
            logged_error.contains("access"),
            "a gRPC INTERNAL error maps to 5xx and must log despite the HTTP 200: {logged_error:?}"
        );

        ctx.grpc_completion = grpc_completion("0");
        let logged_ok = capture_logs(|| {
            let _claimed = filter.emit_deferred_record(&ctx, 200);
        });
        assert!(
            !logged_ok.contains("access"),
            "a successful gRPC call maps to 2xx and must be excluded by an errors-only filter: {logged_ok:?}"
        );
    }

    #[test]
    fn deferred_record_logs_non_canonical_grpc_failures() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("conditions:\n  status_classes: [5xx]").unwrap();
        let filter = test_filter(&yaml);
        let req = grpc_request();
        let mut ctx = crate::test_utils::make_filter_context(&req);

        ctx.grpc_completion = grpc_completion("20");
        let logged = capture_logs(|| {
            let _claimed = filter.emit_deferred_record(&ctx, 200);
        });
        assert!(
            logged.contains("access"),
            "a non-canonical grpc-status is still a failure and must map to 5xx, not the HTTP 200: {logged:?}"
        );
    }

    #[test]
    fn deferred_record_ignores_stray_grpc_status_on_non_grpc_request() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
        let filter = test_filter(&yaml);
        let req = crate::test_utils::make_request(http::Method::GET, "/rest/thing");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.grpc_completion = grpc_completion("0");

        for _ in 0..4 {
            let logged = capture_logs(|| {
                let _claimed = filter.emit_deferred_record(&ctx, 200);
            });
            assert!(
                logged.contains("access"),
                "a non-gRPC request must always log; a stray grpc-status must not enable sampling: {logged:?}"
            );
        }
    }

    fn grpc_request() -> crate::context::Request {
        let mut req = crate::test_utils::make_request(http::Method::POST, "/pkg.Svc/Method");
        let _prev = req.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );
        req
    }

    fn grpc_completion(status: &'static str) -> Option<praxis_core::grpc::GrpcCompletion> {
        let mut trailers = http::HeaderMap::new();
        let _prev = trailers.insert("grpc-status", http::HeaderValue::from_static(status));
        praxis_core::grpc::GrpcCompletion::from_headers(&trailers)
    }

    #[test]
    fn render_text_template_substitutes_request_id_and_response_header() {
        let template = "{method} id={request_id} agent={response_header.user-agent}";
        let mut request_headers = HashSet::new();
        let mut response_headers = HashSet::new();

        request_headers.insert(String::from("user-agent"));
        response_headers.insert(String::from("user-agent"));
        let parts = parse_template(template, &request_headers, &response_headers).unwrap();
        assert_eq!(parts.len(), 5, "method, literal, request_id, literal, response_header");

        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-request-id", "abdc".parse().unwrap());
        let ctx = crate::test_utils::make_filter_context(&req);
        let mut response_headers_map = http::HeaderMap::new();
        response_headers_map.insert("user-agent", "my-agent".parse().unwrap());
        let line = render_text_template(&parts, &ctx, 200, Some(&response_headers_map), 5);
        assert_eq!(
            line, "GET id=abdc agent=my-agent",
            "template should interpolate method, request id, and response header"
        );
    }

    // -------------------------------------------------------------------------
    // Sinks
    // -------------------------------------------------------------------------

    #[test]
    fn from_config_no_sink_defaults_to_tracing() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = test_filter(&config);
        assert!(matches!(filter.sink, RuntimeSink::Tracing));
    }

    /// A background flush can expose an incomplete next record.
    fn complete_ndjson_count(contents: &str) -> Option<usize> {
        if !contents.is_empty() && !contents.ends_with('\n') {
            return None;
        }
        let mut count = 0_usize;
        for line in contents.lines() {
            if serde_json::from_str::<BTreeMap<String, String>>(line).is_err() {
                return None;
            }
            count = count.saturating_add(1);
        }
        Some(count)
    }

    /// Read a file, retrying briefly so a background writer thread has time to
    /// flush before the assertion runs.
    #[expect(clippy::disallowed_methods, reason = "sync sink tests poll with thread::sleep")]
    fn read_file_with_retry(path: &std::path::Path) -> String {
        for _ in 0..100 {
            if let Ok(contents) = std::fs::read_to_string(path)
                && !contents.is_empty()
            {
                return contents;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn complete_ndjson_count_requires_a_final_newline() {
        assert_eq!(complete_ndjson_count(""), Some(0), "empty input is zero records");
        assert_eq!(
            complete_ndjson_count("{\"a\":\"1\"}\n"),
            Some(1),
            "one newline-terminated record counts"
        );
        assert_eq!(
            complete_ndjson_count("{\"a\":\"1\"}\n{\"b\":\"2\"}\n"),
            Some(2),
            "two newline-terminated records count"
        );
        assert!(
            complete_ndjson_count("{\"a\":\"1\"}").is_none(),
            "a JSON object without a newline is not a finished record"
        );
        assert!(
            complete_ndjson_count("{\"a\":\"1\"}\nnot-json\n").is_none(),
            "invalid JSON is not a finished record"
        );
        assert!(
            complete_ndjson_count("{\"a\":\"1\"}\n{\"b\"").is_none(),
            "a truncated trailing record is not finished"
        );
    }

    #[test]
    fn from_config_parses_stdout_sink() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: stdout").unwrap();
        let filter = test_filter(&yaml);
        let RuntimeSink::Direct(sink) = &filter.sink else {
            panic!("stdout sink should resolve to a direct sink");
        };
        assert_eq!(&*sink.dest, "stdout");
    }

    #[test]
    fn from_config_rejects_sink_stdout_with_path() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: stdout\n  path: /tmp/x.log").unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("stdout sink with a path should fail");
        assert!(err.to_string().contains("does not accept a path"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_sink_file_without_path() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: file").unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("file sink without a path should fail");
        assert!(err.to_string().contains("requires a path"), "got: {err}");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn from_config_rejects_syslog_udp_without_address() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: syslog\n  transport: udp").unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("syslog udp without an address should fail");
        assert!(err.to_string().contains("requires an address"), "got: {err}");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn from_config_rejects_syslog_tcp_without_address() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: syslog\n  transport: tcp").unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("syslog tcp without an address should fail");
        assert!(err.to_string().contains("requires an address"), "got: {err}");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn from_config_rejects_syslog_unix_with_address() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("sink:\n  type: syslog\n  transport: unix\n  address: 127.0.0.1:514").unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("syslog unix with an address should fail");
        assert!(err.to_string().contains("does not accept an address"), "got: {err}");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn from_config_rejects_syslog_udp_with_path() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("sink:\n  type: syslog\n  transport: udp\n  address: 127.0.0.1:514\n  path: /dev/log")
                .unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("syslog udp with a path should fail");
        assert!(err.to_string().contains("does not accept a path"), "got: {err}");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn from_config_rejects_syslog_fields_on_stdout() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: stdout\n  facility: local0").unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("stdout sink with a syslog field should fail");
        assert!(err.to_string().contains("does not accept syslog fields"), "got: {err}");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn from_config_rejects_syslog_fields_on_file() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("sink:\n  type: file\n  path: /tmp/x.log\n  transport: tcp").unwrap();
        let err = AccessLogFilter::from_config(&yaml)
            .err()
            .expect("file sink with a syslog field should fail");
        assert!(err.to_string().contains("does not accept syslog fields"), "got: {err}");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn syslog_unix_sink_delivers_rendered_line() {
        // Bind a datagram receiver first so the writer thread's lazy connect
        // succeeds, then drive the emit path and confirm the framed line lands.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("syslog.sock");
        let receiver = UnixDatagram::bind(&sock_path).unwrap();
        receiver.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            "template: '{{method}} {{path}} {{status}}'\nsink:\n  type: syslog\n  transport: unix\n  path: {}\n  facility: local0",
            sock_path.to_str().unwrap()
        ))
        .unwrap();
        let filter = test_filter(&yaml);

        let req = crate::test_utils::make_request(http::Method::GET, "/health");
        let ctx = crate::test_utils::make_filter_context(&req);
        filter.emit_access_log(&ctx, 200, None, 7);

        let mut buf = [0_u8; 2048];
        let n = receiver.recv(&mut buf).unwrap();
        assert_rfc3164(&String::from_utf8_lossy(&buf[..n]), false);
    }

    #[cfg(feature = "access-log-syslog")]
    fn assert_rfc3164(line: &str, expect_hostname: bool) {
        assert!(line.starts_with("<134>"), "PRI for local0.info must be <134>: {line:?}");
        let tag = format!("praxis[{}]: GET /health 200", std::process::id());
        assert!(line.ends_with(&tag), "line must end with TAG[PID]: MSG: {line:?}");
        let header = line.split(" praxis[").next().unwrap_or_default();
        let fields = header.split_whitespace().count();
        if expect_hostname {
            assert_eq!(fields, 4, "remote HEADER must carry PRI+timestamp+hostname: {header:?}");
        } else {
            assert_eq!(fields, 3, "unix HEADER must omit the hostname: {header:?}");
        }
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn syslog_udp_sink_emits_rfc3164_with_hostname() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let address = receiver.local_addr().unwrap().to_string();

        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            "template: '{{method}} {{path}} {{status}}'\nsink:\n  type: syslog\n  transport: udp\n  address: {address}\n  facility: local0"
        )).unwrap();
        let filter = test_filter(&yaml);
        let req = crate::test_utils::make_request(http::Method::GET, "/health");
        let ctx = crate::test_utils::make_filter_context(&req);
        filter.emit_access_log(&ctx, 200, None, 7);

        let mut buf = [0_u8; 2048];
        let n = receiver.recv(&mut buf).unwrap();
        assert_rfc3164(&String::from_utf8_lossy(&buf[..n]), true);
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn syslog_tcp_sink_emits_rfc3164_with_octet_framing() {
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            "template: '{{method}} {{path}} {{status}}'\nsink:\n  type: syslog\n  transport: tcp\n  address: {address}\n  facility: local0"
        )).unwrap();
        let filter = test_filter(&yaml);
        let req = crate::test_utils::make_request(http::Method::GET, "/health");
        let ctx = crate::test_utils::make_filter_context(&req);
        // Two records back-to-back exercise RFC 6587 octet framing as the record
        // delimiter on the stream (the crate writes none).
        filter.emit_access_log(&ctx, 200, None, 7);
        filter.emit_access_log(&ctx, 200, None, 7);

        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 2048];
        let records = loop {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "collector closed before both frames arrived");
            buf.extend_from_slice(&chunk[..n]);
            let records = parse_octet_frames(&buf);
            if records.len() >= 2 {
                break records;
            }
        };
        assert_eq!(records.len(), 2, "two records must be framed separately");
        for record in &records {
            assert_rfc3164(record, true);
        }
    }

    /// Decode RFC 6587 octet-counted frames (`MSG-LEN SP MSG`) from a byte buffer,
    /// returning the messages and ignoring any trailing partial frame.
    #[cfg(feature = "access-log-syslog")]
    fn parse_octet_frames(buf: &[u8]) -> Vec<String> {
        let mut records = Vec::new();
        let mut rest = buf;
        while let Some(sp) = rest.iter().position(|&byte| byte == b' ') {
            let (len_bytes, after) = rest.split_at(sp);
            let Ok(len) = std::str::from_utf8(len_bytes).unwrap_or_default().parse::<usize>() else {
                break;
            };
            match after.get(1..=len) {
                Some(msg) => {
                    records.push(String::from_utf8_lossy(msg).into_owned());
                    rest = after.get(len.saturating_add(1)..).unwrap_or_default();
                },
                None => break,
            }
        }
        records
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn remote_address_rejects_malformed_host_port() {
        for bad in [
            "collector",
            "collector:",
            "collector:0",
            "collector:70000",
            "collector:abc",
            ":514",
            "collector:514:123",
        ] {
            assert!(
                remote_address(false, Some(bad.to_owned())).is_err(),
                "address {bad:?} must be rejected at config time"
            );
        }
        for good in ["collector:514", "127.0.0.1:514", "[::1]:514"] {
            assert!(
                remote_address(false, Some(good.to_owned())).is_ok(),
                "address {good:?} must be accepted"
            );
        }
    }

    /// A formatter standing in for a real sink in connection-level tests.
    #[cfg(feature = "access-log-syslog")]
    fn test_formatter() -> Rfc3164Formatter {
        Rfc3164Formatter {
            priority_base: SyslogFacility::Local0.priority_base(),
            hostname: None,
            process: "praxis".to_owned(),
            pid: std::process::id(),
            octet_framed: false,
        }
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn rfc3164_timestamp_renders_wall_clock_in_its_own_offset() {
        // 12:00:00Z at UTC-04:00 is 08:00:00 local; the HEADER must carry local
        // wall-clock time, not UTC (the crate's formatter would emit 12:00:00).
        use chrono::{FixedOffset, TimeZone as _};
        let offset = FixedOffset::west_opt(4 * 3600).unwrap();
        let instant = offset.with_ymd_and_hms(2026, 1, 2, 8, 0, 0).unwrap();
        assert_eq!(rfc3164_timestamp(&instant), "Jan  2 08:00:00");
        // The same instant one zone east renders a different wall clock.
        let east = FixedOffset::east_opt(2 * 3600).unwrap();
        assert_eq!(rfc3164_timestamp(&instant.with_timezone(&east)), "Jan  2 14:00:00");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn syslog_unix_write_times_out_when_collector_stalls() {
        use std::time::Instant;
        // A Unix stream collector that never drains must not block the writer
        // forever: the bounded write timeout surfaces an error instead. The
        // listener is bound but never accepts, so the connected socket's send
        // buffer fills and the next write blocks until it times out.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stall.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        let mut logger =
            connect_unix(test_formatter(), path.to_str(), Duration::from_millis(200)).expect("connect to collector");
        let payload = "x".repeat(8192);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut timed_out = false;
        while Instant::now() < deadline {
            if logger.info(&payload).is_err() {
                timed_out = true;
                break;
            }
        }
        assert!(
            timed_out,
            "a stalled unix collector must not block the writer indefinitely"
        );
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn rfc3164_message_is_capped_at_1024_bytes() {
        // RFC 3164 §4.1 limits a complete message to 1024 bytes; an overlong rendered
        // line must be truncated on the wire rather than sent in full.
        let formatter = test_formatter();
        let mut out = Vec::new();
        <Rfc3164Formatter as LogFormat<String>>::format(&formatter, &mut out, Severity::LOG_INFO, "a".repeat(4096))
            .unwrap();
        assert!(
            out.len() <= RFC3164_MAX_BYTES,
            "RFC 3164 §4.1 caps the message at {RFC3164_MAX_BYTES} bytes, got {}",
            out.len()
        );
        assert!(std::str::from_utf8(&out).is_ok(), "truncation must keep valid UTF-8");
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    #[expect(clippy::disallowed_methods, reason = "test stalls an op with thread::sleep")]
    fn with_timeout_bounds_a_stalled_operation() {
        // A completed op returns its value; an op that outlasts the timeout surfaces a
        // TimedOut error instead of blocking, which is how unix connect and DNS stay
        // bounded on the writer thread.
        let quick: std::io::Result<u8> = with_timeout(Duration::from_secs(5), || Ok(7));
        assert_eq!(quick.unwrap(), 7);
        let slow: std::io::Result<u8> = with_timeout(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(5));
            Ok(0)
        });
        assert_eq!(slow.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn syslog_writer_backs_off_after_a_failed_connect() {
        // A failed (re)connection must start a cooldown so the writer stops retrying
        // (and stops spawning helper threads) on every subsequent record until it
        // expires. A missing socket path fails the connect quickly.
        let target = SyslogTarget {
            destination: SyslogDestination::Unix {
                path: Some("/nonexistent/praxis-syslog-test.sock".to_owned()),
            },
            formatter: test_formatter(),
            dest: Arc::from("syslog:unix:/nonexistent/praxis-syslog-test.sock"),
        };
        let mut state = SyslogWriterState::default();
        assert!(!state.in_cooldown(), "no cooldown before the first attempt");
        state.emit(&target, "first");
        assert!(state.logger.is_none(), "a missing socket must not yield a logger");
        assert!(
            state.in_cooldown(),
            "a failed connect must start the reconnect cooldown"
        );
    }

    #[cfg(feature = "access-log-syslog")]
    #[test]
    fn stream_fallback_only_on_socket_type_mismatch() {
        use std::io::{Error, ErrorKind};
        // A missing socket or denied permission is a real datagram failure: surface it
        // rather than masking it with a stream-connect fallback.
        assert!(!is_wrong_socket_type(&Error::from(ErrorKind::NotFound)));
        assert!(!is_wrong_socket_type(&Error::from(ErrorKind::PermissionDenied)));
        // InvalidInput and raw EPROTOTYPE both mean the endpoint is a stream socket.
        assert!(is_wrong_socket_type(&Error::from(ErrorKind::InvalidInput)));
        assert!(is_wrong_socket_type(&Error::from_raw_os_error(EPROTOTYPE_ERRNO)));
    }

    #[test]
    fn from_config_file_sink_opens_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap())).unwrap();
        let filter = test_filter(&yaml);
        assert!(
            matches!(filter.sink, RuntimeSink::Direct(_)),
            "file sink should be created"
        );
        assert!(log_path.exists(), "log file should be created on disk");
    }

    #[test]
    fn file_sink_writes_ndjson_line() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap())).unwrap();
        let filter = test_filter(&yaml);

        let req = crate::test_utils::make_request(http::Method::GET, "/health");
        let ctx = crate::test_utils::make_filter_context(&req);
        filter.emit_access_log(&ctx, 200, None, 7);

        // The write happens on the background writer thread, so poll briefly
        // for the line to land before asserting.
        let contents = read_file_with_retry(&log_path);
        let line = contents.lines().next().expect("file sink should write one NDJSON line");
        let record: BTreeMap<String, String> = serde_json::from_str(line).unwrap();
        assert_eq!(record.get("method").map(String::as_str), Some("GET"));
        assert_eq!(record.get("path").map(String::as_str), Some("/health"));
        assert_eq!(record.get("status").map(String::as_str), Some("200"));
        let timestamp = record.get("timestamp").expect("sink record must carry a timestamp");
        assert!(
            timestamp.contains('T') && timestamp.ends_with('Z'),
            "timestamp should be RFC 3339 UTC: {timestamp:?}"
        );
    }

    #[test]
    fn file_sink_writes_template_line() {
        // A text template routed to a direct sink renders its own line verbatim,
        // not an NDJSON record, matching what the tracing path would log.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("template.log");
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            "template: \"{{method}} {{path}} {{status}}\"\nsink:\n  type: file\n  path: {}",
            log_path.to_str().unwrap()
        ))
        .unwrap();
        let filter = test_filter(&yaml);

        let req = crate::test_utils::make_request(http::Method::GET, "/health");
        let ctx = crate::test_utils::make_filter_context(&req);
        filter.emit_access_log(&ctx, 200, None, 7);

        let contents = read_file_with_retry(&log_path);
        let line = contents
            .lines()
            .next()
            .expect("file sink should write one template line");
        assert_eq!(
            line, "GET /health 200",
            "template sink should write the rendered line, not JSON"
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        clippy::disallowed_methods,
        reason = "concurrency test spawns threads and polls with thread::sleep"
    )]
    fn file_sink_shares_one_writer_per_path() {
        // Two filters pointed at the same path must share a single writer so
        // their NDJSON records never interleave, even under concurrency.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("shared.log");
        let cfg_a = format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap());
        // A different spelling of the same file (a `.` segment) must canonicalize
        // to the same registry key, so both filters resolve to one writer.
        let alt_path = dir.path().join(".").join("shared.log");
        let cfg_b = format!("sink:\n  type: file\n  path: {}", alt_path.to_str().unwrap());
        let filter_a = Arc::new(test_filter(&serde_yaml::from_str(&cfg_a).unwrap()));
        let filter_b = Arc::new(test_filter(&serde_yaml::from_str(&cfg_b).unwrap()));

        // Both filters must share one `DirectSink`, which the canonical-key
        // registry proves by handing back the same `Arc`.
        let sink = |filter: &AccessLogFilter| match &filter.sink {
            RuntimeSink::Direct(sink) => Arc::clone(sink),
            RuntimeSink::Tracing => panic!("file sink should resolve to a direct sink"),
        };
        assert!(
            Arc::ptr_eq(&sink(&filter_a), &sink(&filter_b)),
            "both path spellings should resolve to a single shared writer"
        );

        let per_thread = 200;
        let handles: Vec<_> = [(filter_a, "/a"), (filter_b, "/b")]
            .into_iter()
            .map(|(filter, path)| {
                std::thread::spawn(move || {
                    let req = crate::test_utils::make_request(http::Method::GET, path);
                    for _ in 0..per_thread {
                        let ctx = crate::test_utils::make_filter_context(&req);
                        filter.emit_access_log(&ctx, 200, None, 1);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        // The writer thread flushes while this test reads the file, so a read can
        // catch the tail of a line before its newline lands. That partial tail is
        // not a torn record: keep polling until every line parses and the count
        // matches. A real interleave stays unparseable and fails the assert below.
        let expected = per_thread * 2;
        let mut lines = 0;
        for _ in 0..100 {
            let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
            if let Some(count) = complete_ndjson_count(&contents) {
                lines = count;
                if lines == expected {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if lines != expected {
            let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
            for line in contents.lines() {
                serde_json::from_str::<BTreeMap<String, String>>(line)
                    .unwrap_or_else(|e| panic!("line should be valid NDJSON ({e}): {line}"));
            }
        }
        assert_eq!(lines, expected, "all records from both filters should be written");
    }

    #[test]
    fn run_sink_writer_flushes_queue_then_exits_on_shutdown_flag() {
        // A writer whose sender never drops (like stdout) still exits once the
        // shutdown flag is set, after flushing everything already queued.
        let (tx, rx) = sync_channel::<String>(8);
        tx.send("alpha".to_owned()).unwrap();
        tx.send("beta".to_owned()).unwrap();
        let shutdown = AtomicBool::new(true);

        let mut buf: Vec<u8> = Vec::new();
        // Returns because the flag is set, not because the sender dropped: `tx`
        // is deliberately held live across the call.
        run_sink_writer(&mut buf, &rx, "test", &shutdown);
        drop(tx);

        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "alpha\nbeta\n",
            "shutdown must flush records queued before the flag was set"
        );
    }
}
