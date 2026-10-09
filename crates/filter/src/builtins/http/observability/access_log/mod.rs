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
mod tests;
