// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Bandwidth limit filter.
//!
//! Requires the off-by-default `bandwidth` feature. Counts body bytes that
//! pass this filter instance and delays them to the configured rate.
//! Omitting a direction leaves it unlimited.
//! `per_connection` shares one budget across the downstream connection.
//! `per_ip` shares one budget across connections from the same source
//! that pass through this filter instance.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::connectivity::normalize_mapped_ipv4;
use serde::Deserialize;
use tracing::warn;

use crate::{
    BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, RequestExtensions,
    TcpFilter, TcpFilterContext,
    bandwidth::{
        AcquireError, Acquired, BandwidthGrant, BandwidthTable, BudgetKey, ConnectionAlive, DownloadLimited,
        DownstreamConnectionId, InFlightGuard, Schedule, TcpBandwidthPacer, pointer_key, push_download, push_upload,
    },
    factory::parse_filter_config,
};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Whose bytes share a budget.
///
/// ```
/// use praxis_filter::BandwidthMode;
///
/// let mode: BandwidthMode = serde_yaml::from_str("per_connection").unwrap();
/// assert!(matches!(mode, BandwidthMode::PerConnection));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BandwidthMode {
    /// One upload budget and one download budget for the downstream connection.
    PerConnection,

    /// Connections from the same source address share the budgets.
    PerIp,
}

/// YAML configuration for [`BandwidthLimitFilter`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BandwidthLimitConfig {
    /// `per_connection` or `per_ip`.
    mode: BandwidthMode,

    /// Request-body bytes per second. Absent means unlimited.
    #[serde(default)]
    upload_bytes_per_sec: Option<u64>,

    /// Response-body bytes per second. Absent means unlimited.
    #[serde(default)]
    download_bytes_per_sec: Option<u64>,

    /// Burst capacity in bytes. Zero paces from the first byte.
    #[serde(default)]
    burst_bytes: u64,
}

// -----------------------------------------------------------------------------
// Filter
// -----------------------------------------------------------------------------

/// Paces request and response bodies, or TCP payload bytes.
pub struct BandwidthLimitFilter {
    /// How keys are chosen.
    mode: BandwidthMode,

    /// Identity of this filter instance inside the request extensions.
    instance: u64,

    /// Budgets owned by this instance only.
    table: Arc<BandwidthTable>,

    /// Per-request ids used when the protocol did not supply a connection id.
    fallback_ids: AtomicU64,
}

/// One filter instance's claim on a request.
struct BandwidthAttachment {
    /// [`BandwidthLimitFilter::instance`] that created this claim.
    instance: u64,

    /// Upload schedule for this claim.
    upload: Option<Arc<Schedule>>,

    /// Download schedule for this claim.
    download: Option<Arc<Schedule>>,

    /// Upload bytes already reserved for this request.
    paced_upload: u64,

    /// Download bytes already reserved for this request.
    paced_download: u64,

    /// Held until the request ends so the slot stays tracked.
    _guard: InFlightGuard,
}

/// Claims from every bandwidth filter on this request.
#[derive(Default)]
struct BandwidthAttachments {
    /// One entry per filter instance.
    items: Vec<BandwidthAttachment>,
}

/// A body chunk to pace.
#[derive(Clone, Copy)]
struct PaceChunk {
    /// Payload bytes in this call.
    len: u64,

    /// Whether this is the last chunk.
    end_of_stream: bool,

    /// Whether the pipeline also delivers an aggregate buffer at end of stream.
    buffering: bool,

    /// Which schedule to charge.
    direction: ChargeDirection,
}

/// Upload or download.
#[derive(Clone, Copy)]
enum ChargeDirection {
    /// Request body, or client-to-upstream TCP payload.
    Upload,

    /// Response body, or upstream-to-client TCP payload.
    Download,
}

impl BandwidthLimitFilter {
    /// Build the filter from YAML.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the YAML is invalid, neither
    /// direction is set, or a configured rate is zero.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        Ok(Box::new(Self::parse(config)?))
    }

    /// Build the TCP form of this filter from the same YAML.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] under the same conditions as [`Self::from_config`].
    pub fn from_config_tcp(config: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
        Ok(Box::new(Self::parse(config)?))
    }

    /// Parse and validate YAML into an unboxed filter.
    fn parse(config: &serde_yaml::Value) -> Result<Self, FilterError> {
        let cfg: BandwidthLimitConfig = parse_filter_config("bandwidth_limit", config)?;
        validate_rates(&cfg)?;
        let table = BandwidthTable::new(cfg.upload_bytes_per_sec, cfg.download_bytes_per_sec, cfg.burst_bytes);
        Ok(Self::from_table(cfg.mode, Arc::new(table)))
    }

    /// Wrap a table that this instance owns.
    fn from_table(mode: BandwidthMode, table: Arc<BandwidthTable>) -> Self {
        Self {
            mode,
            instance: pointer_key(Arc::as_ptr(&table).addr()),
            table,
            fallback_ids: AtomicU64::new(1),
        }
    }

    /// Attach this instance once per request.
    fn ensure(&self, ctx: &mut HttpFilterContext<'_>) -> Result<(), FilterAction> {
        if attached(&ctx.extensions, self.instance) {
            return Ok(());
        }
        let key = self.http_key(ctx)?;
        let lease = connection_lease(ctx, key);
        let acquired = self.table.acquire(key, lease).map_err(acquire_failed)?;
        store_attachment(&mut ctx.extensions, self.instance, acquired);
        Ok(())
    }

    /// Choose the HTTP budget key.
    fn http_key(&self, ctx: &HttpFilterContext<'_>) -> Result<BudgetKey, FilterAction> {
        match self.mode {
            BandwidthMode::PerConnection => Ok(BudgetKey::Connection(self.connection_id(ctx))),
            BandwidthMode::PerIp => {
                if let Some(ip) = ctx.client_addr {
                    Ok(BudgetKey::Ip(ip))
                } else {
                    warn!("bandwidth_limit: per_ip requires a client address; closing the connection");
                    Err(close_action(CLOSE_MISSING_ADDRESS))
                }
            },
        }
    }

    /// Connection id from the protocol, or a request-local fallback.
    fn connection_id(&self, ctx: &HttpFilterContext<'_>) -> u64 {
        if let Some(id) = ctx.extensions.get::<DownstreamConnectionId>() {
            return id.0;
        }
        warn_missing_connection_id();
        self.fallback_ids.fetch_add(1, Ordering::Relaxed)
    }

    /// Reserve this chunk on the attached schedule.
    fn pace(&self, ctx: &mut HttpFilterContext<'_>, chunk: PaceChunk) -> FilterAction {
        if let Err(action) = self.ensure(ctx) {
            return action;
        }
        if let Some(grant) = take_grant(&mut ctx.extensions, self.instance, &chunk) {
            match chunk.direction {
                ChargeDirection::Upload => push_upload(&mut ctx.extensions, grant),
                ChargeDirection::Download => push_download(&mut ctx.extensions, grant),
            }
        }
        FilterAction::Continue
    }

    /// Install this connection's leg on the TCP pacer.
    fn install_tcp(ctx: &mut TcpFilterContext<'_>, acquired: Acquired) {
        let pacer = ctx
            .bandwidth
            .get_or_insert_with(|| Arc::new(TcpBandwidthPacer::empty()));
        pacer.push(acquired);
    }

    /// Budget key for a TCP connection.
    fn tcp_key(&self, ctx: &TcpFilterContext<'_>) -> Result<BudgetKey, FilterAction> {
        match self.mode {
            BandwidthMode::PerConnection => {
                Ok(BudgetKey::Connection(self.fallback_ids.fetch_add(1, Ordering::Relaxed)))
            },
            BandwidthMode::PerIp => {
                if let Some(ip) = peer_ip(ctx.remote_addr) {
                    Ok(BudgetKey::Ip(ip))
                } else {
                    warn!(
                        remote = ctx.remote_addr,
                        "bandwidth_limit: per_ip could not parse the client address; closing the connection"
                    );
                    Err(close_action(CLOSE_UNPARSEABLE_ADDRESS))
                }
            },
        }
    }
}

#[async_trait]
impl HttpFilter for BandwidthLimitFilter {
    fn name(&self) -> &'static str {
        "bandwidth_limit"
    }

    fn request_body_access(&self) -> BodyAccess {
        if self.table.has_upload() {
            BodyAccess::ReadOnly
        } else {
            BodyAccess::None
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        if self.table.has_download() {
            BodyAccess::ReadOnly
        } else {
            BodyAccess::None
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        match self.ensure(ctx) {
            Ok(()) => Ok(FilterAction::Continue),
            Err(action) => Ok(action),
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Ok(self.pace(ctx, upload_chunk(body.as_ref(), end_of_stream, ctx.request_body_mode)))
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Ok(self.pace(
            ctx,
            download_chunk(body.as_ref(), end_of_stream, ctx.response_body_mode),
        ))
    }
}

#[async_trait]
impl TcpFilter for BandwidthLimitFilter {
    fn name(&self) -> &'static str {
        "bandwidth_limit"
    }

    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let key = match self.tcp_key(ctx) {
            Ok(key) => key,
            Err(action) => return Ok(action),
        };
        match self.table.acquire(key, None) {
            Ok(acquired) => {
                Self::install_tcp(ctx, acquired);
                Ok(FilterAction::Continue)
            },
            Err(error) => Ok(acquire_failed(error)),
        }
    }
}

/// Reject a config that does not name a positive rate.
fn validate_rates(cfg: &BandwidthLimitConfig) -> Result<(), FilterError> {
    if cfg.upload_bytes_per_sec.is_none() && cfg.download_bytes_per_sec.is_none() {
        return Err("bandwidth_limit: set upload_bytes_per_sec or download_bytes_per_sec".into());
    }
    if cfg.upload_bytes_per_sec == Some(0) || cfg.download_bytes_per_sec == Some(0) {
        return Err("bandwidth_limit: byte rates must be greater than 0".into());
    }
    Ok(())
}

/// Describe an upload chunk.
fn upload_chunk(body: Option<&Bytes>, end_of_stream: bool, mode: BodyMode) -> PaceChunk {
    PaceChunk {
        len: body_len(body),
        end_of_stream,
        buffering: is_buffering(mode),
        direction: ChargeDirection::Upload,
    }
}

/// Describe a download chunk.
fn download_chunk(body: Option<&Bytes>, end_of_stream: bool, mode: BodyMode) -> PaceChunk {
    PaceChunk {
        len: body_len(body),
        end_of_stream,
        buffering: is_buffering(mode),
        direction: ChargeDirection::Download,
    }
}

/// Payload length, saturated to `u64`.
fn body_len(body: Option<&Bytes>) -> u64 {
    u64::try_from(body.map_or(0, Bytes::len)).unwrap_or(u64::MAX)
}

/// Whether this mode replays the whole buffer at end of stream.
fn is_buffering(mode: BodyMode) -> bool {
    matches!(mode, BodyMode::StreamBuffer { .. })
}

/// Bytes to reserve for this call.
///
/// A buffered end-of-stream delivery repeats bytes the filter already
/// saw as chunks, so only the unseen tail is charged. A streaming
/// chunk is charged in full, including a final chunk whose size equals
/// the sum of earlier chunks.
fn bytes_to_charge(already: u64, body_len: u64, end_of_stream: bool, buffering: bool) -> u64 {
    if buffering && end_of_stream {
        body_len.saturating_sub(already)
    } else {
        body_len
    }
}

/// Per-connection watch supplied by the protocol, when it has one.
fn connection_lease(ctx: &HttpFilterContext<'_>, key: BudgetKey) -> Option<ConnectionAlive> {
    if matches!(key, BudgetKey::Connection(_)) {
        ctx.extensions.get::<ConnectionAlive>().cloned()
    } else {
        None
    }
}

/// Whether this filter instance already has a claim on the request.
fn attached(extensions: &RequestExtensions, instance: u64) -> bool {
    extensions
        .get::<BandwidthAttachments>()
        .is_some_and(|items| items.items.iter().any(|item| item.instance == instance))
}

/// Remember a new claim.
fn store_attachment(extensions: &mut RequestExtensions, instance: u64, acquired: Acquired) {
    if acquired.download.is_some() {
        extensions.insert(DownloadLimited);
    }
    extensions
        .get_or_insert_with(BandwidthAttachments::default)
        .items
        .push(BandwidthAttachment::from_acquired(instance, acquired));
}

/// Reserve the chunk and advance the per-request counters.
fn take_grant(extensions: &mut RequestExtensions, instance: u64, chunk: &PaceChunk) -> Option<BandwidthGrant> {
    let items = extensions.get_mut::<BandwidthAttachments>()?;
    let attachment = items.items.iter_mut().find(|item| item.instance == instance)?;
    let schedule = match chunk.direction {
        ChargeDirection::Upload => attachment.upload.as_ref().map(Arc::clone),
        ChargeDirection::Download => attachment.download.as_ref().map(Arc::clone),
    }?;
    let already = match chunk.direction {
        ChargeDirection::Upload => attachment.paced_upload,
        ChargeDirection::Download => attachment.paced_download,
    };
    let charge = bytes_to_charge(already, chunk.len, chunk.end_of_stream, chunk.buffering);
    if charge == 0 {
        return None;
    }
    match chunk.direction {
        ChargeDirection::Upload => attachment.paced_upload = already.saturating_add(charge),
        ChargeDirection::Download => attachment.paced_download = already.saturating_add(charge),
    }
    Some(schedule.reserve(charge))
}

impl BandwidthAttachment {
    /// Move a table claim into the request.
    fn from_acquired(instance: u64, acquired: Acquired) -> Self {
        Self {
            instance,
            upload: acquired.upload,
            download: acquired.download,
            paced_upload: 0,
            paced_download: 0,
            _guard: acquired.guard,
        }
    }
}

/// Map a full table to a connection close.
fn acquire_failed(error: AcquireError) -> FilterAction {
    match error {
        AcquireError::Full => {
            warn!("bandwidth_limit: tracking table is full; closing the connection");
            close_action(CLOSE_TABLE_FULL)
        },
    }
}

/// Warn once when HTTP requests have no connection identity.
fn warn_missing_connection_id() {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        warn!("bandwidth_limit: missing downstream connection id; pacing this request alone");
    }
}

/// Logged when a new address cannot be tracked.
const CLOSE_TABLE_FULL: &str = "bandwidth limit tracking table is full";

/// Logged when `per_ip` has no client address.
const CLOSE_MISSING_ADDRESS: &str = "bandwidth limit per_ip has no client address";

/// Logged when `per_ip` cannot parse the client address.
const CLOSE_UNPARSEABLE_ADDRESS: &str = "bandwidth limit per_ip could not parse the client address";

/// Rejection the protocol turns into a close with no response body.
fn close_action(reason: &'static str) -> FilterAction {
    FilterAction::Reject(Rejection::status(503).closing(reason))
}

/// Parse a TCP peer string into a normalized address.
fn peer_ip(remote: &str) -> Option<IpAddr> {
    let ip = remote
        .parse::<SocketAddr>()
        .map(|addr| addr.ip())
        .or_else(|_| remote.parse::<IpAddr>())
        .ok()?;
    Some(normalize_mapped_ipv4(ip))
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
    use std::time::Duration;

    use http::Method;

    use super::*;
    use crate::{
        bandwidth::{commit_upload_pace, connection_close_reason, download_pace_delay, upload_pace_delay},
        test_utils::{make_filter_context, make_request},
    };

    /// One schedule instant, in nanoseconds, for a sharing check's reservations.
    ///
    /// Both reservations use this instant, so a scheduling pause cannot refill the
    /// byte the assertion expects to delay.
    const RESERVED_AT: i128 = 0;

    fn parse(yaml: &str) -> BandwidthLimitFilter {
        let value = serde_yaml::from_str(yaml).unwrap();
        BandwidthLimitFilter::parse(&value).unwrap()
    }

    fn tcp_ctx(remote_addr: &str) -> TcpFilterContext<'_> {
        TcpFilterContext {
            remote_addr,
            local_addr: "127.0.0.1:443",
            sni: None,
            upstream_addr: None,
            cluster: None,
            health_registry: None,
            kv_stores: None,
            connect_time: std::time::Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            bandwidth: None,
        }
    }

    fn remember_connection(ctx: &mut HttpFilterContext<'_>, id: u64, socket: &Arc<()>) {
        ctx.extensions.insert(DownstreamConnectionId(id));
        ctx.extensions.insert(ConnectionAlive::watch(socket));
    }

    /// Upload schedule this filter attached while handling `ctx`.
    fn upload_schedule(ctx: &HttpFilterContext<'_>) -> Arc<Schedule> {
        ctx.extensions
            .get::<BandwidthAttachments>()
            .and_then(|items| items.items.iter().find_map(|item| item.upload.as_ref().map(Arc::clone)))
            .expect("the filter attached an upload schedule")
    }

    fn close_reason_of(action: FilterAction) -> Option<&'static str> {
        match action {
            FilterAction::Reject(rejection) => connection_close_reason(&rejection),
            FilterAction::Continue
            | FilterAction::Release
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_) => {
                panic!("expected a rejection");
            },
        }
    }

    fn expect_continue(action: &FilterAction) {
        assert!(
            matches!(action, FilterAction::Continue),
            "bandwidth pacing continues the transfer"
        );
    }

    fn parse_error(yaml: &str) -> FilterError {
        let value = serde_yaml::from_str(yaml).unwrap();
        match BandwidthLimitFilter::parse(&value) {
            Err(err) => err,
            Ok(_) => panic!("config should be rejected: {yaml}"),
        }
    }

    #[test]
    fn config_requires_one_positive_rate() {
        let missing = parse_error("mode: per_ip");
        assert!(
            missing.to_string().contains("upload_bytes_per_sec"),
            "a direction is required"
        );
        let zero = parse_error("mode: per_ip\nupload_bytes_per_sec: 0\n");
        assert!(zero.to_string().contains("greater than 0"), "a zero rate is rejected");
    }

    #[test]
    fn buffered_end_of_stream_charges_only_the_unseen_tail() {
        assert_eq!(
            bytes_to_charge(400, 1_000, true, true),
            600,
            "the aggregate skips paced bytes"
        );
        assert_eq!(
            bytes_to_charge(400, 400, true, false),
            400,
            "a streaming final chunk is charged in full"
        );
    }

    #[tokio::test]
    async fn per_connection_keeps_a_spent_burst_for_the_next_request() {
        let filter = parse("mode: per_connection\nupload_bytes_per_sec: 1000\nburst_bytes: 1000\n");
        let socket = Arc::new(());
        let req = make_request(Method::POST, "/");
        let mut first = make_filter_context(&req);
        remember_connection(&mut first, 7, &socket);
        expect_continue(&filter.on_request(&mut first).await.unwrap());
        let burst = upload_schedule(&first).reserve_at(1_000, RESERVED_AT);
        assert_eq!(burst.delay(), Duration::ZERO, "the burst covers the first body");
        burst.commit();

        let mut second = make_filter_context(&req);
        remember_connection(&mut second, 7, &socket);
        expect_continue(&filter.on_request(&mut second).await.unwrap());
        let next = upload_schedule(&second).reserve_at(1, RESERVED_AT);
        assert!(
            next.delay() > Duration::ZERO,
            "the same connection does not get a new burst"
        );
    }

    #[tokio::test]
    async fn a_closed_connection_gets_a_new_burst() {
        let filter = parse("mode: per_connection\nupload_bytes_per_sec: 1000\nburst_bytes: 1000\n");
        let socket = Arc::new(());
        {
            let req = make_request(Method::POST, "/");
            let mut ctx = make_filter_context(&req);
            remember_connection(&mut ctx, 7, &socket);
            let mut body = Some(Bytes::from(vec![1_u8; 1_000]));
            expect_continue(&filter.on_request_body(&mut ctx, &mut body, true).await.unwrap());
            commit_upload_pace(&mut ctx.extensions);
        }
        drop(socket);

        let req = make_request(Method::POST, "/");
        let mut ctx = make_filter_context(&req);
        let replacement = Arc::new(());
        remember_connection(&mut ctx, 7, &replacement);
        let mut body = Some(Bytes::from(vec![1_u8; 1_000]));
        expect_continue(&filter.on_request_body(&mut ctx, &mut body, true).await.unwrap());
        assert_eq!(
            upload_pace_delay(&ctx.extensions),
            Some(Duration::ZERO),
            "a closed connection does not leave its burst behind"
        );
    }

    #[tokio::test]
    async fn a_different_connection_gets_its_own_burst() {
        let filter = parse("mode: per_connection\nupload_bytes_per_sec: 1000\nburst_bytes: 1000\n");
        let req = make_request(Method::POST, "/");
        let mut first = make_filter_context(&req);
        first.extensions.insert(DownstreamConnectionId(1));
        let mut body = Some(Bytes::from(vec![1_u8; 1_000]));
        expect_continue(&filter.on_request_body(&mut first, &mut body, true).await.unwrap());

        let mut second = make_filter_context(&req);
        second.extensions.insert(DownstreamConnectionId(2));
        let mut body = Some(Bytes::from(vec![1_u8; 1_000]));
        expect_continue(&filter.on_request_body(&mut second, &mut body, true).await.unwrap());
        assert_eq!(
            upload_pace_delay(&second.extensions),
            Some(Duration::ZERO),
            "another connection has its own burst"
        );
    }

    #[tokio::test]
    async fn per_ip_without_an_address_closes_the_connection() {
        let filter = parse("mode: per_ip\ndownload_bytes_per_sec: 1000\n");
        let req = make_request(Method::GET, "/");
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            close_reason_of(action),
            Some(CLOSE_MISSING_ADDRESS),
            "a missing address closes the connection"
        );
    }

    #[tokio::test]
    async fn per_ip_with_an_unparseable_address_closes_the_connection() {
        let filter = parse("mode: per_ip\nupload_bytes_per_sec: 1000\n");
        let mut ctx = tcp_ctx("not-an-address");
        let action = filter.on_connect(&mut ctx).await.unwrap();
        assert_eq!(
            close_reason_of(action),
            Some(CLOSE_UNPARSEABLE_ADDRESS),
            "an unparseable address closes the connection"
        );
    }

    #[tokio::test]
    async fn a_full_per_ip_table_closes_a_new_address() {
        let table = Arc::new(BandwidthTable::with_limits(None, Some(1_000), 0, 1, 1));
        let filter = BandwidthLimitFilter::from_table(BandwidthMode::PerIp, table);
        let req = make_request(Method::GET, "/");
        let mut first = make_filter_context(&req);
        first.client_addr = Some(IpAddr::from([10, 0, 0, 1]));
        expect_continue(&filter.on_request(&mut first).await.unwrap());

        let mut second = make_filter_context(&req);
        second.client_addr = Some(IpAddr::from([10, 0, 0, 2]));
        let action = filter.on_request(&mut second).await.unwrap();
        assert_eq!(
            close_reason_of(action),
            Some(CLOSE_TABLE_FULL),
            "a full table closes the new address"
        );
        assert!(
            download_pace_delay(&first.extensions).is_none(),
            "the first address is still tracked"
        );
    }

    #[tokio::test]
    async fn buffered_chunks_are_not_charged_twice() {
        let filter = parse("mode: per_connection\nupload_bytes_per_sec: 1000\n");
        let req = make_request(Method::POST, "/");
        let mut ctx = make_filter_context(&req);
        ctx.extensions.insert(DownstreamConnectionId(4));
        ctx.request_body_mode = BodyMode::StreamBuffer {
            max_bytes: Some(10_000),
        };
        let mut part = Some(Bytes::from(vec![1_u8; 400]));
        expect_continue(&filter.on_request_body(&mut ctx, &mut part, false).await.unwrap());
        let first = upload_pace_delay(&ctx.extensions).unwrap();
        commit_upload_pace(&mut ctx.extensions);
        let mut all = Some(Bytes::from(vec![1_u8; 1_000]));
        expect_continue(&filter.on_request_body(&mut ctx, &mut all, true).await.unwrap());
        let second = upload_pace_delay(&ctx.extensions).unwrap();
        assert!(second > first, "the aggregate charges only the unseen tail");
        assert!(
            second < Duration::from_millis(1_100),
            "the aggregate does not charge the whole buffer again"
        );
    }

    #[tokio::test]
    async fn tcp_per_ip_installs_a_shared_pacer() {
        let filter = parse("mode: per_ip\nupload_bytes_per_sec: 1000\nburst_bytes: 1000\n");
        let mut ctx = tcp_ctx("192.0.2.10:40000");
        expect_continue(&filter.on_connect(&mut ctx).await.unwrap());
        let pacer = ctx.bandwidth.as_ref().unwrap();
        let first = pacer.reserve_upload_at(1_000, RESERVED_AT);
        assert_eq!(first.delay(), Duration::ZERO, "the burst covers the first upload");
        first.commit();

        let mut again = tcp_ctx("192.0.2.10:40001");
        expect_continue(&filter.on_connect(&mut again).await.unwrap());
        let second = again.bandwidth.as_ref().unwrap().reserve_upload_at(1, RESERVED_AT);
        assert!(
            second.delay() > Duration::ZERO,
            "the same address shares the upload budget"
        );
    }
}
