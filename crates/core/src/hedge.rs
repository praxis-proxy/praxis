// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Hedge budget, per-request race, and the driver that waits for the first success.
//!
//! A hedge is an extra copy of a request, sent while an earlier attempt
//! may still be running. This budget caps those copies as a fraction of
//! the requests observed on the route so a slow cluster cannot be amplified
//! without bound. The first attempt is never charged; only copies are.
//!
//! A copy takes a single-use reservation
//! ([`HedgeReservation`](crate::hedge::HedgeReservation)). The race holds it
//! while that copy is in flight and drops it when the attempt finishes or
//! when no endpoint can take it. Dropping the reservation returns the
//! admission. [`HedgeRace`](crate::hedge::HedgeRace) also stops at
//! `max_attempts` for the one client request, whether or not the shared
//! budget would allow more.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::task::JoinSet;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Parts-per-10_000 scale. `10%` is `1_000`; `100%` is `10_000`.
const BPS_SCALE: u64 = 10_000;

/// One basis point, in percent. This is the finest budget the counter can store.
const PERCENT_STEP: f64 = 0.01;

/// How far a percent may sit from a basis-point boundary and still be that boundary.
///
/// Half a step is `0.005`. Anything looser would accept a percent the counter
/// cannot store, which is the rounding this check exists to reject.
const PERCENT_STEP_EPSILON: f64 = 1e-4;

// -----------------------------------------------------------------------------
// HedgeBudget
// -----------------------------------------------------------------------------

/// Shared admission counter for one route's hedge policy.
///
/// `try_admit` allows another hedge while
/// `active hedges / active requests < budget_percent / 100`. With no copy in
/// flight that ratio is zero, so any positive budget admits one and a single
/// active request can still hedge. The check uses integer basis points so
/// concurrent callers cannot drift the ratio with float rounding. Both
/// counters are the requests and copies in flight now.
/// A finished request does not leave credit for a later slow period. A
/// config reload builds a new budget.
#[derive(Debug)]
pub struct HedgeBudget {
    /// Client requests currently inside a race on this policy.
    requests: AtomicU64,
    /// Hedge copies reserved or in flight (not the primary attempt).
    hedges: AtomicU64,
    /// Budget in basis points, `0..=10_000`.
    bps: u64,
}

impl HedgeBudget {
    /// Build a budget for `percent` in `0.0..=100.0`.
    ///
    /// `percent` must be a multiple of `0.01` (one basis point).
    /// A finer value, and a non-finite value, is rejected. The stored budget
    /// is then the percent that was requested.
    ///
    /// # Errors
    ///
    /// Returns an error when `percent` is non-finite, outside `0.0..=100.0`,
    /// or not a multiple of `0.01`.
    pub fn try_new(percent: f64) -> Result<Self, String> {
        Ok(Self {
            requests: AtomicU64::new(0),
            hedges: AtomicU64::new(0),
            bps: percent_to_bps(percent)?,
        })
    }

    /// Count one client request that has entered a race.
    pub fn note_request(&self) {
        self.requests.fetch_add(1, Ordering::Release);
    }

    /// The client request left its race.
    pub fn end_request(&self) {
        let mut requests = self.requests.load(Ordering::Relaxed);
        while requests > 0 {
            match self.requests.compare_exchange_weak(
                requests,
                requests.saturating_sub(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => requests = observed,
            }
        }
    }

    /// Return one admission that [`try_reserve`](Self::try_reserve) took.
    ///
    /// Only a dropped [`HedgeReservation`] calls this. The decrement is not
    /// tied to a caller-supplied id; the reservation flag is what makes the
    /// return single-use.
    pub(crate) fn revert_admission(&self) {
        let mut hedges = self.hedges.load(Ordering::Relaxed);
        while hedges > 0 {
            match self.hedges.compare_exchange_weak(
                hedges,
                hedges.saturating_sub(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => hedges = observed,
            }
        }
    }

    /// Try to admit one hedge copy.
    ///
    /// Returns `false` when another copy would meet or pass the configured
    /// percent, and when the percent is zero. Zero copies are under any
    /// positive percent, so the first copy is admitted. Callers that may fail
    /// before the copy is sent use [`try_reserve`](Self::try_reserve) so the
    /// admission cannot be returned twice or charged to the wrong request.
    pub(crate) fn try_admit(&self) -> bool {
        if self.bps == 0 {
            return false;
        }
        let mut hedges = self.hedges.load(Ordering::Relaxed);
        loop {
            let requests = self.requests.load(Ordering::Acquire);
            let used = hedges.saturating_mul(BPS_SCALE);
            let allowed = requests.saturating_mul(self.bps);
            if used >= allowed {
                return false;
            }
            match self.hedges.compare_exchange_weak(
                hedges,
                hedges.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => hedges = observed,
            }
        }
    }

    /// Admit one copy and return a reservation for it.
    ///
    /// Hold the reservation while the copy is in flight. Drop it to return
    /// the admission. A second drop does not decrement the counter.
    #[must_use]
    pub fn try_reserve(self: &Arc<Self>) -> Option<HedgeReservation> {
        self.try_admit().then(|| HedgeReservation {
            budget: Arc::clone(self),
            open: AtomicBool::new(true),
        })
    }

    /// Admitted hedge copies. For tests.
    #[cfg(test)]
    fn hedges(&self) -> u64 {
        self.hedges.load(Ordering::Relaxed)
    }

    /// Stored basis points. For tests.
    #[cfg(test)]
    pub(crate) fn bps(&self) -> u64 {
        self.bps
    }
}

/// One admitted hedge copy.
///
/// The race holds the reservation while the copy is in flight. Dropping it
/// returns the admission, once. A second drop does not decrement the counter.
#[derive(Debug)]
pub struct HedgeReservation {
    /// Budget this copy was charged to.
    budget: Arc<HedgeBudget>,
    /// `true` until the reservation is committed or reverted.
    open: AtomicBool,
}

impl Drop for HedgeReservation {
    fn drop(&mut self) {
        if self.open.swap(false, Ordering::AcqRel) {
            self.budget.revert_admission();
        }
    }
}

// -----------------------------------------------------------------------------
// Response status
// -----------------------------------------------------------------------------

/// A final HTTP status the proxy can return to the client.
///
/// `2xx`, `3xx`, and `4xx` are success: the attempt produced an application
/// response. `5xx` is not, so a peer that is still running may still win.
#[must_use]
pub fn status_is_success(status: u16) -> bool {
    (200..500).contains(&status)
}

// -----------------------------------------------------------------------------
// HedgeRace
// -----------------------------------------------------------------------------

/// Who pays for an attempt that is about to start.
enum CopyAdmission {
    /// The first attempt. It is never charged to the budget.
    Primary,
    /// A copy the race holds until the attempt finishes.
    Reserved(HedgeReservation),
}

/// Result of trying to start one attempt.
enum AttemptStart {
    /// The attempt is in flight.
    Started(Arc<str>),
    /// The shared budget has no room. A later per-try timer may retry.
    BudgetDenied,
    /// The attempt cap is reached, or the cluster has no fresh endpoint.
    NotPlaced,
}

/// One attempt the caller should start now.
#[derive(Debug, PartialEq, Eq)]
pub struct HedgeLaunch {
    /// Endpoint that receives this attempt.
    pub address: Arc<str>,
    /// The primary attempt. Copies are every launch after this one.
    pub primary: bool,
}

/// What the caller should do after a race step.
#[derive(Debug, PartialEq, Eq)]
pub enum HedgeOutcome {
    /// Start `attempts` now. `wait` is the delay before [`HedgeRace::on_timer`]
    /// when further copies may still be started.
    Launch {
        /// Attempts to dial, primary first when it is part of this step.
        attempts: Vec<HedgeLaunch>,
        /// Delay before the next copy while no attempt has succeeded.
        wait: Option<Duration>,
    },
    /// `address` returned a successful response. Cancel every other attempt.
    Won {
        /// Endpoint whose response the caller returns to the client.
        address: Arc<str>,
        /// Attempts still running. The caller stops them.
        cancel: Vec<Arc<str>>,
    },
    /// Every started attempt finished without a successful response,
    /// or no endpoint could be started.
    Lost {
        /// Last unsuccessful HTTP status, when an attempt produced one.
        status: Option<u16>,
    },
    /// Nothing to dial and nothing to cancel. A stale timer or a late
    /// completion after the race already finished.
    Pending,
}

/// One client request's hedge race.
///
/// The primary attempt is not charged to the budget. Each copy is admitted
/// before it is launched, and the admission is returned when no distinct
/// endpoint is left to send it to. A successful response ([`status_is_success`])
/// wins and the caller cancels the attempts still in flight. A copy is started
/// by [`Self::on_timer`] only while an earlier attempt is still waiting for a
/// response.
#[derive(Debug)]
pub struct HedgeRace {
    /// Attempts started immediately, including the primary.
    initial_requests: u32,
    /// Total attempts for this client request, including the primary.
    max_attempts: u32,
    /// Delay before each copy beyond the initial fan-out.
    per_try_timeout: Option<Duration>,
    /// Route budget shared with every other request on the policy.
    budget: Arc<HedgeBudget>,
    /// Endpoints already chosen, in start order.
    started: Vec<Arc<str>>,
    /// Attempts that have been started and have not finished.
    in_flight: Vec<Arc<str>>,
    /// Reservations for copies that are still in flight.
    copies: Vec<(Arc<str>, HedgeReservation)>,
    /// Last HTTP status from an attempt that did not win.
    last_failure: Option<u16>,
    /// The client request has been counted on the budget.
    noted: bool,
    /// A winner was chosen, or no further attempt can succeed.
    closed: bool,
}

impl HedgeRace {
    /// Race driven by an already validated policy.
    ///
    /// `initial_requests` is at least 1 and at most `max_attempts`.
    /// `per_try_timeout` is present when `max_attempts` is greater than
    /// `initial_requests`.
    pub(crate) fn new(
        initial_requests: u32,
        max_attempts: u32,
        per_try_timeout: Option<Duration>,
        budget: Arc<HedgeBudget>,
    ) -> Self {
        Self {
            initial_requests,
            max_attempts,
            per_try_timeout,
            budget,
            started: Vec::new(),
            in_flight: Vec::new(),
            copies: Vec::new(),
            last_failure: None,
            noted: false,
            closed: false,
        }
    }

    /// Count this client request and start the initial fan-out.
    ///
    /// `pick` returns the next endpoint that is not already in the slice,
    /// or `None` when the cluster has no further candidate. A second call
    /// does not count the request again.
    pub fn open<F>(&mut self, mut pick: F) -> HedgeOutcome
    where
        F: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    {
        if self.noted {
            return HedgeOutcome::Pending;
        }
        self.note_once();
        let attempts = self.start_initial(&mut pick);
        self.after_starts(attempts)
    }

    /// The per-try timer fired, or the in-flight attempts all failed.
    ///
    /// Starts one copy when the budget and the cluster both allow it.
    /// A full budget keeps the same per-try delay so a later tick can retry.
    /// No fresh endpoint stops the timer while something is still running,
    /// and ends the race when nothing is.
    pub fn on_timer<F>(&mut self, mut pick: F) -> HedgeOutcome
    where
        F: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    {
        if self.closed {
            return HedgeOutcome::Pending;
        }
        match self.start_one(&mut pick, false) {
            AttemptStart::Started(address) => self.launched_copy(address),
            AttemptStart::BudgetDenied => HedgeOutcome::Launch {
                attempts: Vec::new(),
                wait: self.next_wait(),
            },
            AttemptStart::NotPlaced => {
                if self.in_flight.is_empty() {
                    self.closed = true;
                    HedgeOutcome::Lost {
                        status: self.last_failure,
                    }
                } else {
                    HedgeOutcome::Pending
                }
            },
        }
    }

    /// An attempt finished.
    ///
    /// `status` is `None` when the attempt failed before an HTTP response.
    /// A late completion after the race has finished is ignored.
    pub fn on_complete(&mut self, address: &str, status: Option<u16>) -> HedgeOutcome {
        if self.closed {
            return HedgeOutcome::Pending;
        }
        if self.take_in_flight(address).is_none() {
            return HedgeOutcome::Pending;
        }
        if status.is_some_and(status_is_success) {
            return self.win(address);
        }
        self.remember_failure(status);
        self.finish_if_idle()
    }

    /// Count the client request once.
    fn note_once(&mut self) {
        self.budget.note_request();
        self.noted = true;
    }

    /// Start every attempt that belongs to the initial fan-out.
    fn start_initial<F>(&mut self, pick: &mut F) -> Vec<HedgeLaunch>
    where
        F: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    {
        let mut launches = Vec::new();
        while self.started_count() < self.initial_requests {
            let primary = self.started.is_empty();
            let AttemptStart::Started(address) = self.start_one(pick, primary) else {
                break;
            };
            launches.push(HedgeLaunch { address, primary });
        }
        launches
    }

    /// Start one attempt. A copy that cannot be placed returns its admission.
    fn start_one<F>(&mut self, pick: &mut F, primary: bool) -> AttemptStart
    where
        F: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    {
        if self.started_count() >= self.max_attempts {
            return AttemptStart::NotPlaced;
        }
        let Some(admission) = self.copy_admission(primary) else {
            return AttemptStart::BudgetDenied;
        };
        let Some(address) = self.fresh_endpoint(pick) else {
            return AttemptStart::NotPlaced;
        };
        if let CopyAdmission::Reserved(reservation) = admission {
            self.copies.push((Arc::clone(&address), reservation));
        }
        self.in_flight.push(Arc::clone(&address));
        self.started.push(Arc::clone(&address));
        AttemptStart::Started(address)
    }

    /// The primary is uncharged. A copy is reserved, or denied when the budget is full.
    fn copy_admission(&self, primary: bool) -> Option<CopyAdmission> {
        if primary {
            return Some(CopyAdmission::Primary);
        }
        self.budget.try_reserve().map(CopyAdmission::Reserved)
    }

    /// One admitted copy is now in flight. Arm the next per-try wait when more copies remain.
    fn launched_copy(&self, address: Arc<str>) -> HedgeOutcome {
        HedgeOutcome::Launch {
            attempts: vec![HedgeLaunch {
                address,
                primary: false,
            }],
            wait: self.next_wait(),
        }
    }

    /// Next endpoint that is not already in this race.
    fn fresh_endpoint<F>(&self, pick: &mut F) -> Option<Arc<str>>
    where
        F: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    {
        let address = pick(self.started.as_slice())?;
        let seen = self
            .started
            .iter()
            .any(|existing| existing.as_ref() == address.as_ref());
        if seen { None } else { Some(address) }
    }

    /// Launch step for the initial fan-out, or a loss when nothing started.
    fn after_starts(&mut self, attempts: Vec<HedgeLaunch>) -> HedgeOutcome {
        if attempts.is_empty() {
            self.closed = true;
            return HedgeOutcome::Lost { status: None };
        }
        HedgeOutcome::Launch {
            wait: self.next_wait(),
            attempts,
        }
    }

    /// Delay before the next copy while further attempts are still allowed.
    fn next_wait(&self) -> Option<Duration> {
        if self.closed || self.started_count() >= self.max_attempts {
            return None;
        }
        self.per_try_timeout
    }

    /// Record a non-winning status.
    fn remember_failure(&mut self, status: Option<u16>) {
        if let Some(status) = status {
            self.last_failure = Some(status);
        }
    }

    /// Lose when nothing is left running and no further attempt can start.
    ///
    /// A failure that leaves the race idle starts the next copy immediately
    /// when `max_attempts` still has room. The caller treats an empty launch
    /// with a zero wait as that signal.
    fn finish_if_idle(&mut self) -> HedgeOutcome {
        if !self.in_flight.is_empty() {
            return HedgeOutcome::Pending;
        }
        if self.started_count() < self.max_attempts {
            return HedgeOutcome::Launch {
                attempts: Vec::new(),
                wait: Some(Duration::ZERO),
            };
        }
        self.closed = true;
        HedgeOutcome::Lost {
            status: self.last_failure,
        }
    }

    /// Mark `address` the winner and return the attempts still running.
    fn win(&mut self, address: &str) -> HedgeOutcome {
        self.closed = true;
        let address = self
            .started
            .iter()
            .find(|existing| existing.as_ref() == address)
            .map_or_else(|| Arc::from(address), Arc::clone);
        self.winner_cancel(address)
    }

    /// Build the winning outcome from the attempts that are still running.
    fn winner_cancel(&mut self, address: Arc<str>) -> HedgeOutcome {
        self.copies.clear();
        let cancel = std::mem::take(&mut self.in_flight);
        HedgeOutcome::Won { address, cancel }
    }

    /// Remove a running attempt. `None` when that address is not in flight.
    fn take_in_flight(&mut self, address: &str) -> Option<Arc<str>> {
        let index = self
            .in_flight
            .iter()
            .position(|existing| existing.as_ref() == address)?;
        self.release_copy(address);
        Some(self.in_flight.swap_remove(index))
    }

    /// Return the budget slot for a copy that is no longer in flight.
    fn release_copy(&mut self, address: &str) {
        if let Some(index) = self
            .copies
            .iter()
            .position(|(existing, _)| existing.as_ref() == address)
        {
            self.copies.swap_remove(index);
        }
    }

    /// How many attempts have been started.
    fn started_count(&self) -> u32 {
        u32::try_from(self.started.len()).unwrap_or(u32::MAX)
    }
}

impl Drop for HedgeRace {
    fn drop(&mut self) {
        self.copies.clear();
        if self.noted {
            self.budget.end_request();
            self.noted = false;
        }
    }
}

// -----------------------------------------------------------------------------
// Hedge drive
// -----------------------------------------------------------------------------

/// One finished attempt, successful or not.
#[derive(Debug)]
pub struct HedgeAttempt<T> {
    /// HTTP status. `None` when the attempt failed before a response.
    pub status: Option<u16>,
    /// Payload the caller returns when this attempt wins.
    pub response: Option<T>,
}

/// The attempt the caller should return, or the failure of the whole race.
#[derive(Debug)]
#[must_use]
pub enum HedgeDelivery<T> {
    /// `response` won. Other attempts have been cancelled.
    Ready {
        /// Endpoint that produced `response`.
        address: Arc<str>,
        /// Winning payload.
        response: T,
    },
    /// No attempt produced a successful response.
    Failed {
        /// Last unsuccessful HTTP status, when an attempt produced one.
        status: Option<u16>,
        /// Last unsuccessful payload, when an attempt produced one.
        response: Option<T>,
    },
}

/// In-flight attempt tasks for one [`drive`] call.
struct Flight<T> {
    /// Attempts that have been spawned and have not finished.
    tasks: JoinSet<(Arc<str>, HedgeAttempt<T>)>,
    /// Endpoint for each spawned task, so a panic still names that endpoint.
    addresses: HashMap<tokio::task::Id, Arc<str>>,
}

impl<T> Flight<T>
where
    T: Send + 'static,
{
    /// Empty set of attempts.
    fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            addresses: HashMap::new(),
        }
    }

    /// Spawn every attempt in `attempts`.
    fn launch<S, Fut>(&mut self, start: &mut S, attempts: Vec<HedgeLaunch>)
    where
        S: FnMut(Arc<str>) -> Fut,
        Fut: Future<Output = HedgeAttempt<T>> + Send + 'static,
    {
        for attempt in attempts {
            let address = attempt.address;
            let fut = start(Arc::clone(&address));
            let tracked = Arc::clone(&address);
            let handle = self.tasks.spawn(async move { (address, fut.await) });
            self.addresses.insert(handle.id(), tracked);
        }
    }

    /// Stop every attempt that is still running.
    fn stop(&mut self) {
        self.tasks.abort_all();
    }

    /// True when nothing is running and no timer remains.
    fn idle(&self, deadline: Option<Instant>) -> bool {
        self.tasks.is_empty() && deadline.is_none()
    }

    /// Wait until an attempt finishes or `deadline` elapses.
    async fn next(&mut self, deadline: Option<Instant>) -> Wake<T> {
        tokio::select! {
            biased;
            joined = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => self.joined_wake(joined),
            () = sleep_until(deadline), if deadline.is_some() => Wake::Timer,
        }
    }

    /// Map a joined task onto a wake-up, including a panic.
    ///
    /// A panic still names the endpoint that was running, so the race can
    /// drop that attempt and start the next copy.
    fn joined_wake(&mut self, joined: Option<Joined<T>>) -> Wake<T> {
        match joined {
            Some(Ok((id, (address, attempt)))) => {
                self.addresses.remove(&id);
                Wake::Finished(address, attempt)
            },
            Some(Err(err)) => Wake::Finished(
                self.addresses.remove(&err.id()).unwrap_or_else(|| Arc::from("")),
                HedgeAttempt {
                    status: None,
                    response: None,
                },
            ),
            None => Wake::Finished(
                Arc::from(""),
                HedgeAttempt {
                    status: None,
                    response: None,
                },
            ),
        }
    }
}

/// Run `race` until one attempt succeeds or every attempt has failed.
///
/// `pick` chooses the next endpoint. `start` dials one attempt; dropping
/// its future cancels that attempt. The primary is the first start.
pub async fn drive<T, P, S, Fut>(mut race: HedgeRace, mut pick: P, mut start: S) -> HedgeDelivery<T>
where
    T: Send + 'static,
    P: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    S: FnMut(Arc<str>) -> Fut,
    Fut: Future<Output = HedgeAttempt<T>> + Send + 'static,
{
    let mut flight = Flight::new();
    let HedgeOutcome::Launch { attempts, wait } = race.open(&mut pick) else {
        return HedgeDelivery::Failed {
            status: None,
            response: None,
        };
    };
    flight.launch(&mut start, attempts);
    let delivery = run_flight(&mut race, &mut pick, &mut start, &mut flight, deadline_after(wait)).await;
    flight.stop();
    delivery
}

/// Wait for completions and the per-try timer.
async fn run_flight<T, P, S, Fut>(
    race: &mut HedgeRace,
    pick: &mut P,
    start: &mut S,
    flight: &mut Flight<T>,
    mut deadline: Option<Instant>,
) -> HedgeDelivery<T>
where
    T: Send + 'static,
    P: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    S: FnMut(Arc<str>) -> Fut,
    Fut: Future<Output = HedgeAttempt<T>> + Send + 'static,
{
    let mut last_failure: Option<HedgeAttempt<T>> = None;
    loop {
        if flight.idle(deadline) {
            return failed_from(None, &mut last_failure);
        }
        match flight.next(deadline).await {
            Wake::Finished(address, attempt) => match on_finished(race, &address, attempt, &mut last_failure) {
                AfterAttempt::Done(delivery) => return delivery,
                AfterAttempt::Continue => {},
                AfterAttempt::StartNow => {
                    if let Some(stop) = on_timer(race, pick, start, flight, &mut deadline) {
                        return stop_delivery(stop, &mut last_failure);
                    }
                },
            },
            Wake::Timer => {
                if let Some(stop) = on_timer(race, pick, start, flight, &mut deadline) {
                    return stop_delivery(stop, &mut last_failure);
                }
            },
        }
    }
}

/// The next attempt finished, or the per-try timer fired.
enum Wake<T> {
    /// `address` finished with `attempt`.
    Finished(Arc<str>, HedgeAttempt<T>),
    /// The per-try deadline elapsed.
    Timer,
}

/// A task that finished or panicked.
type Joined<T> = Result<(tokio::task::Id, (Arc<str>, HedgeAttempt<T>)), tokio::task::JoinError>;

/// What the drive does after one attempt finishes.
enum AfterAttempt<T> {
    /// Return this delivery.
    Done(HedgeDelivery<T>),
    /// Keep waiting for the attempts already running.
    Continue,
    /// Nothing is in flight and `max_attempts` still has room. Start the next copy now.
    StartNow,
}

/// Record a finished attempt.
fn on_finished<T>(
    race: &mut HedgeRace,
    address: &Arc<str>,
    attempt: HedgeAttempt<T>,
    last_failure: &mut Option<HedgeAttempt<T>>,
) -> AfterAttempt<T> {
    let status = attempt.status;
    match race.on_complete(address.as_ref(), status) {
        HedgeOutcome::Won { address, .. } => AfterAttempt::Done(ready_or_failed(address, attempt.response)),
        HedgeOutcome::Lost { status: lost } => {
            remember_failure(last_failure, attempt);
            AfterAttempt::Done(failed_from(lost.or(status), last_failure))
        },
        HedgeOutcome::Pending => {
            remember_failure(last_failure, attempt);
            AfterAttempt::Continue
        },
        HedgeOutcome::Launch { attempts, wait } => {
            remember_failure(last_failure, attempt);
            if attempts.is_empty() && wait == Some(Duration::ZERO) {
                AfterAttempt::StartNow
            } else {
                AfterAttempt::Continue
            }
        },
    }
}

/// Why a timer step ends the race.
enum TimerStop {
    /// Every attempt has failed.
    Lost(Option<u16>),
    /// An earlier attempt was reported as the winner.
    Won(Arc<str>),
}

/// The per-try timer fired. `Some` ends the race.
fn on_timer<T, P, S, Fut>(
    race: &mut HedgeRace,
    pick: &mut P,
    start: &mut S,
    flight: &mut Flight<T>,
    deadline: &mut Option<Instant>,
) -> Option<TimerStop>
where
    T: Send + 'static,
    P: FnMut(&[Arc<str>]) -> Option<Arc<str>>,
    S: FnMut(Arc<str>) -> Fut,
    Fut: Future<Output = HedgeAttempt<T>> + Send + 'static,
{
    match race.on_timer(pick) {
        HedgeOutcome::Launch { attempts, wait } => {
            flight.launch(start, attempts);
            *deadline = deadline_after(wait);
            None
        },
        HedgeOutcome::Lost { status } => Some(TimerStop::Lost(status)),
        HedgeOutcome::Won { address, .. } => Some(TimerStop::Won(address)),
        HedgeOutcome::Pending => {
            *deadline = None;
            None
        },
    }
}

/// Turn a timer stop into the delivery the caller returns.
fn stop_delivery<T>(stop: TimerStop, last_failure: &mut Option<HedgeAttempt<T>>) -> HedgeDelivery<T> {
    match stop {
        TimerStop::Lost(status) => failed_from(status, last_failure),
        TimerStop::Won(address) => ready_or_failed(address, take_response(last_failure)),
    }
}

/// Build a winning delivery, or a failure when the winner had no payload.
fn ready_or_failed<T>(address: Arc<str>, response: Option<T>) -> HedgeDelivery<T> {
    match response {
        Some(response) => HedgeDelivery::Ready { address, response },
        None => HedgeDelivery::Failed {
            status: None,
            response: None,
        },
    }
}

/// Failure delivery, preferring `current` over the stored attempt.
fn failed_from<T>(status: Option<u16>, last_failure: &mut Option<HedgeAttempt<T>>) -> HedgeDelivery<T> {
    let stored = last_failure.take();
    let stored_status = stored.as_ref().and_then(|attempt| attempt.status);
    HedgeDelivery::Failed {
        status: status.or(stored_status),
        response: stored.and_then(|attempt| attempt.response),
    }
}

/// Remember an attempt that did not win.
///
/// A later miss does not replace an earlier response. The client should see
/// the status and body that an attempt actually produced.
fn remember_failure<T>(last_failure: &mut Option<HedgeAttempt<T>>, attempt: HedgeAttempt<T>) {
    let replaces = attempt.response.is_some() || last_failure.as_ref().is_none_or(|kept| kept.response.is_none());
    if replaces && attempt.status.is_none_or(|status| !status_is_success(status)) {
        *last_failure = Some(attempt);
    }
}

/// Move the stored payload out of `last_failure`.
fn take_response<T>(last_failure: &mut Option<HedgeAttempt<T>>) -> Option<T> {
    last_failure.take().and_then(|attempt| attempt.response)
}

/// Absolute time of the next copy, when the race asked for a wait.
fn deadline_after(wait: Option<Duration>) -> Option<Instant> {
    wait.and_then(|wait| Instant::now().checked_add(wait))
}

/// Sleep until `deadline`. A missing deadline never completes.
async fn sleep_until(deadline: Option<Instant>) {
    let Some(deadline) = deadline else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::time::sleep(deadline.saturating_duration_since(Instant::now())).await;
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Map a percent to basis points.
///
/// The percent must already be an integer number of [`PERCENT_STEP`]s.
/// Rounding is not applied: `0.005` is an error, not `0.01`.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the percent is finite and on a 0.01 boundary before the cast"
)]
fn percent_to_bps(percent: f64) -> Result<u64, String> {
    if !percent.is_finite() {
        return Err(format!("hedge_policy: budget_percent must be finite, got {percent}"));
    }
    if !(0.0..=100.0).contains(&percent) {
        return Err(format!(
            "hedge_policy: budget_percent must be in 0.0..=100.0, got {percent}"
        ));
    }
    let steps = percent / PERCENT_STEP;
    let rounded = steps.round();
    if !rounded.is_finite() || (steps - rounded).abs() > PERCENT_STEP_EPSILON {
        return Err(format!(
            "hedge_policy: budget_percent must be a multiple of 0.01, got {percent}"
        ));
    }
    if rounded >= 10_000.0 {
        return Ok(BPS_SCALE);
    }
    if rounded <= 0.0 {
        return Ok(0);
    }
    Ok(rounded as u64)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn zero_percent_admits_nothing() {
        let budget = HedgeBudget::try_new(0.0).unwrap();
        budget.note_request();
        assert!(!budget.try_admit(), "0% must not admit a hedge");
        assert_eq!(budget.hedges(), 0);
    }

    #[test]
    fn first_request_can_hedge_when_percent_is_positive() {
        let budget = HedgeBudget::try_new(10.0).unwrap();
        budget.note_request();
        assert!(budget.try_admit(), "the first request starts under the ratio");
        assert!(!budget.try_admit(), "a second copy on the same request exceeds 10%");
    }

    #[test]
    fn ten_percent_sustains_one_hedge_per_ten_requests() {
        let budget = HedgeBudget::try_new(10.0).unwrap();
        let mut admitted = 0_u32;
        for _ in 0..20 {
            budget.note_request();
            if budget.try_admit() {
                admitted = admitted.saturating_add(1);
            }
        }
        assert_eq!(admitted, 2, "20 requests at 10% admit 2 hedges, got {admitted}");
    }

    #[test]
    fn one_hundred_percent_allows_one_hedge_per_request() {
        let budget = HedgeBudget::try_new(100.0).unwrap();
        for _ in 0..5 {
            budget.note_request();
            assert!(budget.try_admit(), "100% allows one hedge per counted request");
            assert!(!budget.try_admit(), "100% does not allow two hedges on one request");
        }
        assert_eq!(budget.hedges(), 5);
    }

    #[test]
    fn reverted_admission_can_be_used_again() {
        let budget = HedgeBudget::try_new(10.0).unwrap();
        budget.note_request();
        assert!(budget.try_admit(), "the first copy is under 10%");
        budget.revert_admission();
        assert_eq!(budget.hedges(), 0, "a copy that was not sent is not charged");
        assert!(budget.try_admit(), "the reverted slot is available");
        assert!(!budget.try_admit(), "only one copy is under 10% for one request");
    }

    #[test]
    fn rejects_non_finite_and_finer_than_one_basis_point() {
        let non_finite = HedgeBudget::try_new(f64::NAN).unwrap_err();
        assert!(non_finite.contains("finite"), "{non_finite}");

        let half = HedgeBudget::try_new(0.005).unwrap_err();
        assert!(half.contains("multiple of 0.01"), "{half}");

        let tenth = HedgeBudget::try_new(0.001).unwrap_err();
        assert!(tenth.contains("multiple of 0.01"), "{tenth}");

        let one = HedgeBudget::try_new(0.01).unwrap();
        assert_eq!(one.bps(), 1, "0.01% is one basis point");
    }

    #[test]
    fn success_statuses_are_non_5xx_final_responses() {
        assert!(status_is_success(200));
        assert!(status_is_success(204));
        assert!(status_is_success(302));
        assert!(status_is_success(404));
        assert!(status_is_success(429));
        assert!(!status_is_success(500));
        assert!(!status_is_success(503));
        assert!(!status_is_success(101), "a 1xx is not a final response");
        assert!(!status_is_success(100));
    }

    #[test]
    fn fan_out_starts_the_primary_and_one_admitted_copy() {
        let mut race = race_with(2, 2, None, 100.0);
        let outcome = race.open(two_endpoints);
        let HedgeOutcome::Launch { attempts, wait } = outcome else {
            panic!("the initial fan-out should launch");
        };
        let mut launched = attempts.into_iter();
        let primary = launched.next().unwrap();
        let copy = launched.next().unwrap();
        assert!(primary.primary, "the first attempt is the primary");
        assert!(!copy.primary, "the second attempt is a copy");
        assert_ne!(primary.address, copy.address);
        assert!(wait.is_none(), "max_attempts equals the fan-out, so no timer remains");
        assert_eq!(race.budget.hedges(), 1, "only the copy is charged");
    }

    #[test]
    fn zero_budget_starts_only_the_primary() {
        let mut race = race_with(2, 2, None, 0.0);
        let HedgeOutcome::Launch { attempts, .. } = race.open(two_endpoints) else {
            panic!("the primary should still start");
        };
        let primary = attempts.into_iter().next().unwrap();
        assert!(primary.primary, "a 0% budget still starts the primary");
        assert_eq!(race.budget.hedges(), 0);
    }

    #[test]
    fn missing_second_endpoint_returns_the_copy_admission() {
        let mut race = race_with(2, 2, None, 100.0);
        let HedgeOutcome::Launch { attempts, .. } = race.open(one_endpoint) else {
            panic!("the only endpoint should start");
        };
        assert_eq!(attempts.len(), 1, "the missing endpoint is not a second attempt");
        assert_eq!(race.budget.hedges(), 0, "a copy that was not sent is not charged");
    }

    #[test]
    fn timer_starts_a_copy_while_the_primary_is_still_running() {
        let mut race = race_with(1, 2, Some(50), 100.0);
        let HedgeOutcome::Launch { wait, .. } = race.open(two_endpoints) else {
            panic!("the primary should start");
        };
        assert_eq!(wait, Some(Duration::from_millis(50)));
        let HedgeOutcome::Launch { attempts, wait: next } = race.on_timer(two_endpoints) else {
            panic!("the timer should start the copy");
        };
        let copy = attempts.into_iter().next().unwrap();
        assert!(!copy.primary, "the timer starts a copy");
        assert!(next.is_none(), "both attempts are started");
        assert_eq!(race.budget.hedges(), 1);
    }

    #[test]
    fn success_cancels_the_attempt_still_running() {
        let mut race = race_with(2, 2, None, 100.0);
        let HedgeOutcome::Launch { attempts, .. } = race.open(two_endpoints) else {
            panic!("both attempts should start");
        };
        let mut launched = attempts.into_iter();
        let primary = launched.next().unwrap().address;
        let copy = launched.next().unwrap().address;
        let HedgeOutcome::Won { address, cancel } = race.on_complete(primary.as_ref(), Some(200)) else {
            panic!("a 2xx wins");
        };
        assert_eq!(address, primary);
        assert_eq!(cancel, vec![copy]);
        assert!(matches!(race.on_timer(two_endpoints), HedgeOutcome::Pending));
        assert!(matches!(
            race.on_complete(address.as_ref(), Some(200)),
            HedgeOutcome::Pending
        ));
    }

    #[test]
    fn client_error_wins_and_upstream_error_does_not() {
        let mut race = race_with(1, 2, Some(50), 100.0);
        drop(race.open(two_endpoints));
        let HedgeOutcome::Launch { attempts, wait } = race.on_complete("10.0.0.1:80", Some(503)) else {
            panic!("a lone 503 starts the next copy immediately");
        };
        assert!(attempts.is_empty(), "the race asks the driver to start the copy");
        assert_eq!(wait, Some(Duration::ZERO));
        let HedgeOutcome::Launch { attempts: started, .. } = race.on_timer(two_endpoints) else {
            panic!("the next copy starts without waiting for the per-try timer");
        };
        assert_eq!(started.len(), 1, "one copy replaces the failed primary");

        let mut waiting = race_with(2, 2, None, 100.0);
        drop(waiting.open(two_endpoints));
        assert!(matches!(
            waiting.on_complete("10.0.0.1:80", Some(404)),
            HedgeOutcome::Won { .. }
        ));
    }

    #[test]
    fn failure_while_the_other_attempt_is_running_keeps_waiting() {
        let mut race = race_with(2, 2, None, 100.0);
        drop(race.open(two_endpoints));
        assert!(matches!(
            race.on_complete("10.0.0.1:80", Some(503)),
            HedgeOutcome::Pending
        ));
        let HedgeOutcome::Lost { status } = race.on_complete("10.0.0.2:80", None) else {
            panic!("both attempts failed");
        };
        assert_eq!(status, Some(503));
    }

    #[test]
    fn no_endpoint_loses_and_a_second_open_is_ignored() {
        let mut race = race_with(1, 1, None, 100.0);
        assert!(matches!(
            race.open(|_exclude| None),
            HedgeOutcome::Lost { status: None }
        ));
        assert!(matches!(race.open(one_endpoint), HedgeOutcome::Pending));
        assert_eq!(race.budget.hedges(), 0);
    }

    #[tokio::test]
    async fn primary_success_does_not_start_a_copy() {
        let race = race_with(1, 2, Some(60_000), 100.0);
        let started = Arc::new(std::sync::Mutex::new(0_u32));
        let counter = Arc::clone(&started);
        let delivery = drive(race, two_endpoints, move |address| {
            let mut count = counter.lock().unwrap();
            *count = count.saturating_add(1);
            drop(count);
            async move {
                HedgeAttempt {
                    status: Some(200),
                    response: Some(address),
                }
            }
        })
        .await;
        let HedgeDelivery::Ready { response, .. } = delivery else {
            panic!("the primary response should win");
        };
        assert_eq!(response.as_ref(), "10.0.0.1:80");
        assert_eq!(*started.lock().unwrap(), 1, "the timer has not fired");
    }

    #[tokio::test]
    async fn slow_primary_loses_to_the_copy() {
        let race = race_with(1, 2, Some(15), 100.0);
        let delivery = drive(race, two_endpoints, |address| async move {
            if address.as_ref() == "10.0.0.1:80" {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            HedgeAttempt {
                status: Some(200),
                response: Some(address),
            }
        })
        .await;
        let HedgeDelivery::Ready { response, .. } = delivery else {
            panic!("the copy should win while the primary is still running");
        };
        assert_eq!(response.as_ref(), "10.0.0.2:80");
    }

    #[tokio::test]
    async fn drive_returns_the_last_failure_when_every_attempt_fails() {
        let race = race_with(2, 2, None, 100.0);
        let delivery = drive(race, two_endpoints, |address| async move {
            HedgeAttempt {
                status: Some(503),
                response: Some(address),
            }
        })
        .await;
        let HedgeDelivery::Failed { status, .. } = delivery else {
            panic!("a 503 is not a winning response");
        };
        assert_eq!(status, Some(503));
    }

    #[tokio::test]
    async fn a_failed_primary_starts_the_next_copy_without_waiting() {
        let race = race_with(1, 2, Some(5_000), 100.0);
        let delivery = tokio::time::timeout(
            Duration::from_millis(500),
            drive::<Arc<str>, _, _, _>(race, two_endpoints, |address| async move {
                if address.as_ref() == "10.0.0.1:80" {
                    HedgeAttempt {
                        status: Some(503),
                        response: Some(Arc::from("slow")),
                    }
                } else {
                    HedgeAttempt {
                        status: Some(200),
                        response: Some(Arc::from("fast")),
                    }
                }
            }),
        )
        .await
        .expect("the copy starts before the per-try timer");
        let HedgeDelivery::Ready { response, .. } = delivery else {
            panic!("the copy should win");
        };
        assert_eq!(response.as_ref(), "fast");
    }

    #[tokio::test]
    async fn a_panicked_primary_still_names_its_endpoint() {
        let race = race_with(1, 2, Some(5_000), 100.0);
        let delivery = tokio::time::timeout(
            Duration::from_millis(500),
            drive::<Arc<str>, _, _, _>(race, two_endpoints, |address| async move {
                assert!(
                    address.as_ref() != "10.0.0.1:80",
                    "the primary attempt failed inside its task"
                );
                HedgeAttempt {
                    status: Some(200),
                    response: Some(address),
                }
            }),
        )
        .await
        .expect("the copy starts after the panic");
        let HedgeDelivery::Ready { response, .. } = delivery else {
            panic!("the copy should win");
        };
        assert_eq!(response.as_ref(), "10.0.0.2:80");
    }

    #[tokio::test]
    async fn a_later_miss_keeps_the_earlier_error_body() {
        let race = race_with(1, 2, Some(5_000), 100.0);
        let delivery = drive::<Arc<str>, _, _, _>(race, two_endpoints, |address| async move {
            if address.as_ref() == "10.0.0.1:80" {
                HedgeAttempt {
                    status: Some(503),
                    response: Some(Arc::from("retry-after")),
                }
            } else {
                HedgeAttempt {
                    status: None,
                    response: None,
                }
            }
        })
        .await;
        let HedgeDelivery::Failed { status, response } = delivery else {
            panic!("neither attempt wins");
        };
        assert_eq!(status, Some(503));
        assert_eq!(response.as_deref(), Some("retry-after"));
    }

    #[tokio::test]
    async fn drive_does_not_start_a_copy_when_the_budget_is_zero() {
        let race = race_with(2, 2, None, 0.0);
        let started = Arc::new(std::sync::Mutex::new(0_u32));
        let counter = Arc::clone(&started);
        let delivery = drive(race, two_endpoints, move |address| {
            let mut count = counter.lock().unwrap();
            *count = count.saturating_add(1);
            drop(count);
            async move {
                HedgeAttempt {
                    status: Some(204),
                    response: Some(address),
                }
            }
        })
        .await;
        assert!(matches!(delivery, HedgeDelivery::Ready { .. }));
        assert_eq!(*started.lock().unwrap(), 1, "a 0% budget admits no copy");
    }

    #[test]
    fn timer_without_a_second_endpoint_stops() {
        let mut race = race_with(1, 2, Some(50), 100.0);
        let HedgeOutcome::Launch { .. } = race.open(one_endpoint) else {
            panic!("the primary should start");
        };
        assert!(
            matches!(race.on_timer(one_endpoint), HedgeOutcome::Pending),
            "no second endpoint should not arm another wait"
        );
        assert_eq!(race.budget.hedges(), 0, "the unsent copy is returned");
    }

    #[test]
    fn denied_copy_keeps_the_per_try_timer() {
        let mut race = race_with(1, 2, Some(50), 0.0);
        let HedgeOutcome::Launch { wait, .. } = race.open(two_endpoints) else {
            panic!("the primary should start");
        };
        assert_eq!(
            wait,
            Some(Duration::from_millis(50)),
            "the primary arms the per-try timer"
        );
        let HedgeOutcome::Launch { attempts, wait: retry } = race.on_timer(two_endpoints) else {
            panic!("a denied copy should keep the timer");
        };
        assert!(attempts.is_empty(), "the denied copy is not sent");
        assert_eq!(
            retry,
            Some(Duration::from_millis(50)),
            "the same per-try delay stays armed"
        );
        assert_eq!(race.budget.hedges(), 0, "a denied copy is not charged");
    }

    #[test]
    fn reservation_drop_returns_the_admission_while_it_is_held() {
        let budget = Arc::new(HedgeBudget::try_new(100.0).unwrap());
        budget.note_request();
        let dropped = budget.try_reserve().expect("the first copy is admitted");
        drop(dropped);
        assert_eq!(budget.hedges(), 0, "an unsent copy is returned");
        let kept = budget.try_reserve().expect("the returned slot can be used");
        assert_eq!(budget.hedges(), 1, "holding the reservation keeps the slot");
        drop(kept);
        assert_eq!(budget.hedges(), 0, "finishing the copy returns the slot");
    }

    #[test]
    fn finished_requests_do_not_bank_hedge_credit() {
        let budget = Arc::new(HedgeBudget::try_new(10.0).unwrap());
        for _ in 0..20 {
            budget.note_request();
        }
        assert!(budget.try_admit(), "twenty active requests admit a copy");
        assert!(budget.try_admit(), "10% of twenty active requests admits two");
        assert!(!budget.try_admit(), "the third copy is over the active budget");
        budget.revert_admission();
        budget.revert_admission();
        for _ in 0..20 {
            budget.end_request();
        }
        budget.note_request();
        assert!(budget.try_admit(), "one active request at 10% still admits one copy");
        assert!(!budget.try_admit(), "completed requests do not leave a second slot");
    }

    #[test]
    fn concurrent_reservations_stop_at_the_budget() {
        let budget = Arc::new(HedgeBudget::try_new(10.0).unwrap());
        for _ in 0..10 {
            budget.note_request();
        }
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let budget = Arc::clone(&budget);
            let held = Arc::clone(&held);
            handles.push(std::thread::spawn(move || {
                if let Some(reservation) = budget.try_reserve() {
                    held.lock().unwrap().push(reservation);
                    true
                } else {
                    false
                }
            }));
        }
        let mut admitted = 0_u32;
        for handle in handles {
            if handle.join().unwrap() {
                admitted = admitted.saturating_add(1);
            }
        }
        assert_eq!(admitted, 1, "10% of 10 requests admits one copy");
        assert_eq!(budget.hedges(), 1, "the held reservation is still charged");
        held.lock().unwrap().clear();
        assert_eq!(budget.hedges(), 0, "dropping the reservation returns the slot");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn race_with(initial: u32, max_attempts: u32, timeout_ms: Option<u64>, percent: f64) -> HedgeRace {
        HedgeRace::new(
            initial,
            max_attempts,
            timeout_ms.map(Duration::from_millis),
            Arc::new(HedgeBudget::try_new(percent).unwrap()),
        )
    }

    fn one_endpoint(exclude: &[Arc<str>]) -> Option<Arc<str>> {
        next_endpoint(&["10.0.0.1:80"], exclude)
    }

    fn two_endpoints(exclude: &[Arc<str>]) -> Option<Arc<str>> {
        next_endpoint(&["10.0.0.1:80", "10.0.0.2:80"], exclude)
    }

    fn next_endpoint(addresses: &[&str], exclude: &[Arc<str>]) -> Option<Arc<str>> {
        addresses
            .iter()
            .map(|address| Arc::<str>::from(*address))
            .find(|address| exclude.iter().all(|existing| existing.as_ref() != address.as_ref()))
    }
}
