// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Outbound subrequest chain binding.
//!
//! A *chain-binding filter* is an application-provided HTTP filter (for
//! example an AI callout) that owns a prebuilt outbound [`FilterPipeline`].
//! Rather than parsing and building its outbound chain on every request, the
//! filter binds the chain once at construction time through a
//! [`ChainBindingContext`] and stores the resulting pipeline.
//!
//! The context is handed to the filter's factory by the pipeline builder. It
//! exposes exactly one operation, [`ChainBindingContext::bind_chain`], which
//! resolves a [`ChainRef`] into a [`FilterPipeline`]:
//!
//! - **Named** references resolve against the top-level `filter_chains`, so outbound chains can be shared and reused.
//! - **Inline** references embed their filters directly.
//!
//! Nested filters resolve through the *active* [`FilterRegistry`], so
//! application-registered filters are available inside outbound chains.
//! Reference cycles and excessive nesting are rejected during construction —
//! before the pipeline is activated — so an invalid outbound chain fails the
//! build (and any hot reload) instead of the request.
//!
//! [`ChainRef`]: praxis_core::config::ChainRef

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    sync::Arc,
};

use praxis_core::config::{
    ChainRef, FilterEntry, InsecureOptions, validate_chain_entries_branch_chains, validate_chain_entries_cardinality,
    validate_chain_entries_conditions, validate_chain_entries_inline_clusters,
};

use crate::{FilterError, filter::HttpFilter, pipeline::FilterPipeline, registry::FilterRegistry};

/// Maximum nesting depth permitted when resolving outbound chain references.
///
/// Bounds inline-chain recursion (which carries no name for the cycle
/// detector to catch) and caps how deep one outbound chain may pull in
/// further outbound chains before the build is rejected.
pub(crate) const MAX_OUTBOUND_CHAIN_DEPTH: usize = 10;

/// Factory for an application filter that binds an outbound chain at
/// construction time.
///
/// Registered via [`FilterRegistry::register_chain_binding`]. The factory
/// receives the filter's configuration and a [`ChainBindingContext`] through
/// which it resolves its configured outbound chain into a prebuilt
/// [`FilterPipeline`]. It is an [`Arc`]'d closure so callers can capture
/// application state (clients, credentials providers) at registration time.
///
/// [`FilterRegistry::register_chain_binding`]: crate::FilterRegistry::register_chain_binding
pub type ChainBindingHttpFactory =
    Arc<dyn Fn(&serde_yaml::Value, &ChainBindingContext<'_>) -> Result<Box<dyn HttpFilter>, FilterError> + Send + Sync>;

// -----------------------------------------------------------------------------
// ResolutionStack
// -----------------------------------------------------------------------------

/// Tracks the named chains currently being resolved so reference cycles are
/// rejected during construction instead of recursing until a depth or
/// instance limit trips.
///
/// The stack is shared across the whole pipeline build (branch resolution and
/// outbound binding alike) via a shared reference. [`bind_chain`] takes `&self`
/// so the public API stays ergonomic, so mutation goes through interior
/// mutability rather than a `&mut` in any public signature.
///
/// [`bind_chain`]: ChainBindingContext::bind_chain
pub(crate) struct ResolutionStack {
    /// Names currently being resolved, innermost last.
    active: RefCell<Vec<Box<str>>>,
}

impl ResolutionStack {
    /// Create an empty resolution stack.
    pub(crate) fn new() -> Self {
        Self {
            active: RefCell::new(Vec::new()),
        }
    }

    /// Push `name` onto the stack, returning a guard that pops it on drop.
    ///
    /// Returns an error naming the cycle if `name` is already being resolved.
    pub(crate) fn enter(&self, name: &str) -> Result<ResolutionGuard<'_>, FilterError> {
        let mut active = self.active.borrow_mut();
        if let Some(start) = active.iter().position(|n| n.as_ref() == name) {
            let mut path: Vec<&str> = active.iter().skip(start).map(Box::as_ref).collect();
            path.push(name);
            return Err(format!("chain reference cycle detected: {}", path.join(" -> ")).into());
        }
        active.push(Box::from(name));
        Ok(ResolutionGuard { stack: self })
    }
}

/// Pops the most recently entered chain name when dropped, keeping the
/// resolution stack balanced across early returns and panics.
pub(crate) struct ResolutionGuard<'a> {
    /// The stack to pop on drop.
    stack: &'a ResolutionStack,
}

impl Drop for ResolutionGuard<'_> {
    fn drop(&mut self) {
        self.stack.active.borrow_mut().pop();
    }
}

// -----------------------------------------------------------------------------
// ChainBindingContext
// -----------------------------------------------------------------------------

/// Construction-time handle a chain-binding filter uses to resolve its
/// configured outbound chain into a prebuilt [`FilterPipeline`].
///
/// The context is created by the pipeline builder and lives only for the
/// duration of one filter's construction. It carries the active
/// [`FilterRegistry`] (so nested filters resolve against the same registry,
/// including application-registered filters), the top-level named-chain lookup
/// table, the shared cycle-detection stack, and the current nesting depth.
pub struct ChainBindingContext<'a> {
    /// Active registry, used to instantiate nested filters.
    registry: &'a FilterRegistry,

    /// Top-level named-chain lookup table.
    chains: &'a HashMap<&'a str, &'a [FilterEntry]>,

    /// Shared cycle-detection stack.
    stack: &'a ResolutionStack,

    /// Current *outbound* nesting depth: how many outbound bindings deep this
    /// context sits. Bounded by [`MAX_OUTBOUND_CHAIN_DEPTH`] and tracked
    /// independently of branch nesting — a chain-binding filter reached at any
    /// branch depth still binds at outbound depth zero.
    outbound_depth: usize,

    /// Operator's declared insecure posture, threaded so inline outbound
    /// chains are gated by the same SSRF/TLS-verify rules as top-level chains.
    insecure: &'a InsecureOptions,

    /// Build-wide count of filter instances materialized so far, shared across
    /// branch resolution and outbound binding alike. Binding an outbound chain
    /// forwards this counter rather than resetting it, so a fan-out split across
    /// binding boundaries is still bounded by one ceiling.
    budget: &'a Cell<usize>,

    /// Build-wide count of branch *definitions* seen so far, checked against the
    /// core total-branch ceiling. Distinct from `budget` (materialized instances):
    /// binding an *inline* outbound chain accumulates its branch definitions into
    /// this counter rather than resetting it, so several inline bindings cannot
    /// each stay under the ceiling while exceeding it collectively. The counter is
    /// seeded configuration-wide — every named chain plus the listener's own
    /// branches — so a named outbound chain the listener never references (which
    /// still materializes when bound) is already in the baseline that inline
    /// bindings accumulate on top of. Named outbound chains are top-level
    /// `filter_chains` the whole-config pass already counted config-wide, so they
    /// are validated but not re-accumulated here.
    branch_budget: &'a Cell<usize>,
}

impl<'a> ChainBindingContext<'a> {
    /// Create a context for resolving outbound chains at `outbound_depth`.
    #[expect(
        clippy::too_many_arguments,
        reason = "bundles the build-time resources outbound binding threads through"
    )]
    pub(crate) fn new(
        registry: &'a FilterRegistry,
        chains: &'a HashMap<&'a str, &'a [FilterEntry]>,
        stack: &'a ResolutionStack,
        outbound_depth: usize,
        insecure: &'a InsecureOptions,
        budget: &'a Cell<usize>,
        branch_budget: &'a Cell<usize>,
    ) -> Self {
        Self {
            registry,
            chains,
            stack,
            outbound_depth,
            insecure,
            budget,
            branch_budget,
        }
    }

    /// The active registry, used by the builder to instantiate filters.
    pub(crate) fn registry(&self) -> &'a FilterRegistry {
        self.registry
    }

    /// Resolve a chain reference into a prebuilt outbound [`FilterPipeline`].
    ///
    /// Named references resolve against the top-level `filter_chains`; inline
    /// references embed their filters directly. Nested filters resolve through
    /// the active registry, so application-registered filters are available.
    /// Reference cycles and excessive nesting are rejected here, before the
    /// pipeline is activated.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the reference is unknown, forms a cycle,
    /// exceeds the maximum nesting depth, or any nested filter fails to build.
    pub fn bind_chain(&self, chain_ref: &ChainRef) -> Result<FilterPipeline, FilterError> {
        if self.outbound_depth >= MAX_OUTBOUND_CHAIN_DEPTH {
            return Err(format!("outbound chain nesting depth exceeds maximum ({MAX_OUTBOUND_CHAIN_DEPTH})").into());
        }
        let (name, mut entries) = self.resolve_ref(chain_ref)?;
        // Named references participate in cycle detection; the guard pops the
        // name when this resolution returns. Inline references carry no name to
        // key on and are bounded by depth alone.
        let _guard = name.map(|n| self.stack.enter(n)).transpose()?;
        self.validate_bound_entries(name, &entries)?;
        // The bound pipeline is independent, so filter IDs restart at zero and
        // its branch nesting restarts at zero too — outbound binding is a fresh
        // pipeline boundary, not a continuation of the parent's branch depth.
        // Only the *outbound* depth advances (so runaway nested bindings are
        // still bounded), and the materialization budget is the parent build's,
        // forwarded so the whole build stays under one ceiling.
        let mut next_filter_id: usize = 0;
        let filters = crate::pipeline::build_branch::resolve_chain_filters_with_stack(
            &mut entries,
            self.registry,
            self.chains,
            0,
            &mut next_filter_id,
            self.insecure,
            self.stack,
            self.budget,
            self.branch_budget,
            self.outbound_depth + 1,
        )?;
        let pipeline = FilterPipeline::from_filters(filters);
        Self::reject_non_http_filters(&pipeline, name)?;
        Self::reject_terminal_filters(&pipeline, name)?;
        // A bound outbound chain is a real pipeline, so hold it to the same
        // structural ordering validation top-level chains face — a
        // `load_balancer` with no cluster selector, a misplaced terminal filter,
        // etc. would otherwise 502 at request time instead of failing the build.
        self.enforce_bound_ordering(&pipeline, &entries, name.unwrap_or("<inline>"))?;
        Ok(pipeline)
    }

    /// Apply the config-level gates a bound chain's entries would otherwise
    /// bypass by never appearing in `Config::filter_chains`.
    ///
    /// Runs the same per-chain filter cardinality cap, empty-predicate condition
    /// validation, inline-cluster SSRF/TLS gating, and branch-chain constraint
    /// checks (the re-entrant `max_iterations` ceiling, nesting depth, name
    /// uniqueness, chain-reference resolution, and the total-branch ceiling) the
    /// whole-config validation applies to top-level chains.
    ///
    /// Terminal-filter rejection happens after the pipeline is built, in
    /// [`reject_terminal_filters`], so it can scan branch sub-chains too.
    ///
    /// [`reject_terminal_filters`]: Self::reject_terminal_filters
    fn validate_bound_entries(&self, name: Option<&str>, entries: &[FilterEntry]) -> Result<(), FilterError> {
        let label = name.unwrap_or("<inline>");
        // A bound chain never appears in `Config::filter_chains`, so the
        // per-chain filter cap and empty-`when`/`unless` predicate validation the
        // whole-config walk applies never reach it — enforce both here.
        validate_chain_entries_cardinality(label, entries).map_err(|e| FilterError::from(e.to_string()))?;
        validate_chain_entries_conditions(label, entries).map_err(|e| FilterError::from(e.to_string()))?;
        // Inline clusters reachable only through this outbound chain never appear
        // in `Config::filter_chains`, so gate them with the operator's declared
        // posture — the same SSRF/insecure-TLS rules top-level clusters face.
        validate_chain_entries_inline_clusters(label, entries, self.insecure)
            .map_err(|e| FilterError::from(e.to_string()))?;
        // Enforce the core branch constraints here too. `Named` branch refs
        // resolve against the same top-level chains the runtime builder sees.
        //
        // The total-branch ceiling bounds branch definitions across the whole
        // build. Only *inline* outbound chains need to accumulate into the shared
        // budget: they never appear in `Config::filter_chains`, so the whole-config
        // `validate_branch_chains` pass never counts them, and several inline
        // bindings could otherwise each stay under the ceiling while exceeding it
        // collectively. A *named* outbound chain is a top-level `filter_chain`,
        // so that pass already counted its branches once toward the config-wide
        // ceiling; re-counting them per binding would falsely reject the
        // documented shared/reused named-chain pattern. Named chains are therefore
        // validated standalone (against a zero baseline, always satisfied since the
        // config-wide total is already <= the ceiling) without touching the budget.
        let known_chains: std::collections::HashSet<&str> = self.chains.keys().copied().collect();
        if name.is_none() {
            let prior = self.branch_budget.get();
            let total = validate_chain_entries_branch_chains(label, entries, &known_chains, prior)
                .map_err(|e| FilterError::from(e.to_string()))?;
            self.branch_budget.set(total);
        } else {
            validate_chain_entries_branch_chains(label, entries, &known_chains, 0)
                .map_err(|e| FilterError::from(e.to_string()))?;
        }
        Ok(())
    }

    /// Reject a bound pipeline that holds a filter below the HTTP layer.
    ///
    /// A filtered sub-request runs only the HTTP request phase, so a TCP-level
    /// filter builds without error but the executor never invokes it — the
    /// config silently behaves unlike what the operator wrote.
    fn reject_non_http_filters(pipeline: &FilterPipeline, name: Option<&str>) -> Result<(), FilterError> {
        let tcp_filters = pipeline.non_http_filters();
        if !tcp_filters.is_empty() {
            return Err(format!(
                "outbound chain '{}' contains TCP-level filter(s) [{}] that an HTTP filtered \
                 sub-request cannot run",
                name.unwrap_or("<inline>"),
                tcp_filters.join(", ")
            )
            .into());
        }
        Ok(())
    }

    /// Reject a bound pipeline that holds a terminal filter, at any depth.
    ///
    /// A terminal filter short-circuits the request phase with a response and no
    /// upstream. The filtered sub-request executor forwards to a resolved
    /// upstream and never surfaces such a response — it drops the terminal action
    /// and then errors that no upstream resolved — so reject terminal filters
    /// regardless of position (unlike a top-level chain, where a terminal filter
    /// is valid as the last entry). Scans branch sub-chains too, so one buried in
    /// a branch is caught at build time rather than activating at runtime.
    fn reject_terminal_filters(pipeline: &FilterPipeline, name: Option<&str>) -> Result<(), FilterError> {
        let terminal = pipeline.terminal_filters();
        if !terminal.is_empty() {
            return Err(format!(
                "outbound chain '{}' contains terminal filter(s) [{}] that an HTTP filtered \
                 sub-request cannot run (it forwards to a resolved upstream and cannot surface a \
                 terminal response)",
                name.unwrap_or("<inline>"),
                terminal.join(", ")
            )
            .into());
        }
        Ok(())
    }

    /// Resolve a [`ChainRef`] into its optional cycle-detection name and an
    /// owned copy of its filter entries.
    ///
    /// Named references are looked up in the top-level `filter_chains`; inline
    /// references carry their filters directly and have no name to key cycle
    /// detection on.
    fn resolve_ref<'r>(&self, chain_ref: &'r ChainRef) -> Result<(Option<&'r str>, Vec<FilterEntry>), FilterError> {
        match chain_ref {
            ChainRef::Named(name) => {
                let entries = self
                    .chains
                    .get(name.as_str())
                    .ok_or_else(|| FilterError::from(format!("outbound chain references unknown chain '{name}'")))?
                    .to_vec();
                Ok((Some(name.as_str()), entries))
            },
            ChainRef::Inline { filters, .. } => Ok((None, filters.clone())),
        }
    }

    /// Apply top-level structural ordering validation to a bound pipeline.
    ///
    /// Honors the operator's declared skip posture the same way the server's
    /// `validate_pipeline` does: downgrade to warnings under
    /// `skip_pipeline_validation`, otherwise reject the build.
    fn enforce_bound_ordering(
        &self,
        pipeline: &FilterPipeline,
        entries: &[FilterEntry],
        chain_label: &str,
    ) -> Result<(), FilterError> {
        let errors = pipeline.ordering_errors(
            entries,
            self.insecure.allow_open_security_filters,
            &self.insecure.skip_pipeline_checks,
        );
        if self.insecure.skip_pipeline_validation {
            for msg in &errors {
                tracing::warn!(outbound_chain = chain_label, "{msg}");
            }
        } else if !errors.is_empty() {
            return Err(format!(
                "outbound chain '{chain_label}' failed pipeline validation: {}",
                errors.join("; ")
            )
            .into());
        }
        Ok(())
    }
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
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use async_trait::async_trait;
    use praxis_core::config::{BranchChainConfig, FailureMode, MAX_BRANCH_DEPTH, SkipPipelineChecks};

    use super::*;
    use crate::{FilterAction, FilterFactory, HttpFilterContext};

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    // A no-op filter standing in for an application callout.
    struct ProbeFilter;

    #[async_trait]
    impl HttpFilter for ProbeFilter {
        fn name(&self) -> &'static str {
            "test_callout"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    // Register a chain-binding callout filter that resolves the `outbound_chain`
    // key of its config and records the number of filters it bound into `sink`.
    fn register_probe(registry: &mut FilterRegistry, sink: Arc<Mutex<Option<usize>>>) {
        registry
            .register_chain_binding(
                "test_callout",
                Arc::new(move |config: &serde_yaml::Value, ctx: &ChainBindingContext<'_>| {
                    let raw = config
                        .get("outbound_chain")
                        .cloned()
                        .ok_or_else(|| FilterError::from("missing outbound_chain"))?;
                    let chain_ref: ChainRef = serde_yaml::from_value(raw)
                        .map_err(|e| FilterError::from(format!("bad outbound_chain: {e}")))?;
                    let pipeline = ctx.bind_chain(&chain_ref)?;
                    *sink.lock().expect("sink lock") = Some(pipeline.len());
                    let filter: Box<dyn HttpFilter> = Box::new(ProbeFilter);
                    Ok(filter)
                }),
            )
            .expect("register chain binding");
    }

    // Parse a `Vec<FilterEntry>` from YAML.
    fn entries(yaml: &str) -> Vec<FilterEntry> {
        serde_yaml::from_str(yaml).expect("parse entries")
    }

    // A minimal filter entry with no branches or config.
    fn make_entry(filter_type: &str) -> FilterEntry {
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            failure_mode: FailureMode::default(),
            filter_type: filter_type.to_owned(),
            name: None,
            response_conditions: vec![],
        }
    }

    // A one-filter chain whose branch fans out over `refs` named references to
    // `target`. Nesting these multiplies the materialized instance count,
    // mirroring the expansion the instance ceiling guards against.
    fn fanout_chain(target: &str, refs: usize, branch: &str) -> Vec<FilterEntry> {
        vec![FilterEntry {
            branch_chains: Some(vec![BranchChainConfig {
                chains: std::iter::repeat_with(|| ChainRef::Named(target.to_owned()))
                    .take(refs)
                    .collect(),
                max_iterations: None,
                name: branch.to_owned(),
                on_result: None,
                rejoin: "next".to_owned(),
            }]),
            ..make_entry("request_id")
        }]
    }

    // A reference chain-binding callout that owns a prebuilt outbound pipeline.
    //
    // This is the pattern an application callout (for example an AI provider
    // filter) follows: bind the outbound chain once at construction, hold it as
    // an `Arc<FilterPipeline>`, and delegate the framework's nesting hooks so the
    // bound pipeline participates in runtime-resource propagation, hot-reload
    // file discovery, and insecure-option application.
    struct OutboundCallout {
        outbound: Arc<FilterPipeline>,
    }

    #[async_trait]
    impl HttpFilter for OutboundCallout {
        fn name(&self) -> &'static str {
            "outbound_callout"
        }

        fn visit_nested_pipelines(&mut self, visitor: &mut dyn FnMut(&mut FilterPipeline)) {
            if let Some(pipeline) = Arc::get_mut(&mut self.outbound) {
                visitor(pipeline);
            } else {
                debug_assert!(false, "outbound pipeline must be uniquely owned during configuration");
            }
        }

        fn referenced_files(&self) -> Vec<std::path::PathBuf> {
            self.outbound.referenced_files()
        }

        fn apply_insecure_options(&self, options: &InsecureOptions) {
            self.outbound.apply_insecure_options(options);
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    // Register the reference callout, binding whatever `outbound_chain` resolves
    // to into a prebuilt pipeline owned by the returned filter.
    fn register_outbound_callout(registry: &mut FilterRegistry) {
        registry
            .register_chain_binding(
                "outbound_callout",
                Arc::new(|config: &serde_yaml::Value, ctx: &ChainBindingContext<'_>| {
                    let raw = config
                        .get("outbound_chain")
                        .cloned()
                        .ok_or_else(|| FilterError::from("missing outbound_chain"))?;
                    let chain_ref: ChainRef = serde_yaml::from_value(raw)
                        .map_err(|e| FilterError::from(format!("bad outbound_chain: {e}")))?;
                    let outbound = ctx.bind_chain(&chain_ref)?;
                    let filter: Box<dyn HttpFilter> = Box::new(OutboundCallout {
                        outbound: Arc::new(outbound),
                    });
                    Ok(filter)
                }),
            )
            .expect("register outbound_callout");
    }

    // A nested filter, placed inside an outbound chain, that declares a
    // referenced document so a test can prove the bound pipeline is reachable by
    // hot-reload file discovery.
    struct OutboundProbeFilter;

    #[async_trait]
    impl HttpFilter for OutboundProbeFilter {
        fn name(&self) -> &'static str {
            "outbound_probe"
        }

        fn referenced_files(&self) -> Vec<std::path::PathBuf> {
            vec![std::path::PathBuf::from("/etc/praxis/outbound-probe-doc.yaml")]
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    fn register_outbound_probe(registry: &mut FilterRegistry) {
        registry
            .register(
                "outbound_probe",
                FilterFactory::Http(Arc::new(|_| Ok(Box::new(OutboundProbeFilter)))),
            )
            .expect("register outbound_probe");
    }

    // A custom (non-builtin) filter that declares it can return a terminal
    // response and does so. Its name is not a hard-coded builtin terminal name,
    // so name-based detection would miss it; capability-based detection must
    // still reject it inside an outbound chain.
    struct CustomTerminalFilter;

    #[async_trait]
    impl HttpFilter for CustomTerminalFilter {
        fn name(&self) -> &'static str {
            "custom_terminal"
        }

        fn produces_terminal_response(&self) -> bool {
            true
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::TerminalResponse(Box::new(crate::TerminalResponse::new(
                200,
            ))))
        }
    }

    fn register_custom_terminal(registry: &mut FilterRegistry) {
        registry
            .register(
                "custom_terminal",
                FilterFactory::Http(Arc::new(|_| Ok(Box::new(CustomTerminalFilter)))),
            )
            .expect("register custom_terminal");
    }

    // A nested filter that records whether `apply_insecure_options` reached it.
    struct InsecureSinkFilter {
        applied: Arc<AtomicBool>,
    }

    #[async_trait]
    impl HttpFilter for InsecureSinkFilter {
        fn name(&self) -> &'static str {
            "insecure_sink"
        }

        fn apply_insecure_options(&self, _options: &InsecureOptions) {
            self.applied.store(true, Ordering::SeqCst);
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    fn register_insecure_sink(registry: &mut FilterRegistry, applied: Arc<AtomicBool>) {
        registry
            .register(
                "insecure_sink",
                FilterFactory::Http(Arc::new(move |_| {
                    let filter: Box<dyn HttpFilter> = Box::new(InsecureSinkFilter {
                        applied: Arc::clone(&applied),
                    });
                    Ok(filter)
                })),
            )
            .expect("register insecure_sink");
    }

    #[test]
    fn binds_inline_outbound_chain() {
        let sink = Arc::new(Mutex::new(None));
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::clone(&sink));

        let mut top = entries(
            "
- filter: test_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
      - filter: headers
",
        );
        let chains = HashMap::new();
        FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("build pipeline");

        assert_eq!(
            *sink.lock().expect("sink lock"),
            Some(2),
            "callout should bind the 2-filter inline outbound chain"
        );
    }

    #[test]
    fn binds_named_outbound_chain() {
        let sink = Arc::new(Mutex::new(None));
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::clone(&sink));

        let outbound = entries("- filter: request_id\n- filter: headers\n- filter: compression\n");
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("outbound", outbound.as_slice())]);
        let mut top = entries("- filter: test_callout\n  outbound_chain: outbound\n");
        FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("build pipeline");

        assert_eq!(
            *sink.lock().expect("sink lock"),
            Some(3),
            "callout should resolve the named outbound chain against filter_chains"
        );
    }

    #[test]
    fn unknown_named_outbound_chain_errors() {
        let sink = Arc::new(Mutex::new(None));
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::clone(&sink));

        let chains = HashMap::new();
        let mut top = entries("- filter: test_callout\n  outbound_chain: missing\n");
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("unknown chain") && err.to_string().contains("missing"),
            "an outbound reference to an undefined chain must fail the build: {err}"
        );
    }

    #[test]
    fn direct_cycle_rejected() {
        let sink = Arc::new(Mutex::new(None));
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::clone(&sink));

        let a = entries("- filter: test_callout\n  outbound_chain: a\n");
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("a", a.as_slice())]);
        let mut top = entries("- filter: test_callout\n  outbound_chain: a\n");
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("cycle") && err.to_string().contains("a -> a"),
            "a chain that binds itself must be rejected as a cycle, not a depth error: {err}"
        );
    }

    #[test]
    fn indirect_cycle_rejected() {
        let sink = Arc::new(Mutex::new(None));
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::clone(&sink));

        let a = entries("- filter: test_callout\n  outbound_chain: b\n");
        let b = entries("- filter: test_callout\n  outbound_chain: a\n");
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("a", a.as_slice()), ("b", b.as_slice())]);
        let mut top = entries("- filter: test_callout\n  outbound_chain: a\n");
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("cycle") && err.to_string().contains("a -> b -> a"),
            "an a -> b -> a cycle across outbound chains must be reported as a cycle: {err}"
        );
    }

    #[test]
    fn excessive_nesting_rejected() {
        let sink = Arc::new(Mutex::new(None));
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::clone(&sink));

        // A non-cyclic line c0 -> c1 -> ... -> c10 exceeds the nesting cap;
        // no name repeats, so cycle detection does not fire and the depth
        // limit is what must reject the build.
        let names: Vec<String> = (0..=MAX_OUTBOUND_CHAIN_DEPTH).map(|i| format!("c{i}")).collect();
        let owned: Vec<Vec<FilterEntry>> = (0..=MAX_OUTBOUND_CHAIN_DEPTH)
            .map(|i| entries(&format!("- filter: test_callout\n  outbound_chain: c{}\n", i + 1)))
            .collect();
        let chains: HashMap<&str, &[FilterEntry]> = names
            .iter()
            .zip(owned.iter())
            .map(|(name, e)| (name.as_str(), e.as_slice()))
            .collect();
        let mut top = entries("- filter: test_callout\n  outbound_chain: c0\n");
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("nesting depth"),
            "an outbound chain nested past the maximum depth must be rejected: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Inline-cluster safety gating (issue #1074, F1)
    // -------------------------------------------------------------------------

    #[test]
    fn inline_outbound_chain_ssrf_endpoint_rejected() {
        // An inline cluster reachable only through an outbound chain must be
        // gated by the same SSRF rules as a top-level `clusters:` list. With the
        // strict default posture, an endpoint resolving to a loopback address
        // must fail the build instead of silently bypassing the check.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: load_balancer
        clusters:
          - name: web
            endpoints:
              - address: \"127.0.0.1:80\"
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("sensitive address"),
            "an inline outbound-chain endpoint resolving to a sensitive address must be rejected \
             unless insecure_options.allow_private_endpoints is set: {err}"
        );
    }

    #[test]
    fn inline_outbound_chain_ssrf_endpoint_allowed_with_flag() {
        // The same chain must build when the operator opts in to private
        // endpoints, proving the gate is threaded from the declared posture and
        // not an unconditional rejection.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: load_balancer
        clusters:
          - name: web
            endpoints:
              - address: \"127.0.0.1:80\"
",
        );
        let chains = HashMap::new();
        // Opt in to the private endpoint (the concern under test) and skip the
        // unrelated lb-without-router ordering check so a lone load_balancer —
        // the minimal cluster-bearing chain — does not fail for a reason other
        // than SSRF gating.
        let insecure = InsecureOptions {
            allow_private_endpoints: true,
            skip_pipeline_checks: SkipPipelineChecks {
                lb_without_router: true,
                ..SkipPipelineChecks::default()
            },
            ..InsecureOptions::default()
        };
        FilterPipeline::build_with_chains(&mut top, &registry, &chains, &insecure)
            .expect("outbound chain with an opted-in private endpoint must build");
    }

    // -------------------------------------------------------------------------
    // Materialization budget across binding boundaries (issue #1074, F2)
    // -------------------------------------------------------------------------

    #[test]
    fn outbound_binding_does_not_reset_materialization_budget() {
        // Each outbound chain fans out to ~59k filter instances — comfortably
        // under the 100k ceiling on its own. Binding two of them in one build
        // materializes ~118k total. If binding reset the budget, a config could
        // split an unbounded fan-out across binding boundaries and evade the
        // ceiling entirely, so the budget must be shared across the whole build.
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::new(Mutex::new(None)));

        let leaf = vec![make_entry("request_id")];
        let c1 = fanout_chain("leaf", 20, "b1");
        let c2 = fanout_chain("c1", 20, "b2");
        let c3 = fanout_chain("c2", 20, "b3");
        let outbound = fanout_chain("c3", 7, "b_out"); // 1 + 7*8421 = 58_948 instances
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([
            ("leaf", leaf.as_slice()),
            ("c1", c1.as_slice()),
            ("c2", c2.as_slice()),
            ("c3", c3.as_slice()),
            ("outbound", outbound.as_slice()),
        ]);

        let mut top = entries(
            "
- filter: test_callout
  outbound_chain: outbound
- filter: test_callout
  outbound_chain: outbound
",
        );
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("two ~59k outbound bindings must exceed the shared 100k budget");

        assert!(
            err.to_string().contains("filter instances"),
            "binding an outbound chain must not reset the materialization budget: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Total-branch budget across binding boundaries (issue #1074)
    //
    // `MAX_TOTAL_BRANCHES` bounds config complexity across the whole build, not
    // each chain in isolation. Bound outbound chains never appear in
    // `Config::filter_chains`, so the whole-config `validate_branch_chains` pass
    // never counts their branches. If each binding counted its branches from a
    // fresh zero, several bindings could each stay under the ceiling while
    // exceeding it collectively — and the branches already present in the
    // listener config would go uncounted. The budget must accumulate across the
    // whole build.
    // -------------------------------------------------------------------------

    // Build the YAML for an outbound-binding callout whose inline outbound chain
    // defines `branches` branch chains, packed at the per-filter cap of 16, each
    // resolving against the known named chain `utility` so only the branch name
    // (not an inline sub-chain name) counts toward the total-branch ceiling.
    fn outbound_callout_with_branches(branches: usize) -> String {
        use std::fmt::Write as _;
        let mut s = String::from("- filter: outbound_callout\n  outbound_chain:\n    name: outbound\n    filters:\n");
        let mut emitted = 0;
        while emitted < branches {
            s.push_str("      - filter: request_id\n        branch_chains:\n");
            for _ in 0..16 {
                if emitted >= branches {
                    break;
                }
                writeln!(s, "          - name: br_{emitted}\n            chains: [utility]").unwrap();
                emitted += 1;
            }
        }
        s
    }

    #[test]
    fn outbound_bindings_share_total_branch_budget() {
        // Two outbound bindings, each defining 144 branch chains — comfortably
        // under the 256 ceiling on its own, but 288 together. If binding reset
        // the branch count, a config could split an unbounded branch count across
        // binding boundaries and evade the ceiling entirely, so the total must be
        // shared across the whole build.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let utility = entries("- filter: headers\n");
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("utility", utility.as_slice())]);

        let top_yaml = format!(
            "{}{}",
            outbound_callout_with_branches(144),
            outbound_callout_with_branches(144)
        );
        let mut top = entries(&top_yaml);
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("two 144-branch outbound bindings must exceed the shared 256-branch ceiling");

        assert!(
            err.to_string().contains("total branch count") && err.to_string().contains("256"),
            "binding an outbound chain must not reset the total-branch budget: {err}"
        );
    }

    #[test]
    fn outbound_binding_branch_budget_counts_listener_branches() {
        // The listener pipeline already defines 144 branch chains at its top
        // level, and a single outbound binding adds 144 more. Neither exceeds the
        // ceiling alone, but 288 together must. The bound chain's budget must be
        // seeded with the branches already present in the listener config, not
        // start from zero.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let utility = entries("- filter: headers\n");
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("utility", utility.as_slice())]);

        // 144 branch chains at the listener top level (9 filters x 16 branches).
        let mut listener_branches = {
            use std::fmt::Write as _;
            let mut s = String::new();
            let mut emitted = 0;
            while emitted < 144 {
                s.push_str("- filter: request_id\n  branch_chains:\n");
                for _ in 0..16 {
                    if emitted >= 144 {
                        break;
                    }
                    writeln!(s, "    - name: top_br_{emitted}\n      chains: [utility]").unwrap();
                    emitted += 1;
                }
            }
            s
        };
        // One outbound binding that adds another 144 branch chains.
        listener_branches.push_str(&outbound_callout_with_branches(144));

        let mut top = entries(&listener_branches);
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("listener branches plus a bound chain's branches must exceed the shared ceiling");

        assert!(
            err.to_string().contains("total branch count") && err.to_string().contains("256"),
            "the bound chain's branch budget must count the listener's existing branches: {err}"
        );
    }

    // Build top-level filter entries defining `count` branch chains (packed at
    // the 16-per-filter cap), each resolving to the known named chain `utility`
    // so only the branch name — not an inline sub-chain name — counts toward the
    // total-branch ceiling. `prefix` keeps branch names unique within the chain.
    fn filters_with_branches(count: usize, prefix: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let mut emitted = 0;
        while emitted < count {
            s.push_str("- filter: request_id\n  branch_chains:\n");
            for _ in 0..16 {
                if emitted >= count {
                    break;
                }
                writeln!(s, "    - name: {prefix}_{emitted}\n      chains: [utility]").unwrap();
                emitted += 1;
            }
        }
        s
    }

    #[test]
    fn reused_named_outbound_chain_counts_branches_once() {
        // A named outbound chain is a top-level `filter_chain`, already counted
        // (and capped at 256) config-wide by `validate_branch_chains`. Binding it
        // from several callouts must not re-count its branches per binding — that
        // would falsely reject the documented shared/reused named-outbound-chain
        // pattern for a config the whole-config pass accepts. Only inline
        // outbound chains, which never appear in `Config::filter_chains`, escape
        // that pass and so must accumulate into the shared budget.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let utility = entries("- filter: headers\n");
        // A named `outbound` chain defining 130 branch chains: under the 256
        // ceiling on its own, but 260 if wrongly counted once per binding.
        let outbound_yaml = filters_with_branches(130, "nb");
        let outbound = entries(&outbound_yaml);
        let chains: HashMap<&str, &[FilterEntry]> =
            HashMap::from([("utility", utility.as_slice()), ("outbound", outbound.as_slice())]);

        // Two callouts, each binding the SAME named chain by reference (a bare
        // string resolves to ChainRef::Named).
        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain: outbound
- filter: outbound_callout
  outbound_chain: outbound
",
        );
        FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("a shared named outbound chain's branches must be counted once, not per binding");
    }

    #[test]
    fn outbound_named_and_inline_branches_share_config_wide_budget() {
        // The total-branch ceiling is configuration-wide, not per listener. A
        // named outbound chain the listener never references still materializes
        // when bound, and the whole-config `validate_branch_chains` pass counts it
        // toward the ceiling. Seeding the build budget with only the listener's
        // own branches would let a bound named chain (200) and an inline outbound
        // chain (100) each stay under the ceiling while 300 branch definitions
        // materialize in one build — twice the ceiling's intent. The seed must
        // span the whole configuration so the two pools cannot be additive.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let utility = entries("- filter: headers\n");
        // A named chain with 200 branch chains that the listener does not list in
        // its `filter_chains`, so a listener-scoped seed would not count it.
        let named_yaml = filters_with_branches(200, "nb");
        let named = entries(&named_yaml);
        let chains: HashMap<&str, &[FilterEntry]> =
            HashMap::from([("utility", utility.as_slice()), ("named_ob", named.as_slice())]);

        // One callout binds the named 200-branch chain by reference; a second
        // binds an inline chain of 100 branches. 300 branch definitions
        // materialize in one build.
        let top_yaml = format!(
            "- filter: outbound_callout\n  outbound_chain: named_ob\n{}",
            outbound_callout_with_branches(100)
        );
        let mut top = entries(&top_yaml);
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("a bound named chain (200) plus an inline chain (100) must exceed the config-wide 256 ceiling");

        assert!(
            err.to_string().contains("total branch count") && err.to_string().contains("256"),
            "the branch budget must span the whole configuration, not just the listener's own branches: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Outbound-depth vs branch-depth decoupling (issue #1074, F5)
    // -------------------------------------------------------------------------

    #[test]
    fn outbound_binding_branch_depth_starts_fresh() {
        // A bound outbound pipeline is an independent pipeline: its branch
        // nesting restarts at zero rather than continuing the parent's. An
        // outbound chain whose internal branches nest to the maximum branch
        // depth must therefore build. If binding leaked the parent's depth into
        // the bound pipeline (one counter conflating branch and outbound
        // nesting), the same chain would spuriously trip the branch-depth
        // ceiling one level early.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        // outbound(0) -> d1(1) -> ... -> d{n}(n) -> leaf(n+1); with the fix the
        // deepest resolve lands at exactly MAX_BRANCH_DEPTH and is accepted.
        let intermediate = MAX_BRANCH_DEPTH - 1;
        let leaf = vec![make_entry("request_id")];
        let owned: Vec<Vec<FilterEntry>> = (1..=intermediate)
            .map(|i| {
                let target = if i == intermediate {
                    "leaf".to_owned()
                } else {
                    format!("d{}", i + 1)
                };
                fanout_chain(&target, 1, &format!("b{i}"))
            })
            .collect();
        let names: Vec<String> = (1..=intermediate).map(|i| format!("d{i}")).collect();
        let outbound = fanout_chain("d1", 1, "b0");

        let mut chains: HashMap<&str, &[FilterEntry]> =
            HashMap::from([("leaf", leaf.as_slice()), ("outbound", outbound.as_slice())]);
        for (name, chain) in names.iter().zip(owned.iter()) {
            chains.insert(name.as_str(), chain.as_slice());
        }

        let mut top = entries("- filter: outbound_callout\n  outbound_chain: outbound\n");
        FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("an outbound chain nested to the maximum branch depth must build");
    }

    // -------------------------------------------------------------------------
    // Outbound-pipeline ordering validation (issue #1074, F3)
    // -------------------------------------------------------------------------

    #[test]
    fn outbound_chain_ordering_violation_rejected() {
        // A bound outbound chain is a real pipeline and must pass the same
        // structural ordering validation as a top-level chain. A load_balancer
        // with no preceding cluster selector would 502 at runtime, so it must
        // fail the build instead of binding silently. The endpoint uses a
        // non-sensitive TEST-NET address so the SSRF gate does not fire first
        // and mask the ordering error under test.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: load_balancer
        clusters:
          - name: web
            endpoints:
              - address: \"192.0.2.1:80\"
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("without a preceding router"),
            "an outbound chain whose load_balancer has no cluster selector must fail ordering \
             validation, not bind silently: {err}"
        );
    }

    #[test]
    fn outbound_chain_ordering_violation_downgraded_with_skip_flag() {
        // The same chain must build when the operator skips that ordering check,
        // proving the gate is threaded from the declared posture rather than an
        // unconditional rejection.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: load_balancer
        clusters:
          - name: web
            endpoints:
              - address: \"192.0.2.1:80\"
",
        );
        let chains = HashMap::new();
        let insecure = InsecureOptions {
            skip_pipeline_checks: SkipPipelineChecks {
                lb_without_router: true,
                ..SkipPipelineChecks::default()
            },
            ..InsecureOptions::default()
        };
        FilterPipeline::build_with_chains(&mut top, &registry, &chains, &insecure)
            .expect("outbound chain must build when the ordering check is skipped");
    }

    // -------------------------------------------------------------------------
    // Review remediation: branch-chain constraint enforcement
    //
    // Inline outbound chains never appear in `Config::filter_chains`, so the
    // whole-config `validate_branch_chains` pass never sees them. Their branch
    // chains must still face the same core constraints — notably the
    // `max_iterations <= 100` ceiling that bounds re-entrant request loops —
    // instead of bypassing them and permitting an extremely long loop.
    // -------------------------------------------------------------------------

    #[test]
    fn outbound_chain_branch_max_iterations_over_ceiling_rejected() {
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        // A branch that re-enters more than the ceiling permits must fail the
        // build; the runtime branch builder only requires `max_iterations` to be
        // present for backward rejoins and never enforces the ceiling, so
        // without a bind-time check this loop would activate unbounded.
        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
        branch_chains:
          - name: loop
            max_iterations: 101
            rejoin: next
            chains:
              - name: sub
                filters:
                  - filter: headers
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("max_iterations") && err.to_string().contains("101"),
            "an outbound-chain branch exceeding the max_iterations ceiling must be rejected at \
             build time, not activate an unbounded re-entrant loop: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Review remediation: protocol-level suitability of bound filters
    //
    // A filtered sub-request runs an HTTP pipeline. A TCP-level filter placed in
    // an outbound chain builds without error but the HTTP executor silently
    // skips it at runtime, so the invalid configuration activates and behaves
    // unlike what the operator wrote. Reject it at build time.
    // -------------------------------------------------------------------------

    #[test]
    fn outbound_chain_with_tcp_filter_rejected() {
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: tcp_access_log
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("tcp_access_log")
                && (err.to_string().contains("TCP") || err.to_string().contains("HTTP")),
            "a TCP-level filter in an HTTP outbound chain must be rejected at build time, not \
             silently skipped at runtime: {err}"
        );
    }

    #[test]
    fn outbound_chain_with_branch_nested_tcp_filter_rejected() {
        // The TCP-level filter is buried inside a branch sub-chain of the
        // outbound chain, not at its top level. The runtime executor skips it
        // just the same, so the build-time rejection must scan branch sub-chains
        // too — not only the top-level filter list.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
        branch_chains:
          - name: b1
            chains:
              - name: inner
                filters:
                  - filter: tcp_access_log
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("tcp_access_log")
                && (err.to_string().contains("TCP") || err.to_string().contains("HTTP")),
            "a TCP-level filter nested inside a branch of an HTTP outbound chain must be rejected at \
             build time, not silently skipped at runtime: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Review remediation: terminal filters rejected in outbound chains
    //
    // A terminal filter (e.g. `iterative_request_router`) can short-circuit the
    // request phase with a response and no upstream. The filtered sub-request
    // executor forwards to a resolved upstream and never surfaces that response,
    // so it drops the terminal action and then errors that no upstream resolved.
    // Reject terminal filters at build time instead.
    // -------------------------------------------------------------------------

    #[test]
    #[expect(clippy::too_many_lines, reason = "inline valid-IRR YAML fixture")]
    fn outbound_chain_with_terminal_filter_rejected() {
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        // A fully valid IRR (so nothing else fails the build first): one step
        // with a router + load_balancer over a non-sensitive TEST-NET endpoint.
        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: iterative_request_router
        initial_step: only
        max_iterations: 3
        steps:
          - name: only
            filters:
              - filter: router
                routes:
                  - path_prefix: \"/\"
                    cluster: svc
              - filter: load_balancer
                clusters:
                  - name: svc
                    endpoints:
                      - \"192.0.2.1:80\"
            on_result:
              - default: true
                done: true
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("terminal") && err.to_string().contains("iterative_request_router"),
            "a terminal filter in an outbound chain must be rejected at build time, not activate \
             and drop its terminal response at runtime: {err}"
        );
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "inline valid-IRR YAML fixture nested in a branch")]
    fn outbound_chain_with_branch_nested_terminal_filter_rejected() {
        // The terminal filter is buried inside a branch sub-chain of the outbound
        // chain, not at its top level. It activates and drops its terminal
        // response at runtime just the same, so the build-time rejection must
        // scan branch sub-chains too — not only the top-level entry list.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
        branch_chains:
          - name: b1
            chains:
              - name: inner
                filters:
                  - filter: iterative_request_router
                    initial_step: only
                    max_iterations: 3
                    steps:
                      - name: only
                        filters:
                          - filter: router
                            routes:
                              - path_prefix: \"/\"
                                cluster: svc
                          - filter: load_balancer
                            clusters:
                              - name: svc
                                endpoints:
                                  - \"192.0.2.1:80\"
                        on_result:
                          - default: true
                            done: true
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("terminal") && err.to_string().contains("iterative_request_router"),
            "a terminal filter nested inside a branch of an outbound chain must be rejected at build \
             time, not activate and drop its terminal response at runtime: {err}"
        );
    }

    #[test]
    fn outbound_chain_with_custom_terminal_filter_rejected() {
        // A *custom* filter — not the builtin `iterative_request_router` — that
        // declares it produces terminal responses. Name-based detection only
        // knows the hard-coded builtin terminal names, so it would let this
        // through; the executor would then drop its terminal action and error
        // that no upstream resolved. Capability-based detection must reject it at
        // build time.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);
        register_custom_terminal(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: custom_terminal
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("terminal") && err.to_string().contains("custom_terminal"),
            "a custom filter that declares it produces terminal responses must be rejected in an \
             outbound chain, not escape because its name is not a hard-coded builtin: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Review remediation: bound chains face the top-level per-chain filter cap
    // and empty-predicate condition validation
    //
    // A bound outbound chain never appears in `Config::filter_chains`, so the
    // whole-config `validate_filter_chains` walk never sees it. Without an
    // explicit bind-time check it would bypass the per-chain filter cardinality
    // limit and the `when`/`unless` empty-predicate validation top-level chains
    // face.
    // -------------------------------------------------------------------------

    #[test]
    fn outbound_chain_over_filter_limit_rejected() {
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        // 101 filters — one past the per-chain cap. A bound chain must face the
        // same limit, or a runaway outbound chain builds unbounded.
        let filters_yaml = "      - filter: request_id\n".repeat(101);
        let top_yaml =
            format!("- filter: outbound_callout\n  outbound_chain:\n    name: outbound\n    filters:\n{filters_yaml}");
        let mut top = entries(&top_yaml);
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("too many filters") && err.to_string().contains("101"),
            "an outbound chain exceeding the per-chain filter limit must be rejected at build time, \
             not build unbounded: {err}"
        );
    }

    #[test]
    fn outbound_chain_empty_condition_rejected() {
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        // An empty `unless` predicate matches every request, so it silently
        // disables the filter — almost always a config accident.
        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
        conditions:
          - unless: {}
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("condition 0 is empty"),
            "an outbound chain filter with an empty condition predicate must be rejected at build \
             time, the same as a top-level chain: {err}"
        );
    }

    #[test]
    fn outbound_chain_branch_nested_empty_condition_rejected() {
        // The empty predicate is buried inside a branch sub-chain of the outbound
        // chain, not at its top level. Condition validation must recurse into
        // branch sub-chains too, matching the top-level walk.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
        branch_chains:
          - name: b1
            chains:
              - name: inner
                filters:
                  - filter: headers
                    conditions:
                      - unless: {}
",
        );
        let chains = HashMap::new();
        let err = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .err()
            .expect("build should fail");

        assert!(
            err.to_string().contains("condition 0 is empty"),
            "an empty condition predicate nested inside a branch of an outbound chain must be \
             rejected at build time: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Reload / runtime-propagation contract (issue #1074, requirement 4)
    // -------------------------------------------------------------------------

    #[test]
    fn outbound_chain_surfaces_referenced_files_for_reload() {
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);
        register_outbound_probe(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: outbound_probe
",
        );
        let chains = HashMap::new();
        let parent = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("build pipeline");

        assert!(
            parent
                .referenced_files()
                .contains(&std::path::PathBuf::from("/etc/praxis/outbound-probe-doc.yaml")),
            "the rebuilt parent must surface documents referenced inside the bound outbound chain so \
             editing them triggers a hot reload"
        );
    }

    #[test]
    fn outbound_chain_surfaces_branch_nested_referenced_files_for_reload() {
        // The file-referencing filter is buried inside a branch sub-chain of the
        // outbound chain. Hot-reload file discovery must still surface its
        // document, or editing a document referenced only from a branch would not
        // trigger a reload.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);
        register_outbound_probe(&mut registry);

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
        branch_chains:
          - name: b1
            chains:
              - name: inner
                filters:
                  - filter: outbound_probe
",
        );
        let chains = HashMap::new();
        let parent = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("build pipeline");

        assert!(
            parent
                .referenced_files()
                .contains(&std::path::PathBuf::from("/etc/praxis/outbound-probe-doc.yaml")),
            "the rebuilt parent must surface documents referenced by filters nested inside a branch of \
             the bound outbound chain so editing them triggers a hot reload"
        );
    }

    #[test]
    fn outbound_pipeline_receives_and_retains_runtime_resources() {
        // A chain-binding filter owns its outbound pipeline; the framework reaches
        // it only through `visit_nested_pipelines`. Bind through the public API,
        // then drive the same propagation the parent pipeline's `set_*` methods
        // perform, and confirm the resource reaches — and persists on — the bound
        // pipeline.
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);

        let stack = ResolutionStack::new();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let insecure = InsecureOptions::default();
        let (budget, branch_budget) = (Cell::new(0), Cell::new(0));
        let ctx = ChainBindingContext::new(&registry, &chains, &stack, 0, &insecure, &budget, &branch_budget);
        let chain_ref = ChainRef::Inline {
            name: "outbound".to_owned(),
            filters: entries("- filter: request_id\n- filter: headers\n"),
        };
        let outbound = ctx.bind_chain(&chain_ref).expect("bind outbound chain");
        let mut callout = OutboundCallout {
            outbound: Arc::new(outbound),
        };

        assert!(
            !callout.outbound.records_filter_duration_metrics(),
            "the bound pipeline starts with metrics recording disabled"
        );

        callout.visit_nested_pipelines(&mut |pipeline| pipeline.set_record_filter_duration_metrics(true));

        assert!(
            callout.outbound.records_filter_duration_metrics(),
            "a runtime resource set on the parent must propagate into the bound outbound pipeline"
        );

        // Re-observe through a fresh visit to prove the value persisted on the
        // bound pipeline rather than being a transient during-visit view.
        let mut observed = false;
        callout.visit_nested_pipelines(&mut |pipeline| observed = pipeline.records_filter_duration_metrics());
        assert!(
            observed,
            "the propagated runtime resource must persist on the bound outbound pipeline"
        );
    }

    #[test]
    fn outbound_chain_receives_insecure_options() {
        let applied = Arc::new(AtomicBool::new(false));
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);
        register_insecure_sink(&mut registry, Arc::clone(&applied));

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: insecure_sink
",
        );
        let chains = HashMap::new();
        let parent = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("build pipeline");

        parent.apply_insecure_options(&InsecureOptions::default());

        assert!(
            applied.load(Ordering::SeqCst),
            "insecure options applied to the parent must reach filters inside the bound outbound chain"
        );
    }

    #[test]
    fn outbound_chain_applies_insecure_options_to_branch_nested_filters() {
        // The insecure-option-aware filter is buried inside a branch sub-chain of
        // the outbound chain. Insecure options applied to the parent must still
        // reach it, or a branch-contained filter would silently keep its secure
        // defaults while the operator believed the override applied everywhere.
        let applied = Arc::new(AtomicBool::new(false));
        let mut registry = FilterRegistry::with_builtins();
        register_outbound_callout(&mut registry);
        register_insecure_sink(&mut registry, Arc::clone(&applied));

        let mut top = entries(
            "
- filter: outbound_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
        branch_chains:
          - name: b1
            chains:
              - name: inner
                filters:
                  - filter: insecure_sink
",
        );
        let chains = HashMap::new();
        let parent = FilterPipeline::build_with_chains(&mut top, &registry, &chains, &InsecureOptions::default())
            .expect("build pipeline");

        parent.apply_insecure_options(&InsecureOptions::default());

        assert!(
            applied.load(Ordering::SeqCst),
            "insecure options applied to the parent must reach filters nested inside a branch of the \
             bound outbound chain"
        );
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "two-version reload with explicit YAML fixtures")]
    fn rebuilt_outbound_pipeline_reflects_config_change() {
        let sink = Arc::new(Mutex::new(None));
        let mut registry = FilterRegistry::with_builtins();
        register_probe(&mut registry, Arc::clone(&sink));
        let chains = HashMap::new();

        // v1: a 2-filter outbound chain.
        let mut v1 = entries(
            "
- filter: test_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
      - filter: headers
",
        );
        FilterPipeline::build_with_chains(&mut v1, &registry, &chains, &InsecureOptions::default()).expect("build v1");
        assert_eq!(
            *sink.lock().expect("sink lock"),
            Some(2),
            "v1 binds a 2-filter outbound chain"
        );

        // v2 (a reload): a 3-filter outbound chain must re-bind from the new config.
        let mut v2 = entries(
            "
- filter: test_callout
  outbound_chain:
    name: outbound
    filters:
      - filter: request_id
      - filter: headers
      - filter: compression
",
        );
        FilterPipeline::build_with_chains(&mut v2, &registry, &chains, &InsecureOptions::default()).expect("build v2");
        assert_eq!(
            *sink.lock().expect("sink lock"),
            Some(3),
            "rebuilding after a config change must re-bind the outbound chain from the new config"
        );
    }
}
