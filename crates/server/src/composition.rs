// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Data-only server composition for embedding Praxis.
//!
//! [`ServerComposition`] describes how a downstream binary customizes an
//! embedded Praxis server without reaching into its lifecycle. It is passed
//! to [`run_server_with_composition`] and carries three things:
//!
//! 1. **Registry construction** — how the filter [`FilterRegistry`] is built. The factory runs once at startup and
//!    receives a [`RegistryContext`] exposing the server-owned [`SubRequestClient`], the one runtime handle a
//!    downstream registry commonly needs while wiring its filters.
//! 2. **Pipeline-extension factories** — each produces a fresh [`PipelineExtension`] per listener pipeline. Factories
//!    receive an immutable [`ExtensionContext`] and must be synchronous and side-effect-free; they run again on every
//!    hot reload.
//! 3. **Read-only pipeline validators** — each inspects a built pipeline via a [`ValidatorContext`] and may reject it,
//!    but cannot mutate it.
//!
//! The composition never exposes mutable pipelines, watchers, listeners, or
//! publication handles: it is a description consumed by the server, not a hook
//! into a running one.
//!
//! [`run_server_with_composition`]: crate::run_server_with_composition
//! [`SubRequestClient`]: praxis_core::subrequest::SubRequestClient

use std::{fmt, sync::Arc};

use praxis_core::{
    config::{Config, FilterEntry, Listener},
    subrequest::SubRequestClient,
};
use praxis_filter::{FilterPipeline, FilterRegistry, PipelineExtension};

// -----------------------------------------------------------------------------
// Function Types
// -----------------------------------------------------------------------------

/// Builds the filter registry once at startup from immutable server context.
///
/// [`FnOnce`] because [`FilterRegistry`] is not `Clone`: the registry is
/// constructed a single time, wrapped in an `Arc`, and reused across reloads.
type RegistryFactory = Box<dyn FnOnce(&RegistryContext<'_>) -> Result<FilterRegistry, CompositionError>>;

/// Produces a fresh [`PipelineExtension`] for one listener pipeline.
///
/// `Send + Sync` because the factory is carried into the hot-reload watcher
/// thread and invoked again for each rebuilt pipeline.
type ExtensionFactory =
    Box<dyn Fn(&ExtensionContext<'_>) -> Result<Box<dyn PipelineExtension>, CompositionError> + Send + Sync>;

/// Validates a built pipeline read-only, rejecting it on error.
///
/// `Send + Sync` for the same reason as [`ExtensionFactory`].
type PipelineValidator = Box<dyn Fn(&ValidatorContext<'_>) -> Result<(), CompositionError> + Send + Sync>;

// -----------------------------------------------------------------------------
// CompositionError
// -----------------------------------------------------------------------------

/// Error returned by a registry factory, extension factory, or validator.
///
/// A factory or validator that returns this rejects pipeline construction, both
/// at startup and on reload, exactly like a built-in validation failure.
#[derive(Debug)]
pub struct CompositionError {
    /// Human-readable description of what went wrong.
    message: String,
}

impl CompositionError {
    /// Create a composition error with the given message.
    #[must_use]
    pub fn new<S: Into<String>>(message: S) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CompositionError {}

impl From<String> for CompositionError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for CompositionError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

// -----------------------------------------------------------------------------
// Contexts
// -----------------------------------------------------------------------------

/// Immutable server context handed to the registry factory at startup.
///
/// Deliberately narrow: it exposes the server-owned [`SubRequestClient`], not
/// general server state, so a downstream registry can wire the shared
/// sub-request client into its filters while it is being built.
///
/// [`SubRequestClient`]: praxis_core::subrequest::SubRequestClient
pub struct RegistryContext<'ctx> {
    /// The server-owned shared sub-request client.
    subrequest_client: &'ctx SubRequestClient,
}

impl<'ctx> RegistryContext<'ctx> {
    /// Construct a registry context.
    pub(crate) fn new(subrequest_client: &'ctx SubRequestClient) -> Self {
        Self { subrequest_client }
    }

    /// The server-owned shared sub-request client.
    #[must_use]
    pub fn subrequest_client(&self) -> &SubRequestClient {
        self.subrequest_client
    }
}

/// Immutable context handed to a pipeline-extension factory per listener.
pub struct ExtensionContext<'ctx> {
    /// The full effective configuration.
    config: &'ctx Config,
    /// The listener whose pipeline is being built.
    listener: &'ctx Listener,
    /// The server-owned shared sub-request client.
    subrequest_client: &'ctx SubRequestClient,
}

impl<'ctx> ExtensionContext<'ctx> {
    /// Construct an extension context.
    pub(crate) fn new(
        config: &'ctx Config,
        listener: &'ctx Listener,
        subrequest_client: &'ctx SubRequestClient,
    ) -> Self {
        Self {
            config,
            listener,
            subrequest_client,
        }
    }

    /// The full effective configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        self.config
    }

    /// The listener whose pipeline is being built.
    #[must_use]
    pub fn listener(&self) -> &Listener {
        self.listener
    }

    /// The server-owned shared sub-request client.
    #[must_use]
    pub fn subrequest_client(&self) -> &SubRequestClient {
        self.subrequest_client
    }
}

/// Read-only context handed to a pipeline validator after a pipeline is built.
///
/// A validator may inspect the configuration, the listener, the flattened
/// filter entries, and the completed pipeline, but cannot mutate any of them.
pub struct ValidatorContext<'ctx> {
    /// The full effective configuration.
    config: &'ctx Config,
    /// The listener whose pipeline was built.
    listener: &'ctx Listener,
    /// The flattened filter entries after chain concatenation.
    entries: &'ctx [FilterEntry],
    /// The completed, ordering-validated pipeline.
    pipeline: &'ctx FilterPipeline,
}

impl<'ctx> ValidatorContext<'ctx> {
    /// Construct a validator context.
    pub(crate) fn new(
        config: &'ctx Config,
        listener: &'ctx Listener,
        entries: &'ctx [FilterEntry],
        pipeline: &'ctx FilterPipeline,
    ) -> Self {
        Self {
            config,
            listener,
            entries,
            pipeline,
        }
    }

    /// The full effective configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        self.config
    }

    /// The listener whose pipeline was built.
    #[must_use]
    pub fn listener(&self) -> &Listener {
        self.listener
    }

    /// The flattened filter entries after chain concatenation.
    #[must_use]
    pub fn entries(&self) -> &[FilterEntry] {
        self.entries
    }

    /// The completed, ordering-validated pipeline.
    #[must_use]
    pub fn pipeline(&self) -> &FilterPipeline {
        self.pipeline
    }
}

// -----------------------------------------------------------------------------
// PipelineComposition
// -----------------------------------------------------------------------------

/// The reload-durable half of a [`ServerComposition`].
///
/// Holds the pipeline-extension factories and validators, wrapped in `Arc`s so
/// they can be cheaply carried into the hot-reload watcher and applied on every
/// rebuild. Cloning shares the same factories. The default value applies no
/// extensions and no validators, which is what the standard non-embedded server
/// uses.
#[derive(Clone, Default)]
pub(crate) struct PipelineComposition {
    /// Factories producing a fresh extension per listener pipeline.
    extension_factories: Arc<[ExtensionFactory]>,
    /// Read-only validators run against each built pipeline.
    validators: Arc<[PipelineValidator]>,
}

impl PipelineComposition {
    /// Apply every extension factory to `pipeline` for the given context.
    ///
    /// Each factory produces a fresh [`PipelineExtension`]; a factory error
    /// rejects the pipeline.
    pub(crate) fn apply_extensions(
        &self,
        pipeline: &mut FilterPipeline,
        ctx: &ExtensionContext<'_>,
    ) -> Result<(), CompositionError> {
        for factory in self.extension_factories.iter() {
            pipeline.add_pipeline_extension(factory(ctx)?);
        }
        Ok(())
    }

    /// Run every validator against the built pipeline.
    ///
    /// A validator error rejects the pipeline.
    pub(crate) fn validate(&self, ctx: &ValidatorContext<'_>) -> Result<(), CompositionError> {
        for validator in self.validators.iter() {
            validator(ctx)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// ServerComposition
// -----------------------------------------------------------------------------

/// A data-only description of how to compose an embedded Praxis server.
///
/// Construct one with [`ServerComposition::standard`] (built-in and
/// auto-discovered filters), [`ServerComposition::with_registry`] (a
/// pre-built registry), or [`ServerComposition::with_registry_factory`] (a
/// registry built from server context), then layer on pipeline extensions and
/// validators. Pass it to [`run_server_with_composition`].
///
/// ```
/// use praxis::{CompositionError, PipelineExtension, RequestExtensions, ServerComposition};
///
/// // A pipeline-scoped resource a downstream filter retrieves per request.
/// #[derive(Clone)]
/// struct ModelRegistry;
///
/// impl PipelineExtension for ModelRegistry {
///     fn prepare(&self, extensions: &mut RequestExtensions) {
///         extensions.insert(self.clone());
///     }
/// }
///
/// let composition = ServerComposition::standard()
///     // A fresh extension is produced for each listener pipeline.
///     .add_pipeline_extension_factory(|_ctx| Ok(Box::new(ModelRegistry)))
///     // A read-only validator that rejects pipelines it disapproves of.
///     .add_pipeline_validator(|ctx| {
///         if ctx.listener().name.is_empty() {
///             Err(CompositionError::new("listener requires a name"))
///         } else {
///             Ok(())
///         }
///     });
/// # let _ = composition;
/// // praxis::run_server_with_composition(config, composition, config_path, log_level);
/// ```
///
/// [`run_server_with_composition`]: crate::run_server_with_composition
pub struct ServerComposition {
    /// Builds the filter registry once at startup.
    registry_factory: RegistryFactory,
    /// Factories producing a fresh extension per listener pipeline.
    extension_factories: Vec<ExtensionFactory>,
    /// Read-only validators run against each built pipeline.
    validators: Vec<PipelineValidator>,
}

impl ServerComposition {
    /// A composition using built-in and auto-discovered external filters.
    ///
    /// This is the registry the standard `praxis` binary uses; it ignores the
    /// registry context. Equivalent to the behavior of [`run_server`].
    ///
    /// [`run_server`]: crate::run_server
    #[must_use]
    pub fn standard() -> Self {
        Self::with_registry_factory(|_ctx| Ok(crate::build_full_registry()))
    }

    /// A composition wrapping an already-built [`FilterRegistry`].
    ///
    /// Equivalent to the behavior of [`run_server_with_registry`]; the registry
    /// context is ignored.
    ///
    /// [`run_server_with_registry`]: crate::run_server_with_registry
    #[must_use]
    pub fn with_registry(registry: FilterRegistry) -> Self {
        Self::with_registry_factory(move |_ctx| Ok(registry))
    }

    /// A composition whose registry is built from server context at startup.
    ///
    /// The factory receives a [`RegistryContext`] exposing the server-owned
    /// [`SubRequestClient`] and runs exactly once. Returning an error aborts
    /// startup.
    ///
    /// [`SubRequestClient`]: praxis_core::subrequest::SubRequestClient
    #[must_use]
    pub fn with_registry_factory<F>(factory: F) -> Self
    where
        F: FnOnce(&RegistryContext<'_>) -> Result<FilterRegistry, CompositionError> + 'static,
    {
        Self {
            registry_factory: Box::new(factory),
            extension_factories: Vec::new(),
            validators: Vec::new(),
        }
    }

    /// Register a pipeline-extension factory.
    ///
    /// The factory is invoked once per listener pipeline (at startup and on
    /// every reload), producing a fresh [`PipelineExtension`]. It must be
    /// synchronous and side-effect-free; returning an error rejects the
    /// pipeline.
    #[must_use]
    pub fn add_pipeline_extension_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&ExtensionContext<'_>) -> Result<Box<dyn PipelineExtension>, CompositionError> + Send + Sync + 'static,
    {
        self.extension_factories.push(Box::new(factory));
        self
    }

    /// Register a read-only pipeline validator.
    ///
    /// The validator is invoked once per built pipeline (at startup and on
    /// every reload) with a [`ValidatorContext`]. Returning an error rejects
    /// the pipeline.
    #[must_use]
    pub fn add_pipeline_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&ValidatorContext<'_>) -> Result<(), CompositionError> + Send + Sync + 'static,
    {
        self.validators.push(Box::new(validator));
        self
    }

    /// Split into the startup-only registry factory and the reload-durable
    /// pipeline composition.
    pub(crate) fn into_parts(self) -> (RegistryFactory, PipelineComposition) {
        (
            self.registry_factory,
            PipelineComposition {
                extension_factories: Arc::from(self.extension_factories),
                validators: Arc::from(self.validators),
            },
        )
    }
}

impl Default for ServerComposition {
    fn default() -> Self {
        Self::standard()
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
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use praxis_core::subrequest::SubRequestConnector;
    use praxis_filter::RequestExtensions;

    use super::*;

    /// A marker resource inserted into per-request extensions.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Marker(u8);

    impl PipelineExtension for Marker {
        fn prepare(&self, extensions: &mut RequestExtensions) {
            extensions.insert(self.clone());
        }
    }

    #[test]
    fn composition_error_display_is_the_message() {
        let err = CompositionError::new("boom");
        assert_eq!(err.to_string(), "boom", "Display should render the message verbatim");
        assert_eq!(err.message(), "boom", "message() should return the message");
    }

    #[test]
    fn composition_error_converts_from_str_and_string() {
        let from_str: CompositionError = "slice".into();
        let from_string: CompositionError = String::from("owned").into();
        assert_eq!(from_str.message(), "slice");
        assert_eq!(from_string.message(), "owned");
    }

    #[test]
    fn default_composition_has_no_extensions_or_validators() {
        let (_factory, pipeline) = ServerComposition::default().into_parts();
        assert!(
            pipeline.extension_factories.is_empty(),
            "the standard composition applies no extensions"
        );
        assert!(
            pipeline.validators.is_empty(),
            "the standard composition applies no validators"
        );
    }

    #[test]
    fn with_registry_factory_receives_the_subrequest_client() {
        let client = empty_subrequest_client();
        let observed = Arc::new(AtomicUsize::new(0));
        let observed_in_factory = Arc::clone(&observed);
        let composition = ServerComposition::with_registry_factory(move |ctx| {
            // Record the client's address: the connector is opaque, so we prove
            // the exact server-owned client is exposed rather than a value copy.
            observed_in_factory.store(std::ptr::from_ref(ctx.subrequest_client()).addr(), Ordering::SeqCst);
            Ok(FilterRegistry::with_builtins())
        });
        let (factory, _pipeline) = composition.into_parts();
        let ctx = RegistryContext::new(&client);
        factory(&ctx).expect("standard registry build should succeed");
        assert_eq!(
            observed.load(Ordering::SeqCst),
            std::ptr::from_ref(&client).addr(),
            "the factory must observe the server-owned client"
        );
    }

    #[test]
    fn apply_extensions_runs_each_factory_and_injects_resources() {
        let client = empty_subrequest_client();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in_factory = Arc::clone(&calls);
        let composition = ServerComposition::standard().add_pipeline_extension_factory(move |_ctx| {
            calls_in_factory.fetch_add(1, Ordering::SeqCst);
            let ext: Box<dyn PipelineExtension> = Box::new(Marker(7));
            Ok(ext)
        });
        let (_factory, pipeline_composition) = composition.into_parts();

        let config = single_listener_config();
        let listener = &config.listeners[0];
        let mut pipeline = empty_pipeline();
        let ext_ctx = ExtensionContext::new(&config, listener, &client);
        pipeline_composition
            .apply_extensions(&mut pipeline, &ext_ctx)
            .expect("extension application should succeed");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the factory should run exactly once here"
        );

        let mut request_extensions = RequestExtensions::new();
        pipeline.prepare_extensions(&mut request_extensions);
        assert_eq!(
            request_extensions.get::<Marker>(),
            Some(&Marker(7)),
            "the produced extension must inject its resource per request"
        );
    }

    #[test]
    fn apply_extensions_propagates_factory_errors() {
        let client = empty_subrequest_client();
        let composition = ServerComposition::standard()
            .add_pipeline_extension_factory(|_ctx| Err(CompositionError::new("factory refused")));
        let (_factory, pipeline_composition) = composition.into_parts();

        let config = single_listener_config();
        let listener = &config.listeners[0];
        let mut pipeline = empty_pipeline();
        let ext_ctx = ExtensionContext::new(&config, listener, &client);
        let err = pipeline_composition
            .apply_extensions(&mut pipeline, &ext_ctx)
            .expect_err("a failing factory must reject");
        assert_eq!(err.message(), "factory refused");
    }

    #[test]
    fn validate_propagates_validator_errors() {
        let composition = ServerComposition::standard()
            .add_pipeline_validator(|_ctx| Err(CompositionError::new("validator refused")));
        let (_factory, pipeline_composition) = composition.into_parts();

        let config = single_listener_config();
        let listener = &config.listeners[0];
        let pipeline = empty_pipeline();
        let validator_ctx = ValidatorContext::new(&config, listener, &[], &pipeline);
        let err = pipeline_composition
            .validate(&validator_ctx)
            .expect_err("a failing validator must reject");
        assert_eq!(err.message(), "validator refused");
    }

    #[test]
    fn validate_passes_when_every_validator_accepts() {
        let composition = ServerComposition::standard().add_pipeline_validator(|_ctx| Ok(()));
        let (_factory, pipeline_composition) = composition.into_parts();

        let config = single_listener_config();
        let listener = &config.listeners[0];
        let pipeline = empty_pipeline();
        let validator_ctx = ValidatorContext::new(&config, listener, &[], &pipeline);
        assert!(
            pipeline_composition.validate(&validator_ctx).is_ok(),
            "an accepting validator must not reject"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn empty_subrequest_client() -> SubRequestClient {
        SubRequestClient::new(SubRequestConnector::new(8, None))
    }

    fn empty_pipeline() -> FilterPipeline {
        FilterPipeline::build(&mut [], &FilterRegistry::with_builtins()).unwrap()
    }

    fn single_listener_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap()
    }
}
