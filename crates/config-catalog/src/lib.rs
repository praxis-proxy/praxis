//! Stable, runtime-independent types used to describe Praxis configuration.
//!
//! This crate deliberately contains no proxy, filesystem, YAML, or async
//! dependencies so it can be consumed by browser/WASM configuration tools.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Current wire format version.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogFormatVersion {
    /// Incompatible changes increment the major version.
    pub major: u16,
    /// Additive changes increment the minor version.
    pub minor: u16,
}

/// Component producing a catalog fragment.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[expect(
    missing_docs,
    reason = "serialized enum variants are defined by the catalog wire contract"
)]
pub enum ProducerComponent {
    Core,
    Ai,
    Extension,
}

/// Producer provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProducerInfo {
    /// Logical producer kind.
    pub component: ProducerComponent,
    /// Package name.
    pub package: String,
    /// Package version.
    pub version: String,
    /// Optional source revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

/// Compatibility requirements for a fragment.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogCompatibility {
    /// Required catalog format major version.
    pub requires_format_major: u16,
    /// Optional compatible Core package requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_core: Option<VersionRequirement>,
}

/// Features available when a fragment was generated.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeatureProfile {
    /// Features enabled for this artifact.
    #[serde(default)]
    pub available: BTreeSet<String>,
    /// Features enabled by default.
    #[serde(default)]
    pub default_enabled: BTreeSet<String>,
}

/// Stable schema identifier.
#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SchemaId(pub String);

impl From<String> for SchemaId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SchemaId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl std::fmt::Display for SchemaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A semver requirement for the Core package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VersionRequirement(pub String);

impl From<String> for VersionRequirement {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for VersionRequirement {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// A complete producer-owned catalog fragment.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogFragment {
    /// Wire format version.
    pub format_version: CatalogFormatVersion,
    /// Producer provenance.
    pub producer: ProducerInfo,
    /// Compatibility requirements.
    pub compatibility: CatalogCompatibility,
    /// Feature profile used to generate this fragment.
    pub feature_profile: FeatureProfile,
    /// Named reusable schemas.
    #[serde(default)]
    pub schemas: BTreeMap<SchemaId, ConfigSchema>,
    /// Root configuration descriptors.
    #[serde(default)]
    pub roots: Vec<RootConfigDescriptor>,
    /// Filter descriptors.
    #[serde(default)]
    pub filters: Vec<FilterDescriptor>,
    /// Non-fatal generation diagnostics.
    #[serde(default)]
    pub diagnostics: Vec<CatalogDiagnostic>,
}

/// A validated composition of one Core fragment and extension fragments.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MergedCatalog {
    /// Combined catalog data.
    pub fragment: CatalogFragment,
    /// Producer identities included in the composition.
    pub producers: Vec<ProducerInfo>,
}

/// Named configuration schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigSchema {
    /// Stable identifier.
    pub id: SchemaId,
    /// Human-readable title.
    pub title: String,
    /// Documentation.
    #[serde(default)]
    pub description: String,
    /// Schema node.
    pub node: SchemaNode,
    /// Whether this schema is intentionally shared across producer fragments.
    ///
    /// Identical definitions may be coalesced during merge only when both
    /// producers explicitly opt in. Provenance is still retained on the
    /// resulting schema.
    #[serde(default, skip_serializing_if = "is_false")]
    pub shared: bool,
    /// Producer provenance, populated for merged catalogs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer: Option<ProducerInfo>,
}

/// Omit a false wire flag while retaining serde's default for old fragments.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a reference predicate"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

/// Schema node for a configuration value.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchemaNode {
    /// Node shape.
    pub kind: SchemaKind,
    /// Optional title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Documentation.
    #[serde(default)]
    pub description: String,
    /// Literal default value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// Example values.
    #[serde(default)]
    pub examples: Vec<serde_json::Value>,
    /// Portable constraints.
    #[serde(default)]
    pub rules: Vec<PortableRule>,
    /// Whether the value contains credentials or other secrets.
    #[serde(default)]
    pub sensitive: bool,
}

impl SchemaNode {
    /// Construct a schema node with empty optional metadata.
    #[must_use]
    pub fn simple(kind: SchemaKind) -> Self {
        Self {
            kind,
            title: None,
            description: String::new(),
            default: None,
            examples: Vec::new(),
            rules: Vec::new(),
            sensitive: false,
        }
    }

    /// Construct an array schema node.
    #[must_use]
    pub fn array(items: SchemaNode) -> Self {
        Self::simple(SchemaKind::Array {
            items: Box::new(items),
            min_items: None,
            max_items: None,
        })
    }

    /// Construct a map schema node.
    #[must_use]
    pub fn map(values: SchemaNode) -> Self {
        Self::simple(SchemaKind::Map {
            values: Box::new(values),
        })
    }

    /// Construct an object schema node.
    #[must_use]
    pub fn object(fields: Vec<ObjectField>) -> Self {
        Self::simple(SchemaKind::Object {
            fields,
            additional_properties: false,
        })
    }

    /// Construct an enum of string values.
    #[must_use]
    pub fn enum_strings(values: Vec<String>) -> Self {
        Self::simple(SchemaKind::Enum {
            values: values.into_iter().map(serde_json::Value::String).collect(),
        })
    }

    /// Construct a literal schema node.
    #[must_use]
    pub fn literal(value: serde_json::Value) -> Self {
        Self::simple(SchemaKind::Literal { value })
    }

    /// Construct a one-of schema node.
    #[must_use]
    pub fn one_of(variants: Vec<SchemaNode>) -> Self {
        Self::one_of_with_discriminator(variants, None)
    }

    /// Construct a tagged union schema with an optional discriminator field.
    #[must_use]
    pub fn one_of_with_discriminator(variants: Vec<SchemaNode>, discriminator: Option<String>) -> Self {
        Self::simple(SchemaKind::OneOf {
            variants,
            discriminator,
        })
    }

    /// Construct a reference schema node.
    #[must_use]
    pub fn reference(schema_id: String) -> Self {
        Self::simple(SchemaKind::Reference {
            schema_id: SchemaId(schema_id),
        })
    }
}

/// Serializable configuration shape.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[expect(
    missing_docs,
    reason = "serialized schema variants are defined by the catalog wire contract"
)]
pub enum SchemaKind {
    /// Unresolved source types are retained only for diagnostics and always
    /// rejected by validation; generators must never emit this variant.
    Any,
    Boolean,
    Integer,
    Number,
    String,
    Null,
    Literal {
        value: serde_json::Value,
    },
    Enum {
        values: Vec<serde_json::Value>,
    },
    Object {
        fields: Vec<ObjectField>,
        additional_properties: bool,
    },
    Array {
        items: Box<SchemaNode>,
        min_items: Option<usize>,
        max_items: Option<usize>,
    },
    Map {
        values: Box<SchemaNode>,
    },
    OneOf {
        variants: Vec<SchemaNode>,
        discriminator: Option<String>,
    },
    Reference {
        schema_id: SchemaId,
    },
}

/// Field in an object schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
pub struct ObjectField {
    pub serialized_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub schema: SchemaNode,
    pub required: bool,
    #[serde(default)]
    pub flattened: bool,
}

/// A filter's configuration descriptor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
pub struct FilterDescriptor {
    pub name: String,
    pub protocol: Protocol,
    pub category: String,
    #[serde(default)]
    pub description: String,
    pub config_schema: SchemaId,
    #[serde(default)]
    pub required_features: BTreeSet<String>,
    pub capabilities: FilterCapabilities,
    #[serde(default)]
    pub examples: Vec<ConfigExample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    /// Producer provenance retained when fragments are merged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer: Option<ProducerInfo>,
}

/// Runtime phase capabilities of a filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "phase capability flags are an independent wire contract"
)]
pub struct FilterCapabilities {
    #[serde(default)]
    pub security_class: SecurityClass,
    #[serde(default)]
    pub request_headers: bool,
    #[serde(default)]
    pub request_body: bool,
    #[serde(default)]
    pub response_headers: bool,
    #[serde(default)]
    pub response_body: bool,
    #[serde(default)]
    pub terminal: bool,
}

/// Example YAML configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
pub struct ConfigExample {
    pub yaml: String,
}

/// Source location relative to the producer repository.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
pub struct SourceLocation {
    pub path: String,
    pub line: Option<u32>,
}

/// Root configuration descriptor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
pub struct RootConfigDescriptor {
    pub name: String,
    pub schema: SchemaId,
}

/// A portable validation rule.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
pub struct PortableRule {
    pub code: String,
    pub target: String,
    pub kind: RuleKind,
    #[serde(default)]
    pub parameters: BTreeMap<String, serde_json::Value>,
    pub message: String,
}

/// A generator diagnostic.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(missing_docs, reason = "serialized fields are defined by the catalog wire contract")]
pub struct CatalogDiagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub target: String,
    pub message: String,
}

/// Protocol implemented by a filter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[expect(missing_docs, reason = "variants are defined by the catalog wire contract")]
pub enum Protocol {
    Http,
    Tcp,
}

/// Security classification for a filter.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[expect(missing_docs, reason = "variants are defined by the catalog wire contract")]
pub enum SecurityClass {
    #[default]
    Standard,
    Security,
}

/// Severity of a generation diagnostic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[expect(missing_docs, reason = "variants are defined by the catalog wire contract")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Portable validation rule kinds supported by format version 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[expect(missing_docs, reason = "variants are defined by the catalog wire contract")]
pub enum RuleKind {
    NumericBounds,
    LengthBounds,
    Pattern,
    NonEmpty,
    MutualExclusion,
    AtLeastOne,
    UniqueItems,
    ReferenceToNamedObject,
}

impl CatalogFragment {
    /// Validate the complete fragment contract.
    ///
    /// # Errors
    ///
    /// Returns a structured error when any semantic identity, compatibility
    /// requirement, or schema reference violates the wire contract.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.format_version.major != self.compatibility.requires_format_major {
            return Err(ValidationError::Compatibility {
                expected: self.format_version.major,
                found: self.compatibility.requires_format_major,
            });
        }
        self.validate_descriptors()?;
        if !self
            .feature_profile
            .default_enabled
            .is_subset(&self.feature_profile.available)
        {
            return Err(ValidationError::UnknownFeature {
                filter: "feature_profile.default_enabled".to_owned(),
            });
        }
        if let Some(filter) = self
            .filters
            .iter()
            .find(|filter| !filter.required_features.is_subset(&self.feature_profile.available))
        {
            return Err(ValidationError::UnknownFeature {
                filter: filter.name.clone(),
            });
        }
        self.validate_schema_ids()?;
        self.validate_schema_nodes()?;
        Ok(())
    }

    /// Validate descriptor identity and references.
    fn validate_descriptors(&self) -> Result<(), ValidationError> {
        let mut names = BTreeSet::new();
        let mut sources = BTreeSet::new();
        for filter in &self.filters {
            if !names.insert(&filter.name) {
                return Err(ValidationError::DuplicateFilter(filter.name.clone()));
            }
            if let Some(source) = &filter.source
                && !sources.insert((&filter.name, &source.path, source.line))
            {
                return Err(ValidationError::DuplicateSource(source.path.clone()));
            }
            if !self.schemas.contains_key(&filter.config_schema) {
                return Err(ValidationError::DanglingSchema {
                    target: filter.config_schema.clone(),
                });
            }
        }
        let mut roots = BTreeSet::new();
        for root in &self.roots {
            if !roots.insert(&root.name) {
                return Err(ValidationError::Duplicate {
                    kind: "root",
                    name: root.name.clone(),
                });
            }
            if !self.schemas.contains_key(&root.schema) {
                return Err(ValidationError::DanglingSchema {
                    target: root.schema.clone(),
                });
            }
        }
        Ok(())
    }

    /// Validate map keys against embedded schema IDs.
    fn validate_schema_ids(&self) -> Result<(), ValidationError> {
        for (id, schema) in &self.schemas {
            if id != &schema.id {
                return Err(ValidationError::SchemaIdMismatch {
                    key: id.clone(),
                    embedded: schema.id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Validate every schema node recursively.
    fn validate_schema_nodes(&self) -> Result<(), ValidationError> {
        for (id, schema) in &self.schemas {
            validate_node(&schema.node, &self.schemas).map_err(|error| ValidationError::Schema {
                id: id.clone(),
                source: Box::new(error),
            })?;
        }
        Ok(())
    }
}

/// Structured errors returned by fragment validation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(missing_docs, reason = "variants describe stable structured generator failures")]
pub enum ValidationError {
    Compatibility { expected: u16, found: u16 },
    Duplicate { kind: &'static str, name: String },
    DanglingSchema { target: SchemaId },
    SchemaIdMismatch { key: SchemaId, embedded: SchemaId },
    UnresolvedAny,
    Schema { id: SchemaId, source: Box<Self> },
    MissingFeatures { filter: String },
    DuplicateFilter(String),
    DuplicateSource(String),
    UnknownFeature { filter: String },
}

impl ValidationError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Compatibility { .. } => "format_major_mismatch",
            Self::Duplicate { .. } => "duplicate_identity",
            Self::DuplicateFilter(_) => "duplicate_filter",
            Self::DuplicateSource(_) => "duplicate_source",
            Self::DanglingSchema { .. } => "dangling_reference",
            Self::SchemaIdMismatch { .. } => "schema_id_mismatch",
            Self::UnresolvedAny => "unresolved_any",
            Self::Schema { source, .. } => source.code(),
            Self::MissingFeatures { .. } => "missing_features",
            Self::UnknownFeature { .. } => "unknown_feature",
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compatibility { expected, found } => {
                write!(f, "format major {found} is incompatible with {expected}")
            },
            Self::Duplicate { kind, name } => write!(f, "duplicate {kind}: {name}"),
            Self::DanglingSchema { target } => write!(f, "dangling schema: {target}"),
            Self::SchemaIdMismatch { key, embedded } => {
                write!(f, "schema key {key} does not match embedded id {embedded}")
            },
            Self::UnresolvedAny => f.write_str("unresolved `any` schema is not allowed"),
            Self::DuplicateFilter(name) => write!(f, "duplicate filter: {name}"),
            Self::DuplicateSource(path) => write!(f, "duplicate filter source: {path}"),
            Self::MissingFeatures { filter } | Self::UnknownFeature { filter } => {
                write!(f, "filter {filter} requires unavailable features")
            },
            Self::Schema { id, source } => write!(f, "{id}: {source}"),
        }
    }
}

/// Validate a schema node and every nested reference.
fn validate_node(node: &SchemaNode, schemas: &BTreeMap<SchemaId, ConfigSchema>) -> Result<(), ValidationError> {
    match &node.kind {
        SchemaKind::Any => Err(ValidationError::UnresolvedAny),
        SchemaKind::Reference { schema_id } if !schemas.contains_key(schema_id) => {
            Err(ValidationError::DanglingSchema {
                target: schema_id.clone(),
            })
        },
        SchemaKind::Object { fields, .. } => fields
            .iter()
            .try_for_each(|field| validate_node(&field.schema, schemas)),
        SchemaKind::Array { items, .. } => validate_node(items, schemas),
        SchemaKind::Map { values } => validate_node(values, schemas),
        SchemaKind::OneOf { variants, .. } => variants.iter().try_for_each(|variant| validate_node(variant, schemas)),
        SchemaKind::Boolean
        | SchemaKind::Integer
        | SchemaKind::Number
        | SchemaKind::String
        | SchemaKind::Null
        | SchemaKind::Literal { .. }
        | SchemaKind::Enum { .. }
        | SchemaKind::Reference { .. } => Ok(()),
    }
}

/// Host-side catalog generation helpers.
///
/// The serialized model above is intentionally usable in WASM. This module is
/// enabled only by the `generator` feature and is the single policy seam for
/// validating and rendering producer fragments. Consumers provide discovery
/// data and descriptors; they do not implement their own finalization rules.
pub mod generator {
    use std::collections::BTreeSet;

    use super::{CatalogFragment, ConfigSchema, MergedCatalog};

    /// Errors produced while finalizing a catalog fragment.
    #[cfg(feature = "generator")]
    #[derive(Debug)]
    pub enum GenerationError {
        /// The fragment violates the catalog contract.
        Invalid(crate::ValidationError),
        /// JSON serialization failed.
        Serialization(serde_json::Error),
    }

    #[cfg(feature = "generator")]
    impl std::fmt::Display for GenerationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Invalid(error) => error.fmt(f),
                Self::Serialization(error) => write!(f, "catalog serialization failed: {error}"),
            }
        }
    }

    #[cfg(feature = "generator")]
    impl std::error::Error for GenerationError {}

    /// Validate and render a producer fragment deterministically.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or JSON serialization fails.
    #[cfg(feature = "generator")]
    pub fn render(mut fragment: CatalogFragment) -> Result<Vec<u8>, GenerationError> {
        let producer = fragment.producer.clone();
        for schema in fragment.schemas.values_mut() {
            schema.producer.get_or_insert_with(|| producer.clone());
        }
        for filter in &mut fragment.filters {
            filter.producer.get_or_insert_with(|| producer.clone());
        }
        fragment.filters.sort_by(|left, right| {
            (&left.protocol, &left.category, &left.name).cmp(&(&right.protocol, &right.category, &right.name))
        });
        fragment.validate().map_err(GenerationError::Invalid)?;
        let mut bytes = serde_json::to_vec_pretty(&fragment).map_err(GenerationError::Serialization)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Validate a fragment without rendering it.
    ///
    /// # Errors
    ///
    /// Returns an error when the fragment violates the catalog contract.
    #[cfg(feature = "generator")]
    pub fn validate(fragment: &CatalogFragment) -> Result<(), GenerationError> {
        fragment.validate().map_err(GenerationError::Invalid)
    }

    /// Merge a Core fragment with one or more extension fragments.
    ///
    /// The operation is pure: inputs are validated, semantic collections are
    /// combined, and the returned fragment is rendered with the same policy as
    /// a single producer. Extension provenance remains on each descriptor's
    /// source path; duplicate names or schema IDs are rejected closed.
    ///
    /// # Errors
    ///
    /// Returns a structured error when an input is invalid or identities and
    /// compatibility requirements collide.
    #[expect(
        clippy::too_many_lines,
        reason = "merge keeps the producer identity transaction explicit"
    )]
    pub fn merge(core: CatalogFragment, extensions: Vec<CatalogFragment>) -> Result<MergedCatalog, MergeError> {
        core.validate().map_err(MergeError::InvalidCore)?;
        if core.producer.component != crate::ProducerComponent::Core {
            return Err(MergeError::ProducerKind("core fragment required first".to_owned()));
        }
        let mut producers = vec![core.producer.clone()];
        let mut merged = core;
        let core_producer = merged.producer.clone();
        for filter in &mut merged.filters {
            filter.producer.get_or_insert_with(|| core_producer.clone());
        }
        for schema in merged.schemas.values_mut() {
            schema.producer.get_or_insert_with(|| core_producer.clone());
        }
        let mut identities = BTreeSet::new();
        identities.insert((merged.producer.package.clone(), merged.producer.source_revision.clone()));
        for extension in extensions {
            let identity = (
                extension.producer.package.clone(),
                extension.producer.source_revision.clone(),
            );
            if !identities.insert(identity) {
                return Err(MergeError::DuplicateProducer);
            }
            producers.push(extension.producer.clone());
            merge_extension(&mut merged, extension)?;
        }
        merged.validate().map_err(MergeError::Merged)?;
        merged.filters.sort_by(|left, right| {
            (&left.protocol, &left.category, &left.name).cmp(&(&right.protocol, &right.category, &right.name))
        });
        Ok(MergedCatalog {
            fragment: merged,
            producers,
        })
    }

    /// Validate extension compatibility and append its owned data.
    #[expect(
        clippy::too_many_lines,
        reason = "merge invariants are kept together at the pure merge seam"
    )]
    fn merge_extension(merged: &mut CatalogFragment, mut extension: CatalogFragment) -> Result<(), MergeError> {
        if extension.format_version.major != merged.format_version.major {
            return Err(MergeError::FormatMajor {
                expected: merged.format_version.major,
                found: extension.format_version.major,
            });
        }
        if !extension.roots.is_empty() {
            return Err(MergeError::ExtensionRoots);
        }
        extension.validate().map_err(MergeError::InvalidExtension)?;
        if extension.producer.component == crate::ProducerComponent::Core {
            return Err(MergeError::ProducerKind(
                "only one Core fragment may be merged".to_owned(),
            ));
        }
        if let Some(requirement) = extension.compatibility.requires_core.as_ref()
            && !version_satisfies(&merged.producer.version, &requirement.0)?
        {
            return Err(MergeError::CoreRequirement(requirement.0.clone()));
        }
        for filter in &extension.filters {
            if !filter.required_features.is_subset(&extension.feature_profile.available) {
                return Err(MergeError::MissingFeatures);
            }
        }
        for filter in &mut extension.filters {
            filter.producer = Some(extension.producer.clone());
        }
        for (id, schema) in extension.schemas {
            let owned_schema = ConfigSchema {
                producer: Some(extension.producer.clone()),
                ..schema
            };
            if let Some(existing) = merged.schemas.get(&id) {
                if !(existing.shared && owned_schema.shared && schemas_equal_ignoring_producer(existing, &owned_schema))
                {
                    return Err(MergeError::DuplicateSchema(id));
                }
                continue;
            }
            merged.schemas.insert(id, owned_schema);
        }
        merged.filters.extend(extension.filters);
        merged.diagnostics.extend(extension.diagnostics);
        merged
            .feature_profile
            .available
            .extend(extension.feature_profile.available);
        merged
            .feature_profile
            .default_enabled
            .extend(extension.feature_profile.default_enabled);
        Ok(())
    }

    /// Compare schema definitions while excluding merge-populated provenance.
    fn schemas_equal_ignoring_producer(left: &ConfigSchema, right: &ConfigSchema) -> bool {
        let mut left = left.clone();
        let mut right = right.clone();
        left.producer = None;
        right.producer = None;
        serde_json::to_value(left).ok() == serde_json::to_value(right).ok()
    }

    /// Check the supported major-version requirement syntax.
    fn version_satisfies(version: &str, requirement: &str) -> Result<bool, MergeError> {
        let version =
            semver::Version::parse(version).map_err(|_error| MergeError::MalformedVersion(version.to_owned()))?;
        let requirement = semver::VersionReq::parse(requirement)
            .map_err(|_error| MergeError::MalformedRequirement(requirement.to_owned()))?;
        Ok(requirement.matches(&version))
    }

    /// Errors returned when combining producer fragments.
    #[derive(Debug)]
    #[expect(missing_docs, reason = "variants describe stable structured merge failures")]
    pub enum MergeError {
        /// The Core input is invalid.
        InvalidCore(crate::ValidationError),
        /// An extension input is invalid.
        InvalidExtension(crate::ValidationError),
        /// The resulting fragment is invalid.
        Merged(crate::ValidationError),
        /// A fragment has an incompatible wire major.
        FormatMajor { expected: u16, found: u16 },
        /// A producer-kind constraint was violated.
        ProducerKind(String),
        /// Two producers declared the same schema ID.
        DuplicateSchema(crate::SchemaId),
        /// The extension requires a Core version that is not present.
        CoreRequirement(String),
        /// The extension requires unavailable features.
        MissingFeatures,
        /// Two fragments declared the same producer identity.
        DuplicateProducer,
        /// Extensions may not contribute roots.
        ExtensionRoots,
        /// Core producer version was malformed.
        MalformedVersion(String),
        /// Extension Core requirement was malformed.
        MalformedRequirement(String),
    }

    impl std::fmt::Display for MergeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InvalidCore(error) => write!(f, "invalid Core fragment: {error}"),
                Self::InvalidExtension(error) => write!(f, "invalid extension fragment: {error}"),
                Self::FormatMajor { expected, found } => {
                    write!(f, "format major {found} is incompatible with {expected}")
                },
                Self::Merged(error) => write!(f, "invalid merged fragment: {error}"),
                Self::ProducerKind(error) => f.write_str(error),
                Self::DuplicateSchema(id) => write!(f, "duplicate schema: {id}"),
                Self::CoreRequirement(requirement) => write!(f, "Core version does not satisfy {requirement}"),
                Self::MissingFeatures => f.write_str("extension requires unavailable features"),
                Self::DuplicateProducer => f.write_str("duplicate producer identity"),
                Self::ExtensionRoots => f.write_str("extensions may not define roots"),
                Self::MalformedVersion(version) => write!(f, "malformed Core version: {version}"),
                Self::MalformedRequirement(requirement) => write!(f, "malformed Core requirement: {requirement}"),
            }
        }
    }

    impl MergeError {
        /// Stable machine-readable merge error code.
        #[must_use]
        pub const fn code(&self) -> &'static str {
            match self {
                Self::InvalidCore(error) | Self::InvalidExtension(error) | Self::Merged(error) => error.code(),
                Self::FormatMajor { .. } => "incompatible_format",
                Self::ProducerKind(_) => "non_core_first",
                Self::DuplicateSchema(_) => "schema_collision",
                Self::CoreRequirement(_) => "incompatible_core_version",
                Self::MissingFeatures => "unknown_feature",
                Self::DuplicateProducer => "duplicate_producer",
                Self::ExtensionRoots => "extension_roots",
                Self::MalformedVersion(_) => "malformed_version",
                Self::MalformedRequirement(_) => "malformed_requirement",
            }
        }
    }

    impl std::error::Error for MergeError {}

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeMap;

        use super::*;
        use crate::{
            CatalogCompatibility, CatalogFormatVersion, FeatureProfile, FilterCapabilities, ProducerComponent,
            ProducerInfo, Protocol, SchemaId, SchemaKind, SchemaNode,
        };

        fn fragment() -> CatalogFragment {
            CatalogFragment {
                format_version: CatalogFormatVersion { major: 1, minor: 0 },
                producer: ProducerInfo {
                    component: ProducerComponent::Core,
                    package: "test".to_owned(),
                    version: "0.0.0".to_owned(),
                    source_revision: None,
                },
                compatibility: CatalogCompatibility::default(),
                feature_profile: FeatureProfile::default(),
                schemas: BTreeMap::default(),
                roots: Vec::new(),
                filters: Vec::new(),
                diagnostics: Vec::new(),
            }
        }

        fn owned(component: ProducerComponent, package: &str) -> CatalogFragment {
            let mut value = fragment();
            value.producer = ProducerInfo {
                component,
                package: package.to_owned(),
                version: "1.2.3".to_owned(),
                source_revision: Some(package.to_owned()),
            };
            value.compatibility.requires_format_major = 1;
            value.feature_profile.available.insert("feature-a".to_owned());
            value
        }

        fn with_filter(mut value: CatalogFragment, name: &str, schema: &str) -> CatalogFragment {
            value.schemas.insert(
                schema.into(),
                ConfigSchema {
                    id: schema.into(),
                    title: name.to_owned(),
                    description: String::new(),
                    shared: false,
                    node: SchemaNode::simple(SchemaKind::String),
                    producer: None,
                },
            );
            value.filters.push(crate::FilterDescriptor {
                name: name.to_owned(),
                protocol: Protocol::Http,
                category: "test".to_owned(),
                description: String::new(),
                config_schema: schema.into(),
                required_features: BTreeSet::new(),
                capabilities: FilterCapabilities::default(),
                examples: Vec::new(),
                source: None,
                producer: None,
            });
            value
        }

        #[cfg(feature = "generator")]
        #[test]
        fn render_rejects_dangling_schema() {
            let mut value = fragment();
            value.filters.push(crate::FilterDescriptor {
                name: "z".to_owned(),
                protocol: Protocol::Http,
                category: "b".to_owned(),
                description: String::new(),
                config_schema: "missing".into(),
                required_features: BTreeSet::default(),
                capabilities: FilterCapabilities::default(),
                examples: Vec::new(),
                source: None,
                producer: None,
            });
            assert!(render(value).is_err(), "dangling schemas must be rejected");
        }

        #[test]
        #[expect(
            clippy::expect_used,
            clippy::min_ident_chars,
            reason = "merge success assertions remain concise"
        )]
        fn merge_sorts_and_preserves_roots_and_provenance() {
            let mut core = with_filter(owned(ProducerComponent::Core, "core"), "z", "core.z");
            core.roots.push(crate::RootConfigDescriptor {
                name: "Config".to_owned(),
                schema: "core.z".into(),
            });
            let extension = with_filter(owned(ProducerComponent::Extension, "ext"), "a", "ext.a");
            let merged = merge(core, vec![extension]).expect("compatible fragments merge");
            assert_eq!(
                merged
                    .fragment
                    .filters
                    .iter()
                    .map(|f| f.name.as_str())
                    .collect::<Vec<_>>(),
                ["a", "z"]
            );
            assert_eq!(merged.fragment.roots.len(), 1);
            assert!(merged.fragment.filters.iter().all(|f| f.producer.is_some()));
            assert!(merged.fragment.schemas.values().all(|s| s.producer.is_some()));
        }

        #[test]
        #[expect(
            clippy::expect_used,
            clippy::indexing_slicing,
            clippy::too_many_lines,
            reason = "matrix test intentionally enumerates each stable merge failure code"
        )]
        fn merge_reports_exact_contract_errors() {
            let core = owned(ProducerComponent::Core, "core");
            let mut wrong_format = owned(ProducerComponent::Extension, "fmt");
            wrong_format.format_version.major = 2;
            assert_eq!(
                merge(core.clone(), vec![wrong_format])
                    .expect_err("format mismatch")
                    .code(),
                "incompatible_format"
            );

            let mut bad_version = owned(ProducerComponent::Extension, "version");
            bad_version.compatibility.requires_core = Some("not semver".into());
            assert_eq!(
                merge(core.clone(), vec![bad_version])
                    .expect_err("malformed requirement")
                    .code(),
                "malformed_requirement"
            );

            let mut bad_feature = with_filter(
                owned(ProducerComponent::Extension, "feature"),
                "feature",
                "feature.schema",
            );
            bad_feature.filters[0].required_features.insert("missing".to_owned());
            assert_eq!(
                merge(core.clone(), vec![bad_feature])
                    .expect_err("unknown feature")
                    .code(),
                "unknown_feature"
            );

            let mut roots = owned(ProducerComponent::Extension, "roots");
            roots.roots.push(crate::RootConfigDescriptor {
                name: "Root".to_owned(),
                schema: "missing".into(),
            });
            assert_eq!(
                merge(core.clone(), vec![roots]).expect_err("extension roots").code(),
                "extension_roots"
            );

            let duplicate = owned(ProducerComponent::Extension, "core");
            assert_eq!(
                merge(core.clone(), vec![duplicate])
                    .expect_err("duplicate producer")
                    .code(),
                "duplicate_producer"
            );
            let non_core = owned(ProducerComponent::Extension, "first");
            assert_eq!(
                merge(non_core, Vec::new()).expect_err("Core must be first").code(),
                "non_core_first"
            );
        }

        #[test]
        #[expect(
            clippy::expect_used,
            clippy::shadow_unrelated,
            reason = "collision assertions use exact structured error codes"
        )]
        fn merge_rejects_filter_and_schema_collisions() {
            let core = with_filter(owned(ProducerComponent::Core, "core"), "same", "core.same");
            let filter = with_filter(owned(ProducerComponent::Extension, "ext"), "same", "ext.same");
            assert_eq!(
                merge(core, vec![filter]).expect_err("duplicate filter").code(),
                "duplicate_filter"
            );
            let core = with_filter(owned(ProducerComponent::Core, "core"), "core", "shared");
            let extension = with_filter(owned(ProducerComponent::Extension, "ext"), "ext", "shared");
            assert_eq!(
                merge(core, vec![extension]).expect_err("schema collision").code(),
                "schema_collision"
            );
        }

        #[test]
        #[expect(
            clippy::expect_used,
            reason = "shared-schema merge assertions need readable failures"
        )]
        fn merge_allows_identical_explicitly_shared_schema() {
            let mut core = with_filter(owned(ProducerComponent::Core, "core"), "core", "shared");
            let mut extension = with_filter(owned(ProducerComponent::Extension, "ext"), "ext", "shared");
            core.schemas
                .get_mut(&SchemaId("shared".into()))
                .expect("shared schema")
                .shared = true;
            extension
                .schemas
                .get_mut(&SchemaId("shared".into()))
                .expect("shared schema")
                .shared = true;
            extension
                .schemas
                .get_mut(&SchemaId("shared".into()))
                .expect("shared schema")
                .title = "core".into();
            let merged = merge(core, vec![extension]).expect("shared definitions may be coalesced");
            assert_eq!(merged.fragment.schemas.len(), 1);
            assert_eq!(
                merged
                    .fragment
                    .schemas
                    .get(&SchemaId("shared".into()))
                    .expect("merged shared schema")
                    .producer
                    .as_ref()
                    .expect("schema provenance")
                    .package,
                "core"
            );
        }

        #[test]
        #[expect(
            clippy::expect_used,
            reason = "shared-schema negative assertions need readable failures"
        )]
        fn merge_requires_both_shared_and_identical_definitions() {
            let mut core = with_filter(owned(ProducerComponent::Core, "core"), "core", "shared");
            let mut extension = with_filter(owned(ProducerComponent::Extension, "ext"), "ext", "shared");
            core.schemas
                .get_mut(&SchemaId("shared".into()))
                .expect("shared schema")
                .shared = true;
            assert_eq!(
                merge(core.clone(), vec![extension.clone()])
                    .expect_err("one-sided sharing")
                    .code(),
                "schema_collision"
            );
            extension
                .schemas
                .get_mut(&SchemaId("shared".into()))
                .expect("shared schema")
                .shared = true;
            extension
                .schemas
                .get_mut(&SchemaId("shared".into()))
                .expect("shared schema")
                .title = "different".into();
            assert_eq!(
                merge(core, vec![extension])
                    .expect_err("different shared definitions")
                    .code(),
                "schema_collision"
            );
        }

        #[test]
        fn fragment_allows_distinct_filters_from_one_source_file() {
            let mut value = with_filter(owned(ProducerComponent::Core, "core"), "first", "first");
            value.filters[0].source = Some(crate::SourceLocation {
                path: "src/filter.rs".to_owned(),
                line: Some(10),
            });
            let mut second = with_filter(value.clone(), "second", "second");
            second.filters[1].source = Some(crate::SourceLocation {
                path: "src/filter.rs".to_owned(),
                line: Some(10),
            });
            second.validate().expect("distinct descriptors may share a source file");
        }
    }
}

/// Pure fragment composition APIs available to WASM consumers.
pub mod merge {
    pub use super::generator::{MergeError, merge};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "default-surface smoke test needs a clear failure")]
    fn default_surface_exposes_pure_merge() {
        let fragment = CatalogFragment {
            format_version: CatalogFormatVersion { major: 1, minor: 0 },
            producer: ProducerInfo {
                component: ProducerComponent::Core,
                package: "core".into(),
                version: "1.0.0".into(),
                source_revision: None,
            },
            compatibility: CatalogCompatibility {
                requires_format_major: 1,
                requires_core: None,
            },
            feature_profile: FeatureProfile::default(),
            schemas: BTreeMap::new(),
            roots: Vec::new(),
            filters: Vec::new(),
            diagnostics: Vec::new(),
        };
        let merged = merge::merge(fragment, Vec::new()).expect("pure merge is available without generator feature");
        assert_eq!(merged.producers.len(), 1);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "invalid fixture must produce a structured validation error"
    )]
    fn default_enabled_features_must_be_available() {
        let fragment = CatalogFragment {
            format_version: CatalogFormatVersion { major: 1, minor: 0 },
            producer: ProducerInfo {
                component: ProducerComponent::Core,
                package: "core".into(),
                version: "1.0.0".into(),
                source_revision: None,
            },
            compatibility: CatalogCompatibility {
                requires_format_major: 1,
                requires_core: None,
            },
            feature_profile: FeatureProfile {
                available: BTreeSet::new(),
                default_enabled: BTreeSet::from(["missing-feature".to_owned()]),
            },
            schemas: BTreeMap::new(),
            roots: Vec::new(),
            filters: Vec::new(),
            diagnostics: Vec::new(),
        };

        assert_eq!(
            fragment.validate().expect_err("invalid feature profile").code(),
            "unknown_feature"
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "round-trip fixture defines the complete wire shape"
    )]
    #[expect(clippy::expect_used, reason = "round-trip assertions need readable failure messages")]
    fn fragment_round_trips_and_validates() {
        let id = "core.filter.http.test".to_owned();
        let mut fragment = CatalogFragment {
            format_version: CatalogFormatVersion { major: 1, minor: 0 },
            producer: ProducerInfo {
                component: ProducerComponent::Core,
                package: "core".into(),
                version: "0.1.0".into(),
                source_revision: None,
            },
            compatibility: CatalogCompatibility {
                requires_format_major: 1,
                requires_core: None,
            },
            feature_profile: FeatureProfile::default(),
            schemas: BTreeMap::new(),
            roots: vec![],
            filters: vec![],
            diagnostics: vec![],
        };
        fragment.schemas.insert(
            SchemaId(id.clone()),
            ConfigSchema {
                id: SchemaId(id.clone()),
                title: "Test".into(),
                description: String::new(),
                shared: false,
                node: SchemaNode {
                    kind: SchemaKind::String,
                    title: None,
                    description: String::new(),
                    default: None,
                    examples: vec![],
                    rules: vec![],
                    sensitive: false,
                },
                producer: None,
            },
        );
        fragment.filters.push(FilterDescriptor {
            name: "test".into(),
            protocol: Protocol::Http,
            category: "test".into(),
            description: String::new(),
            config_schema: SchemaId(id),
            required_features: BTreeSet::new(),
            capabilities: FilterCapabilities::default(),
            examples: vec![],
            source: None,
            producer: None,
        });
        fragment.validate().expect("fixture must validate");
        let encoded = serde_json::to_string(&fragment).expect("catalog must serialize");
        let decoded: CatalogFragment = serde_json::from_str(&encoded).expect("catalog must deserialize");
        assert_eq!(decoded.filters.len(), 1);
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "negative fixture documents the fail-closed policy")]
    fn unresolved_any_is_rejected_fail_closed() {
        let mut fragment = CatalogFragment {
            format_version: CatalogFormatVersion { major: 1, minor: 0 },
            producer: ProducerInfo {
                component: ProducerComponent::Core,
                package: "core".into(),
                version: "0.1.0".into(),
                source_revision: None,
            },
            compatibility: CatalogCompatibility {
                requires_format_major: 1,
                requires_core: None,
            },
            feature_profile: FeatureProfile::default(),
            schemas: BTreeMap::new(),
            roots: Vec::new(),
            filters: Vec::new(),
            diagnostics: Vec::new(),
        };
        let id: SchemaId = "core.any".into();
        fragment.schemas.insert(
            id.clone(),
            ConfigSchema {
                id,
                title: "Any".into(),
                description: String::new(),
                shared: false,
                node: SchemaNode::simple(SchemaKind::Any),
                producer: None,
            },
        );
        assert!(
            matches!(fragment.validate(), Err(ValidationError::Schema { source, .. }) if matches!(*source, ValidationError::UnresolvedAny)),
            "unresolved source types must fail closed"
        );
    }
}
