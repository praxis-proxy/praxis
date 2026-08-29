// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Streaming capture of JSON-RPC envelope fields.
//!
//! [`parse_json_rpc_envelope`] previously materialized the whole body as
//! a [`serde_json::Value`] to read four top-level fields — for LLM/MCP
//! payloads the `params` subtree is nearly the entire body, allocated as
//! a DOM and immediately dropped, per request. This module captures only
//! the envelope fields (`jsonrpc`, `id`, `method`, `result`/`error`
//! presence) through a serde visitor, consuming everything else with a
//! depth-bounded ignore ([`BoundedIgnore`]): serde still scans and
//! validates every byte, and nesting is capped at [`MAX_ENVELOPE_DEPTH`]
//! so the accepted and rejected inputs match the previous DOM parser
//! (`serde_json::from_slice::<Value>`, which rejected over-deep bodies via
//! its recursion limit), including duplicate-key last-wins semantics (the
//! visitor overwrites like a DOM map insert).
//!
//! [`parse_json_rpc_envelope`]: super::envelope::parse_json_rpc_envelope
//! [`IgnoredAny`]: serde::de::IgnoredAny

use serde::de::{DeserializeSeed, Deserializer, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};

// -----------------------------------------------------------------------------
// Depth-bounded ignore
// -----------------------------------------------------------------------------

/// Maximum JSON nesting depth accepted inside an ignored subtree (`params`,
/// `result`, `error`, unknown fields, and container-valued `jsonrpc`/`id`/
/// `method`).
///
/// The pre-streaming parser materialized the whole body with
/// `serde_json::from_slice::<Value>`, which rejects input nested past
/// `serde_json`'s recursion limit. [`IgnoredAny`]'s `ignore_value` is iterative
/// and unbounded, so without this cap the streaming parser would silently
/// accept pathologically deep bodies the DOM parser rejected. Capping restores
/// that fail-closed behavior and bounds [`BoundedIgnore`]'s own recursion.
const MAX_ENVELOPE_DEPTH: usize = 128;

/// Ignore any JSON value like [`IgnoredAny`], but reject nesting deeper than
/// [`MAX_ENVELOPE_DEPTH`]. `depth` is the level of the value about to be
/// consumed (0 for a top-level ignored value).
struct BoundedIgnore {
    /// Nesting level of the value about to be consumed (0 at the top).
    depth: usize,
}

impl BoundedIgnore {
    /// A bound starting at nesting depth zero.
    fn new() -> Self {
        Self { depth: 0 }
    }
}

impl<'de> DeserializeSeed<'de> for BoundedIgnore {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BoundedIgnore {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        if self.depth >= MAX_ENVELOPE_DEPTH {
            return Err(A::Error::custom("JSON nesting exceeds maximum depth"));
        }
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(BoundedIgnore { depth: self.depth + 1 })?;
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        if self.depth >= MAX_ENVELOPE_DEPTH {
            return Err(A::Error::custom("JSON nesting exceeds maximum depth"));
        }
        while seq
            .next_element_seed(BoundedIgnore { depth: self.depth + 1 })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Captured Fields
// -----------------------------------------------------------------------------

/// The `jsonrpc` field as captured.
#[derive(Clone, Debug)]
pub(super) enum RawVersion {
    /// Key absent, or present with a non-string value (both map to
    /// `MissingVersion`, matching the old `as_str` chain).
    Missing,
    /// Present as a string.
    Str(String),
}

/// The `id` field as captured.
#[derive(Clone, Debug)]
pub(super) enum RawId {
    /// Key absent.
    Missing,
    /// Explicit `null`.
    Null,
    /// String id.
    Str(String),
    /// Integer id (i64/u64), pre-rendered.
    Integer(String),
    /// Floating-point id, pre-rendered.
    Number(String),
    /// Bool, object, or array — invalid per JSON-RPC.
    Invalid,
}

/// The `method` field as captured.
#[derive(Clone, Debug)]
pub(super) enum RawMethod {
    /// Key absent.
    Missing,
    /// Present as a string.
    Str(String),
    /// Present with a non-string value.
    NotString,
}

/// Envelope-relevant fields of a single JSON-RPC message object.
#[derive(Clone, Debug)]
pub(super) struct RawMessage {
    /// The `jsonrpc` version field.
    pub(super) version: RawVersion,
    /// The `id` field.
    pub(super) id: RawId,
    /// Whether a `result` or `error` key is present (any value,
    /// `null` included — presence, not truthiness).
    pub(super) has_result_or_error: bool,
    /// The `method` field.
    pub(super) method: RawMethod,
}

impl RawMessage {
    /// An all-absent message, filled in by the map visitor.
    fn empty() -> Self {
        Self {
            version: RawVersion::Missing,
            id: RawId::Missing,
            has_result_or_error: false,
            method: RawMethod::Missing,
        }
    }
}

/// The JSON root as captured.
#[derive(Debug)]
pub(super) enum RawTop {
    /// A single message object.
    Message(RawMessage),
    /// A batch array of per-item captures (`None` for non-object
    /// items). Memory stays bounded by the old DOM shape: each capture
    /// holds only the envelope fields, never the item's `params`.
    Batch(Vec<Option<RawMessage>>),
    /// Any other root value (string, number, bool, null).
    Other,
}

// -----------------------------------------------------------------------------
// Visitors
// -----------------------------------------------------------------------------

/// Seed for the JSON root.
pub(super) struct TopSeed;

impl<'de> DeserializeSeed<'de> for TopSeed {
    type Value = RawTop;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(TopVisitor)
    }
}

/// Visitor dispatching on the root value kind.
struct TopVisitor;

impl<'de> Visitor<'de> for TopVisitor {
    type Value = RawTop;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON-RPC message, batch, or other JSON value")
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Ok(RawTop::Message(capture_message(map)?))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(ItemSeed)? {
            items.push(item);
        }
        Ok(RawTop::Batch(items))
    }

    // Scalar roots: consumed by serde already; classify as Other.
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(RawTop::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(RawTop::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(RawTop::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(RawTop::Other)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(RawTop::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RawTop::Other)
    }
}

/// Seed for one batch item: `Some(RawMessage)` for objects, `None`
/// (consumed) otherwise.
struct ItemSeed;

impl<'de> DeserializeSeed<'de> for ItemSeed {
    type Value = Option<RawMessage>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ItemVisitor)
    }
}

/// Visitor for one batch item.
struct ItemVisitor;

impl<'de> Visitor<'de> for ItemVisitor {
    type Value = Option<RawMessage>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON-RPC batch item")
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Ok(Some(capture_message(map)?))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(BoundedIgnore::new())?.is_some() {}
        Ok(None)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
}

/// Capture envelope fields from a message object, last key wins
/// (duplicate keys overwrite, matching DOM map semantics).
fn capture_message<'de, A>(mut map: A) -> Result<RawMessage, A::Error>
where
    A: MapAccess<'de>,
{
    let mut message = RawMessage::empty();
    while let Some(key) = map.next_key::<std::borrow::Cow<'_, str>>()? {
        match key.as_ref() {
            "jsonrpc" => message.version = map.next_value_seed(VersionSeed)?,
            "id" => message.id = map.next_value_seed(IdSeed)?,
            "method" => message.method = map.next_value_seed(MethodSeed)?,
            "result" | "error" => {
                map.next_value_seed(BoundedIgnore::new())?;
                message.has_result_or_error = true;
            },
            _ => {
                map.next_value_seed(BoundedIgnore::new())?;
            },
        }
    }
    Ok(message)
}

/// Seed capturing `jsonrpc` as string-or-missing.
struct VersionSeed;

impl<'de> DeserializeSeed<'de> for VersionSeed {
    type Value = RawVersion;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(VersionVisitor)
    }
}

/// Visitor behind [`VersionSeed`].
struct VersionVisitor;

impl<'de> Visitor<'de> for VersionVisitor {
    type Value = RawVersion;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a jsonrpc version value")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(RawVersion::Str(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(RawVersion::Str(v))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(RawVersion::Missing)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(RawVersion::Missing)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(RawVersion::Missing)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(RawVersion::Missing)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RawVersion::Missing)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(BoundedIgnore::new())?;
        }
        Ok(RawVersion::Missing)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element_seed(BoundedIgnore::new())?.is_some() {}
        Ok(RawVersion::Missing)
    }
}

/// Seed capturing and classifying the `id` field.
struct IdSeed;

impl<'de> DeserializeSeed<'de> for IdSeed {
    type Value = RawId;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(IdVisitor)
    }
}

/// Visitor behind [`IdSeed`].
struct IdVisitor;

impl<'de> Visitor<'de> for IdVisitor {
    type Value = RawId;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON-RPC id value")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(RawId::Str(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(RawId::Str(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(RawId::Integer(v.to_string()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(RawId::Integer(v.to_string()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
        // Render through serde_json::Number so the string form is
        // byte-identical to the old DOM-based `Number::to_string`.
        Ok(serde_json::Number::from_f64(v).map_or(RawId::Invalid, |n| RawId::Number(n.to_string())))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RawId::Null)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(RawId::Invalid)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(BoundedIgnore::new())?;
        }
        Ok(RawId::Invalid)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element_seed(BoundedIgnore::new())?.is_some() {}
        Ok(RawId::Invalid)
    }
}

/// Seed capturing `method` as string-or-not.
struct MethodSeed;

impl<'de> DeserializeSeed<'de> for MethodSeed {
    type Value = RawMethod;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(MethodVisitor)
    }
}

/// Visitor behind [`MethodSeed`].
struct MethodVisitor;

impl<'de> Visitor<'de> for MethodVisitor {
    type Value = RawMethod;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON-RPC method value")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(RawMethod::Str(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(RawMethod::Str(v))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(RawMethod::NotString)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(RawMethod::NotString)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(RawMethod::NotString)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(RawMethod::NotString)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RawMethod::NotString)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(BoundedIgnore::new())?;
        }
        Ok(RawMethod::NotString)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element_seed(BoundedIgnore::new())?.is_some() {}
        Ok(RawMethod::NotString)
    }
}
