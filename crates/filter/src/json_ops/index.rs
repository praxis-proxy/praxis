// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Compile-time trie index for JSON Pointer operations.
//!
//! Digit tokens are linked as both an object key and an array index so RFC 6901
//! parent-type dispatch works: `/0` rewrites `{"0": ...}` and `[...]` from the
//! same compiled op. `/-` is array-append for add, not object key `"-"`.

use std::collections::HashMap;

use super::ops::{CompiledOp, OpKind};

// -----------------------------------------------------------------------------
// Path tokens
// -----------------------------------------------------------------------------

/// One segment of the walk path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PathToken {
    /// Object member key (unescaped or decoded).
    Key(String),
    /// Array index.
    Index(usize),
}

/// Whether `path` equals decoded pointer `tokens`.
pub(super) fn path_eq_tokens(path: &[PathToken], tokens: &[String]) -> bool {
    if path.len() != tokens.len() {
        return false;
    }
    path.iter().zip(tokens).all(|(segment, token)| match segment {
        PathToken::Key(key) => key == token,
        PathToken::Index(idx) => array_index(token) == Some(*idx),
    })
}

// -----------------------------------------------------------------------------
// Trie
// -----------------------------------------------------------------------------

/// Trie node id.
type NodeId = u32;

/// One node in the compiled pointer trie.
#[derive(Clone, Debug, Default)]
struct PathNode {
    /// Any op extends strictly beyond this prefix.
    nested: bool,
    /// Extract op index at exactly this path.
    extract_idx: Option<u32>,
    /// Mutating op index at exactly this path.
    mutate_idx: Option<u32>,
    /// Any extract op passes through this prefix.
    extract_branch: bool,
    /// Object-key children; digit tokens are also linked in `array_children`.
    object_children: HashMap<String, NodeId>,
    /// Array-index children; digit tokens are also linked in `object_children`.
    array_children: HashMap<usize, NodeId>,
    /// Add op targeting `/path/-`.
    array_append: Option<u32>,
}

/// Precompiled lookup structure for pointer ops.
#[derive(Clone, Debug)]
pub(super) struct OpPathIndex {
    /// Trie nodes; index 0 is the document root.
    nodes: Vec<PathNode>,
    /// Empty sink used when `path` is not in the trie (no parent fallthrough).
    miss: NodeId,
    /// Fallback when a node id is out of range (`build` always inserts root).
    empty: PathNode,
}

/// RFC 6901 array index: unsigned integer with no leading zeros (`0` allowed).
pub(super) fn array_index(token: &str) -> Option<usize> {
    if token.is_empty() || (token.starts_with('0') && token.len() > 1) {
        return None;
    }
    if !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// Convert a compact node id to a `Vec` index.
fn nid(id: NodeId) -> Option<usize> {
    usize::try_from(id).ok()
}

impl OpPathIndex {
    /// Build a trie from compiled ops.
    #[expect(clippy::too_many_lines, reason = "trie construction is a linear walk over ops")]
    pub(super) fn build(ops: &[CompiledOp]) -> Self {
        let mut nodes = vec![PathNode::default()];

        for (idx, op) in ops.iter().enumerate() {
            let Some(idx_u32) = u32::try_from(idx).ok() else {
                continue;
            };

            if op.tokens.is_empty() {
                if let Some(node) = nodes.get_mut(0) {
                    if op.kind == OpKind::Extract {
                        node.extract_idx = Some(idx_u32);
                        node.extract_branch = true;
                    } else if op.kind.is_mutating() {
                        node.mutate_idx = Some(idx_u32);
                    }
                }
                continue;
            }

            let mut node_id = 0_u32;
            for (depth, token) in op.tokens.iter().enumerate() {
                let is_last = depth.saturating_add(1) == op.tokens.len();

                // JSON Pointer "-" is array-append for add, not object key "-".
                if token == "-" && is_last && op.kind == OpKind::Add {
                    if let Some(node) = nid(node_id).and_then(|i| nodes.get_mut(i)) {
                        node.array_append = Some(idx_u32);
                    }
                    break;
                }

                let parent_idx = node_id;
                node_id = ensure_child(&mut nodes, parent_idx, token);

                if let Some(parent) = nid(parent_idx).and_then(|i| nodes.get_mut(i)) {
                    if !is_last {
                        parent.nested = true;
                    }
                    if op.kind == OpKind::Extract {
                        parent.extract_branch = true;
                    }
                }

                if is_last && let Some(node) = nid(node_id).and_then(|i| nodes.get_mut(i)) {
                    match op.kind {
                        OpKind::Extract => node.extract_idx = Some(idx_u32),
                        OpKind::Add | OpKind::Replace | OpKind::Remove => node.mutate_idx = Some(idx_u32),
                    }
                }
            }
        }

        let miss = u32::try_from(nodes.len()).unwrap_or(0);
        nodes.push(PathNode::default());
        Self {
            nodes,
            miss,
            empty: PathNode::default(),
        }
    }

    /// Node `id`, or root, or `empty` if the trie has no nodes.
    fn node(&self, id: NodeId) -> &PathNode {
        nid(id)
            .and_then(|i| self.nodes.get(i))
            .or_else(|| self.nodes.first())
            .unwrap_or(&self.empty)
    }

    /// Whether any extract op might match `path` or extend beyond it.
    pub(super) fn extract_branch_at(&self, path: &[PathToken]) -> bool {
        let node = self.node_at(path);
        node.extract_branch || node.extract_idx.is_some()
    }

    /// Whether any extract op targets a path strictly below `path`.
    pub(super) fn has_descendant_extracts(&self, path: &[PathToken]) -> bool {
        self.node_at(path).extract_branch
    }

    /// Whether this node is an op target or has ops below it (must tokenize, not span-copy).
    pub(super) fn has_descendant_ops(&self, path: &[PathToken]) -> bool {
        Self::node_has_work(self.node_at(path))
    }

    /// Whether `rewrite_value` must run for object child `key`.
    pub(super) fn child_needs_rewrite(&self, path: &[PathToken], key: &str) -> bool {
        self.child_object_node(path, key)
            .is_some_and(|node_id| Self::node_has_work(self.node(node_id)))
    }

    /// Whether `rewrite_value` must run for array element `idx`.
    pub(super) fn child_index_needs_rewrite(&self, path: &[PathToken], idx: usize) -> bool {
        self.child_array_node(path, idx)
            .is_some_and(|node_id| Self::node_has_work(self.node(node_id)))
    }

    /// Whether this node is an op target or has ops below it.
    fn node_has_work(node: &PathNode) -> bool {
        node.nested
            || node.mutate_idx.is_some()
            || node.extract_idx.is_some()
            || !node.object_children.is_empty()
            || !node.array_children.is_empty()
            || node.array_append.is_some()
    }

    /// Extract op index at exactly `path`.
    pub(super) fn extract_at(&self, path: &[PathToken]) -> Option<u32> {
        self.node_at(path).extract_idx
    }

    /// Mutating op index at `path` + object key `last`.
    pub(super) fn mutate_child_key(&self, path: &[PathToken], last: &str) -> Option<u32> {
        self.child_object_node(path, last)
            .and_then(|node_id| self.node(node_id).mutate_idx)
    }

    /// Mutating op index at `path` + array index `idx`.
    pub(super) fn mutate_at_index(&self, path: &[PathToken], idx: usize) -> Option<u32> {
        self.child_array_node(path, idx)
            .and_then(|node_id| self.node(node_id).mutate_idx)
    }

    /// Add targeting `/path/-`.
    pub(super) fn add_append(&self, path: &[PathToken]) -> Option<u32> {
        self.node_at(path).array_append
    }

    /// Trie node at `path`, or the empty miss node if `path` is not in the trie.
    fn node_at(&self, path: &[PathToken]) -> &PathNode {
        let mut node_id = 0_u32;
        for segment in path {
            let node = self.node(node_id);
            let next = match segment {
                PathToken::Key(key) => node.object_children.get(key).copied(),
                PathToken::Index(idx) => node.array_children.get(idx).copied(),
            };
            match next {
                Some(id) => node_id = id,
                None => return self.node(self.miss),
            }
        }
        self.node(node_id)
    }

    /// Child node for object key `key` under `path`.
    fn child_object_node(&self, path: &[PathToken], key: &str) -> Option<NodeId> {
        self.node_at(path).object_children.get(key).copied()
    }

    /// Child node for array index `idx` under `path`.
    fn child_array_node(&self, path: &[PathToken], idx: usize) -> Option<NodeId> {
        self.node_at(path).array_children.get(&idx).copied()
    }
}

/// Existing child for `token`, if already linked as an object key or array index.
fn child_id_for_token(nodes: &[PathNode], parent_idx: u32, token: &str) -> Option<NodeId> {
    let parent = nid(parent_idx).and_then(|i| nodes.get(i))?;
    if let Some(idx) = array_index(token)
        && let Some(&id) = parent.array_children.get(&idx)
    {
        return Some(id);
    }
    parent.object_children.get(token).copied()
}

/// Link `token` as an object key and, when it is an RFC 6901 array index, as that index.
fn link_token(nodes: &mut [PathNode], parent_idx: u32, token: &str, child: NodeId) {
    let Some(parent) = nid(parent_idx).and_then(|i| nodes.get_mut(i)) else {
        return;
    };
    parent.object_children.entry(token.to_owned()).or_insert(child);
    if let Some(idx) = array_index(token) {
        parent.array_children.entry(idx).or_insert(child);
    }
}

/// Get or create the child node for one pointer token.
///
/// Digit tokens are reachable both as object keys (`"0"`) and as array indices,
/// matching RFC 6901 parent-type dispatch. `"-"` is an object key and, for add,
/// also array append on the parent.
fn ensure_child(nodes: &mut Vec<PathNode>, parent_idx: u32, token: &str) -> NodeId {
    if let Some(id) = child_id_for_token(nodes, parent_idx, token) {
        link_token(nodes, parent_idx, token, id);
        return id;
    }
    let child = u32::try_from(nodes.len()).unwrap_or(0);
    nodes.push(PathNode::default());
    link_token(nodes, parent_idx, token, child);
    child
}
