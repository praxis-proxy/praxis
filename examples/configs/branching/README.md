# Branching Examples

Branch chains enable conditional pipeline execution based on filter results, allowing request paths to diverge and optionally rejoin at defined points.

## When to Use

- Skip expensive processing (guardrails, body inspection) for trusted clients
- Short-circuit pipelines early when a security filter detects a threat
- Run different transformation logic based on request characteristics
- Implement multi-stage validation with fallback paths

## Key Concepts

**Branches** execute when a filter emits a result matching the branch's `on_result` condition. Each branch can:
- Run inline filters
- Reference a named top-level chain
- Nest additional branches (multi-level decision trees)
- Rejoin at `next` (default), `terminal`, or a named filter

**Rejoin points** control where execution resumes after a branch completes. Use `terminal` to stop pipeline processing immediately, or `named` to jump to a specific filter.

**Re-entrance** allows looping back to a named filter with iteration limits to prevent infinite loops.

## Related Documentation

- [Branch Chain Configuration](../../../docs/filters/branch-chains.md)
- [Pipeline Concepts](../../../docs/architecture/pipeline-concepts.md)
- [Filter Reference](../../../docs/filters/reference.md)
