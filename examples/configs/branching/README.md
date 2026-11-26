# Branching Examples

Branch chains run part of a pipeline conditionally, based on filter results.
A request path can diverge and rejoin at a defined point.

## When to Use

- Skip expensive processing (guardrails, body inspection) for trusted clients
- Stop the pipeline early when a security filter detects a threat
- Run different transformations depending on the request
- Build multi-stage validation with fallback paths

## Key Concepts

A **branch** runs when a filter emits a result that matches its `on_result`
condition. A branch can run inline filters, reference a named top-level chain,
or nest further branches.

When a branch finishes, execution **rejoins** at `rejoin: next` (the
default), `rejoin: terminal` (stop the pipeline), or a filter's entry `name`.
**Re-entrance** loops back to an earlier named filter and requires
`max_iterations`.

## Related Documentation

- [Branch Chain Configuration](../../../docs/filters/branch-chains.md)
- [Pipeline Concepts](../../../docs/architecture/pipeline-concepts.md)
- [Filter Reference](../../../docs/filters/reference.md)
