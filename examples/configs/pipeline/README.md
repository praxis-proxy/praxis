# Pipeline Examples

Patterns for organizing and reusing filter chains.

## When to Use

- Share filter chains across listeners
- Compose large pipelines from small, reusable chains
- Put separate concerns (authentication, routing, transformation) in their
  own chains
- Test pipeline configurations in isolation

## Key Concepts

**Filter chains** are named sequences of filters. A listener lists the chains
it runs, and chains can reference other chains to build a composite pipeline.
Filters can also be defined inline, directly in a listener or branch.

**Inherited chain conditions**: a chain's `conditions:` apply to every filter
in it (effective = chain AND filter). See `inherited-conditions.yaml`.

Keep each chain to one concern and name it for its purpose, so it can be
reused (authentication, observability, routing) and tested on its own.

## Related Documentation

- [Pipeline Concepts](../../../docs/architecture/pipeline-concepts.md)
- [Filter Configuration](../../../docs/filters/README.md)
- [Branch Chains](../../../docs/filters/branch-chains.md)
