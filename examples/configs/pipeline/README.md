# Pipeline Examples

Pipeline composition patterns for organizing and reusing filter chains.

## When to Use

- Share filter chains across multiple listeners
- Compose complex pipelines from smaller, reusable chains
- Separate concerns (authentication, routing, transformation) into dedicated chains
- Test pipeline configurations in isolation

## Key Concepts

**Filter Chains**: Named sequences of filters that can be referenced by listeners or other chains.

**Chain References**: Listeners specify which chains to execute. Chains can reference other chains to build composite pipelines.

**Inline vs Named Chains**: Filters can be defined inline (directly in a listener or branch) or as named top-level chains that are referenced by name.

**Inherited Chain Conditions**: A chain's `conditions:` are inherited by
every filter it contains (effective = chain AND filter). See
`inherited-conditions.yaml`.

## Best Practices

- Create reusable chains for common patterns (authentication, observability, routing)
- Use descriptive chain names that reflect their purpose
- Keep chains focused on a single concern
- Test chains independently before composing them

## Related Documentation

- [Pipeline Architecture](../../../docs/architecture/pipeline.md)
- [Filter Configuration](../../../docs/filters/README.md)
- [Branch Chains](../../../docs/architecture/branch-chains.md)
