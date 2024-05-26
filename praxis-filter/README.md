# Praxis Filter

Filter pipeline engine for the Praxis proxy. All request
processing is implemented as filters.

Provides the `HttpFilter` and `TcpFilter` traits, the
pipeline executor, built-in filters, the filter registry,
and the `register_filters!` macro for custom extensions.

See the [docs](../docs/filters.md) for usage and the
[extensions guide](../docs/extensions.md) for writing
custom filters.
