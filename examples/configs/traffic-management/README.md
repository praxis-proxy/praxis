# Traffic Management Examples

Traffic management filters control routing, load balancing, failure handling,
and the request lifecycle.

## When to Use

- Route requests to different upstreams by path, headers, or body content
- Spread load across healthy endpoints
- Handle failures with retries, circuit breakers, and timeouts
- Limit request rates per client
- Enforce deadlines on upstream requests (HTTP and gRPC)

## Key Filters

- [`router`](../../../docs/filters/http/traffic_management/router.md): picks
  an upstream cluster by path prefix, exact path, host, or header, including
  headers promoted from the body. Per-route retry policies set retriable
  status codes, backoff, and a retry budget.
- [`load_balancer`](../../../docs/filters/http/traffic_management/load_balancer.md):
  picks an endpoint in the cluster (`round_robin`, `least_connections`, `p2c`,
  `random`, `consistent_hash`, `maglev`, `ring_hash`, `subset`, `zone_aware`,
  `priority`) and works with active health checks.
- [`circuit_breaker`](../../../docs/filters/http/traffic_management/circuit_breaker.md):
  stops sending traffic to a failing upstream so it can recover.
- [`rate_limit`](../../../docs/filters/http/traffic_management/rate_limit.md):
  token bucket limits, per client or global, with 429 responses.
- [`timeout`](../../../docs/filters/http/traffic_management/timeout.md) and
  [`grpc_timeout`](../../../docs/filters/http/traffic_management/grpc_timeout.md):
  deadlines for upstream requests; `grpc_timeout` honors the `grpc-timeout`
  header.

Pair health checks with circuit breakers, set retry budgets to prevent retry
storms, and route on headers promoted by `json_body_field` rather than
buffering bodies in the router.

## Related Documentation

- [Router Filter](../../../docs/filters/http/traffic_management/router.md)
- [Load Balancing](../../../docs/filters/http/traffic_management/load_balancer.md)
- [Health Checking](../../../docs/operating/health-checking.md)
