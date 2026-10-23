# Traffic Management Examples

Traffic management filters control routing, load balancing, failure handling, and request lifecycle behavior.

## When to Use

- Route requests to different upstreams based on path, headers, or body content
- Distribute load across healthy endpoints with various strategies
- Handle failures with retries, circuit breakers, and timeouts
- Limit request rates or impose quotas per client
- Enforce deadlines for upstream requests (HTTP and gRPC)

## Key Filters

**Router**: Selects an upstream cluster based on path prefixes, exact matches, regex patterns, or header values. Supports routing on body-derived metadata.

**Load Balancer**: Distributes requests across cluster endpoints using round-robin, least-request, or random strategies. Integrates with active health checks.

**Retry**: Retries failed requests with configurable backoff, jitter, and budget limits. Supports per-status-code and per-method retry policies.

**Circuit Breaker**: Temporarily stops sending traffic to failing upstreams to prevent cascading failures and allow recovery time.

**Rate Limit**: Enforces request rate limits using token bucket or leaky bucket algorithms. Supports per-client keying.

**Timeout**: Sets deadlines for upstream requests. For gRPC, translates to `grpc-timeout` headers.

## Best Practices

- Use health checks with circuit breakers for robust failure handling
- Set retry budgets to prevent retry storms
- Combine rate limiting with backpressure signals (429 responses)
- Route on promoted headers (from `json_body_field`) rather than buffering bodies in the router itself

## Related Documentation

- [Router Filter](../../../docs/filters/http/traffic_management/router.md)
- [Load Balancing](../../../docs/filters/http/traffic_management/load_balancer.md)
- [Health Checking](../../../docs/operating/health-checking.md)
