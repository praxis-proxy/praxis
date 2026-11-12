# HTTP Correctness

A proxy must enforce HTTP invariants that upstream servers
and downstream clients may not. These are critical
correctness and security concerns.

The Praxis project _strongly_ prefers relying on
[Cloudflare]'s protocol implementations whenever feasible.
Praxis is modular, so it is possible to swap in other
implementations, but Cloudflare has a good track record of
providing correct, hardened and high performance protocol
implementations which are battle-tested with years of
production experience.

- For TCP, we rely on [Pingora]
- For HTTP/1 + HTTP/2, we rely on [Pingora]
- For QUIC + HTTP/3, we rely on [Quiche]

[Cloudflare]: https://cloudflare.com
[Pingora]: https://github.com/cloudflare/pingora
[Quiche]: https://github.com/cloudflare/quiche

## What Pingora Handles

Pingora 0.8.x handles several correctness concerns at
the framework level:

- **Request smuggling**: Content-Length vs
  Transfer-Encoding validation per
  [RFC 9112](https://datatracker.ietf.org/doc/html/rfc9112).
  Invalid Content-Length headers are rejected. Request
  body draining before connection reuse.
- **Backpressure**: H2 flow control and bounded H1
  channels between upstream reader and downstream writer.
- **Connection pool safety**: connections are only pooled
  when requests complete cleanly. Unconsumed response
  bodies cause the connection to be discarded.

## What Praxis Handles

- **Hop-by-hop headers**: Pingora does not strip
  hop-by-hop headers on the H1-to-H1 path. Praxis
  strips `Connection`, `Keep-Alive`,
  `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`,
  and `Proxy-Authenticate`, plus any custom headers
  declared in the `Connection` header value.
  `Proxy-Authorization` is stripped on the request
  path only (it is request-specific per RFC 9110).
  Stripping is applied on both request
  (`upstream_request_filter`) and response
  (`response_filter`) paths per
  [RFC 9110 Section 7.6.1].
- **Host header validation**: Praxis rejects requests
  with conflicting `Host` headers (400) and
  canonicalizes duplicate identical values. Missing
  `Host` on HTTP/1.1 is rejected per
  [RFC 9112](https://datatracker.ietf.org/doc/html/rfc9112).
- **Proxy headers**: Pingora adds no `X-Forwarded-For`,
  `X-Forwarded-Proto`, or similar headers. Praxis
  injects these with configurable trust boundaries
  via the `forwarded_headers` filter.
- **Reserved internal headers**: Praxis uses
  `x-praxis-*` and AI extension prefixes (`x-ext-protocol-*`,
  `x-ext-agent-*`, reserved for the `praxis-ai` package)
  for proxy-internal routing metadata (e.g.
  body-derived fields promoted to headers). These are
  rejected from client requests (400), stripped before
  forwarding to backends, and stripped from backend
  responses before reaching clients.
- **Retry safety**: GET, HEAD, OPTIONS, and QUERY are eligible for automatic
  retries under the configured policy. Other methods require
  `allow_non_idempotent`. Pingora's separate `ReusedOnly` path requires a
  reused connection and an intact replay buffer, regardless of method.
  A fresh-connection EOF on that path is not retried. A truncated replay
  buffer is never retried.

[RFC 9110 Section 7.6.1]:https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1

## HTTP QUERY

Both network backends forward [RFC 10008] QUERY requests, including the
request body, over HTTP/1.1 and HTTP/2. QUERY uses the normal body path;
body filters and configured hedging can request buffering as usual.

QUERY is safe and idempotent, so it joins GET, HEAD, and OPTIONS in the
automatic replay policy. Retry conditions, attempt and budget limits,
deadlines, and body replay limits still apply. Replaying a consumed request
body is limited to 64 KiB; larger requests can still be forwarded. Configured
hedging on Pingora also admits QUERY under its existing attempt and body limits.

The origin implements the query operation and validates its media type and
content. Praxis forwards the origin's `Accept-Query`, `Allow`, and redirect
responses. QUERY's cacheability does not add a response cache to Praxis.

For browser use, explicitly add QUERY to the CORS `allow_methods` list and
allow the request's `Content-Type` header. The CSRF filter keeps its existing
defaults: QUERY requires a trusted origin unless explicitly included in
`safe_methods`. See the functional
[HTTP QUERY example](../../examples/configs/traffic-management/http-query.yaml).

[RFC 10008]: https://datatracker.ietf.org/doc/html/rfc10008

## Related

- [Architecture Overview](overview.md)
- [Connection Lifecycle](connection-lifecycle.md)
- [RFC Conformance conventions](../developing/conventions.md#rfc-conformance)
