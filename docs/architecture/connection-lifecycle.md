# Connection Lifecycle

## HTTP Connection Lifecycle

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Pingora
    participant RF as request_filter
    participant BF as request_body_filter
    participant UP as upstream_peer
    participant B as Backend
    participant RSF as response_filter
    participant RBF as response_body_filter

    C->>P: TCP + TLS + HTTP decode
    P->>RF: request_filter(session, ctx)
    RF->>RF: pipeline.execute_http_request()
    Note over RF: router sets ctx.cluster<br/>load_balancer sets ctx.upstream

    opt body present
        P->>BF: request_body_filter(body, eos)
        BF->>BF: buffer or stream through pipeline
    end

    P->>UP: upstream_peer(ctx)
    UP->>UP: build HttpPeer from ctx.upstream

    opt upstream connect failure
        P->>P: fail_to_connect (retry if idempotent)
    end

    P->>P: upstream_request_filter (strip hop-by-hop)
    P->>B: forward request
    B-->>P: response headers

    P->>RSF: response_filter(upstream_response, ctx)
    RSF->>RSF: pipeline.execute_http_response()

    loop each body chunk
        B-->>P: response body chunk
        P->>RBF: response_body_filter(body, eos)
    end

    P-->>C: response
    P->>P: logging (response-filter cleanup)
```

Request filters run in declared order and response filters in reverse.
`request_body_filter` runs only if a filter declares body access.
`response_body_filter` is `async`, but the `on_response_body` hooks it runs are
plain `fn`s.
`logging` re-runs the response filters when the response phase was skipped
(upstream error, filter rejection), and the upstream connection then goes back
to the pool. [Pingora Handler Lifecycle](pingora-handler-lifecycle.md)
describes each hook.

## TCP Connection Lifecycle

1. TCP accept, optional TLS handshake
2. `on_connect`: TCP filters run in order
3. Bidirectional byte forwarding to upstream
4. `on_disconnect`: TCP filters run on close

[TCP Proxy](tcp-proxy.md) covers SNI routing and timeouts.

## Related

- [Architecture Overview](overview.md)
- [Payload Processing](payload-processing.md)
- [HTTP Correctness](http-correctness.md)
