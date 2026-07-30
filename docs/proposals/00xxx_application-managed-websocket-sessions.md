---
issue: TODO
discussion: TODO
status: proposed
authors:
  - franciscojavierarceo
graduation_criteria:
  - Originating GitHub Discussion approved and EPIC issue linked
  - How? section added after the What? and Why? direction is accepted
  - Public extension boundary reviewed by Praxis core and downstream
    extension stakeholders
  - WebSocket lifecycle, backpressure, resource-limit, cancellation,
    and security requirements agreed
  - Follow-up design demonstrates both a native WebSocket upstream and
    an HTTP/SSE upstream without provider-specific behavior in core
stakeholders:
  - franciscojavierarceo
  - shaneutt
  - usize
---

# Application-Managed WebSocket Sessions

## What?

Add an opt-in application-managed WebSocket session capability to
Praxis. An extension should be able to claim a validated WebSocket
upgrade and asynchronously consume and produce complete WebSocket
messages for the lifetime of that connection.

This capability complements the existing transparent WebSocket proxy.
Routes that do not opt in continue forwarding upgraded bytes unchanged.
Application-managed routes deliberately terminate the downstream
WebSocket in Praxis so an extension can implement an application
protocol that cannot be expressed as a transparent byte tunnel.

The capability is independent of any particular application protocol,
provider, or upstream transport. An application-managed session may
mediate another WebSocket connection, translate messages to an
HTTP-streaming upstream, or produce responses through another
extension-owned workflow. Praxis core owns the generic transport
lifecycle; extensions own application semantics.

### Goals

- Let explicitly configured extensions accept a validated WebSocket
  upgrade and run an asynchronous, bidirectional session.
- Deliver complete text and binary messages rather than exposing
  arbitrary transport chunks as application messages.
- Let an application consume, replace, suppress, and produce messages
  while preserving message ordering.
- Support persistent connections that carry multiple logical
  application operations.
- Keep the upstream transport independent from the downstream
  WebSocket. Native WebSocket and HTTP/SSE upstreams must both be
  possible without provider-specific logic in Praxis core.
- Keep handshake validation, RFC 6455 framing, control frames,
  fragmentation, negotiated extensions, close handling, cancellation,
  backpressure, timeouts, and resource limits under framework control.
- Preserve handshake-time authentication, tenant identity,
  authorization policy, and immutable connection context across the
  managed session while permitting authorized routing decisions for
  each logical operation.
- Provide lifecycle and failure signals suitable for metrics,
  tracing, and application-level diagnostics.
- Preserve the existing transparent upgraded-connection fast path for
  every route that does not select application management.
- Keep application-managed sessions compatible with dynamic pipeline
  reload by retaining the configuration and extension state selected
  for an accepted connection.

### Non-Goals

- Adding OpenAI Responses, vLLM, Codex, or any other
  provider-specific protocol to Praxis core.
- Replacing transparent WebSocket proxying as the default behavior.
- Requiring every WebSocket connection to be decoded into complete
  application messages.
- Requiring an upstream server to support WebSockets.
- Defining response hydration, conversation persistence, token
  accounting, or provider credential policy in Praxis core.
- Persisting or logging raw WebSocket messages, prompts, responses,
  tool payloads, credentials, or other application content.
- Treating passive observation as sufficient for routes that must
  modify messages or initiate independent upstream work.
- Acting as a general-purpose forward proxy or TLS interception
  proxy.

### Required Capabilities

**Explicit session selection**

Application management is selected by trusted configuration and
request processing before the upgrade completes. An arbitrary
client-supplied header cannot activate an application handler or
choose its protected configuration.

**Framework-owned WebSocket transport**

Praxis performs the downstream handshake and owns protocol correctness
for the resulting connection. Extensions interact with bounded
message-level primitives rather than client masking, frame fragments,
or raw upgraded-body chunks.

**Asynchronous bidirectional execution**

An application can wait for external state or upstream events without
blocking a synchronous response callback. Downstream reads, upstream
work, downstream writes, cancellation, and connection shutdown remain
coordinated and backpressured.

**Transport-independent upstream work**

The application is not required to open a matching upstream WebSocket.
It can use a native WebSocket upstream when one implements the desired
protocol, or translate each logical operation to an HTTP or streaming
HTTP exchange when that is the available backend interface.

**Connection-scoped policy**

The accepted session retains the authenticated identity, authorization
policy, selected application, and relevant immutable configuration for
its lifetime. Later application messages cannot switch tenants,
handlers, or protected upstream policy through untrusted fields.
Applications may still select an eligible upstream for each logical
operation within that captured policy.

**Bounded failure behavior**

The framework and application can distinguish handshake rejection,
application errors, upstream errors, protocol errors, cancellation,
and disconnects. Failure policy is explicit: a route that requires
application processing does not silently fall back to an uninspected
transparent tunnel.

## Why?

### Motivation

Praxis currently forwards HTTP/1.1 WebSocket upgrades as transparent
bidirectional byte streams. This is the correct behavior for a reverse
proxy whose downstream and upstream speak the same application
protocol and whose filters only need to process the opening HTTP
exchange.

After a successful upgrade, however, Praxis intentionally excludes the
raw bytes from its ordinary HTTP body-filter lifecycle. The proxy does
not expose complete WebSocket messages, and the HTTP lifecycle models
the connection as one request ending in a `101` response. An extension
therefore cannot safely implement several logical operations carried
over one persistent socket, perform asynchronous work for an
application message, or generate application messages independently
of an upstream byte stream.

That gap matters for AI clients and backends whose supported transports
do not line up exactly.

OpenAI Codex uses the Responses API WebSocket mode and sends
`response.create` messages over a persistent connection. OpenAI's SaaS
Responses API provides a compatible native WebSocket upstream, so a
Praxis AI application can mediate WebSocket messages while retaining
the upstream protocol and streaming behavior. OpenAI documents this
transport at `wss://api.openai.com/v1/responses`, with repeated
`response.create` events on one connection.

vLLM provides the Responses API over HTTP, returning JSON or
server-sent events for streaming responses. It does not need to expose
the same WebSocket transport for Praxis to serve the Codex client. A
Praxis AI application should be able to accept the downstream
WebSocket, hydrate and validate each logical Responses request, invoke
vLLM over HTTP/SSE, and emit the resulting Responses events as
WebSocket messages.

Both cases require the same core capability: an application owns the
logical WebSocket session while remaining free to choose its upstream
transport. Encoding either OpenAI WebSocket behavior or a vLLM bridge
in Praxis core would put provider policy in the wrong layer. Requiring
a separate sidecar would duplicate listener security, lifecycle,
limits, cancellation, tracing, and configuration that Praxis already
owns.

Passive upgraded-stream observation does not close this gap. A
read-only observer can extract metadata, but it cannot hydrate a
request, replace a message, wait for an external lookup, suppress
forwarding, initiate an HTTP exchange, or synthesize downstream
events. Exposing raw upgraded bytes through HTTP body hooks is also
insufficient: transport chunks are not WebSocket message boundaries,
and the existing response-body callback cannot host an independent
asynchronous application lifecycle.

Forcing clients to abandon WebSocket mode would avoid the immediate
transport mismatch but would change their preferred behavior and
prevent Praxis from supporting persistent application sessions.
Adding native WebSocket support to every backend would likewise make
backend transport an unnecessary prerequisite for gateway
compatibility.

Application-managed sessions establish a reusable boundary:

- Praxis core owns secure, bounded WebSocket transport;
- downstream extensions own application protocols and logical
  operations;
- upstream adapters select WebSocket, HTTP/SSE, or another appropriate
  transport; and
- transparent routes retain today's forwarding path and cost.

This boundary supports the immediate Responses use cases without
making the core API Responses-specific, and it leaves room for other
stateful WebSocket protocols that require gateway participation.

References:

- [OpenAI Responses API WebSocket mode][openai-websocket]
- [OpenAI `response.create` WebSocket event][openai-response-create]
- [vLLM OpenAI-compatible server][vllm-server]
- [vLLM Responses API router source][vllm-responses-router]

[openai-websocket]: https://developers.openai.com/api/docs/guides/websocket-mode
[openai-response-create]: https://developers.openai.com/api/reference/resources/responses/websocket-events#response.create
[vllm-server]: https://docs.vllm.ai/en/latest/serving/online_serving/
[vllm-responses-router]: https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/openai/responses/api_router.py

### User Stories

- As a Praxis AI operator, I want Codex to use its normal Responses
  WebSocket transport through Praxis so that the gateway can hydrate
  and govern each logical request.
- As an OpenAI SaaS user, I want Praxis to mediate a Responses
  WebSocket connection to the compatible SaaS WebSocket upstream so
  that streaming and persistent connection behavior are preserved.
- As a vLLM operator, I want the same downstream Responses WebSocket
  to use vLLM's HTTP/SSE API so that vLLM does not need a WebSocket
  implementation merely to support WebSocket clients.
- As an extension author, I want complete, backpressured WebSocket
  messages and an asynchronous session lifecycle so that I do not
  reimplement framing and connection management inside raw body
  callbacks.
- As a security engineer, I want the application handler, tenant, and
  upstream policy fixed from trusted handshake-time context so that a
  later message cannot cross an authorization boundary.
- As an SRE, I want application, upstream, cancellation, and protocol
  failures to have distinct lifecycle signals so that persistent
  sessions can be diagnosed without logging their content.
- As a Praxis operator, I want ordinary WebSocket routes to retain
  transparent forwarding unless I explicitly enable an application
  handler so that adopting this capability does not change unrelated
  traffic.
- As a Praxis maintainer, I want provider protocols to remain outside
  core so that the WebSocket lifecycle can evolve independently from
  OpenAI, vLLM, or other downstream extensions.
