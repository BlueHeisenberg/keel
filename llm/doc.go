// SPDX-License-Identifier: Apache-2.0

// Package llm is a client for OpenAI-compatible /chat/completions endpoints:
// blocking completions, SSE streaming, incremental tool-call assembly, and
// repair of malformed tool arguments.
//
// It holds no model registry, no credential store and no authorization policy.
// An [Endpoint] — base URL, model name, API key — is supplied on every call and
// the caller decides where it came from. There is no routing, no fallback, no
// connection pooling and no retry policy here either: those are decisions about
// which machine to talk to, and they belong to the program that knows what the
// machines are.
//
// What this package does provide, to make those decisions possible, is a typed
// distinction between the two ways a call can fail. A [TransportError] means the
// bytes never made it there and back — connection refused, TLS failure, a stream
// cut mid-flight — and the same request sent to a different endpoint may well
// succeed. An [APIError] means the endpoint answered, and its answer was a
// refusal; re-sending it elsewhere is usually just a slower way to be refused
// again. Use [IsTransport] and [IsAPI], or errors.As with the concrete types.
// Two sentinels sit outside that pair: [ErrInvalidRequest] for a call that could
// not be built, and [ErrEmptyResponse] for a success that carried no completion.
// The second covers a case the finish reason cannot: a reasoning model that
// spends its turn thinking and answers nothing. [EmptyResponseError.Reasoning]
// is what tells that apart from an endpoint that is simply broken, and the two
// deserve opposite responses.
//
// Error strings here are safe to log. [APIError] deliberately keeps the
// provider's prose out of its Error method, because those bodies quote the
// request back — see the type documentation.
//
// # Deadlines
//
// Use [Endpoint.Timeout] for per-attempt deadlines, and reserve ctx for the real
// caller's lifetime.
//
// The two are not interchangeable, and getting it wrong fails quietly in the
// direction that hurts. A deadline set on ctx belongs to the caller, so when it
// fires this package reports the caller's own context error — not a
// [TransportError] — because from in here a caller that has given up and a
// caller that set a short deadline look identical, and hanging up teaches you
// nothing about the endpoint. A deadline set on [Endpoint.Timeout] belongs to
// the attempt, and when it fires you get a [TransportError] wrapping
// context.DeadlineExceeded, because an endpoint that stopped answering is
// precisely a fact about that endpoint.
//
// So a caller that wraps each attempt in its own context.WithTimeout will see
// every slow endpoint classified as its own cancellation, [IsTransport] will
// report false, and cooldown will never trigger for the machines that most
// deserve it. Put the per-attempt bound on the Endpoint.
//
// # Naming
//
// [ChatMessage.Role] is the wire protocol's own term for who authored a message
// — one of [RoleSystem], [RoleUser], [RoleAssistant], [RoleTool]. It has nothing
// to do with authorization: it grants no permission, identifies no person, and
// is not related to whatever a consuming product means by a role. It is named
// after the protocol because that is what every provider's documentation calls
// it and what any user of this package will reach for first.
package llm
