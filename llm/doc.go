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
