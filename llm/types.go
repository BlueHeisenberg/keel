// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"encoding/json"
	"time"
)

// Endpoint identifies one OpenAI-compatible chat-completions endpoint and the
// credential used to reach it. It is passed to every call; this package never
// stores one, never caches one, and never reads any part of one from the
// environment.
type Endpoint struct {
	// BaseURL is the API root, including any version prefix — for example
	// "https://api.example.com/v1". "/chat/completions" is appended to it, after
	// trailing slashes are trimmed.
	BaseURL string

	// Model is the provider-side model name, sent as the "model" request field.
	Model string

	// APIKey is sent as "Authorization: Bearer <key>" when non-empty. It is
	// never logged, never included in an error message, and never persisted.
	// Supply it from wherever the caller keeps secrets.
	APIKey string

	// ExtraBody is shallow-merged over the generated request body, so
	// provider-specific knobs can be passed through — for example
	// {"chat_template_kwargs":{"enable_thinking":false}}. Keys present in
	// ExtraBody override the generated ones.
	ExtraBody json.RawMessage

	// Label is an optional human-readable identifier for this endpoint. It is
	// used only in log lines and error messages; it has no protocol meaning.
	Label string

	// Timeout bounds one call end to end, streaming included. Zero means no
	// bound beyond the caller's context, which is the right setting for long
	// streams. When the deadline fires the call returns a [TransportError]: an
	// endpoint that stopped answering is a reason to try a different one.
	Timeout time.Duration
}

// Role is the protocol's term for who authored a message. It carries no
// authorization meaning of any kind: it grants nothing, identifies nobody, and
// is unrelated to whatever a consuming product calls a role.
const (
	// RoleSystem is the instruction message that conditions the conversation.
	RoleSystem = "system"
	// RoleUser is a message from whoever is driving the conversation.
	RoleUser = "user"
	// RoleAssistant is a message produced by the model, possibly carrying tool
	// calls.
	RoleAssistant = "assistant"
	// RoleTool is the result of one tool call, fed back to the model.
	RoleTool = "tool"
)

// ChatMessage is one message in a conversation, in the OpenAI wire format.
//
// An assistant message that requests tools populates ToolCalls. A message
// carrying a tool result sets Role to [RoleTool] plus ToolCallID, Name and
// Content.
type ChatMessage struct {
	// Role is who authored this message: [RoleSystem], [RoleUser],
	// [RoleAssistant] or [RoleTool]. It is the protocol's own vocabulary and
	// says nothing about permissions.
	Role string `json:"role"`

	// Content is the message text. It deliberately has no omitempty: an
	// assistant message carrying tool_calls must still serialize
	// `"content": ""`, or stricter OpenAI-compatible servers reject the whole
	// conversation. Every other message kind populates it anyway.
	Content string `json:"content"`

	// ToolCalls are the tool invocations requested by an assistant message.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	// ToolCallID links a "tool" message back to the ToolCall it answers.
	ToolCallID string `json:"tool_call_id,omitempty"`

	// Name is the tool name on a "tool" message.
	Name string `json:"name,omitempty"`
}

// ToolCall is one tool invocation requested by the model.
type ToolCall struct {
	// ID is echoed back in the ToolCallID of the message carrying the result.
	// Providers that omit it get a deterministic "call_<n>" synthesized, because
	// an empty id makes strict servers reject the follow-up request.
	ID string `json:"id"`

	// Type is always "function" in the current protocol.
	Type string `json:"type"`

	// Function names the tool and carries its arguments.
	Function FunctionCall `json:"function"`
}

// FunctionCall holds the name and arguments of a tool invocation. Arguments is
// a JSON-encoded string rather than a parsed object, matching the wire format;
// it has passed through [SanitizeToolArgs] and is guaranteed to parse.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// FunctionSpec describes one callable function offered to the model.
type FunctionSpec struct {
	// Name is the identifier the model uses to call the function.
	Name string `json:"name"`

	// Description tells the model when to call it.
	Description string `json:"description,omitempty"`

	// Parameters is a JSON Schema object describing the arguments.
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

// ToolSpec offers one tool to the model, in the OpenAI tools format.
type ToolSpec struct {
	// Type is always "function" in the current protocol.
	Type string `json:"type"`

	// Function describes the callable.
	Function FunctionSpec `json:"function"`
}

// ChatReq is one chat-completion request. The model name and credentials come
// from the [Endpoint], not from here, so the same ChatReq can be sent to
// different endpoints unchanged.
type ChatReq struct {
	// Messages is the conversation so far, oldest first.
	Messages []ChatMessage `json:"messages"`

	// Temperature is the sampling temperature. Nil leaves it to the provider.
	Temperature *float64 `json:"temperature,omitempty"`

	// MaxTokens caps the completion length. Nil leaves it to the provider.
	MaxTokens *int `json:"maxTokens,omitempty"`

	// Tools enables tool calling when non-empty.
	Tools []ToolSpec `json:"tools,omitempty"`

	// ToolChoice controls tool-use behaviour: "auto", "none", "required", or a
	// specific function. Empty leaves it to the provider, which typically means
	// "auto" whenever Tools is set.
	ToolChoice string `json:"tool_choice,omitempty"`
}

// Chunk is one streamed fragment of a completion, or its terminal marker.
//
// Exactly one Chunk with Done set is emitted per successful stream, and it
// carries the assembled ToolCalls and the token counts. A caller driving an
// agent loop should inspect ToolCalls on the Done chunk and, when it is
// non-empty, execute each call and feed back one ChatMessage with Role
// [RoleTool] per result.
type Chunk struct {
	// Delta is the text fragment produced by this event.
	Delta string `json:"delta,omitempty"`

	// Done marks the terminal chunk of a stream.
	Done bool `json:"done,omitempty"`

	// Err is never set by this package — failures are reported through the
	// error returned by ChatStream. The field exists for callers that multiplex
	// several streams onto one channel and need to carry a failure inline.
	Err error `json:"-"`

	// TokensIn and TokensOut are the prompt and completion token counts
	// reported by the provider, present on the Done chunk when the provider
	// sends a usage payload. Zero means the provider did not report them.
	TokensIn  int `json:"tokensIn,omitempty"`
	TokensOut int `json:"tokensOut,omitempty"`

	// ToolCalls are the fully assembled tool invocations, attached to the Done
	// chunk.
	ToolCalls []ToolCall `json:"toolCalls,omitempty"`
}

// Response is a complete non-streaming completion.
type Response struct {
	// Content is the assistant's message text.
	Content string `json:"content"`

	// ToolCalls are the tool invocations the model requested, if any.
	ToolCalls []ToolCall `json:"toolCalls,omitempty"`

	// FinishReason is the provider's reason for stopping — "stop", "length",
	// "tool_calls" — or empty if it reported none.
	FinishReason string `json:"finishReason,omitempty"`

	// TokensIn and TokensOut are the prompt and completion token counts
	// reported by the provider. Zero means the provider did not report them.
	TokensIn  int `json:"tokensIn,omitempty"`
	TokensOut int `json:"tokensOut,omitempty"`
}
