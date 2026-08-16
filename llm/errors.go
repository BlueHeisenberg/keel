// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidRequest is wrapped by the errors returned when a call cannot even be
// built — an unparseable [Endpoint.ExtraBody], a request body that will not
// marshal, a base URL that is not a valid URL. Nothing was sent, no endpoint was
// contacted, and sending the same thing somewhere else will fail identically.
// It is neither a [TransportError] nor an [APIError].
var ErrInvalidRequest = errors.New("llm: invalid request")

// ErrEmptyResponse reports a successful exchange that carried no completion: a
// 2xx with no choices at all, a choice with neither content nor tool calls, or a
// stream that reached its end having emitted no text and assembled no tool call.
//
// The endpoint answered but produced nothing usable — a reasonable caller treats
// this as grounds to try another endpoint. It is deliberately neither a
// [TransportError] (the exchange completed) nor an [APIError] (the status was a
// success), because it is neither: it is a well-formed answer that says nothing.
// Reporting it as success is worse than either, since silence from a broken
// machine is indistinguishable from a model that chose not to speak, and a
// caller would credit the endpoint for a completion it never produced.
//
// # Not every empty answer is a malfunction
//
// Before failing over, check the finish reason — from [EmptyResponseError] on
// either path, or from the [Response] that [Provider.Chat] returns alongside the
// error. [FinishContentFilter] means the provider declined on purpose, and that
// decision is final: walking the rest of a fallback chain will get the request
// refused again at every stop, or answered by whichever machine has the weakest
// scruples, which is worse than refusing.
//
// # The finish reason is not enough on its own
//
// A reasoning model can spend a whole turn thinking and answer nothing, and the
// finish reason does not identify that case — it cannot be made to. Measured
// against vLLM 0.27 serving Qwen3, the identical request came back empty under
// both [FinishLength] and [FinishStop], the latter with the token budget barely
// half spent. A caller reading only the finish reason sees "stop", concludes the
// model chose to say nothing, and reports a healthy endpoint as mute.
//
// What identifies it is [EmptyResponseError.Reasoning]. Non-empty means the
// model produced a thinking trace and no answer, and failing over is the wrong
// response: the next endpoint running the same class of model behaves the same
// way. What helps is room to answer in — a larger max_tokens — or a request that
// spends less of the budget thinking, such as the [Endpoint.ExtraBody] that
// turns thinking off. This package does not choose between those; it makes the
// choice visible.
//
// Any other empty answer — no content, no tool call, no reasoning, no refusal —
// is a malfunction, and trying elsewhere is right.
//
// Errors that wrap this sentinel are always an [EmptyResponseError], so
// errors.As reaches the finish reason and the reasoning trace without parsing an
// error string.
var ErrEmptyResponse = errors.New("llm: endpoint produced no completion")

// EmptyResponseError is the concrete error wrapping [ErrEmptyResponse]. It
// exists so the finish reason survives as data: a caller deciding whether to
// fail over needs to tell a deliberate refusal from a broken endpoint, and that
// decision must not depend on matching substrings in an error message.
type EmptyResponseError struct {
	// Endpoint is the endpoint that produced nothing, for diagnostics. The API
	// key is never included.
	Endpoint string

	// FinishReason is the provider's reported reason for stopping, if it sent
	// one — compare against [FinishContentFilter] before failing over. Empty
	// means the provider reported nothing, which is itself a malfunction.
	FinishReason string

	// Detail names the shape of the emptiness ("no choices", "empty choice",
	// "empty stream", [DetailReasoningOnly]). It is a fixed classification,
	// never provider text.
	Detail string

	// Reasoning is the model's thinking trace, when it produced one and then
	// said nothing. Non-empty means the endpoint and the model both worked: the
	// model thought and did not answer. That is a different fault from silence,
	// and the one signal that tells them apart — see [ErrEmptyResponse].
	//
	// It is model output, so [EmptyResponseError.Error] does not render it, for
	// the same reason [APIError.Error] omits the provider's prose. Read the
	// field when you want it.
	Reasoning string
}

// DetailReasoningOnly is the [EmptyResponseError.Detail] value for an answer
// that carried a reasoning trace and no content.
const DetailReasoningOnly = "reasoning only"

// Error implements error. Like [APIError.Error] it renders only classifiers,
// never provider prose or caller content.
func (e *EmptyResponseError) Error() string {
	msg := fmt.Sprintf("llm: %s produced no completion (%s", e.Endpoint, e.Detail)
	if e.FinishReason != "" {
		msg += fmt.Sprintf(", finish_reason %s", e.FinishReason)
	}
	return msg + ")"
}

// Unwrap returns [ErrEmptyResponse] so errors.Is identifies the condition.
func (e *EmptyResponseError) Unwrap() error { return ErrEmptyResponse }

// TransportError reports that the exchange with the endpoint did not complete:
// the connection was refused or reset, DNS or TLS failed, the per-call
// [Endpoint.Timeout] fired, or a stream was cut before it finished.
//
// The request may or may not have been processed, but no usable answer came
// back. Nothing about it says the request was wrong, so retrying it against a
// different endpoint is reasonable — this is the failure that a caller with more
// than one machine available should route around.
type TransportError struct {
	// Op is the stage that failed: "connect", "read" or "stream".
	Op string

	// Endpoint is the base URL that was being contacted, for diagnostics. The
	// API key is never included.
	Endpoint string

	// Err is the underlying failure, typically a *url.Error, a syscall error or
	// context.DeadlineExceeded. Compare it with errors.Is.
	Err error
}

// Error implements error.
func (e *TransportError) Error() string {
	return fmt.Sprintf("llm: transport %s to %s: %v", e.Op, e.Endpoint, e.Err)
}

// Unwrap returns the underlying failure so errors.Is and errors.As reach it.
func (e *TransportError) Unwrap() error { return e.Err }

// APIError reports that the endpoint answered and the answer was a non-2xx
// status. The network worked; the provider declined.
//
// A 400 describing a malformed request, a 404 for an unknown model, a 401 for a
// bad key — none of these get better by being sent to another machine, and a
// caller that fails over on them just spends longer arriving at the same result.
// StatusCode carries the full detail for callers that want to treat, say, 429 or
// 503 as worth retrying; this package deliberately makes no such policy itself.
//
// # What Error does not say
//
// Error deliberately omits Message and Body, and reports only the status, the
// provider's error Type and Code, and the endpoint. This is not tidiness. An
// error string is the one part of a failure that reaches a log by default,
// often at the top of a stack nobody is thinking carefully about — and provider
// error bodies routinely quote the request back, so a 400 can carry the text of
// whatever somebody just typed. Rendering that into the operator's log by
// default would make every consumer responsible for scrubbing it, and most
// would not know they had to.
//
// The prose is not lost, only unlisted: read [APIError.Detail], or the Message
// and Body fields directly. A caller that wants the provider's words has to ask
// for them by name, at which point disclosing them is a decision rather than an
// accident.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Status is the HTTP status line, for example "429 Too Many Requests".
	Status string

	// Endpoint is the base URL that answered, for diagnostics. The API key is
	// never included.
	Endpoint string

	// Message is the human-readable message extracted from the provider's error
	// body, when it follows a recognizable shape. Empty if none was found.
	Message string

	// Type is the provider's error class, for example "invalid_request_error".
	// Empty if the body did not carry one.
	Type string

	// Code is the provider's machine-readable error code. Empty if the body did
	// not carry one.
	Code string

	// Body is the raw response body, truncated to 4 KiB. It is retained
	// verbatim because provider error shapes vary and Message may be empty.
	Body string
}

// Error implements error. It renders the status, the provider's error class and
// code, and the endpoint — never the provider's prose. See the type
// documentation for why, and [APIError.Detail] for how to get the prose.
func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("llm: ")
	b.WriteString(e.Endpoint)
	b.WriteString(" returned ")
	if e.Status != "" {
		b.WriteString(e.Status)
	} else {
		fmt.Fprintf(&b, "%d", e.StatusCode)
	}

	switch {
	case e.Type != "" && e.Code != "":
		fmt.Fprintf(&b, " (type %s, code %s)", e.Type, e.Code)
	case e.Type != "":
		fmt.Fprintf(&b, " (type %s)", e.Type)
	case e.Code != "":
		fmt.Fprintf(&b, " (code %s)", e.Code)
	}
	return b.String()
}

// Detail returns the provider's own description of the failure: the parsed
// Message, the raw Body, or both when the body carries more than the message.
//
// It is a method rather than part of Error so that disclosing it is a decision.
// The text is whatever the provider chose to send, which for a rejected request
// frequently includes the request itself — prompt text, tool arguments, an
// entire message. Treat the result as caller content, not as diagnostics: log it
// where content is allowed to go, or not at all.
func (e *APIError) Detail() string {
	switch {
	case e.Message == "":
		return e.Body
	case e.Body == "" || strings.Contains(e.Body, e.Message):
		return e.Message
	default:
		return e.Message + ": " + e.Body
	}
}

// IsTransport reports whether err was caused by a failure to exchange bytes
// with the endpoint, and is therefore worth retrying elsewhere. It is shorthand
// for errors.As against [TransportError].
func IsTransport(err error) bool {
	var te *TransportError
	return errors.As(err, &te)
}

// IsAPI reports whether err is a non-2xx answer from the endpoint. It is
// shorthand for errors.As against [APIError].
func IsAPI(err error) bool {
	var ae *APIError
	return errors.As(err, &ae)
}

// maxErrorBodyBytes bounds how much of a provider's error body is read. A
// misbehaving endpoint must not be able to make an error allocation unbounded.
const maxErrorBodyBytes = 4096

// newAPIError builds an APIError from a non-2xx response, parsing the common
// provider error envelopes best-effort.
func newAPIError(ep Endpoint, statusCode int, status string, body []byte) *APIError {
	e := &APIError{
		StatusCode: statusCode,
		Status:     status,
		Endpoint:   endpointLabel(ep),
		Body:       strings.TrimSpace(string(body)),
	}
	msg, typ, code := parseErrorEnvelope(body)
	e.Message, e.Type, e.Code = msg, typ, code
	return e
}

// parseErrorEnvelope pulls a message, type and code out of a provider error
// body. It understands the OpenAI object form ({"error":{"message":…}}), the
// string form ({"error":"…"}), and the flat forms used by several
// OpenAI-compatible servers ({"message":…}, {"detail":…}). Anything else yields
// empty strings and leaves the caller with the raw body.
func parseErrorEnvelope(body []byte) (message, typ, code string) {
	var envelope struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Detail  string          `json:"detail"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", "", ""
	}

	if len(envelope.Error) > 0 {
		var asString string
		if err := json.Unmarshal(envelope.Error, &asString); err == nil {
			return asString, "", ""
		}
		var asObject struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    any    `json:"code"`
		}
		if err := json.Unmarshal(envelope.Error, &asObject); err == nil {
			return asObject.Message, asObject.Type, scalarString(asObject.Code)
		}
	}

	if envelope.Message != "" {
		return envelope.Message, "", ""
	}
	return envelope.Detail, "", ""
}

// scalarString renders a JSON scalar as a string. Providers disagree on whether
// an error code is a string or a number.
func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	default:
		return fmt.Sprint(t)
	}
}

// endpointLabel picks the most useful identifier for an endpoint in a message,
// preferring the caller's own label. It never returns the API key.
func endpointLabel(ep Endpoint) string {
	if ep.Label != "" {
		return ep.Label
	}
	return ep.BaseURL
}
