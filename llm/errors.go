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

// Error implements error.
func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "llm: %s returned %d", e.Endpoint, e.StatusCode)
	switch {
	case e.Message != "":
		fmt.Fprintf(&b, ": %s", e.Message)
	case e.Body != "":
		fmt.Fprintf(&b, ": %s", e.Body)
	}
	if e.Code != "" {
		fmt.Fprintf(&b, " (code %s)", e.Code)
	}
	return b.String()
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
