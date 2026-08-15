// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Provider talks to one OpenAI-compatible chat-completions endpoint, blocking or
// streaming. It is an interface so that callers can substitute a fake without a
// network, and so that a consuming program can wrap it with the routing and
// retry policy this package refuses to have an opinion about.
type Provider interface {
	// Chat sends req to ep and waits for the whole completion.
	//
	// It returns a [TransportError] if the exchange did not complete, an
	// [APIError] if the endpoint answered non-2xx, an error wrapping
	// [ErrInvalidRequest] if the request could not be built at all, and an
	// [EmptyResponseError] if the answer was a success carrying no content and
	// no tool calls.
	//
	// On [ErrEmptyResponse] — and only then — the returned Response is
	// deliberately populated rather than zeroed, against the usual Go shape.
	// FinishReason and the token counts are exactly what a caller needs to tell
	// a provider that declined on purpose from an endpoint that is broken, and
	// those two warrant opposite responses: a [FinishContentFilter] is final and
	// re-asking elsewhere only finds a machine with weaker scruples, whereas any
	// other empty answer is grounds to try another endpoint. Discarding that
	// signal to honour a convention would make the convention cost more than it
	// is worth. Content and ToolCalls are empty by definition. Every other error
	// returns a zero Response, as usual.
	Chat(ctx context.Context, ep Endpoint, req ChatReq) (Response, error)

	// ChatStream sends req to ep with streaming enabled and emits every text
	// delta into out, followed by exactly one chunk with Done set carrying the
	// assembled tool calls and token counts.
	//
	// It does NOT close out: the caller owns that channel and may be
	// multiplexing several streams onto it. Sends respect ctx, so a cancelled
	// context unblocks a stalled send rather than leaking the goroutine. On
	// error, no Done chunk is emitted and the error is returned — the same kinds
	// as Chat.
	//
	// A stream that ends having emitted no text and assembled no tool call is an
	// [EmptyResponseError], not a success: nothing is sent to out and the error
	// is returned instead. Since nothing was forwarded, failing over is safe —
	// but read the finish reason first, because [FinishContentFilter] is a
	// deliberate refusal and re-asking elsewhere is the wrong response to it.
	//
	// A caller that fails over between endpoints wants [ChatStreamReader]
	// instead: this signature commits the caller's channel before the endpoint
	// has accepted the request, which puts the failover decision on the wrong
	// side of the first token.
	ChatStream(ctx context.Context, ep Endpoint, req ChatReq, out chan<- Chunk) error

	// ChatStreamReader sends req to ep with streaming enabled and returns the
	// stream for the caller to pull, rather than pushing into a channel.
	//
	// The split is where the protocol puts it, and it is the whole point of this
	// entry point: the returned error covers everything up to and including
	// response-header validation — building the request, connecting, TLS, the
	// status line — so a caller holding several endpoints may safely fail over
	// on it. Nothing has been emitted yet and nobody downstream has seen a
	// partial answer.
	//
	// Any error from [Stream.Next], by contrast, means output has already begun,
	// and failing over is NOT safe: retrying a started response against another
	// endpoint produces spliced or duplicated output. That rule is deliberately
	// conservative — a caller that tracks whether it has forwarded anything yet
	// can do better on a stream that failed before its first chunk — but the
	// safe default is to surface the failure rather than retry it.
	//
	// The one carve-out is [ErrEmptyResponse], which Next returns in place of a
	// terminal chunk when the stream produced nothing at all. That one IS safe
	// to fail over on, by construction: it can only arise when no chunk was ever
	// handed back, so there is no partial output to splice.
	//
	// The caller must Close the returned stream.
	ChatStreamReader(ctx context.Context, ep Endpoint, req ChatReq) (Stream, error)
}

// Stream is an in-progress streamed completion, pulled one chunk at a time.
// It is not safe for concurrent use.
type Stream interface {
	// Next returns the next chunk. Text deltas arrive first, then exactly one
	// chunk with Done set carrying the assembled tool calls, token counts and
	// finish reason; after that Next returns io.EOF.
	//
	// An [EmptyResponseError] replaces the terminal chunk when the stream
	// produced nothing usable, and is the one error here that is safe to fail
	// over on. Any other error means the stream failed mid-answer — see
	// [Provider.ChatStreamReader] for why that is not a failover signal.
	//
	// Errors are sticky: once Next has failed it keeps returning the same error.
	Next() (Chunk, error)

	// Close releases the underlying connection. It is idempotent and safe to
	// call at any point, including on a stream that is only partly read: an
	// abandoned stream is aborted rather than drained, so Close never waits on
	// a provider that is still sending. After Close, Next returns
	// [ErrStreamClosed].
	Close() error
}

// ErrStreamClosed is returned by [Stream.Next] after the stream has been closed.
var ErrStreamClosed = errors.New("llm: stream closed")

// DefaultResponseHeaderTimeout bounds how long the default client waits for an
// endpoint to begin answering. It is the knob that matters for failover: a
// machine that has not sent a response header is a machine to give up on, while
// a stream that is still delivering tokens should be left alone however long it
// takes.
const DefaultResponseHeaderTimeout = 60 * time.Second

// Options configures a [Provider].
type Options struct {
	// Client is the HTTP client to use. Nil builds one with no overall timeout —
	// deadlines come from ctx and [Endpoint.Timeout], because a client-level
	// timeout would cut healthy long streams. Supplying a client puts its
	// transport, proxy, TLS configuration and connection pooling entirely under
	// the caller's control, and makes ResponseHeaderTimeout below inert.
	Client *http.Client

	// Logger receives debug-level request lines and warnings about provider
	// misbehaviour (unparseable events, repaired tool arguments). Nil uses
	// slog.Default(). The API key is never logged.
	Logger *slog.Logger

	// ResponseHeaderTimeout overrides [DefaultResponseHeaderTimeout] on the
	// client this package builds. It is ignored when Client is supplied.
	ResponseHeaderTimeout time.Duration
}

// httpProvider is the net/http-backed [Provider].
type httpProvider struct {
	logger *slog.Logger
	client *http.Client
}

var _ Provider = (*httpProvider)(nil)

// New returns a [Provider] backed by net/http. The zero Options value is valid
// and gives a client suitable for streaming.
func New(opts Options) Provider {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	client := opts.Client
	if client == nil {
		headerTimeout := opts.ResponseHeaderTimeout
		if headerTimeout <= 0 {
			headerTimeout = DefaultResponseHeaderTimeout
		}
		client = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				ResponseHeaderTimeout: headerTimeout,
			},
			// No Timeout: ctx and Endpoint.Timeout cut streams, a hard client
			// timeout would cut them while they are still healthy.
		}
	}

	return &httpProvider{logger: logger, client: client}
}

// maxResponseBytes bounds a non-streaming response body. A provider that answers
// with an unbounded body must not be able to exhaust the caller's memory.
const maxResponseBytes = 32 << 20

// Chat implements [Provider].
func (p *httpProvider) Chat(ctx context.Context, ep Endpoint, req ChatReq) (Response, error) {
	callCtx, cancel := withTimeout(ctx, ep.Timeout)
	defer cancel()

	resp, err := p.send(ctx, callCtx, ep, req, false)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()

	var parsed openAIChatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&parsed); err != nil {
		return Response{}, p.transportErr(ctx, "read", ep, fmt.Errorf("decode response: %w", err))
	}

	out := Response{}
	if parsed.Usage != nil {
		out.TokensIn = parsed.Usage.PromptTokens
		out.TokensOut = parsed.Usage.CompletionTokens
	}

	if len(parsed.Choices) == 0 {
		return out, &EmptyResponseError{Endpoint: endpointLabel(ep), Detail: "no choices"}
	}

	choice := parsed.Choices[0]
	out.Content = choice.Message.Content
	out.FinishReason = choice.FinishReason
	out.ToolCalls = p.normalizeToolCalls(ctx, choice.Message.ToolCalls)

	if out.Content == "" && len(out.ToolCalls) == 0 {
		return out, &EmptyResponseError{
			Endpoint:     endpointLabel(ep),
			FinishReason: choice.FinishReason,
			Detail:       "empty choice",
		}
	}
	return out, nil
}

// ChatStream implements [Provider]. It is [ChatStreamReader] with the pulling
// done for the caller.
func (p *httpProvider) ChatStream(ctx context.Context, ep Endpoint, req ChatReq, out chan<- Chunk) error {
	stream, err := p.openStream(ctx, ep, req)
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		chunk, err := stream.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := p.emit(stream.parent, stream.callCtx, ep, out, chunk); err != nil {
			return err
		}
		if chunk.Done {
			return nil
		}
	}
}

// ChatStreamReader implements [Provider].
func (p *httpProvider) ChatStreamReader(ctx context.Context, ep Endpoint, req ChatReq) (Stream, error) {
	stream, err := p.openStream(ctx, ep, req)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

// openStream performs the request and returns the stream positioned just after
// response-header validation — the boundary a failing-over caller needs.
func (p *httpProvider) openStream(ctx context.Context, ep Endpoint, req ChatReq) (*httpStream, error) {
	// Always derive a cancellable context, even without Endpoint.Timeout, so
	// that Close can abort a request the caller has walked away from.
	callCtx, cancel := streamContext(ctx, ep.Timeout)

	resp, err := p.send(ctx, callCtx, ep, req, true)
	if err != nil {
		cancel()
		return nil, err
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, sseScannerInitial), sseScannerMax)

	return &httpStream{
		provider: p,
		parent:   ctx,
		callCtx:  callCtx,
		cancel:   cancel,
		endpoint: ep,
		body:     resp.Body,
		scanner:  scanner,
	}, nil
}

// httpStream is the net/http-backed [Stream]. It spawns no goroutines: Next
// reads the connection synchronously, so abandoning a stream leaks nothing once
// Close has cancelled the request.
type httpStream struct {
	provider *httpProvider
	parent   context.Context
	callCtx  context.Context
	cancel   context.CancelFunc
	endpoint Endpoint
	body     io.ReadCloser
	scanner  *bufio.Scanner

	// toolAccum accumulates in-progress tool calls by stream index. A slice is
	// enough: indices arrive in order and gaps are uncommon.
	toolAccum []*toolAccumEntry

	// lastUsage holds the most recent usage payload seen, attached to the Done
	// chunk so the caller can budget tokens.
	lastUsage *openAIUsage

	// finishReason holds the last non-empty finish_reason seen on the stream. It
	// is what lets an empty stream be told apart from a deliberate refusal.
	finishReason string

	// produced records whether any text delta has been handed to the caller. It
	// decides whether the end of the stream is a completion or an
	// [ErrEmptyResponse], and it must stay false until a delta actually leaves
	// Next — an empty stream is only safe to fail over on because nothing was
	// forwarded.
	produced bool

	finished bool
	closed   bool
	err      error
}

var _ Stream = (*httpStream)(nil)

// ensureIndex grows the accumulator to cover idx, refusing indices beyond
// maxToolCallIndex so a buggy or hostile provider cannot exhaust memory.
func (s *httpStream) ensureIndex(idx int) bool {
	if idx < 0 || idx > maxToolCallIndex {
		return false
	}
	for len(s.toolAccum) <= idx {
		s.toolAccum = append(s.toolAccum, &toolAccumEntry{})
	}
	return true
}

// fail records a sticky stream failure and classifies it.
func (s *httpStream) fail(err error) error {
	s.err = s.provider.transportErr(s.parent, "stream", s.endpoint, err)
	return s.err
}

// finish handles the end of the stream, from either the [DONE] sentinel or a
// clean close. It returns the terminal chunk, or an [EmptyResponseError] when
// the stream delivered no text and assembled no tool call — the same defect the
// blocking path reports, arriving by a different route.
func (s *httpStream) finish() (Chunk, error) {
	s.finished = true

	done := Chunk{Done: true, FinishReason: s.finishReason}
	if len(s.toolAccum) > 0 {
		done.ToolCalls = s.provider.assembleToolCalls(s.parent, s.toolAccum)
	}
	if s.lastUsage != nil {
		done.TokensIn = s.lastUsage.PromptTokens
		done.TokensOut = s.lastUsage.CompletionTokens
	}

	if !s.produced && len(done.ToolCalls) == 0 {
		// Nothing was ever handed to the caller, so nothing downstream has seen
		// a partial answer and failing over remains safe. Report rather than
		// deliver a terminal chunk that would look like a completed turn.
		s.err = &EmptyResponseError{
			Endpoint:     endpointLabel(s.endpoint),
			FinishReason: s.finishReason,
			Detail:       "empty stream",
		}
		return Chunk{}, s.err
	}
	return done, nil
}

// Next implements [Stream].
//
// A malformed event is logged and skipped rather than ending the stream: one bad
// frame out of a thousand should cost a token, not the whole turn.
func (s *httpStream) Next() (Chunk, error) {
	switch {
	case s.closed:
		return Chunk{}, ErrStreamClosed
	case s.err != nil:
		return Chunk{}, s.err
	case s.finished:
		return Chunk{}, io.EOF
	}

	log := s.provider.logger
	for s.scanner.Scan() {
		if err := s.callCtx.Err(); err != nil {
			return Chunk{}, s.fail(err)
		}

		line := s.scanner.Text()

		// Skip blank lines and comments. Some providers send ": keep-alive".
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			// Field lines other than data (event:, id:, retry:) carry nothing
			// this protocol uses.
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))

		if payload == "[DONE]" {
			return s.finish()
		}

		var event openAIStreamEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			log.WarnContext(s.parent, "llm: skipping unparseable stream event",
				"endpoint", endpointLabel(s.endpoint), "err", err)
			continue
		}

		if event.Usage != nil {
			s.lastUsage = event.Usage
		}
		if len(event.Choices) == 0 {
			continue
		}
		choice := event.Choices[0]
		if choice.FinishReason != "" {
			s.finishReason = choice.FinishReason
		}

		for _, tc := range choice.Delta.ToolCalls {
			if !s.ensureIndex(tc.Index) {
				log.WarnContext(s.parent, "llm: ignoring out-of-range tool_call index",
					"endpoint", endpointLabel(s.endpoint), "index", tc.Index)
				continue
			}
			entry := s.toolAccum[tc.Index]
			if tc.ID != "" {
				entry.id = tc.ID
			}
			if tc.Type != "" {
				entry.callType = tc.Type
			}
			if tc.Function.Name != "" {
				entry.name = tc.Function.Name
			}
			if tc.Function.Arguments != "" {
				entry.arguments.WriteString(tc.Function.Arguments)
			}
		}

		if delta := choice.Delta.Content; delta != "" {
			s.produced = true
			return Chunk{Delta: delta}, nil
		}
	}

	if err := s.scanner.Err(); err != nil {
		return Chunk{}, s.fail(err)
	}

	// The stream ended without a [DONE] sentinel. Providers vary on whether they
	// send one; a clean close is still a complete answer.
	return s.finish()
}

// Close implements [Stream].
func (s *httpStream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	// Cancel first: it aborts a read that is still waiting on the provider, so
	// closing a half-read stream returns immediately instead of blocking on a
	// body that may never end.
	s.cancel()

	err := s.body.Close()
	if err != nil && errors.Is(err, context.Canceled) {
		// Our own cancellation, not a failure worth reporting.
		return nil
	}
	return err
}

// send builds and performs the request and validates the status. parent is the
// caller's context and callCtx the one carrying Endpoint.Timeout; keeping both
// is what lets a failure be attributed either to the caller giving up (returned
// as the caller's own context error) or to the endpoint being too slow (a
// TransportError, which is a routing signal).
//
// On success the response body is open and belongs to the caller. On any error
// it has been drained and closed.
func (p *httpProvider) send(parent, callCtx context.Context, ep Endpoint, req ChatReq, stream bool) (*http.Response, error) {
	httpReq, err := buildRequest(callCtx, ep, req, stream)
	if err != nil {
		return nil, err
	}

	p.logger.DebugContext(parent, "llm: chat completions request",
		"endpoint", endpointLabel(ep),
		"model", ep.Model,
		"stream", stream,
		"authenticated", ep.APIKey != "",
	)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, p.transportErr(parent, "connect", ep, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		resp.Body.Close()
		return nil, newAPIError(ep, resp.StatusCode, resp.Status, body)
	}
	return resp, nil
}

// buildRequest assembles the HTTP request, merging Endpoint.ExtraBody over the
// generated body.
func buildRequest(ctx context.Context, ep Endpoint, req ChatReq, stream bool) (*http.Request, error) {
	body := map[string]any{
		"model":    ep.Model,
		"messages": req.Messages,
		"stream":   stream,
	}
	if stream {
		// Ask for a final usage payload on the stream so the caller can enforce
		// a real token budget rather than estimating one.
		body["stream_options"] = map[string]any{"include_usage": true}
	}
	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}
	if req.MaxTokens != nil {
		body["max_tokens"] = *req.MaxTokens
	}
	if len(req.Tools) > 0 {
		body["tools"] = req.Tools
		if req.ToolChoice != "" {
			body["tool_choice"] = req.ToolChoice
		}
	}

	// ExtraBody is shallow-merged last so its keys win, which is the point of it.
	if len(ep.ExtraBody) > 0 {
		var extra map[string]any
		if err := json.Unmarshal(ep.ExtraBody, &extra); err != nil {
			return nil, fmt.Errorf("%w: unmarshal extra body: %v", ErrInvalidRequest, err)
		}
		for k, v := range extra {
			body[k] = v
		}
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request: %v", ErrInvalidRequest, err)
	}

	url := strings.TrimRight(ep.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrInvalidRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}
	if ep.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+ep.APIKey)
	}
	return httpReq, nil
}

// withTimeout derives a context carrying d, or returns the parent unchanged when
// d is not positive. The returned cancel is always safe to call.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

// streamContext is withTimeout for a stream, where the derived context must
// always be cancellable: a stream outlives the call that opened it, and Close
// needs something to pull to abort a request still in flight.
func streamContext(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// transportErr classifies a failed exchange. If the caller's own context is
// already done, that is the honest cause and it is returned as-is so
// errors.Is(err, context.Canceled) holds — a caller that hung up has not learned
// anything about the endpoint. Everything else is a TransportError, including a
// fired Endpoint.Timeout, which very much is a fact about the endpoint.
func (p *httpProvider) transportErr(parent context.Context, op string, ep Endpoint, err error) error {
	if parentErr := parent.Err(); parentErr != nil {
		return fmt.Errorf("llm: %s: %w", op, parentErr)
	}
	return &TransportError{Op: op, Endpoint: endpointLabel(ep), Err: err}
}

// openAIToolCallDelta is a partial tool-call fragment. The protocol spreads one
// tool call across several events keyed by index: the first carries the id and
// function name, later ones carry argument fragments to be concatenated.
type openAIToolCallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function"`
}

// openAIDelta is the delta fragment inside one streamed event.
type openAIDelta struct {
	Content   string                `json:"content"`
	ToolCalls []openAIToolCallDelta `json:"tool_calls,omitempty"`
}

// openAIChoice is one entry in the choices array of a streamed event.
type openAIChoice struct {
	Delta        openAIDelta `json:"delta"`
	FinishReason string      `json:"finish_reason,omitempty"`
}

// openAIUsage is the token-usage object. On a stream it arrives on the final
// event when stream_options.include_usage is set; it may appear null earlier.
type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// openAIStreamEvent is one parsed SSE data payload.
type openAIStreamEvent struct {
	Choices []openAIChoice `json:"choices"`
	Usage   *openAIUsage   `json:"usage,omitempty"`
}

// openAIChatResponse is a complete non-streaming response body.
type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content   string     `json:"content"`
			ToolCalls []ToolCall `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason,omitempty"`
	} `json:"choices"`
	Usage *openAIUsage `json:"usage,omitempty"`
}

// toolAccumEntry accumulates one in-progress tool call across delta fragments.
type toolAccumEntry struct {
	id        string
	callType  string
	name      string
	arguments strings.Builder
}

// maxToolCallIndex bounds tool-call slice growth so a buggy or hostile provider
// sending a huge index cannot exhaust memory.
const maxToolCallIndex = 256

// sseScannerBuffer sizes the line scanner. Individual token deltas and usage
// payloads are small, but a provider may emit a large tool-argument fragment in
// one event, so allow up to 1 MiB per line before treating it as broken.
const (
	sseScannerInitial = 64 * 1024
	sseScannerMax     = 1024 * 1024
)

// emit sends one chunk, giving up if the call is cancelled so a caller that
// stops reading cannot wedge the send forever.
func (p *httpProvider) emit(parent, callCtx context.Context, ep Endpoint, out chan<- Chunk, c Chunk) error {
	select {
	case out <- c:
		return nil
	case <-callCtx.Done():
		return p.transportErr(parent, "stream", ep, callCtx.Err())
	}
}

// assembleToolCalls turns accumulated fragments into tool calls. Entries with no
// name are skipped: they are gaps or empty deltas carrying nothing.
//
// Two provider misbehaviours are absorbed here rather than passed on, because
// both are silently destructive otherwise:
//
//   - Malformed arguments are normalized by [SanitizeToolArgsFixup], and a
//     repair or a drop is logged. A silently dropped argument set loses the
//     model's intent with no trace at all.
//   - A missing id is synthesized as "call_<n>". The id is echoed back in the
//     follow-up tool message, and an empty one makes strict servers reject the
//     entire conversation with a 400.
func (p *httpProvider) assembleToolCalls(ctx context.Context, accum []*toolAccumEntry) []ToolCall {
	var out []ToolCall
	for _, entry := range accum {
		if entry.name == "" {
			continue
		}
		raw := entry.arguments.String()
		args, fixup := SanitizeToolArgsFixup(raw)
		p.logFixup(ctx, entry.name, raw, fixup)

		id := entry.id
		if id == "" {
			id = fmt.Sprintf("call_%d", len(out))
			p.logger.WarnContext(ctx, "llm: tool call missing id, synthesized a fallback",
				"tool", entry.name, "synthesized_id", id)
		}

		callType := entry.callType
		if callType == "" {
			callType = "function"
		}

		out = append(out, ToolCall{
			ID:       id,
			Type:     callType,
			Function: FunctionCall{Name: entry.name, Arguments: args},
		})
	}
	return out
}

// normalizeToolCalls applies the same argument repair and id synthesis to the
// tool calls of a non-streaming response, so both paths hand back tool calls
// with the same guarantees.
func (p *httpProvider) normalizeToolCalls(ctx context.Context, calls []ToolCall) []ToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]ToolCall, 0, len(calls))
	for _, tc := range calls {
		args, fixup := SanitizeToolArgsFixup(tc.Function.Arguments)
		p.logFixup(ctx, tc.Function.Name, tc.Function.Arguments, fixup)
		tc.Function.Arguments = args

		if tc.ID == "" {
			tc.ID = fmt.Sprintf("call_%d", len(out))
			p.logger.WarnContext(ctx, "llm: tool call missing id, synthesized a fallback",
				"tool", tc.Function.Name, "synthesized_id", tc.ID)
		}
		if tc.Type == "" {
			tc.Type = "function"
		}
		out = append(out, tc)
	}
	return out
}

// logFixup reports an argument repair or drop. A clean or empty argument string
// is unremarkable and stays quiet.
func (p *httpProvider) logFixup(ctx context.Context, tool, raw string, fixup ArgFixup) {
	switch fixup {
	case ArgRepaired:
		p.logger.WarnContext(ctx, "llm: repaired malformed tool call arguments",
			"tool", tool, "raw_len", len(raw))
	case ArgDropped:
		p.logger.WarnContext(ctx, "llm: dropped unparseable tool call arguments, defaulted to {}",
			"tool", tool, "raw_len", len(raw))
	}
}
