// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	// [APIError] if the endpoint answered non-2xx, and an error wrapping
	// [ErrInvalidRequest] if the request could not be built at all.
	Chat(ctx context.Context, ep Endpoint, req ChatReq) (Response, error)

	// ChatStream sends req to ep with streaming enabled and emits every text
	// delta into out, followed by exactly one chunk with Done set carrying the
	// assembled tool calls and token counts.
	//
	// It does NOT close out: the caller owns that channel and may be
	// multiplexing several streams onto it. Sends respect ctx, so a cancelled
	// context unblocks a stalled send rather than leaking the goroutine. On
	// error, no Done chunk is emitted and the error is returned — the same three
	// kinds as Chat.
	ChatStream(ctx context.Context, ep Endpoint, req ChatReq, out chan<- Chunk) error
}

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
	if len(parsed.Choices) > 0 {
		choice := parsed.Choices[0]
		out.Content = choice.Message.Content
		out.FinishReason = choice.FinishReason
		out.ToolCalls = p.normalizeToolCalls(ctx, choice.Message.ToolCalls)
	}
	return out, nil
}

// ChatStream implements [Provider].
func (p *httpProvider) ChatStream(ctx context.Context, ep Endpoint, req ChatReq, out chan<- Chunk) error {
	callCtx, cancel := withTimeout(ctx, ep.Timeout)
	defer cancel()

	resp, err := p.send(ctx, callCtx, ep, req, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return p.parseSSE(ctx, callCtx, ep, resp.Body, out)
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

// parseSSE reads the event stream and emits chunks to out until the [DONE]
// sentinel, the end of the stream, or a cancelled context. It does not close out.
//
// A malformed event is logged and skipped rather than aborting the stream: one
// bad frame out of a thousand should cost a token, not the whole turn.
func (p *httpProvider) parseSSE(parent, callCtx context.Context, ep Endpoint, r io.Reader, out chan<- Chunk) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, sseScannerInitial), sseScannerMax)

	// toolAccum accumulates in-progress tool calls by stream index. A slice is
	// enough: indices arrive in order and gaps are uncommon.
	var toolAccum []*toolAccumEntry

	// lastUsage holds the most recent usage payload seen, attached to the Done
	// chunk so the caller can budget tokens.
	var lastUsage *openAIUsage

	ensureIndex := func(idx int) bool {
		if idx < 0 || idx > maxToolCallIndex {
			return false
		}
		for len(toolAccum) <= idx {
			toolAccum = append(toolAccum, &toolAccumEntry{})
		}
		return true
	}

	for scanner.Scan() {
		if err := callCtx.Err(); err != nil {
			return p.transportErr(parent, "stream", ep, err)
		}

		line := scanner.Text()

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
			return p.emit(parent, callCtx, ep, out, p.buildDoneChunk(parent, toolAccum, lastUsage))
		}

		var event openAIStreamEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			p.logger.WarnContext(parent, "llm: skipping unparseable stream event",
				"endpoint", endpointLabel(ep), "err", err)
			continue
		}

		if event.Usage != nil {
			lastUsage = event.Usage
		}
		if len(event.Choices) == 0 {
			continue
		}
		choice := event.Choices[0]

		for _, tc := range choice.Delta.ToolCalls {
			if !ensureIndex(tc.Index) {
				p.logger.WarnContext(parent, "llm: ignoring out-of-range tool_call index",
					"endpoint", endpointLabel(ep), "index", tc.Index)
				continue
			}
			entry := toolAccum[tc.Index]
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
			if err := p.emit(parent, callCtx, ep, out, Chunk{Delta: delta}); err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return p.transportErr(parent, "stream", ep, err)
	}

	// The stream ended without a [DONE] sentinel. Providers vary on whether they
	// send one; a clean close is still a complete answer, so emit the terminal
	// chunk and let the caller finish normally.
	return p.emit(parent, callCtx, ep, out, p.buildDoneChunk(parent, toolAccum, lastUsage))
}

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

// buildDoneChunk constructs the terminal chunk, attaching the assembled tool
// calls and the reported token usage.
func (p *httpProvider) buildDoneChunk(ctx context.Context, toolAccum []*toolAccumEntry, usage *openAIUsage) Chunk {
	done := Chunk{Done: true}
	if len(toolAccum) > 0 {
		done.ToolCalls = p.assembleToolCalls(ctx, toolAccum)
	}
	if usage != nil {
		done.TokensIn = usage.PromptTokens
		done.TokensOut = usage.CompletionTokens
	}
	return done
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
