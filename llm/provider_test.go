// SPDX-License-Identifier: Apache-2.0

package llm_test

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
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BlueHeisenberg/keel/llm"
)

// quietProvider returns a provider whose logs are discarded, so a test that
// deliberately provokes provider misbehaviour does not spray the output.
func quietProvider(t *testing.T) llm.Provider {
	t.Helper()
	return llm.New(llm.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
}

// cannedSSE builds a minimal OpenAI-compatible SSE body from text deltas,
// terminated by the [DONE] sentinel.
func cannedSSE(deltas []string) string {
	var sb strings.Builder
	for _, d := range deltas {
		sb.WriteString("data: " + fmt.Sprintf(`{"choices":[{"delta":{"content":%s}}]}`, jsonStr(d)) + "\n\n")
	}
	sb.WriteString("data: [DONE]\n\n")
	return sb.String()
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// collect drains out until a Done chunk arrives. ChatStream never closes the
// channel, so Done is the only stop condition.
func collect(out <-chan llm.Chunk) []llm.Chunk {
	var chunks []llm.Chunk
	for c := range out {
		chunks = append(chunks, c)
		if c.Done {
			break
		}
	}
	return chunks
}

// startCollector drains out in the background so the provider never blocks on a
// send, and returns a function that waits for the collected chunks.
func startCollector(out <-chan llm.Chunk) func() []llm.Chunk {
	done := make(chan []llm.Chunk, 1)
	go func() { done <- collect(out) }()
	return func() []llm.Chunk { return <-done }
}

func joinDeltas(chunks []llm.Chunk) string {
	var sb strings.Builder
	for _, c := range chunks {
		sb.WriteString(c.Delta)
	}
	return sb.String()
}

func doneChunk(t *testing.T, chunks []llm.Chunk) llm.Chunk {
	t.Helper()
	for _, c := range chunks {
		if c.Done {
			return c
		}
	}
	t.Fatal("no Done chunk received")
	return llm.Chunk{}
}

// sseServer serves a fixed SSE body and captures the decoded request body.
func sseServer(t *testing.T, body string) (*httptest.Server, <-chan map[string]any) {
	t.Helper()
	seen := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		select {
		case seen <- decoded:
		default:
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// --- streaming ---------------------------------------------------------------

// TestChatStream_ParsesDeltas checks that every text delta on a canned SSE body
// is delivered in order and that the stream terminates with a Done chunk.
func TestChatStream_ParsesDeltas(t *testing.T) {
	srv, _ := sseServer(t, cannedSSE([]string{"Hello", ", ", "world", "!"}))

	out := make(chan llm.Chunk, 32)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "test-model", APIKey: "sk-noop"}
	req := llm.ChatReq{Messages: []llm.ChatMessage{{Role: llm.RoleUser, Content: "hi"}}}
	if err := quietProvider(t).ChatStream(context.Background(), ep, req, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}

	chunks := wait()
	if got := joinDeltas(chunks); got != "Hello, world!" {
		t.Errorf("assembled deltas = %q, want %q", got, "Hello, world!")
	}
	for _, c := range chunks {
		if c.Err != nil {
			t.Errorf("unexpected Chunk.Err: %v", c.Err)
		}
	}
	doneChunk(t, chunks)
}

// TestChatStream_RequestShape checks the generated request: POST to the right
// path, streaming enabled, usage requested, bearer credential attached.
func TestChatStream_RequestShape(t *testing.T) {
	seenPath := make(chan string, 1)
	seenAuth := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath <- r.URL.Path
		seenAuth <- r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, cannedSSE([]string{"ok"}))
	}))
	defer srv.Close()

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	// A trailing slash on the base URL must not produce a doubled separator.
	ep := llm.Endpoint{BaseURL: srv.URL + "/", Model: "m", APIKey: "sk-secret"}
	req := llm.ChatReq{Messages: []llm.ChatMessage{{Role: llm.RoleUser, Content: "hi"}}}
	if err := quietProvider(t).ChatStream(context.Background(), ep, req, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	wait()

	if path := <-seenPath; path != "/chat/completions" {
		t.Errorf("path = %q, want %q", path, "/chat/completions")
	}
	if auth := <-seenAuth; auth != "Bearer sk-secret" {
		t.Errorf("Authorization = %q, want bearer credential", auth)
	}
}

// TestChatStream_ExtraBodyMerged checks that Endpoint.ExtraBody keys reach the
// upstream request alongside the generated fields.
func TestChatStream_ExtraBodyMerged(t *testing.T) {
	srv, seen := sseServer(t, cannedSSE([]string{"ok"}))

	out := make(chan llm.Chunk, 32)
	wait := startCollector(out)

	ep := llm.Endpoint{
		BaseURL:   srv.URL,
		Model:     "monster",
		APIKey:    "sk-noop",
		ExtraBody: json.RawMessage(`{"chat_template_kwargs":{"enable_thinking":false}}`),
	}
	req := llm.ChatReq{Messages: []llm.ChatMessage{{Role: llm.RoleUser, Content: "test"}}}
	if err := quietProvider(t).ChatStream(context.Background(), ep, req, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	wait()

	body := <-seen
	kwargs, ok := body["chat_template_kwargs"].(map[string]any)
	if !ok {
		t.Fatalf("chat_template_kwargs missing or wrong type; body keys: %v", keysOf(body))
	}
	if kwargs["enable_thinking"] != false {
		t.Errorf("enable_thinking = %v, want false", kwargs["enable_thinking"])
	}
	if body["model"] != "monster" {
		t.Errorf("model = %v, want monster", body["model"])
	}
	if body["stream"] != true {
		t.Errorf("stream = %v, want true", body["stream"])
	}
	if opts, ok := body["stream_options"].(map[string]any); !ok || opts["include_usage"] != true {
		t.Errorf("stream_options = %v, want include_usage true", body["stream_options"])
	}
}

// TestChatStream_ExtraBodyOverridesGenerated checks the documented precedence:
// ExtraBody wins over the fields this package generates.
func TestChatStream_ExtraBodyOverridesGenerated(t *testing.T) {
	srv, seen := sseServer(t, cannedSSE([]string{"ok"}))

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	ep := llm.Endpoint{
		BaseURL:   srv.URL,
		Model:     "generated",
		ExtraBody: json.RawMessage(`{"model":"override"}`),
	}
	if err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	wait()

	if body := <-seen; body["model"] != "override" {
		t.Errorf("model = %v, want override", body["model"])
	}
}

// cannedToolCallSSE simulates a streaming tool-call turn: name in the first
// event, arguments split across later events, then finish_reason and [DONE].
func cannedToolCallSSE(callID, name string, argChunks []string) string {
	var sb strings.Builder
	sb.WriteString("data: " + fmt.Sprintf(
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":%s,"type":"function","function":{"name":%s,"arguments":""}}]},"finish_reason":null}]}`,
		jsonStr(callID), jsonStr(name)) + "\n\n")
	for _, arg := range argChunks {
		sb.WriteString("data: " + fmt.Sprintf(
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":%s}}]},"finish_reason":null}]}`,
			jsonStr(arg)) + "\n\n")
	}
	sb.WriteString(`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n")
	sb.WriteString(`data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}` + "\n\n")
	sb.WriteString("data: [DONE]\n\n")
	return sb.String()
}

// TestChatStream_ToolCallsAssembled checks that tool-call fragments spread over
// several events are concatenated onto the terminal chunk, with usage attached.
func TestChatStream_ToolCallsAssembled(t *testing.T) {
	srv, _ := sseServer(t, cannedToolCallSSE("call_abc123", "shell.exec",
		[]string{`{"cmd":"ls`, ` -la /`, `work"}`}))

	out := make(chan llm.Chunk, 32)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "monster"}
	req := llm.ChatReq{
		Messages: []llm.ChatMessage{{Role: llm.RoleUser, Content: "list files"}},
		Tools: []llm.ToolSpec{{
			Type: "function",
			Function: llm.FunctionSpec{
				Name:        "shell.exec",
				Description: "Run a shell command",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"cmd":{"type":"string"}}}`),
			},
		}},
	}
	if err := quietProvider(t).ChatStream(context.Background(), ep, req, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}

	done := doneChunk(t, wait())
	if len(done.ToolCalls) != 1 {
		t.Fatalf("assembled %d tool calls, want 1", len(done.ToolCalls))
	}
	tc := done.ToolCalls[0]
	if tc.ID != "call_abc123" {
		t.Errorf("ID = %q, want call_abc123", tc.ID)
	}
	if tc.Type != "function" {
		t.Errorf("Type = %q, want function", tc.Type)
	}
	if tc.Function.Name != "shell.exec" {
		t.Errorf("Name = %q, want shell.exec", tc.Function.Name)
	}
	if want := `{"cmd":"ls -la /work"}`; tc.Function.Arguments != want {
		t.Errorf("Arguments = %q, want %q", tc.Function.Arguments, want)
	}
	if done.TokensIn != 7 || done.TokensOut != 3 {
		t.Errorf("usage = (%d, %d), want (7, 3)", done.TokensIn, done.TokensOut)
	}
}

// TestChatStream_ToolsInRequestBody checks that declared tools and tool_choice
// are forwarded upstream.
func TestChatStream_ToolsInRequestBody(t *testing.T) {
	srv, seen := sseServer(t, cannedSSE([]string{"ok"}))

	out := make(chan llm.Chunk, 32)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "monster"}
	req := llm.ChatReq{
		Messages:   []llm.ChatMessage{{Role: llm.RoleUser, Content: "go"}},
		Tools:      []llm.ToolSpec{{Type: "function", Function: llm.FunctionSpec{Name: "memory.read"}}},
		ToolChoice: "auto",
	}
	if err := quietProvider(t).ChatStream(context.Background(), ep, req, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	wait()

	body := <-seen
	if _, ok := body["tools"]; !ok {
		t.Errorf("tools missing from request body; keys: %v", keysOf(body))
	}
	if body["tool_choice"] != "auto" {
		t.Errorf("tool_choice = %v, want auto", body["tool_choice"])
	}
}

// TestChatStream_MissingToolCallIDSynthesized checks the fallback that keeps a
// run alive when a provider omits the tool-call id: strict servers reject the
// follow-up conversation if the echoed id is empty.
func TestChatStream_MissingToolCallIDSynthesized(t *testing.T) {
	body := `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"probe","arguments":"{}"}}]}}]}` + "\n\n" +
		"data: [DONE]\n\n"
	srv, _ := sseServer(t, body)

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	if err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}

	done := doneChunk(t, wait())
	if len(done.ToolCalls) != 1 {
		t.Fatalf("assembled %d tool calls, want 1", len(done.ToolCalls))
	}
	if done.ToolCalls[0].ID != "call_0" {
		t.Errorf("synthesized ID = %q, want call_0", done.ToolCalls[0].ID)
	}
}

// TestChatStream_PlainChatHasNoToolCalls checks that an ordinary completion does
// not acquire phantom tool calls.
func TestChatStream_PlainChatHasNoToolCalls(t *testing.T) {
	srv, _ := sseServer(t, cannedSSE([]string{"hello", " world"}))

	out := make(chan llm.Chunk, 32)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "test-model"}
	req := llm.ChatReq{Messages: []llm.ChatMessage{{Role: llm.RoleUser, Content: "hi"}}}
	if err := quietProvider(t).ChatStream(context.Background(), ep, req, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}

	if done := doneChunk(t, wait()); len(done.ToolCalls) > 0 {
		t.Errorf("plain chat produced tool calls: %v", done.ToolCalls)
	}
}

// TestChatStream_MalformedFrameSurvives checks that junk on the wire costs at
// most the affected event. An unparseable frame, a bare data line, unknown SSE
// fields and comments must all be skipped without panicking or aborting.
func TestChatStream_MalformedFrameSurvives(t *testing.T) {
	body := ": keep-alive\n\n" +
		"event: ping\n\n" +
		`data: {"choices":[{"delta":{"content":"a"}}]}` + "\n\n" +
		"data: {not json at all\n\n" +
		"data:\n\n" +
		"data: []\n\n" +
		`data: {"choices":[{"delta":{"content":"b"}}]}` + "\n\n" +
		`data: {"choices":[{"delta":{"tool_calls":[{"index":99999,"function":{"name":"boom"}}]}}]}` + "\n\n" +
		"data: [DONE]\n\n"
	srv, _ := sseServer(t, body)

	out := make(chan llm.Chunk, 32)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	if err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}

	chunks := wait()
	if got := joinDeltas(chunks); got != "ab" {
		t.Errorf("assembled deltas = %q, want %q", got, "ab")
	}
	if done := doneChunk(t, chunks); len(done.ToolCalls) != 0 {
		t.Errorf("out-of-range tool_call index was accepted: %v", done.ToolCalls)
	}
}

// TestChatStream_NoDoneSentinel checks that a clean close without [DONE] is
// still a complete answer: some OpenAI-compatible servers never send it.
func TestChatStream_NoDoneSentinel(t *testing.T) {
	srv, _ := sseServer(t, `data: {"choices":[{"delta":{"content":"x"}}]}`+"\n\n")

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	if err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	chunks := wait()
	if got := joinDeltas(chunks); got != "x" {
		t.Errorf("assembled deltas = %q, want %q", got, "x")
	}
	doneChunk(t, chunks)
}

// --- non-streaming -----------------------------------------------------------

// TestChat_Success checks a complete non-streaming completion: content, usage,
// finish reason, and tool arguments repaired on the way out.
func TestChat_Success(t *testing.T) {
	const respBody = `{"choices":[{"message":{"content":"Hello","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":5}}`

	seen := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		seen <- decoded
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, respBody)
	}))
	defer srv.Close()

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m", APIKey: "sk-noop"}
	req := llm.ChatReq{Messages: []llm.ChatMessage{{Role: llm.RoleUser, Content: "hi"}}}
	resp, err := quietProvider(t).Chat(context.Background(), ep, req)
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}

	if body := <-seen; body["stream"] != false {
		t.Errorf("stream = %v, want false for a blocking call", body["stream"])
	}
	if resp.Content != "Hello" {
		t.Errorf("Content = %q, want Hello", resp.Content)
	}
	if resp.FinishReason != "tool_calls" {
		t.Errorf("FinishReason = %q, want tool_calls", resp.FinishReason)
	}
	if resp.TokensIn != 11 || resp.TokensOut != 5 {
		t.Errorf("usage = (%d, %d), want (11, 5)", resp.TokensIn, resp.TokensOut)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("got %d tool calls, want 1", len(resp.ToolCalls))
	}
	if want := `{"q":"x"}`; resp.ToolCalls[0].Function.Arguments != want {
		t.Errorf("Arguments = %q, want %q (trailing brace repaired)",
			resp.ToolCalls[0].Function.Arguments, want)
	}
}

// recordingHandler is a slog.Handler that appends every record it receives.
// Using a real Handler rather than parsing text/JSON output is what lets a
// test tell "reached some logger" apart from "reached the exact handler that
// was injected" -- which is the distinction that matters here, since a
// consumer's structured logging (JSON, routed to a file, whatever) is a
// Handler the consumer configured, not a format keel could match by accident.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(name string) slog.Handler       { return h }

func (h *recordingHandler) find(msg string) (slog.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message == msg {
			return r, true
		}
	}
	return slog.Record{}, false
}

// TestChat_RepairedToolArgsReachInjectedLogger checks that the warning emitted
// when a small model's malformed tool-call arguments are repaired lands on the
// *injected* logger's handler, not on whatever slog.Default() happens to be at
// the time. A consumer that configured JSON logging to a file must see this
// line through that handler -- if it instead escapes to the package default,
// it shows up as loose text on stderr instead of in the consumer's structured
// log.
func TestChat_RepairedToolArgsReachInjectedLogger(t *testing.T) {
	const respBody = `{"choices":[{"message":{"content":"Hello","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}}"}}]},"finish_reason":"tool_calls"}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, respBody)
	}))
	defer srv.Close()

	h := &recordingHandler{}
	provider := llm.New(llm.Options{Logger: slog.New(h)})

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	if _, err := provider.Chat(context.Background(), ep, llm.ChatReq{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}

	rec, ok := h.find("llm: repaired malformed tool call arguments")
	if !ok {
		t.Fatal("repair warning did not reach the injected logger's handler")
	}
	if rec.Level != slog.LevelWarn {
		t.Errorf("level = %v, want Warn", rec.Level)
	}
}

// TestChat_EmptyResponse checks that a 2xx carrying nothing usable is reported
// as a failure rather than as a completion that happened to be silent. A caller
// that took it for success would credit a broken endpoint with an answer and
// show a member an empty reply.
func TestChat_EmptyResponse(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantFinish string
		wantDetail string
	}{
		{
			name:       "no choices",
			body:       `{"choices":[]}`,
			wantDetail: "no choices",
		},
		{
			name:       "choices absent entirely",
			body:       `{}`,
			wantDetail: "no choices",
		},
		{
			name:       "choice with neither content nor tool calls",
			body:       `{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}],"usage":{"prompt_tokens":9,"completion_tokens":0}}`,
			wantFinish: llm.FinishContentFilter,
			wantDetail: "empty choice",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, c.body)
			}))
			defer srv.Close()

			resp, err := quietProvider(t).Chat(context.Background(),
				llm.Endpoint{BaseURL: srv.URL, Label: "silent-box"}, llm.ChatReq{})
			if err == nil {
				t.Fatalf("Chat succeeded with %+v, want ErrEmptyResponse", resp)
			}
			if !errors.Is(err, llm.ErrEmptyResponse) {
				t.Errorf("errors.Is(%v, ErrEmptyResponse) = false, want true", err)
			}
			// The endpoint answered, so neither of the two transport/provider
			// classifications applies.
			if llm.IsTransport(err) || llm.IsAPI(err) {
				t.Error("an empty completion is neither a transport nor a provider failure")
			}
			if !strings.Contains(err.Error(), "silent-box") {
				t.Errorf("error %q should name the endpoint", err.Error())
			}

			// The finish reason must be reachable as data, not by reading the
			// error text: it decides whether failing over is right.
			var emptyErr *llm.EmptyResponseError
			if !errors.As(err, &emptyErr) {
				t.Fatalf("errors.As(*EmptyResponseError) failed for %T", err)
			}
			if emptyErr.FinishReason != c.wantFinish {
				t.Errorf("FinishReason = %q, want %q", emptyErr.FinishReason, c.wantFinish)
			}
			if emptyErr.Detail != c.wantDetail {
				t.Errorf("Detail = %q, want %q", emptyErr.Detail, c.wantDetail)
			}

			// And the Response comes back populated — the deliberate exception
			// to the usual Go shape, for exactly the same reason.
			if resp.FinishReason != c.wantFinish {
				t.Errorf("Response.FinishReason = %q, want %q", resp.FinishReason, c.wantFinish)
			}
			if resp.Content != "" || len(resp.ToolCalls) != 0 {
				t.Errorf("Response should carry no completion, got %+v", resp)
			}
		})
	}
}

// TestChat_EmptyResponseKeepsUsage checks the specific reason the Response is
// returned alongside the error: a router must be able to tell a deliberate
// refusal from a broken endpoint, and the usage counts still describe real work.
func TestChat_EmptyResponseKeepsUsage(t *testing.T) {
	const body = `{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}],"usage":{"prompt_tokens":9,"completion_tokens":0}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	resp, err := quietProvider(t).Chat(context.Background(), llm.Endpoint{BaseURL: srv.URL}, llm.ChatReq{})
	if !errors.Is(err, llm.ErrEmptyResponse) {
		t.Fatalf("Chat error = %v, want ErrEmptyResponse", err)
	}
	if resp.FinishReason != llm.FinishContentFilter {
		t.Errorf("FinishReason = %q, want %q", resp.FinishReason, llm.FinishContentFilter)
	}
	if resp.TokensIn != 9 {
		t.Errorf("TokensIn = %d, want 9", resp.TokensIn)
	}
}

// TestFinishReasonConstants pins the constants to the wire vocabulary, so a
// caller comparing against them is comparing against what providers send.
func TestFinishReasonConstants(t *testing.T) {
	want := map[string]string{
		llm.FinishStop:          "stop",
		llm.FinishLength:        "length",
		llm.FinishToolCalls:     "tool_calls",
		llm.FinishContentFilter: "content_filter",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("finish reason constant = %q, want %q", got, expected)
		}
	}
}

// TestChat_ToolCallsOnlyIsNotEmpty checks the boundary of the emptiness rule: a
// tool-call turn legitimately carries no text, and must not be mistaken for a
// broken response.
func TestChat_ToolCallsOnlyIsNotEmpty(t *testing.T) {
	const body = `{"choices":[{"message":{"content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"probe","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	resp, err := quietProvider(t).Chat(context.Background(), llm.Endpoint{BaseURL: srv.URL}, llm.ChatReq{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("got %d tool calls, want 1", len(resp.ToolCalls))
	}
}

// --- error classification ----------------------------------------------------

// TestAPIError_BadRequest is the load-bearing case for the caller's routing
// decision: a 400 means the request is wrong, and sending it to another machine
// only wastes time. It must classify as an API error and NOT as transport.
func TestAPIError_BadRequest(t *testing.T) {
	const errBody = `{"error":{"message":"invalid model","type":"invalid_request_error","code":"model_not_found"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errBody)
	}))
	defer srv.Close()

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "ghost", APIKey: "sk-noop"}
	out := make(chan llm.Chunk, 4)
	err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out)
	if err == nil {
		t.Fatal("ChatStream succeeded on a 400")
	}

	if !llm.IsAPI(err) {
		t.Errorf("IsAPI(%v) = false, want true", err)
	}
	if llm.IsTransport(err) {
		t.Error("a 400 must not classify as a transport failure: retrying elsewhere cannot help")
	}

	var apiErr *llm.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) failed for %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", apiErr.StatusCode)
	}
	if apiErr.Message != "invalid model" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "invalid model")
	}
	if apiErr.Type != "invalid_request_error" {
		t.Errorf("Type = %q, want invalid_request_error", apiErr.Type)
	}
	if apiErr.Code != "model_not_found" {
		t.Errorf("Code = %q, want model_not_found", apiErr.Code)
	}
	if !strings.Contains(apiErr.Body, "invalid model") {
		t.Errorf("Body = %q, want the raw provider body retained", apiErr.Body)
	}
	if strings.Contains(err.Error(), "sk-noop") {
		t.Error("API key leaked into the error message")
	}
}

// TestAPIError_ErrorDoesNotDiscloseContent is the leak guard. Provider 400
// bodies quote the rejected request back, so anything Error() renders by default
// ends up in an operator's log — including whatever a member just typed. The
// prose must be reachable only by asking for it.
func TestAPIError_ErrorDoesNotDiscloseContent(t *testing.T) {
	// A body shaped like a real provider rejection that echoes the request.
	const secret = "my private message about the dentist appointment"
	errBody := fmt.Sprintf(
		`{"error":{"message":"Invalid 'messages[0].content': %s","type":"invalid_request_error","code":"string_above_max_length"}}`,
		secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errBody)
	}))
	defer srv.Close()

	_, err := quietProvider(t).Chat(context.Background(),
		llm.Endpoint{BaseURL: srv.URL, Label: "provider-a"}, llm.ChatReq{})
	if err == nil {
		t.Fatal("Chat succeeded on a 400")
	}

	rendered := err.Error()
	if strings.Contains(rendered, secret) {
		t.Errorf("Error() disclosed echoed request content: %q", rendered)
	}

	var apiErr *llm.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) failed for %T", err)
	}
	if strings.Contains(apiErr.Error(), apiErr.Message) {
		t.Error("Error() must not render the provider Message")
	}
	if strings.Contains(apiErr.Error(), apiErr.Body) {
		t.Error("Error() must not render the raw Body")
	}

	// What Error() must still carry: enough to act on without reading content.
	for _, want := range []string{"provider-a", "400", "invalid_request_error", "string_above_max_length"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("Error() = %q, missing %q", rendered, want)
		}
	}

	// And the prose remains available to a caller that asks by name.
	if !strings.Contains(apiErr.Detail(), secret) {
		t.Errorf("Detail() = %q, want the provider's message", apiErr.Detail())
	}
}

// TestAPIError_Detail checks the shapes Detail collapses: message alone, body
// alone, and the two combined only when the body carries more.
func TestAPIError_Detail(t *testing.T) {
	cases := []struct {
		name   string
		apiErr llm.APIError
		want   string
	}{
		{
			name:   "message parsed out of the body",
			apiErr: llm.APIError{Message: "bad model", Body: `{"error":{"message":"bad model"}}`},
			want:   "bad model",
		},
		{
			name:   "body only",
			apiErr: llm.APIError{Body: "<html>502</html>"},
			want:   "<html>502</html>",
		},
		{
			name:   "message and an unrelated body",
			apiErr: llm.APIError{Message: "bad model", Body: "upstream detail"},
			want:   "bad model: upstream detail",
		},
		{
			name:   "neither",
			apiErr: llm.APIError{},
			want:   "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.apiErr.Detail(); got != c.want {
				t.Errorf("Detail() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestAPIError_RateLimited checks that a 429 is an API error carrying its status
// intact, so a caller can apply its own backoff policy without string matching.
func TestAPIError_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}`)
	}))
	defer srv.Close()

	_, err := quietProvider(t).Chat(context.Background(), llm.Endpoint{BaseURL: srv.URL}, llm.ChatReq{})
	if err == nil {
		t.Fatal("Chat succeeded on a 429")
	}
	if llm.IsTransport(err) {
		t.Error("a 429 is an answer, not a transport failure")
	}

	var apiErr *llm.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) failed for %T", err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", apiErr.StatusCode)
	}
	if apiErr.Message != "rate limit exceeded" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "rate limit exceeded")
	}
}

// TestAPIError_StringErrorBody checks the other common envelope shape: some
// OpenAI-compatible servers put a bare string under "error".
func TestAPIError_StringErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"model not found"}`)
	}))
	defer srv.Close()

	_, err := quietProvider(t).Chat(context.Background(), llm.Endpoint{BaseURL: srv.URL}, llm.ChatReq{})
	var apiErr *llm.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) failed for %v", err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", apiErr.StatusCode)
	}
	if apiErr.Message != "model not found" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "model not found")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error text %q should mention the status", err.Error())
	}
}

// TestAPIError_NonJSONBody checks that an HTML error page from a proxy still
// yields a usable APIError rather than a parse failure.
func TestAPIError_NonJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "<html><body>502 Bad Gateway</body></html>")
	}))
	defer srv.Close()

	_, err := quietProvider(t).Chat(context.Background(), llm.Endpoint{BaseURL: srv.URL}, llm.ChatReq{})
	var apiErr *llm.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) failed for %v", err)
	}
	if apiErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want 502", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Body, "Bad Gateway") {
		t.Errorf("Body = %q, want the raw body retained", apiErr.Body)
	}
}

// TestTransportError_ConnectionRefused is the mirror of the 400 case: nothing
// answered, so the same request may well succeed against a different machine.
func TestTransportError_ConnectionRefused(t *testing.T) {
	// Take a real port, then close the listener so nothing is behind it.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	ep := llm.Endpoint{BaseURL: deadURL, Model: "m", Label: "dead-box"}
	out := make(chan llm.Chunk, 4)
	err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out)
	if err == nil {
		t.Fatal("ChatStream succeeded against a closed port")
	}

	if !llm.IsTransport(err) {
		t.Errorf("IsTransport(%v) = false, want true", err)
	}
	if llm.IsAPI(err) {
		t.Error("a refused connection must not classify as a provider error: nothing answered")
	}

	var te *llm.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("errors.As(*TransportError) failed for %T", err)
	}
	if te.Op != "connect" {
		t.Errorf("Op = %q, want connect", te.Op)
	}
	if te.Endpoint != "dead-box" {
		t.Errorf("Endpoint = %q, want the endpoint label", te.Endpoint)
	}
	if te.Unwrap() == nil {
		t.Error("TransportError must wrap the underlying failure")
	}
}

// TestTransportError_MidStreamDisconnect checks that a stream cut after headers
// and partial data is a transport failure, not a silently truncated success.
func TestTransportError_MidStreamDisconnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("test server does not support hijacking")
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()

		// A chunked response whose terminating chunk never arrives.
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		frame := `data: {"choices":[{"delta":{"content":"partial"}}]}` + "\n\n"
		fmt.Fprintf(buf, "%x\r\n%s\r\n", len(frame), frame)
		writeFlush(t, buf)
	}))
	defer srv.Close()

	out := make(chan llm.Chunk, 8)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range out {
		}
	}()

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out)
	close(out)
	<-drained

	if err == nil {
		t.Fatal("a stream cut mid-flight was reported as success")
	}
	if !llm.IsTransport(err) {
		t.Errorf("IsTransport(%v) = false, want true", err)
	}
	if llm.IsAPI(err) {
		t.Error("a severed stream must not classify as a provider error")
	}
	var te *llm.TransportError
	if errors.As(err, &te) && te.Op != "stream" {
		t.Errorf("Op = %q, want stream", te.Op)
	}
}

func writeFlush(t *testing.T, buf *bufio.ReadWriter) {
	t.Helper()
	if err := buf.Flush(); err != nil {
		t.Errorf("flush: %v", err)
	}
}

// TestTransportError_EndpointTimeout checks that Endpoint.Timeout expiring is a
// fact about the endpoint — a transport failure worth routing around — and not
// the caller's own cancellation.
func TestTransportError_EndpointTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m", Timeout: 50 * time.Millisecond}
	_, err := quietProvider(t).Chat(context.Background(), ep, llm.ChatReq{})
	if err == nil {
		t.Fatal("Chat succeeded against a server that never answers")
	}
	if !llm.IsTransport(err) {
		t.Errorf("IsTransport(%v) = false, want true", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(%v, DeadlineExceeded) = false, want true", err)
	}
}

// TestChatStream_CallerCancellation checks that a caller hanging up is reported
// as its own context error, not as a transport failure: the caller learned
// nothing about the endpoint, so it is not a reason to route away from it.
func TestChatStream_CallerCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(started)
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan llm.Chunk, 4)
	result := make(chan error, 1)
	ep := llm.Endpoint{BaseURL: srv.URL, Model: "slow"}
	go func() {
		result <- quietProvider(t).ChatStream(ctx, ep, llm.ChatReq{}, out)
	}()

	<-started
	cancel()

	err := <-result
	if err == nil {
		t.Fatal("ChatStream succeeded after cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(%v, context.Canceled) = false, want true", err)
	}
	if llm.IsTransport(err) {
		t.Error("caller cancellation must not classify as a transport failure")
	}
}

// TestInvalidRequest_BadExtraBody checks the third failure class: a request that
// cannot be built at all is neither transport nor provider.
func TestInvalidRequest_BadExtraBody(t *testing.T) {
	ep := llm.Endpoint{
		BaseURL:   "http://127.0.0.1:1",
		Model:     "m",
		ExtraBody: json.RawMessage(`{not json`),
	}
	_, err := quietProvider(t).Chat(context.Background(), ep, llm.ChatReq{})
	if err == nil {
		t.Fatal("Chat succeeded with unparseable ExtraBody")
	}
	if !errors.Is(err, llm.ErrInvalidRequest) {
		t.Errorf("errors.Is(%v, ErrInvalidRequest) = false, want true", err)
	}
	if llm.IsTransport(err) || llm.IsAPI(err) {
		t.Error("an unbuildable request is neither a transport nor a provider failure")
	}
}

// --- construction ------------------------------------------------------------

// TestNew_InjectedClientIsUsed checks that a supplied client fully replaces the
// default one, which is what makes the provider testable without a socket.
func TestNew_InjectedClientIsUsed(t *testing.T) {
	rt := &recordingTransport{body: cannedSSE([]string{"injected"})}
	provider := llm.New(llm.Options{
		Client: &http.Client{Transport: rt},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: "https://provider.invalid/v1", Model: "m"}
	if err := provider.ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	if got := joinDeltas(wait()); got != "injected" {
		t.Errorf("assembled deltas = %q, want %q", got, "injected")
	}
	if rt.calls != 1 {
		t.Errorf("injected transport saw %d calls, want 1", rt.calls)
	}
	if rt.url != "https://provider.invalid/v1/chat/completions" {
		t.Errorf("request URL = %q", rt.url)
	}
}

type recordingTransport struct {
	body  string
	calls int
	url   string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.calls++
	rt.url = r.URL.String()
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(rt.body)),
		Request:    r,
	}, nil
}

// TestAPIKeyNeverLogged checks the credential handling promise: the key goes on
// the wire and nowhere else, at any log level.
func TestAPIKeyNeverLogged(t *testing.T) {
	const secret = "sk-do-not-log-me-0123456789"

	srv, _ := sseServer(t, cannedSSE([]string{"ok"}))

	var logs bytes.Buffer
	provider := llm.New(llm.Options{
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m", APIKey: secret}
	if err := provider.ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	wait()

	if logs.Len() == 0 {
		t.Fatal("expected at least one debug log line to inspect")
	}
	if strings.Contains(logs.String(), secret) {
		t.Errorf("API key leaked into logs: %s", logs.String())
	}
}

// --- pull-based streaming ----------------------------------------------------

// TestChatStreamReader_PullsChunks checks the pull contract: deltas first, then
// one terminal chunk, then io.EOF, and io.EOF again on every call after that.
func TestChatStreamReader_PullsChunks(t *testing.T) {
	srv, _ := sseServer(t, cannedSSE([]string{"one", "two"}))

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	stream, err := quietProvider(t).ChatStreamReader(context.Background(), ep, llm.ChatReq{})
	if err != nil {
		t.Fatalf("ChatStreamReader: %v", err)
	}
	defer stream.Close()

	var deltas []string
	var sawDone bool
	for {
		chunk, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if chunk.Done {
			sawDone = true
			continue
		}
		deltas = append(deltas, chunk.Delta)
	}

	if got := strings.Join(deltas, ""); got != "onetwo" {
		t.Errorf("deltas = %q, want %q", got, "onetwo")
	}
	if !sawDone {
		t.Error("no terminal chunk before io.EOF")
	}
	if _, err := stream.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("Next after EOF = %v, want io.EOF", err)
	}
}

// TestChatStreamReader_FailoverBoundary is the reason this entry point exists:
// everything up to and including response-header validation must surface as the
// returned error, with no stream handed back and nothing emitted, so a caller
// holding several endpoints can move on without having leaked a partial answer.
func TestChatStreamReader_FailoverBoundary(t *testing.T) {
	t.Run("provider refusal", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"message":"bad model","type":"invalid_request_error"}}`)
		}))
		defer srv.Close()

		stream, err := quietProvider(t).ChatStreamReader(context.Background(),
			llm.Endpoint{BaseURL: srv.URL, Model: "m"}, llm.ChatReq{})
		if err == nil {
			t.Fatal("ChatStreamReader succeeded on a 400")
		}
		if stream != nil {
			t.Error("a failed open must not hand back a stream")
		}
		if !llm.IsAPI(err) || llm.IsTransport(err) {
			t.Errorf("classification wrong for a 400: %v", err)
		}
	})

	t.Run("unreachable endpoint", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		deadURL := dead.URL
		dead.Close()

		stream, err := quietProvider(t).ChatStreamReader(context.Background(),
			llm.Endpoint{BaseURL: deadURL, Model: "m"}, llm.ChatReq{})
		if err == nil {
			t.Fatal("ChatStreamReader succeeded against a closed port")
		}
		if stream != nil {
			t.Error("a failed open must not hand back a stream")
		}
		if !llm.IsTransport(err) {
			t.Errorf("IsTransport(%v) = false, want true", err)
		}
	})
}

// TestChatStreamReader_ErrorIsSticky checks that a mid-stream failure is
// reported identically on every subsequent call, so a caller cannot accidentally
// read past it.
func TestChatStreamReader_ErrorIsSticky(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("test server does not support hijacking")
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()

		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		frame := `data: {"choices":[{"delta":{"content":"partial"}}]}` + "\n\n"
		fmt.Fprintf(buf, "%x\r\n%s\r\n", len(frame), frame)
		writeFlush(t, buf)
	}))
	defer srv.Close()

	stream, err := quietProvider(t).ChatStreamReader(context.Background(),
		llm.Endpoint{BaseURL: srv.URL, Model: "m"}, llm.ChatReq{})
	if err != nil {
		t.Fatalf("ChatStreamReader: %v", err)
	}
	defer stream.Close()

	if chunk, err := stream.Next(); err != nil || chunk.Delta != "partial" {
		t.Fatalf("first Next = (%+v, %v), want the partial delta", chunk, err)
	}

	first, err := stream.Next()
	if err == nil {
		t.Fatalf("second Next succeeded with %+v, want the severed stream reported", first)
	}
	if !llm.IsTransport(err) {
		t.Errorf("IsTransport(%v) = false, want true", err)
	}
	if _, again := stream.Next(); again != err {
		t.Errorf("Next after failure = %v, want the same sticky error %v", again, err)
	}
}

// TestChatStreamReader_CloseReleasesConnection checks that abandoning a stream
// half-read costs nothing: Close must abort the request rather than leave it
// running, so neither the connection nor a goroutine survives it.
func TestChatStreamReader_CloseReleasesConnection(t *testing.T) {
	released := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(released)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("test server does not support flushing")
			return
		}
		// Stream indefinitely: only an aborted request ends this handler.
		for {
			if r.Context().Err() != nil {
				return
			}
			if _, err := fmt.Fprint(w, `data: {"choices":[{"delta":{"content":"tick"}}]}`+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer srv.Close()

	// An injected client so the test can retire idle connections deterministically.
	client := &http.Client{Transport: &http.Transport{}}
	provider := llm.New(llm.Options{
		Client: client,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	baseline := runtime.NumGoroutine()

	stream, err := provider.ChatStreamReader(context.Background(),
		llm.Endpoint{BaseURL: srv.URL, Model: "m"}, llm.ChatReq{})
	if err != nil {
		t.Fatalf("ChatStreamReader: %v", err)
	}

	chunk, err := stream.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if chunk.Delta != "tick" {
		t.Fatalf("Delta = %q, want tick", chunk.Delta)
	}

	// Close mid-body, with the provider still sending.
	if err := stream.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Errorf("second Close: %v, want idempotent nil", err)
	}
	if _, err := stream.Next(); !errors.Is(err, llm.ErrStreamClosed) {
		t.Errorf("Next after Close = %v, want ErrStreamClosed", err)
	}

	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("server still streaming after Close: the request was abandoned, not aborted")
	}

	client.CloseIdleConnections()

	// Goroutine counts settle asynchronously; poll rather than sample once.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := runtime.NumGoroutine()
		if got <= baseline+2 {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutines %d -> %d across an abandoned stream, want no growth", baseline, got)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestChatStream_EmptyStream checks that the streaming path reports the same
// defect as the blocking one. A stream that ends having produced no text and no
// tool call must not deliver a terminal chunk: that would look downstream like a
// completed turn, and would credit a broken endpoint with an answer.
func TestChatStream_EmptyStream(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantFinish string
	}{
		{
			name: "sentinel only",
			body: "data: [DONE]\n\n",
		},
		{
			name: "clean close with no events",
			body: "",
		},
		{
			name:       "finish reason but no content",
			body:       `data: {"choices":[{"delta":{},"finish_reason":"content_filter"}]}` + "\n\ndata: [DONE]\n\n",
			wantFinish: llm.FinishContentFilter,
		},
		{
			name:       "empty deltas only",
			body:       `data: {"choices":[{"delta":{"content":""},"finish_reason":"stop"}]}` + "\n\ndata: [DONE]\n\n",
			wantFinish: llm.FinishStop,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := sseServer(t, c.body)

			out := make(chan llm.Chunk, 8)
			ep := llm.Endpoint{BaseURL: srv.URL, Model: "m", Label: "silent-box"}
			err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out)

			if err == nil {
				t.Fatal("ChatStream reported success for a stream that produced nothing")
			}
			if !errors.Is(err, llm.ErrEmptyResponse) {
				t.Errorf("errors.Is(%v, ErrEmptyResponse) = false, want true", err)
			}
			if llm.IsTransport(err) || llm.IsAPI(err) {
				t.Error("an empty stream is neither a transport nor a provider failure")
			}

			// Nothing may have reached the caller: that is what makes failing
			// over safe here.
			if len(out) != 0 {
				t.Errorf("%d chunks were emitted before the empty-stream error, want 0", len(out))
			}

			var emptyErr *llm.EmptyResponseError
			if !errors.As(err, &emptyErr) {
				t.Fatalf("errors.As(*EmptyResponseError) failed for %T", err)
			}
			if emptyErr.FinishReason != c.wantFinish {
				t.Errorf("FinishReason = %q, want %q", emptyErr.FinishReason, c.wantFinish)
			}
			if emptyErr.Detail != "empty stream" {
				t.Errorf("Detail = %q, want %q", emptyErr.Detail, "empty stream")
			}
		})
	}
}

// TestChatStream_ToolCallOnlyStreamIsNotEmpty checks the boundary: a turn that
// requests a tool and says nothing is a real completion, not an empty one.
func TestChatStream_ToolCallOnlyStreamIsNotEmpty(t *testing.T) {
	srv, _ := sseServer(t, cannedToolCallSSE("call_1", "probe", []string{`{}`}))

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	if err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}

	done := doneChunk(t, wait())
	if len(done.ToolCalls) != 1 {
		t.Fatalf("got %d tool calls, want 1", len(done.ToolCalls))
	}
	if done.FinishReason != llm.FinishToolCalls {
		t.Errorf("Done.FinishReason = %q, want %q", done.FinishReason, llm.FinishToolCalls)
	}
}

// TestChatStream_DoneChunkCarriesFinishReason checks that the reason a normal
// completion stopped survives onto the terminal chunk, testable against the
// constants rather than a literal.
func TestChatStream_DoneChunkCarriesFinishReason(t *testing.T) {
	body := `data: {"choices":[{"delta":{"content":"hi"},"finish_reason":null}]}` + "\n\n" +
		`data: {"choices":[{"delta":{},"finish_reason":"length"}]}` + "\n\n" +
		"data: [DONE]\n\n"
	srv, _ := sseServer(t, body)

	out := make(chan llm.Chunk, 8)
	wait := startCollector(out)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m"}
	if err := quietProvider(t).ChatStream(context.Background(), ep, llm.ChatReq{}, out); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}

	if done := doneChunk(t, wait()); done.FinishReason != llm.FinishLength {
		t.Errorf("Done.FinishReason = %q, want %q", done.FinishReason, llm.FinishLength)
	}
}

// TestChatStreamReader_EmptyStreamIsSafeToFailOver checks the pull path's
// version: Next returns the empty-response error in place of a terminal chunk,
// having handed back nothing at all, and it stays sticky afterwards.
func TestChatStreamReader_EmptyStreamIsSafeToFailOver(t *testing.T) {
	body := `data: {"choices":[{"delta":{},"finish_reason":"content_filter"}]}` + "\n\ndata: [DONE]\n\n"
	srv, _ := sseServer(t, body)

	ep := llm.Endpoint{BaseURL: srv.URL, Model: "m", Label: "filtered-box"}
	stream, err := quietProvider(t).ChatStreamReader(context.Background(), ep, llm.ChatReq{})
	if err != nil {
		t.Fatalf("ChatStreamReader: %v", err)
	}
	defer stream.Close()

	chunk, err := stream.Next()
	if err == nil {
		t.Fatalf("first Next returned %+v, want ErrEmptyResponse", chunk)
	}
	if !errors.Is(err, llm.ErrEmptyResponse) {
		t.Errorf("errors.Is(%v, ErrEmptyResponse) = false, want true", err)
	}
	if chunk.Done {
		t.Error("a terminal chunk was handed back alongside the empty-stream error")
	}

	var emptyErr *llm.EmptyResponseError
	if !errors.As(err, &emptyErr) {
		t.Fatalf("errors.As(*EmptyResponseError) failed for %T", err)
	}
	if emptyErr.FinishReason != llm.FinishContentFilter {
		t.Errorf("FinishReason = %q, want %q", emptyErr.FinishReason, llm.FinishContentFilter)
	}
	if !strings.Contains(err.Error(), "filtered-box") {
		t.Errorf("error %q should name the endpoint", err.Error())
	}

	if _, again := stream.Next(); again != err {
		t.Errorf("Next after the empty-stream error = %v, want the same sticky error", again)
	}
}

// TestChatMessage_WireFormat pins the protocol mapping: the role constants are
// the exact strings the API expects, and an assistant message carrying tool
// calls still serializes an empty content field — stricter OpenAI-compatible
// servers reject the conversation without it.
func TestChatMessage_WireFormat(t *testing.T) {
	roles := map[string]string{
		llm.RoleSystem:    "system",
		llm.RoleUser:      "user",
		llm.RoleAssistant: "assistant",
		llm.RoleTool:      "tool",
	}
	for got, want := range roles {
		if got != want {
			t.Errorf("role constant = %q, want %q", got, want)
		}
	}

	encoded, err := json.Marshal(llm.ChatMessage{
		Role:      llm.RoleAssistant,
		ToolCalls: []llm.ToolCall{{ID: "call_1", Type: "function"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"role":"assistant"`, `"content":""`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("encoded message %s is missing %s", encoded, want)
		}
	}
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
