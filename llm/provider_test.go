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
	"strings"
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

// TestChat_EmptyChoices checks that a response with no choices is not a panic.
func TestChat_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[]}`)
	}))
	defer srv.Close()

	resp, err := quietProvider(t).Chat(context.Background(), llm.Endpoint{BaseURL: srv.URL}, llm.ChatReq{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if resp.Content != "" || len(resp.ToolCalls) != 0 {
		t.Errorf("empty choices produced %+v, want zero Response", resp)
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
