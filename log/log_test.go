// SPDX-License-Identifier: Apache-2.0

package log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewWritesTextByDefault(t *testing.T) {
	var buf bytes.Buffer
	l := New(Options{Out: &buf})
	l.Info("hello", "key", "value")

	out := buf.String()
	if !strings.Contains(out, "msg=hello") || !strings.Contains(out, "key=value") {
		t.Fatalf("expected text-handler output, got %q", out)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("default handler must not be JSON, got %q", out)
	}
}

func TestNewJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	l := New(Options{Out: &buf, JSON: true})
	l.Info("hello", "key", "value")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("expected JSON output, got %q: %v", buf.String(), err)
	}
	if rec["msg"] != "hello" || rec["key"] != "value" {
		t.Fatalf("unexpected record: %v", rec)
	}
}

func TestNewLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := New(Options{Out: &buf, Level: slog.LevelWarn})
	l.Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("info record should be filtered at warn level, got %q", buf.String())
	}
	l.Warn("kept")
	if !strings.Contains(buf.String(), "kept") {
		t.Fatalf("warn record should be emitted, got %q", buf.String())
	}

	var debugBuf bytes.Buffer
	d := New(Options{Out: &debugBuf, Level: slog.LevelDebug})
	d.Debug("visible")
	if !strings.Contains(debugBuf.String(), "visible") {
		t.Fatalf("debug record should be emitted at debug level, got %q", debugBuf.String())
	}
}

// New must not reconfigure the process-wide logger. This is the whole reason
// SetDefault is a separate call.
func TestNewDoesNotTouchDefault(t *testing.T) {
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	var buf bytes.Buffer
	built := New(Options{Out: &buf, JSON: true})
	if slog.Default() != before {
		t.Fatal("New changed slog.Default()")
	}

	SetDefault(built)
	if slog.Default() != built {
		t.Fatal("SetDefault did not install the logger")
	}
	slog.Info("through the default")
	if !strings.Contains(buf.String(), "through the default") {
		t.Fatalf("default logger did not write to the configured writer, got %q", buf.String())
	}
}

func TestRedact(t *testing.T) {
	if got := Redact(""); got != "" {
		t.Errorf("Redact(\"\") = %q, want empty string", got)
	}
	for _, secret := range []string{"x", "hunter2", strings.Repeat("s3cr3t", 700)} {
		got := Redact(secret)
		if got != redacted {
			t.Errorf("Redact(%d chars) = %q, want %q", len(secret), got, redacted)
		}
		if strings.Contains(got, secret) {
			t.Errorf("Redact leaked its input")
		}
	}
}
