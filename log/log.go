// SPDX-License-Identifier: Apache-2.0

// Package log builds slog loggers from explicit options and redacts values that
// must never reach a log sink.
//
// Construction has no global side effects: New returns a logger and nothing
// else happens. A library that reconfigures the process's default logger when
// somebody builds a component is a library that fights its host, so the choice
// of a process-wide default is left to the application, which can make it by
// calling SetDefault.
package log

import (
	"io"
	"log/slog"
	"os"
)

// redacted is the fixed placeholder substituted for every non-empty secret.
// It is a constant so that redacted values reveal nothing about length or
// shape of what they replaced.
const redacted = "***redacted***"

// Options describes a logger. The zero value is useful: info level, text
// handler, standard output.
type Options struct {
	// Level is the minimum record level that will be emitted. The zero value
	// is slog.LevelInfo.
	Level slog.Level

	// JSON selects the JSON handler. False (the default) selects the
	// human-readable text handler.
	JSON bool

	// Out is where records are written. Nil means os.Stdout.
	Out io.Writer

	// AddSource includes the source file and line of the log call in each
	// record. Off by default: it costs a stack walk per record.
	AddSource bool
}

// New returns a logger built from opts. It does not touch slog's default
// logger; see SetDefault.
func New(opts Options) *slog.Logger {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	handlerOpts := &slog.HandlerOptions{Level: opts.Level, AddSource: opts.AddSource}

	var handler slog.Handler
	if opts.JSON {
		handler = slog.NewJSONHandler(out, handlerOpts)
	} else {
		handler = slog.NewTextHandler(out, handlerOpts)
	}
	return slog.New(handler)
}

// SetDefault installs l as the logger returned by slog.Default, for
// applications that want one. It is a thin wrapper over slog.SetDefault,
// separated from New so that the global change is always a deliberate,
// greppable act by the program's main function rather than a side effect of
// building a component.
func SetDefault(l *slog.Logger) {
	slog.SetDefault(l)
}

// Redact returns a fixed placeholder for any non-empty string, and the empty
// string for empty input. Use it on every value that may carry a passphrase,
// API key, token, or other credential before it reaches a log record.
//
// The empty case is passed through deliberately: "" is not a secret, and
// distinguishing "unset" from "set but hidden" in a log line is worth more than
// the nothing it discloses.
func Redact(s string) string {
	if s == "" {
		return ""
	}
	return redacted
}
