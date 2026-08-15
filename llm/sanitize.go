// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"encoding/json"
	"strings"
)

// ArgFixup classifies what [SanitizeToolArgsFixup] had to do to an argument
// string, so a caller can decide whether the event deserves attention.
type ArgFixup int

const (
	// ArgClean means the input was already valid, canonical JSON.
	ArgClean ArgFixup = iota

	// ArgEmpty means the input was empty and became "{}". Models routinely emit
	// nothing for a no-argument tool; this is benign.
	ArgEmpty

	// ArgRepaired means the input parsed but was not canonical — trailing junk,
	// stray whitespace, unusual formatting — and was re-marshalled. The model's
	// intent survived intact.
	ArgRepaired

	// ArgDropped means the input could not be parsed at all and was replaced
	// with "{}". This is data loss: the model asked for something and the
	// request is gone. Surface it.
	ArgDropped
)

// String renders the classification for logs.
func (f ArgFixup) String() string {
	switch f {
	case ArgClean:
		return "clean"
	case ArgEmpty:
		return "empty"
	case ArgRepaired:
		return "repaired"
	case ArgDropped:
		return "dropped"
	default:
		return "unknown"
	}
}

// SanitizeToolArgs normalizes a model-emitted tool-call argument string into
// valid JSON, discarding the classification. See [SanitizeToolArgsFixup].
func SanitizeToolArgs(s string) string {
	out, _ := SanitizeToolArgsFixup(s)
	return out
}

// SanitizeToolArgsFixup normalizes a model-emitted tool-call argument string
// into valid JSON and reports what it had to do.
//
// This exists because malformed arguments are doubly destructive. The string is
// dispatched to the tool, and it is also echoed back to the provider in the next
// request — where an OpenAI-compatible server that cannot parse it rejects the
// entire conversation with a 400 ("Extra data: …"), ending the run. A single
// stray brace, which models emit often enough to matter (`{"path":"/work"}}`),
// otherwise takes down everything that follows it.
//
// The repair decodes the FIRST JSON value in the string — json.Decoder stops
// there and ignores anything after it, which is exactly what fixes the stray
// brace — and re-marshals it canonically. Input that is empty or unparseable
// falls back to "{}", degrading one bad tool call to a no-argument call instead
// of failing the run. The result always parses.
func SanitizeToolArgsFixup(s string) (string, ArgFixup) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "{}", ArgEmpty
	}

	decoder := json.NewDecoder(strings.NewReader(trimmed))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "{}", ArgDropped
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}", ArgDropped
	}

	out := string(encoded)
	if out != trimmed {
		// Trailing data, whitespace or non-canonical formatting was corrected.
		return out, ArgRepaired
	}
	return out, ArgClean
}
