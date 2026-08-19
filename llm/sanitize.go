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

	// ArgRepaired means something was thrown away to make the input parse: the
	// first JSON value decoded, and there was more after it — the stray brace,
	// the trailing junk. The model's intent survived, but only because the
	// remainder was discarded, and the remainder is not always nothing.
	ArgRepaired

	// ArgDropped means the input could not be parsed at all and was replaced
	// with "{}". This is data loss: the model asked for something and the
	// request is gone. Surface it.
	ArgDropped

	// ArgReformatted means the input was valid, complete JSON that re-encodes to
	// a different string: a space after a colon, an indented block, keys in the
	// order the model wrote them rather than sorted. Nothing was discarded and
	// nothing was corrected — the value that goes out is the value that came in.
	//
	// This used to be reported as ArgRepaired, which made "repaired" the verdict
	// on every healthy call from any model that pretty-prints its arguments (and,
	// because re-encoding a map sorts the keys, on most that do not). A signal
	// that fires on success is one operators stop reading, which is where a real
	// ArgDropped goes to hide.
	//
	// Declared last so the values of the four above it are unchanged for anything
	// already compiled against them.
	ArgReformatted
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
	case ArgReformatted:
		return "reformatted"
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
//
// The classification is drawn on what was LOST, not on whether the bytes changed.
// Comparing the re-encoding to the input as a string cannot tell the two apart:
// re-marshalling a decoded object sorts its keys and drops every space, so a
// model that writes `{"query": "boiler", "limit": 5}` — valid, complete, nothing
// wrong with it — produces a different string and used to be called repaired,
// the same verdict as the stray brace the function was written for. What
// separates them is the decoder's own offset: if it stopped short of the end of
// the input, something was thrown away and that is a repair; if it consumed the
// lot, the difference is spelling and that is [ArgReformatted].
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
	switch {
	case strings.TrimSpace(trimmed[decoder.InputOffset():]) != "":
		// The decoder stopped before the end: trailing data was discarded.
		return out, ArgRepaired
	case out != trimmed:
		return out, ArgReformatted
	default:
		return out, ArgClean
	}
}
