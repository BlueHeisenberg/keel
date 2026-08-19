// SPDX-License-Identifier: Apache-2.0

package llm_test

import (
	"testing"

	"github.com/BlueHeisenberg/keel/llm"
)

func TestSanitizeToolArgs(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"path":"/work"}}`, `{"path":"/work"}`}, // the reported bug: trailing extra brace
		{`{"path": "/work"}}`, `{"path":"/work"}`},
		{``, `{}`},
		{`{}`, `{}`},
		{`{"a":1}`, `{"a":1}`},
		{`not json at all`, `{}`},
		{`{"x":"y"} trailing junk`, `{"x":"y"}`},
	}
	for _, c := range cases {
		if got := llm.SanitizeToolArgs(c.in); got != c.want {
			t.Errorf("SanitizeToolArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeToolArgsFixup(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		outcome llm.ArgFixup
	}{
		{``, `{}`, llm.ArgEmpty},
		{`{}`, `{}`, llm.ArgClean},
		{`{"a":1}`, `{"a":1}`, llm.ArgClean},
		{`{"path":"/work"}}`, `{"path":"/work"}`, llm.ArgRepaired}, // trailing brace
		{`{"x":"y"} junk`, `{"x":"y"}`, llm.ArgRepaired},           // trailing junk
		{`not json`, `{}`, llm.ArgDropped},                         // unparseable, data loss

		// The four rows a live run against a 27B produced, which is why
		// ArgReformatted exists. Every one of the first three is a healthy call
		// and all three used to read "repaired", identically to the fourth.
		{`{"query":"boiler"}`, `{"query":"boiler"}`, llm.ArgClean},
		{`{"query": "boiler"}`, `{"query":"boiler"}`, llm.ArgReformatted},
		{`{"query": "boiler", "limit": 5}`, `{"limit":5,"query":"boiler"}`, llm.ArgReformatted},
		{`{"query":"boiler"}}`, `{"query":"boiler"}`, llm.ArgRepaired},

		// Key order alone. Re-marshalling a decoded object sorts the keys, so
		// input a human would call canonical still comes back as different bytes
		// — which is how the string comparison this replaced managed to call even
		// compact, space-free JSON "repaired".
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`, llm.ArgReformatted},
		// Indentation and newlines, discarded without anything being lost.
		{"{\n  \"a\": 1\n}", `{"a":1}`, llm.ArgReformatted},
		// Trailing whitespace is not data. It survives TrimSpace and must not
		// read as a repair.
		{"  {\"a\":1}  ", `{"a":1}`, llm.ArgClean},
	}
	for _, c := range cases {
		got, outcome := llm.SanitizeToolArgsFixup(c.in)
		if got != c.want || outcome != c.outcome {
			t.Errorf("SanitizeToolArgsFixup(%q) = (%q, %s), want (%q, %s)",
				c.in, got, outcome, c.want, c.outcome)
		}
	}
}

func TestArgFixupString(t *testing.T) {
	cases := map[llm.ArgFixup]string{
		llm.ArgClean:    "clean",
		llm.ArgEmpty:    "empty",
		llm.ArgRepaired: "repaired",
		llm.ArgDropped:  "dropped",

		llm.ArgReformatted: "reformatted",

		llm.ArgFixup(9): "unknown",
	}
	for fixup, want := range cases {
		if got := fixup.String(); got != want {
			t.Errorf("ArgFixup(%d).String() = %q, want %q", int(fixup), got, want)
		}
	}
}

// TestArgFixupValuesAreStable pins the wire values of the four outcomes that
// existed before ArgReformatted. keel is a released module: a consumer compiled
// against v0.5.x holds these as integers, and renumbering them would silently
// turn its "dropped" branch into something else.
func TestArgFixupValuesAreStable(t *testing.T) {
	for fixup, want := range map[llm.ArgFixup]int{
		llm.ArgClean:       0,
		llm.ArgEmpty:       1,
		llm.ArgRepaired:    2,
		llm.ArgDropped:     3,
		llm.ArgReformatted: 4,
	} {
		if int(fixup) != want {
			t.Errorf("%s = %d, want %d", fixup, int(fixup), want)
		}
	}
}
