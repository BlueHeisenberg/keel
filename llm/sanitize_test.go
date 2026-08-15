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
		llm.ArgFixup(9): "unknown",
	}
	for fixup, want := range cases {
		if got := fixup.String(); got != want {
			t.Errorf("ArgFixup(%d).String() = %q, want %q", int(fixup), got, want)
		}
	}
}
