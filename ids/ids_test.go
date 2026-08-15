// SPDX-License-Identifier: Apache-2.0

package ids

import (
	"strings"
	"testing"
)

func TestNewFormat(t *testing.T) {
	cases := []string{"org", "usr", "sbx", "x", ""}
	for _, prefix := range cases {
		name := prefix
		if name == "" {
			name = "empty-prefix"
		}
		t.Run(name, func(t *testing.T) {
			id := New(prefix)
			pref := prefix + "_"
			if !strings.HasPrefix(id, pref) {
				t.Fatalf("id %q missing prefix %q", id, pref)
			}
			hex := strings.TrimPrefix(id, pref)
			if len(hex) != 32 {
				t.Fatalf("expected 32 hex chars, got %d in %q", len(hex), id)
			}
			if strings.ContainsAny(hex, "-ABCDEF") {
				t.Fatalf("random component must be lowercase hex without dashes: %q", hex)
			}
			if strings.Trim(hex, "0123456789abcdef") != "" {
				t.Fatalf("random component contains non-hex characters: %q", hex)
			}
		})
	}
}

func TestNewUnique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := New("x")
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}
