// SPDX-License-Identifier: Apache-2.0

package update

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    Version
		wantErr bool
	}{
		{"v1.2.3", Version{1, 2, 3, ""}, false},
		{"1.2.3", Version{1, 2, 3, ""}, false},
		{"V1.2.3", Version{1, 2, 3, ""}, false},
		{"v1.2", Version{1, 2, 0, ""}, false},
		{"v1", Version{1, 0, 0, ""}, false},
		{"v1.2.3-rc1", Version{1, 2, 3, "rc1"}, false},
		{"v1.2.3+build5", Version{1, 2, 3, ""}, false},
		{"v1.2.3-rc1+build5", Version{1, 2, 3, "rc1"}, false},
		{"", Version{}, true},
		{"dev", Version{}, true},
		{"abc", Version{}, true},
		{"v1.2.3.4", Version{}, true},
		{"v1.x.3", Version{}, true},
		{"v1.2.3-", Version{}, true},
		{"v-1.2.3", Version{}, true},
	}
	for _, tc := range cases {
		got, err := ParseVersion(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseVersion(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVersion(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseVersion(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestParseVersionAllowDev(t *testing.T) {
	for _, in := range []string{"", "dev", "  dev  "} {
		v, err := parseVersionAllowDev(in)
		if err != nil {
			t.Fatalf("parseVersionAllowDev(%q): %v", in, err)
		}
		if v.Prerelease != "dev" {
			t.Errorf("parseVersionAllowDev(%q) = %+v, want dev prerelease", in, v)
		}
		real := Version{Major: 0, Minor: 0, Patch: 1}
		if v.Compare(real) != -1 {
			t.Errorf("dev build must sort below every real version")
		}
	}
}

func TestVersionCompare(t *testing.T) {
	mustParse := func(s string) Version {
		v, err := parseVersionAllowDev(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return v
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.10", -1},
		{"v1.2.10", "v1.2.3", 1},
		{"v1.2.3", "1.2.3", 0},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.0.0", "v1.0", 0},
		{"v1.2", "v1.2.0", 0},
		{"v1.2.3-rc1", "v1.2.3", -1},
		{"v1.2.3", "v1.2.3-rc1", 1},
		{"v1.2.3-rc1", "v1.2.3-rc1", 0},
		{"v1.2.3-rc1", "v1.2.3-rc2", -1},
		{"v1.2.4-rc1", "v1.2.3", 1},
		{"dev", "v1.0.0", -1},
		{"v0.0.0", "dev", 1},
		{"dev", "dev", 0},
	}
	for _, tc := range cases {
		if got := mustParse(tc.a).Compare(mustParse(tc.b)); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVersionString(t *testing.T) {
	if s := (Version{1, 2, 3, ""}).String(); s != "v1.2.3" {
		t.Errorf("String = %q", s)
	}
	if s := (Version{1, 2, 3, "rc1"}).String(); s != "v1.2.3-rc1" {
		t.Errorf("String = %q", s)
	}
}
