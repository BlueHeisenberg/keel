// SPDX-License-Identifier: Apache-2.0

package update

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed semantic version. Build metadata ("+…") is ignored
// entirely; a pre-release suffix sorts below the corresponding release.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string // without the leading "-"; empty for a final release
}

// ParseVersion parses a semver-ish version string: an optional leading "v",
// one to three dot-separated numeric components, an optional "-prerelease"
// suffix, and optional "+build" metadata (which is discarded). Anything else
// is an error — a manifest advertising an unparseable version is refused,
// not guessed at.
func ParseVersion(s string) (Version, error) {
	orig := s
	s = strings.TrimSpace(s)
	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
		if pre == "" {
			return Version{}, fmt.Errorf("update: invalid version %q: empty pre-release", orig)
		}
	}
	if s == "" {
		return Version{}, fmt.Errorf("update: invalid version %q", orig)
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return Version{}, fmt.Errorf("update: invalid version %q: more than three components", orig)
	}
	var nums [3]int
	for i, p := range parts {
		if p == "" || !isDigits(p) {
			return Version{}, fmt.Errorf("update: invalid version %q: component %q is not numeric", orig, p)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("update: invalid version %q: %v", orig, err)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Prerelease: pre}, nil
}

// parseVersionAllowDev parses like ParseVersion but maps the conventional
// unversioned build markers "" and "dev" to v0.0.0-dev, which sorts below
// every real version, so an unversioned development build always sees an
// available update.
func parseVersionAllowDev(s string) (Version, error) {
	if isDev(s) {
		return Version{Prerelease: "dev"}, nil
	}
	return ParseVersion(s)
}

func isDev(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s == "dev"
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// String renders the version as "vMAJOR.MINOR.PATCH[-PRERELEASE]".
func (v Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	return s
}

// Compare returns -1 if v < o, 0 if equal, +1 if v > o. At an equal numeric
// core, a version with a pre-release suffix sorts below one without; two
// pre-releases are compared lexically.
func (v Version) Compare(o Version) int {
	if c := cmpInt(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmpInt(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmpInt(v.Patch, o.Patch); c != 0 {
		return c
	}
	switch {
	case v.Prerelease == o.Prerelease:
		return 0
	case v.Prerelease == "":
		return 1
	case o.Prerelease == "":
		return -1
	}
	return strings.Compare(v.Prerelease, o.Prerelease)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
