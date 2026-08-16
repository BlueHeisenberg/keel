// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// ---- mock runner -----------------------------------------------------------

// call records one invocation of the mock runner.
type call struct {
	args  []string
	stdin []byte
	env   []string
}

// mockRunner implements runner for tests.  Each Test configures .responses in
// order; if responses run out, subsequent calls return an empty success.
type mockRunner struct {
	calls     []call
	responses []mockResponse
}

type mockResponse struct {
	stdout []byte
	stderr []byte
	err    error
}

func (m *mockRunner) Run(_ context.Context, args []string, stdin []byte, extraEnv []string) ([]byte, []byte, error) {
	m.calls = append(m.calls, call{args: args, stdin: stdin, env: extraEnv})
	if len(m.responses) == 0 {
		return nil, nil, nil
	}
	resp := m.responses[0]
	m.responses = m.responses[1:]
	return resp.stdout, resp.stderr, resp.err
}

// ok is a helper to queue a success response.
func ok(stdout string) mockResponse {
	return mockResponse{stdout: []byte(stdout)}
}

// fail is a helper to queue an error response.
func fail(msg string) mockResponse {
	return mockResponse{err: errors.New(msg)}
}

// newTestBackend returns a PodmanBackend wired to the provided mock runner.
func newTestBackend(r *mockRunner) *PodmanBackend {
	return newPodmanBackendWithRunner(r, slog.Default())
}

// argString joins args for human-readable test output.
func argString(args []string) string { return strings.Join(args, " ") }

// ---- helpers ---------------------------------------------------------------

// findArg returns the index of the first element in args equal to target, or -1.
func findArg(args []string, target string) int {
	for i, a := range args {
		if a == target {
			return i
		}
	}
	return -1
}

// containsArg reports whether args contains target.
func containsArg(args []string, target string) bool {
	return findArg(args, target) >= 0
}

// argAfter returns the element immediately after key in args, or "".
func argAfter(args []string, key string) string {
	i := findArg(args, key)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

// ---- Create tests ----------------------------------------------------------

func TestCreate_DesktopProfile(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	// Queue: volume create, run
	r.responses = []mockResponse{
		ok(""),                          // volume create
		ok("abc123containerid456789\n"), // run
	}

	spec := Spec{
		Name:          "sb-test-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/desktop:latest",
		Level:         LevelFast,
		Profile:       ProfileDesktop,
		CPUs:          2.0,
		MemoryMB:      2048,
	}

	h, err := b.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	// Verify handle
	if h.ID != "sb-test-1" {
		t.Errorf("Handle.ID = %q, want %q", h.ID, "sb-test-1")
	}
	if h.ContainerID != "abc123containerid456789" {
		t.Errorf("Handle.ContainerID = %q, want trimmed container id", h.ContainerID)
	}
	if _, ok := h.Endpoints["desktop"]; !ok {
		t.Error("Handle.Endpoints missing 'desktop' key for ProfileDesktop")
	}

	// Should have made exactly 2 calls: volume create + run
	if len(r.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(r.calls), r.calls)
	}

	// First call: volume create
	vc := r.calls[0]
	if !containsArg(vc.args, "volume") || !containsArg(vc.args, "create") {
		t.Errorf("call[0] expected 'volume create', got: %s", argString(vc.args))
	}
	volName := b.volumeName("sb-test-1")
	if !containsArg(vc.args, volName) {
		t.Errorf("call[0] missing volume name %q, got: %s", volName, argString(vc.args))
	}

	// Second call: run
	rc := r.calls[1]
	if !containsArg(rc.args, "run") {
		t.Errorf("call[1] expected 'run', got: %s", argString(rc.args))
	}
	// Must have -d flag
	if !containsArg(rc.args, "-d") {
		t.Errorf("call[1] missing -d flag: %s", argString(rc.args))
	}
	// Container name
	wantName := b.containerName("sb-test-1")
	if argAfter(rc.args, "--name") != wantName {
		t.Errorf("call[1] --name = %q, want %q", argAfter(rc.args, "--name"), wantName)
	}
	// Workspace label
	if !containsArg(rc.args, "keel.sandbox=sb-test-1") {
		t.Errorf("call[1] missing workspace label: %s", argString(rc.args))
	}
	// Work volume mount
	wantVol := volName + ":/work"
	if !containsArg(rc.args, wantVol) {
		t.Errorf("call[1] missing volume mount %q: %s", wantVol, argString(rc.args))
	}
	// Memory limit
	if argAfter(rc.args, "--memory") != "2048m" {
		t.Errorf("call[1] --memory = %q, want '2048m': %s", argAfter(rc.args, "--memory"), argString(rc.args))
	}
	// CPU limit
	if argAfter(rc.args, "--cpus") != "2.00" {
		t.Errorf("call[1] --cpus = %q, want '2.00': %s", argAfter(rc.args, "--cpus"), argString(rc.args))
	}
	// Port publish (format: 127.0.0.1:<port>:6080)
	pubIdx := findArg(rc.args, "--publish")
	if pubIdx < 0 {
		t.Errorf("call[1] missing --publish flag for desktop profile: %s", argString(rc.args))
	} else {
		pub := rc.args[pubIdx+1]
		if !strings.HasPrefix(pub, "127.0.0.1:") || !strings.HasSuffix(pub, ":6080") {
			t.Errorf("call[1] --publish %q: want '127.0.0.1:<port>:6080'", pub)
		}
	}
	// Image must be last
	if rc.args[len(rc.args)-1] != "test/desktop:latest" {
		t.Errorf("call[1] image should be last arg, got %q", rc.args[len(rc.args)-1])
	}
}

func TestCreate_WebProfile(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	r.responses = []mockResponse{
		ok(""),               // volume create
		ok("webcontainer\n"), // run
	}

	spec := Spec{
		Name:          "sb-web-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/desktop:latest",
		Profile:       ProfileWeb,
		ServePort:     3000,
	}

	h, err := b.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create (web): %v", err)
	}

	if _, ok := h.Endpoints["web"]; !ok {
		t.Error("Handle.Endpoints missing 'web' key for ProfileWeb")
	}

	if len(r.calls) < 2 {
		t.Fatalf("expected at least 2 calls, got %d", len(r.calls))
	}

	// Check that the run call publishes the servePort (3000), not 6080.
	rc := r.calls[1]
	pubIdx := findArg(rc.args, "--publish")
	if pubIdx < 0 {
		t.Fatalf("call[1] missing --publish for web profile: %s", argString(rc.args))
	}
	pub := rc.args[pubIdx+1]
	if !strings.HasSuffix(pub, ":3000") {
		t.Errorf("call[1] --publish %q: want suffix ':3000'", pub)
	}
	if !strings.HasPrefix(pub, "127.0.0.1:") {
		t.Errorf("call[1] --publish %q: must bind to 127.0.0.1", pub)
	}
}

func TestCreate_HeadlessProfile(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	r.responses = []mockResponse{
		ok(""),             // volume create
		ok("headlessid\n"), // run
	}

	spec := Spec{
		Name:          "sb-hl-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
	}

	h, err := b.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create (headless): %v", err)
	}

	// No endpoints for headless.
	if len(h.Endpoints) != 0 {
		t.Errorf("headless profile should have no endpoints, got %v", h.Endpoints)
	}

	// No --publish flag.
	rc := r.calls[1]
	if containsArg(rc.args, "--publish") {
		t.Errorf("headless profile should not have --publish: %s", argString(rc.args))
	}
}

func TestCreate_ResourceLimits(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	r.responses = []mockResponse{ok(""), ok("cid\n")}

	spec := Spec{
		Name:          "sb-res-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
		CPUs:          0.5,
		MemoryMB:      512,
	}

	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	if argAfter(rc.args, "--cpus") != "0.50" {
		t.Errorf("--cpus = %q, want '0.50'", argAfter(rc.args, "--cpus"))
	}
	if argAfter(rc.args, "--memory") != "512m" {
		t.Errorf("--memory = %q, want '512m'", argAfter(rc.args, "--memory"))
	}
}

func TestCreate_NoLimitsWhenZero(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	r.responses = []mockResponse{ok(""), ok("cid\n")}

	spec := Spec{
		Name:          "sb-nolimit-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
		CPUs:          0,
		MemoryMB:      0,
	}

	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	if containsArg(rc.args, "--cpus") {
		t.Error("--cpus should not be set when CPUs=0")
	}
	if containsArg(rc.args, "--memory") {
		t.Error("--memory should not be set when MemoryMB=0")
	}
}

// TestCreate_ExtraEnv verifies the delivery contract for Spec.Env: the argv
// carries only the variable NAME (`--env FOO`), the value travels through the
// tool's process environment, and the value never appears in any argv element.
// The value never appearing on the argv is the assertion that keeps a caller's
// credential out of the host's process list, where any local user could read
// it via ps while podman runs.
func TestCreate_ExtraEnv(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	r.responses = []mockResponse{ok(""), ok("cid\n")}

	const secret = "123456:AAsekret-bot-token-value"
	spec := Spec{
		Name:          "sb-env-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
		Env:           map[string]string{"FOO": "bar", "BOT_TOKEN": secret},
	}

	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	// Name-only flags on the argv, sorted for determinism.
	if !hasFlagPair(rc.args, "--env", "FOO") || !hasFlagPair(rc.args, "--env", "BOT_TOKEN") {
		t.Errorf("missing name-only --env flags in run args: %s", argString(rc.args))
	}
	// The values must NOT appear in any argv element.
	for _, a := range rc.args {
		if strings.Contains(a, secret) || strings.Contains(a, "FOO=bar") {
			t.Errorf("env value leaked onto argv element %q (world-readable via ps)", a)
		}
	}
	// The values travel through the process environment instead.
	if !containsString(rc.env, "BOT_TOKEN="+secret) || !containsString(rc.env, "FOO=bar") {
		t.Errorf("runner extraEnv missing values, got %q", rc.env)
	}
}

// TestCreate_EnvInvalidKey verifies keys that could act as podman globs
// (`--env K*` imports host variables) or corrupt the K=V form are rejected
// before anything is created.
func TestCreate_EnvInvalidKey(t *testing.T) {
	for _, key := range []string{"", "A=B", "A B", "A*", "A\nB", "1ABC", "A-B"} {
		t.Run(fmt.Sprintf("key=%q", key), func(t *testing.T) {
			r := &mockRunner{}
			b := newTestBackend(r)
			spec := Spec{
				Name:          "sb-env-bad",
				NetworkPolicy: NetworkPolicyOpen,
				Image:         "test/desktop:latest",
				Profile:       ProfileHeadless,
				Env:           map[string]string{key: "v"},
			}
			if _, err := b.Create(context.Background(), spec); err == nil {
				t.Fatalf("expected error for env key %q", key)
			}
			if len(r.calls) != 0 {
				t.Fatalf("expected zero runner calls for bad env key, got %d", len(r.calls))
			}
		})
	}
}

// containsString reports whether ss contains s.
func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// hasFlagPair reports whether args contains flag immediately followed by value.
func hasFlagPair(args []string, flag, value string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}

// ---- Exec tests ------------------------------------------------------------

func TestExec_ArgVector(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	r.responses = []mockResponse{
		{stdout: []byte("hello world\n"), stderr: nil, err: nil},
	}

	res, err := b.Exec(context.Background(), "sb-exec-1",
		[]string{"echo", "hello world"},
		ExecOpts{WorkDir: "/work", RunAs: "agent"},
	)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if string(res.Stdout) != "hello world\n" {
		t.Errorf("Stdout = %q", res.Stdout)
	}

	c := r.calls[0]
	// args[0] is the binary (podman), then "exec"
	if c.args[1] != "exec" {
		t.Errorf("args[1] = %q, want 'exec'", c.args[1])
	}
	if argAfter(c.args, "--workdir") != "/work" {
		t.Errorf("--workdir = %q, want '/work'", argAfter(c.args, "--workdir"))
	}
	if argAfter(c.args, "--user") != "agent" {
		t.Errorf("--user = %q, want 'agent'", argAfter(c.args, "--user"))
	}
	// Container name must precede the command.
	cname := b.containerName("sb-exec-1")
	cnIdx := findArg(c.args, cname)
	if cnIdx < 0 {
		t.Errorf("container name %q not found in exec args: %s", cname, argString(c.args))
	}
	if c.args[len(c.args)-2] != "echo" {
		t.Errorf("expected 'echo' before final arg, got %q", c.args[len(c.args)-2])
	}
}

// TestExec_EnvArgs verifies ExecOpts.Env follows the same delivery contract as
// Spec.Env: name-only `--env` on the argv, value through the process
// environment, value never on the argv.
func TestExec_EnvArgs(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok("")}

	_, err := b.Exec(context.Background(), "sb-exec-2",
		[]string{"sh", "-c", "echo $MY_VAR"},
		ExecOpts{Env: map[string]string{"MY_VAR": "testval"}},
	)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}

	c := r.calls[0]
	if !hasFlagPair(c.args, "--env", "MY_VAR") {
		t.Errorf("missing name-only --env MY_VAR in exec args: %s", argString(c.args))
	}
	for _, a := range c.args {
		if strings.Contains(a, "testval") {
			t.Errorf("env value leaked onto exec argv element %q", a)
		}
	}
	if !containsString(c.env, "MY_VAR=testval") {
		t.Errorf("runner extraEnv missing MY_VAR=testval, got %q", c.env)
	}
}

// ---- Snapshot tests --------------------------------------------------------

func TestSnapshot_ArgVector(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok("sha256:imageref\n")}

	ref, err := b.Snapshot(context.Background(), "sb-snap-1", "before-refactor")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if ref.Ref != "keel/snap-sb-snap-1:before-refactor" {
		t.Errorf("SnapshotRef.Ref = %q, want 'keel/snap-sb-snap-1:before-refactor'", ref.Ref)
	}
	if ref.Label != "before-refactor" {
		t.Errorf("SnapshotRef.Label = %q, want 'before-refactor'", ref.Label)
	}

	c := r.calls[0]
	// args: [podman commit <container> keel/snap:before-refactor]
	if c.args[1] != "commit" {
		t.Errorf("args[1] = %q, want 'commit'", c.args[1])
	}
	cname := b.containerName("sb-snap-1")
	if !containsArg(c.args, cname) {
		t.Errorf("container name %q missing from snapshot args: %s", cname, argString(c.args))
	}
	if !containsArg(c.args, "keel/snap-sb-snap-1:before-refactor") {
		t.Errorf("image tag missing from snapshot args: %s", argString(c.args))
	}
}

func TestSnapshot_EmptyLabel(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok("sha256:random\n")}

	ref, err := b.Snapshot(context.Background(), "sb-snap-2", "")
	if err != nil {
		t.Fatalf("Snapshot with empty label: %v", err)
	}
	// Ref should be auto-generated with "keel/snap-<id>:snap-..." prefix.
	if !strings.HasPrefix(ref.Ref, "keel/snap-sb-snap-2:snap-") {
		t.Errorf("auto-label ref = %q, want prefix 'keel/snap-sb-snap-2:snap-'", ref.Ref)
	}
}

// ---- Inspect / Endpoints tests ---------------------------------------------

// cannedInspectJSON is a minimal `podman inspect` JSON array for a running
// container with noVNC (6080) mapped to a random host port.
const cannedInspectJSON = `[
  {
    "State": {
      "Running": true
    },
    "NetworkSettings": {
      "Ports": {
        "6080/tcp": [
          {
            "HostIp": "127.0.0.1",
            "HostPort": "45678"
          }
        ]
      }
    }
  }
]`

func TestInspect_ParseRunningState(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{{stdout: []byte(cannedInspectJSON)}}

	status, err := b.Inspect(context.Background(), "sb-insp-1")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !status.Running {
		t.Error("Running = false, want true")
	}
	ep, ok := status.Endpoints["desktop"]
	if !ok {
		t.Fatalf("Endpoints missing 'desktop' key; got %v", status.Endpoints)
	}
	if ep != "http://127.0.0.1:45678" {
		t.Errorf("Endpoints['desktop'] = %q, want 'http://127.0.0.1:45678'", ep)
	}
}

const cannedInspectStopped = `[
  {
    "State": {
      "Running": false
    },
    "NetworkSettings": {
      "Ports": {}
    }
  }
]`

func TestInspect_StoppedContainer(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{{stdout: []byte(cannedInspectStopped)}}

	status, err := b.Inspect(context.Background(), "sb-insp-2")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if status.Running {
		t.Error("Running = true for stopped container")
	}
	if len(status.Endpoints) != 0 {
		t.Errorf("Endpoints should be empty for stopped container with no ports; got %v", status.Endpoints)
	}
}

// cannedInspectJSONWithCreated reproduces the "Created" field verbatim as
// measured against real podman 4.9.3 (theharness-dev, `podman inspect --type
// container --format json` on a freshly-run container):
//
//	"Created": "2026-08-16T09:16:21.164392221+02:00"
//
// RFC3339Nano with a numeric zone offset, sub-second precision trimmed of
// trailing zeros. Confirmed against the same real host that this value does
// not change across `podman stop`/`podman start` (only State.StartedAt does).
const cannedInspectJSONWithCreated = `[
  {
    "Created": "2026-08-16T09:16:21.164392221+02:00",
    "State": {
      "Running": true
    },
    "NetworkSettings": {
      "Ports": {}
    }
  }
]`

func TestInspect_CreatedAt_ParsesMeasuredPodmanFormat(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{{stdout: []byte(cannedInspectJSONWithCreated)}}

	status, err := b.Inspect(context.Background(), "sb-created-1")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	want, err := time.Parse(time.RFC3339Nano, "2026-08-16T09:16:21.164392221+02:00")
	if err != nil {
		t.Fatalf("test setup: parse want time: %v", err)
	}
	if !status.CreatedAt.Equal(want) {
		t.Errorf("CreatedAt = %v, want %v", status.CreatedAt, want)
	}
}

func TestInspect_CreatedAt_ParseFailure_LeavesZeroNotError(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	badJSON := `[{"Created":"not-a-timestamp","State":{"Running":true},"NetworkSettings":{"Ports":{}}}]`
	r.responses = []mockResponse{{stdout: []byte(badJSON)}}

	status, err := b.Inspect(context.Background(), "sb-created-2")
	if err != nil {
		t.Fatalf("Inspect should tolerate an unparseable Created field, got error: %v", err)
	}
	if !status.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want zero value for unparseable input", status.CreatedAt)
	}
}

func TestInspect_NotFound(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{
		{err: fmt.Errorf("podman inspect: exit 125: no such container: sbx-sb-missing-1")},
	}

	_, err := b.Inspect(context.Background(), "sb-missing-1")
	if err == nil {
		t.Fatal("expected error for missing container, got nil")
	}
	if !errors.Is(err, ErrSandboxNotFound) {
		t.Errorf("expected ErrSandboxNotFound, got %v", err)
	}
}

func TestDesktopEndpoint(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{{stdout: []byte(cannedInspectJSON)}}

	ep, err := b.DesktopEndpoint(context.Background(), "sb-ep-1")
	if err != nil {
		t.Fatalf("DesktopEndpoint: %v", err)
	}
	if ep != "http://127.0.0.1:45678" {
		t.Errorf("DesktopEndpoint = %q, want 'http://127.0.0.1:45678'", ep)
	}
}

func TestWebEndpoint_WrongProfile(t *testing.T) {
	// A container that only exposes the desktop (6080) endpoint should not
	// satisfy WebEndpoint (no "web" key in endpoints).
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{{stdout: []byte(cannedInspectJSON)}}

	_, err := b.WebEndpoint(context.Background(), "sb-ep-2")
	if err == nil {
		t.Fatal("expected ErrWrongProfile for non-web container, got nil")
	}
	if !errors.Is(err, ErrWrongProfile) {
		t.Errorf("expected ErrWrongProfile, got %v", err)
	}
}

// cannedWebInspectJSON simulates a running web-profile container with port 3000.
const cannedWebInspectJSON = `[
  {
    "State": {
      "Running": true
    },
    "NetworkSettings": {
      "Ports": {
        "3000/tcp": [
          {
            "HostIp": "127.0.0.1",
            "HostPort": "51234"
          }
        ]
      }
    }
  }
]`

func TestWebEndpoint(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{{stdout: []byte(cannedWebInspectJSON)}}

	ep, err := b.WebEndpoint(context.Background(), "sb-webep-1")
	if err != nil {
		t.Fatalf("WebEndpoint: %v", err)
	}
	if ep != "http://127.0.0.1:51234" {
		t.Errorf("WebEndpoint = %q, want 'http://127.0.0.1:51234'", ep)
	}
}

// ---- Purge tests -------------------------------------------------------------

// TestPurge_ArgSequence verifies the explicitly destructive operation still
// destroys when explicitly asked: container stopped, removed, AND the work
// volume removed.  Purge is the only method allowed to issue that volume rm.
func TestPurge_ArgSequence(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{
		ok(""), // stop
		ok(""), // rm
		ok(""), // volume rm
	}

	if err := b.Purge(context.Background(), "sb-destroy-1"); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	if len(r.calls) != 3 {
		t.Fatalf("expected 3 calls (stop, rm, volume rm), got %d", len(r.calls))
	}
	// stop
	if !containsArg(r.calls[0].args, "stop") {
		t.Errorf("call[0] expected 'stop', got: %s", argString(r.calls[0].args))
	}
	// rm
	if !containsArg(r.calls[1].args, "rm") {
		t.Errorf("call[1] expected 'rm', got: %s", argString(r.calls[1].args))
	}
	// volume rm
	if !containsArg(r.calls[2].args, "volume") || !containsArg(r.calls[2].args, "rm") {
		t.Errorf("call[2] expected 'volume rm', got: %s", argString(r.calls[2].args))
	}
	volName := b.volumeName("sb-destroy-1")
	if !containsArg(r.calls[2].args, volName) {
		t.Errorf("call[2] missing volume name %q: %s", volName, argString(r.calls[2].args))
	}
}

// ---- WriteFile / ReadFile tests --------------------------------------------

func TestWriteFile(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	// mkdir + write calls
	r.responses = []mockResponse{ok(""), ok("")}

	data := []byte("hello sandbox\n")
	if err := b.WriteFile(context.Background(), "sb-file-1", "/work/hello.txt", data); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if len(r.calls) != 2 {
		t.Fatalf("expected 2 calls (mkdir, write), got %d", len(r.calls))
	}
	// Second call should be exec -i with cat
	wc := r.calls[1]
	if !containsArg(wc.args, "exec") {
		t.Errorf("write call[1] should be 'exec', got: %s", argString(wc.args))
	}
	if !containsArg(wc.args, "-i") {
		t.Errorf("write call[1] should have -i flag: %s", argString(wc.args))
	}
	if wc.stdin == nil || !bytes.Equal(wc.stdin, data) {
		t.Errorf("write call[1] stdin = %q, want %q", wc.stdin, data)
	}
}

func TestReadFile(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{{stdout: []byte("file content\n")}}

	content, err := b.ReadFile(context.Background(), "sb-file-2", "/work/data.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(content) != "file content\n" {
		t.Errorf("ReadFile = %q, want 'file content\\n'", content)
	}

	c := r.calls[0]
	if !containsArg(c.args, "exec") {
		t.Errorf("ReadFile call should be 'exec': %s", argString(c.args))
	}
	if !containsArg(c.args, "cat") {
		t.Errorf("ReadFile call should use 'cat': %s", argString(c.args))
	}
	if !containsArg(c.args, "/work/data.txt") {
		t.Errorf("ReadFile call missing path: %s", argString(c.args))
	}
}

// ---- NetworkPolicy / egress flag tests -------------------------------------

// fakeLookPath returns a lookPath stub: binaries in present resolve, others fail.
func fakeLookPath(present ...string) func(string) (string, error) {
	set := map[string]bool{}
	for _, p := range present {
		set[p] = true
	}
	return func(name string) (string, error) {
		if set[name] {
			return "/usr/sbin/" + name, nil
		}
		return "", errors.New("not found: " + name)
	}
}

// egressCreateResponses returns the runner responses for a successful
// host-applied egress Create: volume create, run, inspect(pid), inspect(gw),
// nsenter load, exec verify.
func egressCreateResponses() []mockResponse {
	return []mockResponse{
		ok(""),            // volume create
		ok("cid\n"),       // run
		ok("12345\n"),     // inspect pid
		ok("10.88.0.1\n"), // inspect gateway
		ok(""),            // nsenter nft -f -
		ok(""),            // exec verify (nft list table)
	}
}

// TestCreate_NetworkPolicy_InternalOnly verifies that the default policy
// (empty string → internal-only) keeps --add-host but NO LONGER grants
// NET_ADMIN or sets EGRESS (egress is host-applied), and that the
// host-applied lockdown is installed and verified.
func TestCreate_NetworkPolicy_InternalOnly(t *testing.T) {
	for _, policy := range []NetworkPolicy{"", NetworkPolicyInternalOnly} {
		t.Run(string(policy)+"(default-or-explicit)", func(t *testing.T) {
			r := &mockRunner{}
			b := newTestBackend(r)
			b.lookPath = fakeLookPath("nft", "nsenter")
			r.responses = egressCreateResponses()

			spec := Spec{
				Name:          "sb-net-1",
				Image:         "test/desktop:latest",
				Profile:       ProfileHeadless,
				NetworkPolicy: policy,
			}
			if _, err := b.Create(context.Background(), spec); err != nil {
				t.Fatalf("Create: %v", err)
			}

			rc := r.calls[1]

			// Must NOT use --network none.
			for i, a := range rc.args {
				if a == "--network" && i+1 < len(rc.args) && rc.args[i+1] == "none" {
					t.Errorf("internal-only policy should not set --network none: %s", argString(rc.args))
				}
			}
			// Must have --add-host host.containers.internal:host-gateway
			if !containsArg(rc.args, "host.containers.internal:host-gateway") {
				t.Errorf("missing --add-host host.containers.internal:host-gateway: %s", argString(rc.args))
			}
			// Must NOT have --cap-add NET_ADMIN anymore (host-applied egress).
			if containsArg(rc.args, "NET_ADMIN") {
				t.Errorf("internal-only should no longer grant NET_ADMIN: %s", argString(rc.args))
			}
			// Must NOT set EGRESS env anymore.
			if containsEnvArg(rc.args, "EGRESS", "internal-only") {
				t.Errorf("internal-only should no longer set EGRESS: %s", argString(rc.args))
			}

			// A host-side nft load must have happened via nsenter, and a verify.
			if !sawNsenterNftLoad(r.calls) {
				t.Errorf("expected an nsenter ... nft -f - load call; calls: %v", r.calls)
			}
			if !sawEgressVerify(r.calls) {
				t.Errorf("expected an egress verify (nft list table ip keel_egress); calls: %v", r.calls)
			}
		})
	}
}

// TestCreate_InternalOnly_NoHostTooling_FailsClosed verifies that when the host
// lacks nft/nsenter, Create fails closed (destroys the container, errors).
func TestCreate_InternalOnly_NoHostTooling_FailsClosed(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	b.lookPath = fakeLookPath() // neither nft nor nsenter present
	// volume create, run, then Destroy: stop, rm, volume rm.
	r.responses = []mockResponse{ok(""), ok("cid\n"), ok(""), ok(""), ok("")}

	spec := Spec{
		Name:          "sb-net-fail",
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
		NetworkPolicy: NetworkPolicyInternalOnly,
	}
	_, err := b.Create(context.Background(), spec)
	if err == nil {
		t.Fatal("expected fail-closed error when host tooling is missing")
	}
	if !errors.Is(err, ErrEgressUnavailable) {
		t.Errorf("expected ErrEgressUnavailable, got %v", err)
	}
	// Container must have been destroyed (a 'rm' call after run).
	if !containsArg(r.calls[len(r.calls)-1].args, "rm") && !sawDestroy(r.calls) {
		t.Errorf("expected container teardown after fail-closed; calls: %v", r.calls)
	}
}

// sawNsenterNftLoad reports whether any call was `nsenter ... nft -f -`.
func sawNsenterNftLoad(calls []call) bool {
	for _, c := range calls {
		if len(c.args) > 0 && c.args[0] == "nsenter" && containsArg(c.args, "nft") && containsArg(c.args, "-f") {
			return true
		}
	}
	return false
}

// sawEgressVerify reports whether any call listed the keel_egress table.
func sawEgressVerify(calls []call) bool {
	for _, c := range calls {
		if containsArg(c.args, "list") && containsArg(c.args, "keel_egress") {
			return true
		}
	}
	return false
}

// sawDestroy reports whether a Destroy sequence ran (a podman rm call).
func sawDestroy(calls []call) bool {
	for _, c := range calls {
		if containsArg(c.args, "rm") {
			return true
		}
	}
	return false
}

// TestCreate_NetworkPolicy_None verifies --network none is set and no
// --add-host or cap/env flags are added.
func TestCreate_NetworkPolicy_None(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok(""), ok("cid\n")}

	spec := Spec{
		Name:          "sb-net-none",
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
		NetworkPolicy: NetworkPolicyNone,
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	found := false
	for i, a := range rc.args {
		if a == "--network" && i+1 < len(rc.args) && rc.args[i+1] == "none" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("policy=none should have --network none: %s", argString(rc.args))
	}
	// Must NOT have --add-host for none policy.
	if containsArg(rc.args, "--add-host") {
		t.Errorf("policy=none should not have --add-host: %s", argString(rc.args))
	}
	// Must NOT have --cap-add NET_ADMIN.
	if containsArg(rc.args, "NET_ADMIN") {
		t.Errorf("policy=none should not have --cap-add NET_ADMIN: %s", argString(rc.args))
	}
}

// TestCreate_NetworkPolicy_Open verifies no cap/env flags are added but
// --add-host is kept for host access.
func TestCreate_NetworkPolicy_Open(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok(""), ok("cid\n")}

	spec := Spec{
		Name:          "sb-net-open",
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
		NetworkPolicy: NetworkPolicyOpen,
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	// add-host should be present (host access).
	if !containsArg(rc.args, "host.containers.internal:host-gateway") {
		t.Errorf("policy=open should retain --add-host: %s", argString(rc.args))
	}
	// Must NOT have NET_ADMIN or EGRESS.
	if containsArg(rc.args, "NET_ADMIN") {
		t.Errorf("policy=open should not add --cap-add NET_ADMIN: %s", argString(rc.args))
	}
	if containsArg(rc.args, "EGRESS=open") {
		t.Errorf("policy=open should not set EGRESS: %s", argString(rc.args))
	}
}

// TestCreate_NetworkPolicy_Filtered verifies that the proxy env vars are set,
// that egress is host-applied (no NET_ADMIN / EGRESS / ALLOW_HOSTS
// passed to the container), and that the host-applied lockdown is installed.
func TestCreate_NetworkPolicy_Filtered(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	b.lookPath = fakeLookPath("nft", "nsenter")
	r.responses = egressCreateResponses()

	spec := Spec{
		Name:            "sb-net-filt",
		Image:           "test/desktop:latest",
		Profile:         ProfileHeadless,
		NetworkPolicy:   NetworkPolicyFiltered,
		AllowDomains:    []string{"docs.example.com", "*.cdn.example.com"},
		EgressProxyAddr: "127.0.0.1:7070",
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]

	if !containsArg(rc.args, "host.containers.internal:host-gateway") {
		t.Errorf("filtered policy should retain --add-host: %s", argString(rc.args))
	}
	// Host-applied egress: no NET_ADMIN / EGRESS / ALLOW_HOSTS.
	if containsArg(rc.args, "NET_ADMIN") {
		t.Errorf("filtered policy should no longer grant NET_ADMIN: %s", argString(rc.args))
	}
	if containsEnvArg(rc.args, "EGRESS", "filtered") {
		t.Errorf("filtered policy should no longer set EGRESS: %s", argString(rc.args))
	}
	for _, a := range rc.args {
		if strings.HasPrefix(a, "ALLOW_HOSTS=") {
			t.Errorf("filtered policy should no longer set ALLOW_HOSTS: %s", argString(rc.args))
		}
	}
	// Proxy env is still set so the container routes through the host proxy.
	proxyURL := "http://127.0.0.1:7070"
	if !containsEnvArg(rc.args, "HTTP_PROXY", proxyURL) {
		t.Errorf("missing HTTP_PROXY=%s: %s", proxyURL, argString(rc.args))
	}
	if !containsEnvArg(rc.args, "HTTPS_PROXY", proxyURL) {
		t.Errorf("missing HTTPS_PROXY=%s: %s", proxyURL, argString(rc.args))
	}
	// Host-applied lockdown installed + verified.
	if !sawNsenterNftLoad(r.calls) {
		t.Errorf("expected nsenter nft load for filtered policy; calls: %v", r.calls)
	}
	if !sawEgressVerify(r.calls) {
		t.Errorf("expected egress verify for filtered policy; calls: %v", r.calls)
	}
}

// containsEnvArg reports whether args contains "--env key=value".
func containsEnvArg(args []string, key, value string) bool {
	want := key + "=" + value
	for i, a := range args {
		if a == "--env" && i+1 < len(args) && args[i+1] == want {
			return true
		}
	}
	return false
}

// ---- ExecStream smoke test -------------------------------------------------

// TestExecStream_NotRealPodman verifies that ExecStream returns an error (not
// panic) when the podman binary is absent, confirming the error-wrapping path.
// This test does NOT use the mock runner because ExecStream calls exec.Command
// directly (to get a real pipe).  We point the configured binary at a
// nonexistent path.
func TestExecStream_NotRealPodman(t *testing.T) {
	cfg := Config{PodmanBinary: "/nonexistent/podman"}.withDefaults()
	b := &PodmanBackend{
		cfg: cfg,
		r:   execRunner{},
		log: slog.Default(),
	}
	rc, err := b.ExecStream(context.Background(), "sb-stream-1", []string{"echo", "hi"}, ExecOpts{})
	if err == nil {
		_ = rc.Close()
		t.Fatal("expected error when podman binary missing")
	}
	// The error should mention the missing binary in some way; we don't
	// require ErrPodmanUnavailable specifically because exec.Command may not
	// return exec.ErrNotFound for an absolute path — just check non-nil.
	_ = rc // nil is fine here
}

// TestPodman_RejectsMaliciousID asserts that every public PodmanBackend method
// validates the sandbox id against the strict charset BEFORE it ever
// reaches a container/volume name or a podman argument vector.  A malformed id
// (path-traversal, shell metachar, etc.) must fail fast with no runner call.
func TestPodman_RejectsMaliciousID(t *testing.T) {
	badIDs := []string{"../x", "a;b", "a b", "a/b", "a$b", "a&b", "", "a|b", "-a-`b`"}

	for _, id := range badIDs {
		id := id
		t.Run(fmt.Sprintf("id=%q", id), func(t *testing.T) {
			r := &mockRunner{}
			b := newTestBackend(r)
			ctx := context.Background()

			assertRejected := func(name string, err error) {
				t.Helper()
				if err == nil {
					t.Errorf("%s(%q): expected validation error, got nil", name, id)
				}
			}

			_, err := b.Create(ctx, Spec{Name: id, Profile: ProfileHeadless})
			assertRejected("Create", err)
			assertRejected("Start", b.Start(ctx, id))
			assertRejected("Stop", b.Stop(ctx, id))
			assertRejected("Purge", b.Purge(ctx, id))
			_, err = b.Recreate(ctx, Spec{Name: id, Image: "test/img:latest", Profile: ProfileHeadless})
			assertRejected("Recreate", err)
			_, err = b.Exec(ctx, id, []string{"echo", "hi"}, ExecOpts{})
			assertRejected("Exec", err)
			_, err = b.ExecStream(ctx, id, []string{"echo", "hi"}, ExecOpts{})
			assertRejected("ExecStream", err)
			_, err = b.Snapshot(ctx, id, "label")
			assertRejected("Snapshot", err)
			_, err = b.Restore(ctx, id, SnapshotRef{Ref: "keel/snap:x"})
			assertRejected("Restore", err)
			_, err = b.Inspect(ctx, id)
			assertRejected("Inspect", err)
			_, err = b.ContainerAddr(ctx, id, 8080)
			assertRejected("ContainerAddr", err)
			assertRejected("WriteFile", b.WriteFile(ctx, id, "/work/f", []byte("x")))
			_, err = b.ReadFile(ctx, id, "/work/f")
			assertRejected("ReadFile", err)

			// CRITICAL: no method may have shelled out to podman with the bad id.
			if len(r.calls) != 0 {
				t.Fatalf("expected zero runner calls for malicious id %q, got %d: %v",
					id, len(r.calls), r.calls)
			}
		})
	}
}

// TestPodman_AcceptsValidID is a sanity check that the validation does not
// reject legitimate ids: a valid id reaches the runner.
func TestPodman_AcceptsValidID(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	if err := b.Start(context.Background(), "sb-Valid_ID-123"); err != nil {
		t.Fatalf("Start with valid id: %v", err)
	}
	if len(r.calls) == 0 {
		t.Fatal("expected Start to shell out for a valid id")
	}
}

// ---- Spec.Command tests ------------------------------------------------------

// TestCreate_CommandVector_ExactArgv is the round-trip guarantee for
// Spec.Command: every element must arrive as exactly one argv entry after the
// image, byte-identical — spaces, quotes, equals signs and unicode included —
// because there is no shell anywhere on the path to reinterpret them.
func TestCreate_CommandVector_ExactArgv(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok(""), ok("cid\n")}

	command := []string{
		"kenward",
		"--member=david",
		"--config=/etc/kenward/kenward.yaml",
		`--notes=a b "c"`,
		"--unicode=héllo 世界 — ñ",
		"--tricky=x; rm -rf / && echo $(pwned) | `backtick` 'quoted'",
	}
	spec := Spec{
		Name:          "sb-cmd-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
		Command:       command,
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	imgIdx := findArg(rc.args, "test/img:latest")
	if imgIdx < 0 {
		t.Fatalf("image not found in run args: %s", argString(rc.args))
	}
	got := rc.args[imgIdx+1:]
	if len(got) != len(command) {
		t.Fatalf("argv after image has %d elements, want %d: %q", len(got), len(command), got)
	}
	for i := range command {
		if got[i] != command[i] {
			t.Errorf("argv[%d] = %q, want %q (must arrive byte-identical)", i, got[i], command[i])
		}
	}
}

// TestCreate_CommandVector_NoInjection asserts that a crafted argument cannot
// become a second flag: an element that CONTAINS flag-looking text stays one
// element, and none of its fragments appear as standalone argv entries.
func TestCreate_CommandVector_NoInjection(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok(""), ok("cid\n")}

	command := []string{
		`--notes=a b "c"`,
		"--looks-like-two=--evil --evil2",
	}
	spec := Spec{
		Name:          "sb-cmd-2",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
		Command:       command,
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	imgIdx := findArg(rc.args, "test/img:latest")
	if got := len(rc.args[imgIdx+1:]); got != 2 {
		t.Fatalf("argv after image has %d elements, want exactly 2: %q", got, rc.args[imgIdx+1:])
	}
	// No fragment of either element may surface as its own argv entry,
	// anywhere in the vector (before the image would be a podman flag).
	for _, fragment := range []string{"--evil", "--evil2", "a", "b", `"c"`, "--notes=a"} {
		if containsArg(rc.args, fragment) {
			t.Errorf("fragment %q became a standalone argv element: %s", fragment, argString(rc.args))
		}
	}
}

// TestCreate_NoCommand_ImageLast pins today's behaviour for an empty Command:
// the image stays the final argument and the image's own CMD decides.
func TestCreate_NoCommand_ImageLast(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok(""), ok("cid\n")}

	spec := Spec{
		Name:          "sb-cmd-3",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rc := r.calls[1]
	if rc.args[len(rc.args)-1] != "test/img:latest" {
		t.Errorf("with empty Command the image must be last, got %q", rc.args[len(rc.args)-1])
	}
}

// ---- Spec.Files tests ---------------------------------------------------------

// TestCreate_Files_CreateCpStart verifies the provisioning sequence: the
// container is created stopped, the files are copied in as a tar stream with
// exact mode and ownership, and only then is it started — so the entrypoint
// can never observe a missing file.
func TestCreate_Files_CreateCpStart(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{
		ok(""),      // volume create
		ok("cid\n"), // podman create
		ok(""),      // podman cp
		ok(""),      // podman start
	}

	secret := []byte("telegram:\n  bot_token: \"123456:AAsekret\"\n")
	spec := Spec{
		Name:          "sb-files-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
		Command:       []string{"--config=/etc/app/config.yaml"},
		Files: []File{
			{Path: "/etc/app/config.yaml", Data: secret, Mode: 0o600, UID: 1000, GID: 1000},
			{Path: "/var/lib/app/seed", Data: []byte("s"), Mode: 0o644},
		},
	}
	h, err := b.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if h.ContainerID != "cid" {
		t.Errorf("Handle.ContainerID = %q, want %q", h.ContainerID, "cid")
	}
	if len(r.calls) != 4 {
		t.Fatalf("expected 4 calls (volume, create, cp, start), got %d: %v", len(r.calls), r.calls)
	}

	// call[1] must be `podman create`, NOT `run -d`: the workload must not be
	// running while its files are still missing.
	cc := r.calls[1]
	if cc.args[1] != "create" {
		t.Fatalf("call[1] args[1] = %q, want 'create'", cc.args[1])
	}
	if containsArg(cc.args, "-d") {
		t.Errorf("create call must not carry -d: %s", argString(cc.args))
	}
	// Command still rides after the image on the create call.
	imgIdx := findArg(cc.args, "test/img:latest")
	if imgIdx < 0 || imgIdx+1 >= len(cc.args) || cc.args[imgIdx+1] != "--config=/etc/app/config.yaml" {
		t.Errorf("command vector missing after image in create call: %s", argString(cc.args))
	}

	// call[2] is the copy-in: tar on stdin, ownership preserved.
	cp := r.calls[2]
	if cp.args[1] != "cp" {
		t.Fatalf("call[2] args[1] = %q, want 'cp'", cp.args[1])
	}
	if !containsArg(cp.args, "--archive=false") {
		t.Errorf("cp must pass --archive=false so tar ownership is preserved: %s", argString(cp.args))
	}
	if !containsArg(cp.args, "-") || !containsArg(cp.args, b.containerName("sb-files-1")+":/") {
		t.Errorf("cp must read tar from stdin into the container root: %s", argString(cp.args))
	}

	// The tar stream must carry exact paths, contents, modes, and ownership.
	tr := tar.NewReader(bytes.NewReader(cp.stdin))
	entries := map[string]*tar.Header{}
	contents := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading provisioning tar: %v", err)
		}
		data, _ := io.ReadAll(tr)
		entries[hdr.Name] = hdr
		contents[hdr.Name] = data
	}
	cfg, ok := entries["etc/app/config.yaml"]
	if !ok {
		t.Fatalf("tar missing etc/app/config.yaml; entries: %v", entries)
	}
	if cfg.Mode != 0o600 {
		t.Errorf("config mode = %o, want 600 — a bot token must not land world-readable", cfg.Mode)
	}
	if cfg.Uid != 1000 || cfg.Gid != 1000 {
		t.Errorf("config uid:gid = %d:%d, want 1000:1000", cfg.Uid, cfg.Gid)
	}
	if !bytes.Equal(contents["etc/app/config.yaml"], secret) {
		t.Errorf("config content mismatch: got %q", contents["etc/app/config.yaml"])
	}
	if seed, ok := entries["var/lib/app/seed"]; !ok || seed.Mode != 0o644 {
		t.Errorf("seed entry missing or wrong mode: %+v", seed)
	}

	// call[3] starts the now-provisioned container.
	st := r.calls[3]
	if st.args[1] != "start" || !containsArg(st.args, b.containerName("sb-files-1")) {
		t.Errorf("call[3] must be 'start <container>': %s", argString(st.args))
	}
}

// TestCreate_Files_EgressAfterStart verifies ordering with an egress policy:
// create → cp → start → host-applied lockdown, still fail-closed.
func TestCreate_Files_EgressAfterStart(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	b.lookPath = fakeLookPath("nft", "nsenter")
	r.responses = []mockResponse{
		ok(""),            // volume create
		ok("cid\n"),       // create
		ok(""),            // cp
		ok(""),            // start
		ok("12345\n"),     // inspect pid
		ok("10.88.0.1\n"), // inspect gateway
		ok(""),            // nsenter nft -f -
		ok(""),            // exec verify
	}
	spec := Spec{
		Name:          "sb-files-egress",
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
		NetworkPolicy: NetworkPolicyInternalOnly,
		Files:         []File{{Path: "/etc/app/x", Data: []byte("d"), Mode: 0o600}},
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if r.calls[1].args[1] != "create" || r.calls[2].args[1] != "cp" || r.calls[3].args[1] != "start" {
		t.Fatalf("wrong sequence before egress: %v %v %v", r.calls[1].args[1], r.calls[2].args[1], r.calls[3].args[1])
	}
	if !sawNsenterNftLoad(r.calls) || !sawEgressVerify(r.calls) {
		t.Errorf("expected host-applied egress after start; calls: %v", r.calls)
	}
}

// TestCreate_Files_Invalid verifies bad Files entries fail before anything is
// created: no volume, no container, zero runner calls.
func TestCreate_Files_Invalid(t *testing.T) {
	cases := []struct {
		name string
		file File
	}{
		{"relative", File{Path: "etc/x", Data: []byte("d"), Mode: 0o600}},
		{"traversal", File{Path: "/etc/../x", Data: []byte("d"), Mode: 0o600}},
		{"trailing-slash", File{Path: "/etc/x/", Data: []byte("d"), Mode: 0o600}},
		{"doubled-slash", File{Path: "/etc//x", Data: []byte("d"), Mode: 0o600}},
		{"root", File{Path: "/", Data: []byte("d"), Mode: 0o600}},
		{"zero-mode", File{Path: "/etc/x", Data: []byte("d")}},
		{"type-bits", File{Path: "/etc/x", Data: []byte("d"), Mode: fs.ModeDir | 0o755}},
		{"negative-uid", File{Path: "/etc/x", Data: []byte("d"), Mode: 0o600, UID: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &mockRunner{}
			b := newTestBackend(r)
			spec := Spec{
				Name:          "sb-files-bad",
				NetworkPolicy: NetworkPolicyOpen,
				Image:         "test/img:latest",
				Profile:       ProfileHeadless,
				Files:         []File{tc.file},
			}
			if _, err := b.Create(context.Background(), spec); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
			if len(r.calls) != 0 {
				t.Fatalf("expected zero runner calls, got %d: %v", len(r.calls), r.calls)
			}
		})
	}

	t.Run("duplicate-path", func(t *testing.T) {
		r := &mockRunner{}
		b := newTestBackend(r)
		spec := Spec{
			Name:          "sb-files-dup",
			NetworkPolicy: NetworkPolicyOpen,
			Image:         "test/img:latest",
			Profile:       ProfileHeadless,
			Files: []File{
				{Path: "/etc/x", Data: []byte("a"), Mode: 0o600},
				{Path: "/etc/x", Data: []byte("b"), Mode: 0o644},
			},
		}
		if _, err := b.Create(context.Background(), spec); err == nil {
			t.Fatal("expected error for duplicate file path")
		}
		if len(r.calls) != 0 {
			t.Fatalf("expected zero runner calls, got %d", len(r.calls))
		}
	})
}

// TestCreate_Files_FailuresDestroy verifies fail-closed cleanup: if the copy
// or the subsequent start fails, the half-provisioned container is destroyed
// rather than left behind (stopped, without its files, or both).
func TestCreate_Files_FailuresDestroy(t *testing.T) {
	spec := Spec{
		Name:          "sb-files-fail",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
		Files:         []File{{Path: "/etc/app/x", Data: []byte("d"), Mode: 0o600}},
	}

	t.Run("cp-fails", func(t *testing.T) {
		r := &mockRunner{}
		b := newTestBackend(r)
		r.responses = []mockResponse{
			ok(""), ok("cid\n"), fail("cp exploded"),
			ok(""), ok(""), ok(""), // Destroy: stop, rm, volume rm
		}
		if _, err := b.Create(context.Background(), spec); err == nil {
			t.Fatal("expected error when cp fails")
		}
		if !sawDestroy(r.calls) {
			t.Errorf("expected container teardown after cp failure; calls: %v", r.calls)
		}
	})

	t.Run("start-fails", func(t *testing.T) {
		r := &mockRunner{}
		b := newTestBackend(r)
		r.responses = []mockResponse{
			ok(""), ok("cid\n"), ok(""), fail("start exploded"),
			ok(""), ok(""), ok(""), // Destroy: stop, rm, volume rm
		}
		if _, err := b.Create(context.Background(), spec); err == nil {
			t.Fatal("expected error when start fails")
		}
		if !sawDestroy(r.calls) {
			t.Errorf("expected container teardown after start failure; calls: %v", r.calls)
		}
	})
}

// TestCreate_NoFiles_KeepsRunDash verifies the no-Files path is unchanged:
// a single `podman run -d` and no cp/start calls.
func TestCreate_NoFiles_KeepsRunDash(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{ok(""), ok("cid\n")}

	spec := Spec{
		Name:          "sb-nofiles",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
	}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(r.calls) != 2 {
		t.Fatalf("expected 2 calls (volume, run), got %d", len(r.calls))
	}
	if r.calls[1].args[1] != "run" || !containsArg(r.calls[1].args, "-d") {
		t.Errorf("no-Files path must remain 'run -d': %s", argString(r.calls[1].args))
	}
}

// ---- CommandError tests --------------------------------------------------------

// TestCommandError_WithholdsStderr is the leak guard for tool stderr: a podman
// failure whose stderr quotes sensitive text must produce an error whose
// string never contains that text, while Detail() still hands it to a caller
// who asks by name and the exec.ExitError stays reachable for exit codes.
func TestCommandError_WithholdsStderr(t *testing.T) {
	const leaked = "BOT_TOKEN=123456:AAsekret"
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{
		ok(""), // volume create
		{stderr: []byte("Error: invalid flag near " + leaked), err: &exec.ExitError{ProcessState: &os.ProcessState{}}},
	}

	_, err := b.Create(context.Background(), Spec{
		Name:          "sb-cmderr",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:latest",
		Profile:       ProfileHeadless,
	})
	if err == nil {
		t.Fatal("expected error from failing run")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Errorf("error string leaks tool stderr: %q", err.Error())
	}
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As(*CommandError) failed for %T: %v", err, err)
	}
	if !strings.Contains(ce.Detail(), leaked) {
		t.Errorf("Detail() = %q, want the tool's stderr", ce.Detail())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Error("exec.ExitError no longer reachable through the chain")
	}
}

// TestPurge_NotFoundViaCommandErrorDetail verifies the "not found" tolerance
// still works now that podman's stderr lives in CommandError.Detail rather
// than the error string.
func TestPurge_NotFoundViaCommandErrorDetail(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	exit := &exec.ExitError{ProcessState: &os.ProcessState{}}
	r.responses = []mockResponse{
		ok(""), // stop
		{stderr: []byte("Error: no such container sbx-sb-gone"), err: exit},   // rm
		{stderr: []byte("Error: no such volume sbx-sb-gone-work"), err: exit}, // volume rm
	}
	if err := b.Purge(context.Background(), "sb-gone"); err != nil {
		t.Fatalf("Purge must tolerate not-found via CommandError detail: %v", err)
	}
}

// ---- Recreate tests ------------------------------------------------------------

// sawVolumeCommand reports whether any recorded call was a `podman volume ...`
// subcommand (create, rm, anything).  Recreate must never produce one.
func sawVolumeCommand(calls []call) bool {
	for _, c := range calls {
		if len(c.args) > 1 && c.args[1] == "volume" {
			return true
		}
	}
	return false
}

// TestRecreate_PreservesVolume verifies the rolling-update mechanism: the old
// container is removed, a new one is created from the NEW image, the same
// named work volume is reattached — and no volume command of any kind runs, so
// the caller's data cannot be deleted by the operation.
func TestRecreate_PreservesVolume(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{
		ok(""),         // stop old container
		ok(""),         // rm old container
		ok("newcid\n"), // run new container
	}

	h, err := b.Recreate(context.Background(), Spec{
		Name:          "sb-roll-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:v2",
		Profile:       ProfileHeadless,
	})
	if err != nil {
		t.Fatalf("Recreate: %v", err)
	}
	if h.ID != "sb-roll-1" || h.ContainerID != "newcid" {
		t.Errorf("Handle = %+v, want ID sb-roll-1 / ContainerID newcid", h)
	}
	if len(r.calls) != 3 {
		t.Fatalf("expected 3 calls (stop, rm, run), got %d: %v", len(r.calls), r.calls)
	}
	if r.calls[0].args[1] != "stop" || r.calls[1].args[1] != "rm" || r.calls[2].args[1] != "run" {
		t.Fatalf("wrong sequence: %v %v %v", r.calls[0].args[1], r.calls[1].args[1], r.calls[2].args[1])
	}
	// THE guarantee: no `podman volume ...` call anywhere on the path.
	if sawVolumeCommand(r.calls) {
		t.Fatalf("Recreate issued a volume command — it must never touch the volume: %v", r.calls)
	}
	// The EXISTING volume is reattached by name to the new container.
	rc := r.calls[2]
	wantVol := b.volumeName("sb-roll-1") + ":/work"
	if !hasFlagPair(rc.args, "--volume", wantVol) {
		t.Errorf("new container must reattach %q: %s", wantVol, argString(rc.args))
	}
	// The NEW image is used.
	if !containsArg(rc.args, "test/img:v2") {
		t.Errorf("new image missing from run args: %s", argString(rc.args))
	}
}

// TestRecreate_ToleratesAbsentContainer verifies Recreate also repairs a
// sandbox whose container is gone: the rm "no such container" is tolerated and
// the volume is reattached.
func TestRecreate_ToleratesAbsentContainer(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	exit := &exec.ExitError{ProcessState: &os.ProcessState{}}
	r.responses = []mockResponse{
		{stderr: []byte("Error: no such container sbx-sb-roll-2"), err: exit}, // stop
		{stderr: []byte("Error: no such container sbx-sb-roll-2"), err: exit}, // rm
		ok("cid\n"), // run
	}
	if _, err := b.Recreate(context.Background(), Spec{
		Name:          "sb-roll-2",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/img:v2",
		Profile:       ProfileHeadless,
	}); err != nil {
		t.Fatalf("Recreate with absent container: %v", err)
	}
	if sawVolumeCommand(r.calls) {
		t.Fatal("Recreate issued a volume command")
	}
}

// TestRecreate_FailurePathsNeverDeleteVolume is the structural guard the
// consumer asked for: it drives every failure path reachable from Recreate —
// egress lockdown failure, file copy failure, start failure — and fails if ANY
// call on ANY path is a `podman volume` command.  Create's fail-closed cleanup
// purges the volume it just made; Recreate's must not, because the volume
// holds the caller's data.
func TestRecreate_FailurePathsNeverDeleteVolume(t *testing.T) {
	base := Spec{
		Name:    "sb-roll-fail",
		Image:   "test/img:v2",
		Profile: ProfileHeadless,
	}

	t.Run("egress-fails", func(t *testing.T) {
		r := &mockRunner{}
		b := newTestBackend(r)
		b.lookPath = fakeLookPath() // no nft/nsenter → egress lockdown fails
		r.responses = []mockResponse{
			ok(""), ok(""), ok("cid\n"), // stop, rm, run
			ok(""), ok(""), // cleanup: stop, rm — and nothing else
		}
		spec := base
		spec.NetworkPolicy = NetworkPolicyInternalOnly
		if _, err := b.Recreate(context.Background(), spec); err == nil {
			t.Fatal("expected egress failure")
		}
		if sawVolumeCommand(r.calls) {
			t.Fatalf("volume command reached from Recreate egress-failure path: %v", r.calls)
		}
	})

	t.Run("cp-fails", func(t *testing.T) {
		r := &mockRunner{}
		b := newTestBackend(r)
		r.responses = []mockResponse{
			ok(""), ok(""), ok("cid\n"), // stop, rm, create
			fail("cp exploded"),
			ok(""), ok(""), // cleanup: stop, rm — and nothing else
		}
		spec := base
		spec.NetworkPolicy = NetworkPolicyOpen
		spec.Files = []File{{Path: "/etc/app/x", Data: []byte("d"), Mode: 0o600}}
		if _, err := b.Recreate(context.Background(), spec); err == nil {
			t.Fatal("expected cp failure")
		}
		if sawVolumeCommand(r.calls) {
			t.Fatalf("volume command reached from Recreate cp-failure path: %v", r.calls)
		}
	})

	t.Run("start-fails", func(t *testing.T) {
		r := &mockRunner{}
		b := newTestBackend(r)
		r.responses = []mockResponse{
			ok(""), ok(""), ok("cid\n"), ok(""), // stop, rm, create, cp
			fail("start exploded"),
			ok(""), ok(""), // cleanup: stop, rm — and nothing else
		}
		spec := base
		spec.NetworkPolicy = NetworkPolicyOpen
		spec.Files = []File{{Path: "/etc/app/x", Data: []byte("d"), Mode: 0o600}}
		if _, err := b.Recreate(context.Background(), spec); err == nil {
			t.Fatal("expected start failure")
		}
		if sawVolumeCommand(r.calls) {
			t.Fatalf("volume command reached from Recreate start-failure path: %v", r.calls)
		}
	})
}

// podmanEmulator answers `inspect`, `start`, and `stop` the way podman 4.9.3
// actually answers them, observed on a real host (theharness-dev, podman
// 4.9.3, missing name "sbx-does-not-exist-xyz"):
//
//	$ podman inspect --format json nosuchctr
//	[]
//	Error: no such object: "nosuchctr"          (exit 125)
//	$ podman inspect --type container --format json nosuchctr
//	[]
//	Error: no such container nosuchctr          (exit 125)
//	$ podman inspect --format json alpine
//	[ { "Id": ... } ]                            (exit 0 — that is the IMAGE)
//	$ podman start nosuchctr
//	Error: no container with name or ID "nosuchctr" found: no such container  (exit 125)
//	$ podman stop nosuchctr
//	Error: no container with name or ID "nosuchctr" found: no such container  (exit 125)
//
// Bare `inspect` resolves containers *and* images, so it neither says anything
// isNoSuchContainer recognises nor fails at all when an image answers to the
// name.  Everything else falls through to an empty success.
type podmanEmulator struct{ existingImages map[string]bool }

func (p podmanEmulator) Run(_ context.Context, args []string, _ []byte, _ []string) ([]byte, []byte, error) {
	if len(args) < 2 {
		return nil, nil, nil
	}
	exit := &exec.ExitError{ProcessState: &os.ProcessState{}}
	name := args[len(args)-1]
	switch args[1] {
	case "inspect":
		typed := findArg(args, "--type") >= 0
		switch {
		case typed:
			return []byte("[]\n"), []byte("Error: no such container " + name), exit
		case p.existingImages[name]:
			return []byte(`[{"Id":"deadbeef","State":{}}]`), nil, nil
		default:
			return []byte("[]\n"), []byte(`Error: no such object: "` + name + `"`), exit
		}
	case "start", "stop":
		return nil, []byte(`Error: no container with name or ID "` + name + `" found: no such container`), exit
	default:
		return nil, nil, nil
	}
}

// TestInspect_MissingSandboxAgainstRealPodmanBehaviour pins the one thing that
// made isolated mode impossible to run: Inspect must report a sandbox that does
// not exist as ErrSandboxNotFound when podman behaves as podman really behaves.
// Drop `--type container` from Inspect's argv and both halves fail — the first
// with an opaque exit 125 that no caller can turn into "create it", the second
// by reporting a stopped sandbox that is really an image of the same name.
func TestInspect_MissingSandboxAgainstRealPodmanBehaviour(t *testing.T) {
	b := newPodmanBackendWithRunner(podmanEmulator{}, slog.Default())
	if _, err := b.Inspect(context.Background(), "sb-gone"); !errors.Is(err, ErrSandboxNotFound) {
		t.Fatalf("missing sandbox: want ErrSandboxNotFound, got %v", err)
	}

	// An image answering to the sandbox's container name must not be mistaken
	// for the sandbox.
	img := Config{}.withDefaults().NamePrefix + "sb-shadowed"
	b = newPodmanBackendWithRunner(podmanEmulator{existingImages: map[string]bool{img: true}}, slog.Default())
	if _, err := b.Inspect(context.Background(), "sb-shadowed"); !errors.Is(err, ErrSandboxNotFound) {
		t.Fatalf("sandbox shadowed by an image of the same name: want ErrSandboxNotFound, got %v", err)
	}
}

// TestInspect_NotFoundViaCommandErrorDetail does the same for the
// ErrSandboxNotFound mapping in Inspect.
func TestInspect_NotFoundViaCommandErrorDetail(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{
		{stderr: []byte("Error: no such container sbx-sb-gone"), err: &exec.ExitError{ProcessState: &os.ProcessState{}}},
	}
	_, err := b.Inspect(context.Background(), "sb-gone")
	if !errors.Is(err, ErrSandboxNotFound) {
		t.Errorf("expected ErrSandboxNotFound via CommandError detail, got %v", err)
	}
}

// TestStopStart_MissingSandboxAgainstRealPodmanBehaviour pins the gap found
// while verifying the Inspect fix (v0.5.1): podman's message for `start`/`stop`
// on a missing name — `Error: no container with name or ID "…" found: no such
// container` (exit 125) — already matches isNoSuchContainer, but Stop and
// Start never called it and so never produced ErrSandboxNotFound.  kenward's
// rollOne and shutdown both branch on ErrSandboxNotFound from these two calls;
// before this fix those branches were dead.
func TestStopStart_MissingSandboxAgainstRealPodmanBehaviour(t *testing.T) {
	b := newPodmanBackendWithRunner(podmanEmulator{}, slog.Default())

	if err := b.Start(context.Background(), "sb-gone"); !errors.Is(err, ErrSandboxNotFound) {
		t.Errorf("Start on missing sandbox: want ErrSandboxNotFound, got %v", err)
	}
	if err := b.Stop(context.Background(), "sb-gone"); !errors.Is(err, ErrSandboxNotFound) {
		t.Errorf("Stop on missing sandbox: want ErrSandboxNotFound, got %v", err)
	}
}

// TestStopStart_NotFoundViaCommandErrorDetail does the same via the
// CommandError.Detail path (stderr carried out-of-band, as errText reads it),
// matching TestInspect_NotFoundViaCommandErrorDetail.
func TestStopStart_NotFoundViaCommandErrorDetail(t *testing.T) {
	notFoundMsg := []byte(`Error: no container with name or ID "sbx-sb-gone" found: no such container`)
	exit := &exec.ExitError{ProcessState: &os.ProcessState{}}

	t.Run("start", func(t *testing.T) {
		r := &mockRunner{responses: []mockResponse{{stderr: notFoundMsg, err: exit}}}
		b := newTestBackend(r)
		if err := b.Start(context.Background(), "sb-gone"); !errors.Is(err, ErrSandboxNotFound) {
			t.Errorf("expected ErrSandboxNotFound, got %v", err)
		}
	})
	t.Run("stop", func(t *testing.T) {
		r := &mockRunner{responses: []mockResponse{{stderr: notFoundMsg, err: exit}}}
		b := newTestBackend(r)
		if err := b.Stop(context.Background(), "sb-gone"); !errors.Is(err, ErrSandboxNotFound) {
			t.Errorf("expected ErrSandboxNotFound, got %v", err)
		}
	})
}
