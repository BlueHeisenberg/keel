// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// ---- mock runner -----------------------------------------------------------

// call records one invocation of the mock runner.
type call struct {
	args  []string
	stdin []byte
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

func (m *mockRunner) Run(_ context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
	m.calls = append(m.calls, call{args: args, stdin: stdin})
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

func TestCreate_ExtraEnv(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	r.responses = []mockResponse{ok(""), ok("cid\n")}

	spec := Spec{
		Name:          "sb-env-1",
		NetworkPolicy: NetworkPolicyOpen,
		Image:         "test/desktop:latest",
		Profile:       ProfileHeadless,
		Env:           map[string]string{"FOO": "bar"},
	}

	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rc := r.calls[1]
	// There should be an --env FOO=bar somewhere in the args.
	found := false
	for i, a := range rc.args {
		if a == "--env" && i+1 < len(rc.args) && rc.args[i+1] == "FOO=bar" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("missing --env FOO=bar in run args: %s", argString(rc.args))
	}
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
	found := false
	for i, a := range c.args {
		if a == "--env" && i+1 < len(c.args) && c.args[i+1] == "MY_VAR=testval" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("missing --env MY_VAR=testval in exec args: %s", argString(c.args))
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

// ---- Destroy tests ---------------------------------------------------------

func TestDestroy_ArgSequence(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)
	r.responses = []mockResponse{
		ok(""), // stop
		ok(""), // rm
		ok(""), // volume rm
	}

	if err := b.Destroy(context.Background(), "sb-destroy-1"); err != nil {
		t.Fatalf("Destroy: %v", err)
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
			assertRejected("Destroy", b.Destroy(ctx, id))
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
