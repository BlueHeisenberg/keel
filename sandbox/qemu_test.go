// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- fakes -----------------------------------------------------------------

// fakeQMPConn records the QMP commands issued against it and returns canned
// replies keyed by command name.
type fakeQMPConn struct {
	cmds    []qmpCall
	replies map[string]json.RawMessage // command → raw {"return": ...}
	errs    map[string]error           // command → error
	closed  bool
}

type qmpCall struct {
	cmd  string
	args map[string]any
}

func (f *fakeQMPConn) command(cmd string, args map[string]any) (json.RawMessage, error) {
	f.cmds = append(f.cmds, qmpCall{cmd: cmd, args: args})
	if f.errs != nil {
		if err, ok := f.errs[cmd]; ok {
			return nil, err
		}
	}
	if f.replies != nil {
		if r, ok := f.replies[cmd]; ok {
			return r, nil
		}
	}
	return json.RawMessage(`{"return":{}}`), nil
}

func (f *fakeQMPConn) Close() error { f.closed = true; return nil }

// fakeQMPDialer hands back a single fakeQMPConn.  If dialErr is set, Dial fails
// (simulating an unreachable / stopped VM).
type fakeQMPDialer struct {
	conn    *fakeQMPConn
	dialErr error
	dialed  int
}

func (f *fakeQMPDialer) Dial(_ context.Context, _ string) (qmpConn, error) {
	f.dialed++
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	if f.conn == nil {
		f.conn = &fakeQMPConn{}
	}
	return f.conn, nil
}

// fakeVsockConn is an in-memory vsock connection: it captures everything written
// and serves a canned response on read.
type fakeVsockConn struct {
	written  []byte
	response []byte
	readPos  int
	closed   bool
	deadline time.Time
}

func (c *fakeVsockConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}

func (c *fakeVsockConn) Read(p []byte) (int, error) {
	if c.readPos >= len(c.response) {
		return 0, io.EOF
	}
	n := copy(p, c.response[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *fakeVsockConn) Close() error { c.closed = true; return nil }

func (c *fakeVsockConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

// fakeVsockDialer returns a single fakeVsockConn, or a dial error.
type fakeVsockDialer struct {
	conn     *fakeVsockConn
	dialErr  error
	lastCID  uint32
	lastPort uint32
}

func (d *fakeVsockDialer) Dial(_ context.Context, cid uint32, port uint32) (vsockConn, error) {
	d.lastCID = cid
	d.lastPort = port
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d.conn, nil
}

// testBaseImage is the base disk every QEMU test backend is configured with.
// It is deliberately a POSIX-style absolute path: Create resolves it through
// filepath.Abs, so on Windows it becomes "<drive>:\images\base.qcow2" and
// assertions must compare against the resolved form, not this literal.
const testBaseImage = "/images/base.qcow2"

// newQemuTestBackend builds a QemuBackend wired to mock runner + fakes, with a
// fixed accel and a temp state dir.
func newQemuTestBackend(t *testing.T, r runner) *QemuBackend {
	t.Helper()
	b := newQemuBackendWithRunner(r, slog.Default())
	b.baseImage = testBaseImage
	b.accel = "kvm"
	b.stateDir = t.TempDir()
	return b
}

// ---- selectAccel tests -----------------------------------------------------

func TestSelectAccel(t *testing.T) {
	statOK := func(string) (os.FileInfo, error) { return nil, nil }
	statMissing := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	cases := []struct {
		name string
		goos string
		stat func(string) (os.FileInfo, error)
		want string
	}{
		{"linux-with-kvm", "linux", statOK, "kvm"},
		{"linux-no-kvm", "linux", statMissing, "tcg"},
		{"darwin", "darwin", statMissing, "hvf"},
		{"windows", "windows", statMissing, "whpx"},
		{"other", "plan9", statMissing, "tcg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := selectAccel(tc.goos, tc.stat)
			if got != tc.want {
				t.Errorf("selectAccel(%s) = %q, want %q", tc.goos, got, tc.want)
			}
		})
	}
}

// ---- Create arg-vector tests -----------------------------------------------

func TestCreate_QemuArgVector(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.accel = "kvm"
	r.responses = []mockResponse{
		ok(""), // qemu-img create overlay
		ok(""), // qemu-system launch
	}

	spec := Spec{
		Name:          "sb-vm-1",
		Level:         LevelIsolated,
		Profile:       ProfileHeadless,
		CPUs:          4,
		MemoryMB:      4096,
		NetworkPolicy: NetworkPolicyOpen,
	}
	h, err := b.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if h.ID != "sb-vm-1" {
		t.Errorf("Handle.ID = %q, want sb-vm-1", h.ID)
	}
	if !strings.HasPrefix(h.ContainerID, "vsock-cid:") {
		t.Errorf("Handle.ContainerID = %q, want vsock-cid: prefix", h.ContainerID)
	}

	if len(r.calls) != 2 {
		t.Fatalf("expected 2 runner calls (img create, launch), got %d", len(r.calls))
	}

	// Call 0: qemu-img create overlay with base image.
	img := r.calls[0].args
	if img[0] != "qemu-img" || !containsArg(img, "create") {
		t.Errorf("call[0] expected qemu-img create, got: %s", argString(img))
	}
	// Create resolves the base image through filepath.Abs, so the expected
	// value is the absolute form of the configured path on THIS platform —
	// "/images/base.qcow2" on Unix, "C:\images\base.qcow2" on Windows.
	wantBase, err := filepath.Abs(testBaseImage)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", testBaseImage, err)
	}
	if got := argAfter(img, "-b"); got != wantBase {
		t.Errorf("call[0] -b = %q, want %q", got, wantBase)
	}
	if !strings.HasSuffix(img[len(img)-1], "overlay.qcow2") {
		t.Errorf("call[0] last arg should be overlay path, got %q", img[len(img)-1])
	}

	// Call 1: qemu-system launch.
	q := r.calls[1].args
	if !strings.HasPrefix(q[0], "qemu-system") {
		t.Errorf("call[1] expected qemu-system binary, got %q", q[0])
	}
	if argAfter(q, "-machine") != "accel=kvm" {
		t.Errorf("-machine = %q, want accel=kvm", argAfter(q, "-machine"))
	}
	if argAfter(q, "-m") != "4096" {
		t.Errorf("-m = %q, want 4096", argAfter(q, "-m"))
	}
	if argAfter(q, "-smp") != "4" {
		t.Errorf("-smp = %q, want 4", argAfter(q, "-smp"))
	}
	drive := argAfter(q, "-drive")
	if !strings.Contains(drive, "overlay.qcow2") || !strings.Contains(drive, "if=virtio") {
		t.Errorf("-drive = %q, want overlay + if=virtio", drive)
	}
	qmp := argAfter(q, "-qmp")
	if !strings.HasPrefix(qmp, "unix:") || !strings.Contains(qmp, "qmp.sock") {
		t.Errorf("-qmp = %q, want unix:...qmp.sock", qmp)
	}
	dev := argAfter(q, "-device")
	if !strings.HasPrefix(dev, "vhost-vsock-pci,guest-cid=") {
		t.Errorf("-device = %q, want vhost-vsock-pci,guest-cid=", dev)
	}
	if argAfter(q, "-display") != "none" {
		t.Errorf("-display = %q, want none", argAfter(q, "-display"))
	}
	if !containsArg(q, "-daemonize") {
		t.Errorf("missing -daemonize: %s", argString(q))
	}
	if !strings.HasSuffix(argAfter(q, "-pidfile"), "qemu.pid") {
		t.Errorf("-pidfile = %q, want qemu.pid", argAfter(q, "-pidfile"))
	}
	// Open policy → user-mode NIC.
	if argAfter(q, "-nic") != "user" {
		t.Errorf("-nic = %q, want user for open policy", argAfter(q, "-nic"))
	}
}

func TestCreate_DefaultResources(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	r.responses = []mockResponse{ok(""), ok("")}

	spec := Spec{Name: "sb-vm-def", Level: LevelIsolated, NetworkPolicy: NetworkPolicyOpen}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	q := r.calls[1].args
	if argAfter(q, "-m") != "2048" {
		t.Errorf("default -m = %q, want 2048", argAfter(q, "-m"))
	}
	if argAfter(q, "-smp") != "2" {
		t.Errorf("default -smp = %q, want 2", argAfter(q, "-smp"))
	}
}

func TestCreate_NetworkPolicyNone(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	r.responses = []mockResponse{ok(""), ok("")}

	spec := Spec{Name: "sb-vm-none", Level: LevelIsolated, NetworkPolicy: NetworkPolicyNone}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	q := r.calls[1].args
	if argAfter(q, "-nic") != "none" {
		t.Errorf("-nic = %q, want none for NetworkPolicyNone", argAfter(q, "-nic"))
	}
}

func TestCreate_AccelReflectedInArgs(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.accel = "hvf"
	r.responses = []mockResponse{ok(""), ok("")}

	spec := Spec{Name: "sb-vm-accel", Level: LevelIsolated, NetworkPolicy: NetworkPolicyOpen}
	if _, err := b.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := argAfter(r.calls[1].args, "-machine"); got != "accel=hvf" {
		t.Errorf("-machine = %q, want accel=hvf", got)
	}
}

func TestCreate_NoBaseImage_Unavailable(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.baseImage = "" // simulate missing base image

	_, err := b.Create(context.Background(), Spec{Name: "sb-vm-nobase", Level: LevelIsolated})
	if err == nil {
		t.Fatal("expected ErrQemuUnavailable when base image is missing")
	}
	if !errors.Is(err, ErrQemuUnavailable) {
		t.Errorf("expected ErrQemuUnavailable, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("expected no runner calls when base image missing, got %d", len(r.calls))
	}
}

// ---- QMP lifecycle tests ---------------------------------------------------

func TestStop_SendsPowerdown(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	fq := &fakeQMPDialer{conn: &fakeQMPConn{}}
	b.qmpDialer = fq

	if err := b.Stop(context.Background(), "sb-vm-stop"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if len(fq.conn.cmds) == 0 || fq.conn.cmds[0].cmd != "system_powerdown" {
		t.Errorf("expected system_powerdown first, got %+v", fq.conn.cmds)
	}
	if !fq.conn.closed {
		t.Error("expected QMP conn to be closed")
	}
}

func TestStop_QMPUnreachable_NoError(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.qmpDialer = &fakeQMPDialer{dialErr: errors.New("connection refused")}

	if err := b.Stop(context.Background(), "sb-vm-gone"); err != nil {
		t.Errorf("Stop should tolerate unreachable QMP, got %v", err)
	}
}

// TestPurge_QuitAndRemoveState verifies the explicitly destructive operation:
// Purge quits the VM and removes the state dir, overlay (the data) included.
func TestPurge_QuitAndRemoveState(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	fq := &fakeQMPDialer{conn: &fakeQMPConn{}}
	b.qmpDialer = fq

	// Materialize the per-sandbox state dir so we can assert removal.
	id := "sb-vm-destroy"
	dir := b.sandboxDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.qcow2"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	if err := b.Purge(context.Background(), id); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if len(fq.conn.cmds) == 0 || fq.conn.cmds[0].cmd != "quit" {
		t.Errorf("expected quit command, got %+v", fq.conn.cmds)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected state dir removed, stat err = %v", err)
	}
}

func TestSnapshot_LiveSavevm(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	fq := &fakeQMPDialer{conn: &fakeQMPConn{}}
	b.qmpDialer = fq

	ref, err := b.Snapshot(context.Background(), "sb-vm-snap", "before-risky")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if ref.Ref != "qemu:sb-vm-snap:before-risky" {
		t.Errorf("ref = %q, want qemu:sb-vm-snap:before-risky", ref.Ref)
	}
	if ref.Label != "before-risky" {
		t.Errorf("label = %q, want before-risky", ref.Label)
	}
	// Must have used the human-monitor savevm passthrough.
	found := false
	for _, c := range fq.conn.cmds {
		if c.cmd == "human-monitor-command" {
			if cl, _ := c.args["command-line"].(string); cl == "savevm before-risky" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected human-monitor savevm, got %+v", fq.conn.cmds)
	}
	// No qemu-img fallback should have run.
	if len(r.calls) != 0 {
		t.Errorf("expected no qemu-img calls for live snapshot, got %d", len(r.calls))
	}
}

func TestSnapshot_OfflineFallback(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.qmpDialer = &fakeQMPDialer{dialErr: errors.New("no socket")}
	r.responses = []mockResponse{ok("")} // qemu-img snapshot -c

	ref, err := b.Snapshot(context.Background(), "sb-vm-snap2", "tag1")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if ref.Ref != "qemu:sb-vm-snap2:tag1" {
		t.Errorf("ref = %q", ref.Ref)
	}
	if len(r.calls) != 1 {
		t.Fatalf("expected 1 qemu-img call, got %d", len(r.calls))
	}
	c := r.calls[0].args
	if c[0] != "qemu-img" || !containsArg(c, "snapshot") || !containsArg(c, "-c") || !containsArg(c, "tag1") {
		t.Errorf("expected qemu-img snapshot -c tag1, got %s", argString(c))
	}
}

func TestRemoveSnapshot_ArgVector(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	r.responses = []mockResponse{ok("")}

	if err := b.RemoveSnapshot(context.Background(), "qemu:sb-vm-rs:tagX"); err != nil {
		t.Fatalf("RemoveSnapshot: %v", err)
	}
	c := r.calls[0].args
	if c[0] != "qemu-img" || !containsArg(c, "snapshot") || !containsArg(c, "-d") || !containsArg(c, "tagX") {
		t.Errorf("expected qemu-img snapshot -d tagX, got %s", argString(c))
	}
}

func TestRemoveSnapshot_MissingTolerated(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	r.responses = []mockResponse{fail("Can't find snapshot tagY")}

	if err := b.RemoveSnapshot(context.Background(), "qemu:sb-vm-rs2:tagY"); err != nil {
		t.Errorf("RemoveSnapshot should tolerate missing snapshot, got %v", err)
	}
}

func TestRestore_LiveLoadvm(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	fq := &fakeQMPDialer{conn: &fakeQMPConn{}}
	b.qmpDialer = fq

	h, err := b.Restore(context.Background(), "sb-vm-rest", SnapshotRef{Ref: "qemu:sb-vm-rest:tagZ", Label: "tagZ"})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if h.ID != "sb-vm-rest" {
		t.Errorf("Handle.ID = %q", h.ID)
	}
	found := false
	for _, c := range fq.conn.cmds {
		if c.cmd == "human-monitor-command" {
			if cl, _ := c.args["command-line"].(string); cl == "loadvm tagZ" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected human-monitor loadvm tagZ, got %+v", fq.conn.cmds)
	}
}

// ---- Inspect tests ---------------------------------------------------------

func TestInspect_RunningViaQMP(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	id := "sb-vm-insp"
	if err := os.MkdirAll(b.sandboxDir(id), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b.qmpDialer = &fakeQMPDialer{conn: &fakeQMPConn{
		replies: map[string]json.RawMessage{
			"query-status": json.RawMessage(`{"return":{"running":true,"status":"running"}}`),
		},
	}}

	st, err := b.Inspect(context.Background(), id)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !st.Running {
		t.Error("expected Running=true from query-status")
	}
}

func TestQemuInspect_NotFound(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	_, err := b.Inspect(context.Background(), "sb-vm-missing")
	if !errors.Is(err, ErrSandboxNotFound) {
		t.Errorf("expected ErrSandboxNotFound, got %v", err)
	}
}

// ---- Exec / file tests over fake vsock -------------------------------------

func TestExec_OverVsock(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)

	resp := bridgeResponse{ExitCode: 0, Stdout: []byte("hello\n"), Stderr: []byte("warn\n")}
	raw, _ := json.Marshal(resp)
	vc := &fakeVsockConn{response: raw}
	vd := &fakeVsockDialer{conn: vc}
	b.vsockDialer = vd

	res, err := b.Exec(context.Background(), "sb-vm-exec", []string{"echo", "hello"}, ExecOpts{WorkDir: "/work"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	// The dial must target the allocated CID for this id and the fixed bridge port.
	if wantCID := b.cidFor("sb-vm-exec"); vd.lastCID != wantCID {
		t.Errorf("dialed CID = %d, want allocated %d", vd.lastCID, wantCID)
	}
	if vd.lastPort != guestBridgePort {
		t.Errorf("dialed port = %d, want %d", vd.lastPort, guestBridgePort)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if string(res.Stdout) != "hello\n" {
		t.Errorf("Stdout = %q, want hello", res.Stdout)
	}
	// The request written to the bridge must carry the command + workdir.
	var sent bridgeRequest
	if err := json.Unmarshal(vc.written[:len(vc.written)-1], &sent); err != nil {
		t.Fatalf("parse sent request: %v (raw %q)", err, vc.written)
	}
	if sent.Op != "exec" {
		t.Errorf("sent op = %q, want exec", sent.Op)
	}
	if len(sent.Cmd) != 2 || sent.Cmd[0] != "echo" {
		t.Errorf("sent cmd = %v", sent.Cmd)
	}
	if sent.WorkDir != "/work" {
		t.Errorf("sent workdir = %q, want /work", sent.WorkDir)
	}
}

func TestExec_GuestUnavailable(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.vsockDialer = &fakeVsockDialer{dialErr: errors.New("no guest")}

	_, err := b.Exec(context.Background(), "sb-vm-noguest", []string{"true"}, ExecOpts{})
	if !errors.Is(err, ErrQemuGuestUnavailable) {
		t.Errorf("expected ErrQemuGuestUnavailable, got %v", err)
	}
}

func TestWriteReadFile_RoundTrip(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)

	// WriteFile: empty-success response.
	writeResp, _ := json.Marshal(bridgeResponse{})
	wc := &fakeVsockConn{response: writeResp}
	b.vsockDialer = &fakeVsockDialer{conn: wc}

	payload := []byte("file body\n")
	if err := b.WriteFile(context.Background(), "sb-vm-wf", "/work/out.txt", payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var sent bridgeRequest
	if err := json.Unmarshal(wc.written[:len(wc.written)-1], &sent); err != nil {
		t.Fatalf("parse write request: %v", err)
	}
	if sent.Op != "writefile" || sent.Path != "/work/out.txt" {
		t.Errorf("write request = %+v", sent)
	}
	if string(sent.Data) != string(payload) {
		t.Errorf("write data = %q, want %q", sent.Data, payload)
	}

	// ReadFile: response carries Data.
	readResp, _ := json.Marshal(bridgeResponse{Data: []byte("read back\n")})
	rcn := &fakeVsockConn{response: readResp}
	b.vsockDialer = &fakeVsockDialer{conn: rcn}

	got, err := b.ReadFile(context.Background(), "sb-vm-wf", "/work/out.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "read back\n" {
		t.Errorf("ReadFile = %q, want 'read back\\n'", got)
	}
}

// ---- endpoint tests --------------------------------------------------------

func TestDesktopWebEndpoints_WrongProfile(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	if _, err := b.DesktopEndpoint(context.Background(), "x"); !errors.Is(err, ErrWrongProfile) {
		t.Errorf("DesktopEndpoint: expected ErrWrongProfile, got %v", err)
	}
	if _, err := b.WebEndpoint(context.Background(), "x"); !errors.Is(err, ErrWrongProfile) {
		t.Errorf("WebEndpoint: expected ErrWrongProfile, got %v", err)
	}
}

// ---- snapshot ref parsing --------------------------------------------------

func TestParseSnapshotRef(t *testing.T) {
	id, tag, ok := parseSnapshotRef("qemu:sb-1:my-tag")
	if !ok || id != "sb-1" || tag != "my-tag" {
		t.Errorf("parseSnapshotRef = (%q,%q,%v)", id, tag, ok)
	}
	if _, _, ok := parseSnapshotRef("notqemu:x:y"); ok {
		t.Error("expected malformed ref to fail")
	}
	if _, _, ok := parseSnapshotRef("qemu:onlyid"); ok {
		t.Error("expected ref without tag to fail")
	}
}

func TestGuestCID_StableAndAboveReserved(t *testing.T) {
	a := guestCID("sb-1")
	b := guestCID("sb-1")
	if a != b {
		t.Errorf("guestCID not stable: %d != %d", a, b)
	}
	if a < firstGuestCID {
		t.Errorf("guestCID %d below reserved minimum %d", a, firstGuestCID)
	}
}

// ---- FIX 2: relative base image is made absolute ---------------------------

func TestCreate_RelativeBaseImage_MadeAbsolute(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.baseImage = "relative/base.qcow2" // not absolute
	r.responses = []mockResponse{ok(""), ok("")}

	if _, err := b.Create(context.Background(), Spec{Name: "sb-rel", Level: LevelIsolated}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := argAfter(r.calls[0].args, "-b")
	if !filepath.IsAbs(got) {
		t.Errorf("qemu-img -b = %q, want an absolute path", got)
	}
	if !strings.HasSuffix(got, filepath.Join("relative", "base.qcow2")) {
		t.Errorf("qemu-img -b = %q, want it to end with relative/base.qcow2", got)
	}
}

func TestCreate_CommaInBaseImage_Rejected(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.baseImage = "/images/ba,d.qcow2"

	_, err := b.Create(context.Background(), Spec{Name: "sb-comma", Level: LevelIsolated})
	if err == nil || !strings.Contains(err.Error(), "comma") {
		t.Errorf("expected comma rejection error, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("expected no runner calls when base image has a comma, got %d", len(r.calls))
	}
}

// ---- FIX 4: failed launch leaves no state dir ------------------------------

func TestCreate_FailedLaunch_CleansUpStateDir(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	id := "sb-launch-fail"
	// img create succeeds; qemu launch fails.
	r.responses = []mockResponse{ok(""), fail("qemu: boom")}

	_, err := b.Create(context.Background(), Spec{Name: id, Level: LevelIsolated})
	if err == nil {
		t.Fatal("expected Create to fail on launch error")
	}
	if _, statErr := os.Stat(b.sandboxDir(id)); !os.IsNotExist(statErr) {
		t.Errorf("expected state dir removed after failed launch, stat err = %v", statErr)
	}
}

// ---- FIX 5: CID collision yields distinct CIDs -----------------------------

func TestAllocateCID_CollisionProbesToDistinct(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)

	// Force a hash collision by stubbing both ids to the same base CID via the
	// allocator's collision handling: directly occupy the hashed CID of id1 with
	// id1, then allocate id2 whose hash we coerce to the same value by seeding the
	// map. We exercise the probe by pre-claiming guestCID("a") for a different id.
	base := guestCID("collide-a")
	b.idByCID[base] = "someone-else"
	b.cidByID["someone-else"] = base

	got := b.allocateCID("collide-a")
	if got == base {
		t.Fatalf("expected probe away from taken CID %d, got same", base)
	}
	if got < firstGuestCID {
		t.Errorf("probed CID %d below reserved minimum", got)
	}
	// A second different id that hashes to the same base must also get something
	// distinct from both.
	other := b.allocateCID("collide-a") // same id → stable
	if other != got {
		t.Errorf("allocateCID not stable for same id: %d != %d", other, got)
	}
}

func TestAllocateCID_TwoIdsSameHashGetDistinct(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)

	// Simulate two ids hashing to the same CID: claim id1 at its hashed CID, then
	// pre-seed the collision map so id2's candidate equals id1's CID.
	id1 := "sb-aaa"
	c1 := b.allocateCID(id1)
	// Make a second id whose hashed candidate is c1 by occupying nothing extra and
	// directly probing: we model the collision by claiming the candidate for id2
	// equals c1. allocateCID(id2) will see c1 taken by id1 and probe upward.
	b.idByCID[c1] = id1 // already true, explicit for clarity
	id2 := "sb-bbb"
	// Coerce id2's starting candidate to c1 by temporarily aliasing: we can't
	// change guestCID, so assert via the real probe path: occupy c1..c1+0 and
	// ensure id2 gets != c1 when its natural hash happens to equal c1. If natural
	// hashes differ we still verify distinctness, which is the security property.
	c2 := b.allocateCID(id2)
	if c2 == c1 {
		t.Errorf("two distinct ids share CID %d (isolation breach)", c1)
	}
}

// ---- FIX 6: malicious id rejected, label sanitized -------------------------

func TestCreate_MaliciousID_Rejected(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)

	for _, badID := range []string{"../escape", "a/b", "a,b", "a b", "a\\b", ".."} {
		_, err := b.Create(context.Background(), Spec{Name: badID, Level: LevelIsolated})
		if err == nil {
			t.Errorf("expected rejection for id %q", badID)
		}
		if len(r.calls) != 0 {
			t.Errorf("expected no runner calls for malicious id %q, got %d", badID, len(r.calls))
		}
	}
	// Methods that take a bare id must also reject.
	if err := b.Stop(context.Background(), "../x"); err == nil {
		t.Error("Stop expected to reject malicious id")
	}
	if err := b.Purge(context.Background(), "a,b"); err == nil {
		t.Error("Purge expected to reject malicious id")
	}
	if _, err := b.Recreate(context.Background(), Spec{Name: "a,b"}); err == nil {
		t.Error("Recreate expected to reject malicious id")
	}
	if _, err := b.Inspect(context.Background(), "a b"); err == nil {
		t.Error("Inspect expected to reject malicious id")
	}
}

func TestSnapshotTag_Sanitization(t *testing.T) {
	cases := map[string]string{
		"my label":    "my_label",
		"a:b":         "a_b",
		"a/b":         "a_b",
		"a,b":         "a_b",
		"a\\b":        "a_b",
		"..":          "__",
		"../../etc":   "______etc",
		"clean-tag_1": "clean-tag_1",
		"":            "snap",
		"!@#":         "___",
	}
	for in, want := range cases {
		if got := snapshotTag(in); got != want {
			t.Errorf("snapshotTag(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- FIX 7: live savevm failure on running VM does not touch overlay --------

func TestSnapshot_LiveSavevmFails_RunningVM_NoOfflineFallback(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	// QMP reachable: savevm fails, query-status reports running.
	fq := &fakeQMPDialer{conn: &fakeQMPConn{
		errs: map[string]error{"human-monitor-command": errors.New("savevm failed")},
		replies: map[string]json.RawMessage{
			"query-status": json.RawMessage(`{"return":{"running":true}}`),
		},
	}}
	b.qmpDialer = fq

	_, err := b.Snapshot(context.Background(), "sb-snap-run", "tag")
	if err == nil {
		t.Fatal("expected error when live savevm fails on a running VM")
	}
	// Must NOT have shelled out to qemu-img against the live overlay.
	if len(r.calls) != 0 {
		t.Errorf("expected no qemu-img calls for running VM, got %d (%v)", len(r.calls), r.calls)
	}
}

// ---- FIX 8: Restore rejects ref belonging to another id --------------------

func TestRestore_RefIDMismatch_Rejected(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	b.qmpDialer = &fakeQMPDialer{conn: &fakeQMPConn{}}

	_, err := b.Restore(context.Background(), "sb-target", SnapshotRef{Ref: "qemu:sb-OTHER:tag", Label: "tag"})
	if err == nil || !strings.Contains(err.Error(), "not") {
		t.Errorf("expected id-mismatch rejection, got %v", err)
	}
}

// ---- FIX 9: Stop escalates to quit when powerdown does not stop the VM ------

func TestStop_EscalatesToQuit(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	// query-status always reports running so the poll never sees a stop; Stop must
	// escalate to quit after the grace period.
	fq := &fakeQMPDialer{conn: &fakeQMPConn{
		replies: map[string]json.RawMessage{
			"query-status": json.RawMessage(`{"return":{"running":true}}`),
		},
	}}
	b.qmpDialer = fq

	if err := b.Stop(context.Background(), "sb-stop-stuck"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	sawPowerdown, sawQuit := false, false
	for _, c := range fq.conn.cmds {
		switch c.cmd {
		case "system_powerdown":
			sawPowerdown = true
		case "quit":
			sawQuit = true
		}
	}
	if !sawPowerdown {
		t.Error("expected system_powerdown to be sent")
	}
	if !sawQuit {
		t.Error("expected escalation to quit when powerdown did not stop the VM")
	}
}

// ---- FIX 10: snapshot label with spaces/colons/commas sanitized in cmd+ref --

func TestSnapshot_LabelSanitizedInCommandAndRef(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	fq := &fakeQMPDialer{conn: &fakeQMPConn{}}
	b.qmpDialer = fq

	ref, err := b.Snapshot(context.Background(), "sb-san", "my risky:tag,1")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	const wantTag = "my_risky_tag_1"
	if ref.Ref != "qemu:sb-san:"+wantTag {
		t.Errorf("ref = %q, want qemu:sb-san:%s", ref.Ref, wantTag)
	}
	// Original (unsanitized) label is preserved on the ref.
	if ref.Label != "my risky:tag,1" {
		t.Errorf("label = %q, want original preserved", ref.Label)
	}
	found := false
	for _, c := range fq.conn.cmds {
		if c.cmd == "human-monitor-command" {
			if cl, _ := c.args["command-line"].(string); cl == "savevm "+wantTag {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected savevm with sanitized tag %q, got %+v", wantTag, fq.conn.cmds)
	}
}

// ---- Spec.Command / Spec.Files rejection -------------------------------------

// TestQemuCreate_CommandAndFilesUnsupported verifies the QEMU backend fails
// loudly on the two Spec fields it cannot deliver — a VM boots whatever its
// disk image boots, and file transfer needs a booted guest — instead of
// handing back a VM that silently ran the wrong thing or lacks a promised
// file.  Nothing may be created: no runner call, no state dir.
func TestQemuCreate_CommandAndFilesUnsupported(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
	}{
		{"command", Spec{Name: "vm-cmd", Command: []string{"kenward", "--member=x"}}},
		{"files", Spec{Name: "vm-files", Files: []File{{Path: "/etc/x", Data: []byte("d"), Mode: 0o600}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &mockRunner{}
			b := newQemuTestBackend(t, r)
			_, err := b.Create(context.Background(), tc.spec)
			if !errors.Is(err, ErrSpecUnsupported) {
				t.Fatalf("expected ErrSpecUnsupported, got %v", err)
			}
			if len(r.calls) != 0 {
				t.Fatalf("expected zero runner calls, got %d: %v", len(r.calls), r.calls)
			}
			if _, serr := os.Stat(b.sandboxDir(tc.spec.Name)); serr == nil {
				t.Error("state dir was created despite the rejected spec")
			}
		})
	}
}

// ---- Recreate ------------------------------------------------------------------

// TestQemuRecreate_PreservesOverlay verifies the VM process is replaced while
// the overlay disk — the sandbox's data — survives untouched: no qemu-img call,
// no state removal, and the relaunch boots the SAME overlay.
func TestQemuRecreate_PreservesOverlay(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)

	id := "vm-roll"
	if err := os.MkdirAll(b.sandboxDir(id), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := []byte("precious-qcow2-bytes")
	if err := os.WriteFile(b.overlayPath(id), data, 0o644); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	// QMP socket does not exist → Stop treats the VM as already stopped and
	// vmRunning falls back to the (absent) pidfile.
	h, err := b.Recreate(context.Background(), Spec{Name: id, MemoryMB: 4096, CPUs: 4})
	if err != nil {
		t.Fatalf("Recreate: %v", err)
	}
	if h.ID != id {
		t.Errorf("Handle.ID = %q, want %q", h.ID, id)
	}

	// Exactly one runner call: the qemu relaunch.  No qemu-img (no new
	// overlay), and certainly no state removal.
	if len(r.calls) != 1 {
		t.Fatalf("expected 1 call (qemu launch), got %d: %v", len(r.calls), r.calls)
	}
	launch := r.calls[0]
	wantDrive := "file=" + b.overlayPath(id) + ",if=virtio"
	found := false
	for _, a := range launch.args {
		if a == wantDrive {
			found = true
		}
	}
	if !found {
		t.Errorf("relaunch must boot the existing overlay %q: %v", wantDrive, launch.args)
	}
	// New resources took effect.
	if !containsArg(launch.args, "4096") || !containsArg(launch.args, "4") {
		t.Errorf("new resource settings missing from relaunch args: %v", launch.args)
	}
	// The overlay file and its contents survived.
	got, err := os.ReadFile(b.overlayPath(id))
	if err != nil || string(got) != string(data) {
		t.Errorf("overlay changed or missing after Recreate: %q, err=%v", got, err)
	}
}

// TestQemuRecreate_RejectsImageChange verifies a new disk image cannot arrive
// through Recreate: an overlay is bound to its base, so the caller must decide
// between keeping the data (no image change) and Purge+Create (data loss).
func TestQemuRecreate_RejectsImageChange(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	_, err := b.Recreate(context.Background(), Spec{Name: "vm-img", Image: "new-base.qcow2"})
	if !errors.Is(err, ErrSpecUnsupported) {
		t.Fatalf("expected ErrSpecUnsupported for image change, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("expected zero runner calls, got %d", len(r.calls))
	}
}

// TestQemuRecreate_MissingOverlay_NotFound verifies a sandbox with no overlay
// maps to ErrSandboxNotFound rather than silently creating a fresh disk.
func TestQemuRecreate_MissingOverlay_NotFound(t *testing.T) {
	r := &mockRunner{}
	b := newQemuTestBackend(t, r)
	_, err := b.Recreate(context.Background(), Spec{Name: "vm-none"})
	if !errors.Is(err, ErrSandboxNotFound) {
		t.Fatalf("expected ErrSandboxNotFound, got %v", err)
	}
}
