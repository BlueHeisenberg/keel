// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Compile-time assertion: QemuBackend must implement Backend.
var _ Backend = (*QemuBackend)(nil)

// ErrQemuUnavailable is returned when QEMU cannot be used because the
// qemu-system binary is not installed or no base disk image is configured.
// Callers should check errors.Is(err, ErrQemuUnavailable) and surface a clear
// "install QEMU and configure a base image" message rather than crashing.
var ErrQemuUnavailable = errors.New("qemu unavailable: install QEMU and set Config.BaseImage to a qcow2 base disk")

// ErrQemuGuestUnavailable is returned when the in-guest control bridge cannot
// be reached over virtio-vsock: no guest image with the bridge daemon present,
// the VM is not booted far enough to answer, or the host is not Linux (AF_VSOCK
// is a Linux socket family).  The host side of the protocol is implemented
// here; supplying a guest image that carries the bridge is the caller's job.
var ErrQemuGuestUnavailable = errors.New("qemu guest bridge unreachable: a desktop image with the in-guest vsock bridge is required for exec/file ops")

// guestBridgePort is the AF_VSOCK port the in-guest control bridge listens on.
// Fixed by the bridge contract below; a guest image must listen here.
const guestBridgePort = 1024

// firstGuestCID is the lowest legal guest context ID for virtio-vsock.
// CIDs 0–2 are reserved (0 = hypervisor, 1 = local, 2 = host), so guests must
// use >= 3.
const firstGuestCID = 3

// sandboxIDRe is the allowed character set for a sandbox id.  Any id
// passed to a backend method is validated against this to prevent path traversal
// in the per-sandbox state dir and comma-injection into qemu option strings.
var sandboxIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validID rejects ids that could escape the state dir or inject qemu option
// separators.  Callers return the resulting error directly.
func validID(id string) error {
	if !sandboxIDRe.MatchString(id) {
		return fmt.Errorf("qemu: invalid sandbox id %q: must match [A-Za-z0-9_-]+", id)
	}
	return nil
}

// QemuBackend implements Backend for LevelIsolated by launching one
// qemu-system process per sandbox.  It mirrors PodmanBackend's injectable-runner
// discipline (see podman.go) so the entire host-side surface — arg-vector
// construction, QMP control, and vsock dialing — is unit-testable without a real
// VM.
//
// Per-sandbox state lives under <stateDir>/<id>/:
//
//	overlay.qcow2   copy-on-write overlay backed by the configured base image
//	qmp.sock        QMP control unix socket
//	qemu.pid        pidfile written by the daemonized qemu process
//
// The backend stores no other state itself; the caller persists the Handle.
//
// Exec, WriteFile, and ReadFile need the in-guest bridge over AF_VSOCK and so
// work only on a Linux host — see the package documentation.
type QemuBackend struct {
	// cfg holds binary paths, the base image, and the state dir root, with
	// defaults applied.
	cfg Config

	// baseImage is the qcow2 base disk, taken from Config.BaseImage.  Required
	// for real boots; empty → Create returns ErrQemuUnavailable.  Held
	// separately from cfg because Create resolves it to an absolute path and
	// tests override it.
	baseImage string
	// stateDir is the root for per-sandbox state, taken from Config.StateDir.
	stateDir string

	// accel is the chosen accelerator ("kvm"/"hvf"/"whpx"/"tcg").  Derived from
	// selectAccel() at construction; overridable by tests.
	accel string

	// r is the command runner (injectable; see runner in podman.go).
	r runner
	// qmpDialer connects to a QMP unix socket (injectable for tests).
	qmpDialer qmpDialer
	// vsockDialer dials the in-guest bridge over AF_VSOCK (injectable for tests).
	vsockDialer vsockDialer

	// cidMu guards the CID allocator maps below.  Guest CIDs are derived from a
	// hash of the sandbox id, which can collide; collisions would let a host vsock
	// dial for sandbox A reach sandbox B's guest (cross-sandbox isolation breach).
	// The allocator linear-probes from the hashed candidate to the next free CID.
	cidMu   sync.Mutex
	cidByID map[string]uint32 // sandboxID → allocated CID
	idByCID map[uint32]string // CID → sandboxID (collision detection)

	log *slog.Logger
}

// level reports the isolation level this backend implements.
func (b *QemuBackend) level() SandboxLevel { return LevelIsolated }

// NewQemuBackend returns a Backend that drives QEMU VMs (LevelIsolated),
// configured by cfg.  Config.BaseImage is required for real boots; without it
// Create returns ErrQemuUnavailable.  The zero Config is otherwise usable; see
// Config for the defaults it implies, and ConfigFromEnv to read one from the
// environment.
//
// Pass logger from the application; if nil, slog.Default() is used.
//
// Construction picks a hardware accelerator for the host (see selectAccel) and
// logs a warning when it has to fall back to software emulation.  It starts no
// process and creates no directory.
func NewQemuBackend(cfg Config, logger *slog.Logger) *QemuBackend {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.withDefaults()

	accel, err := selectAccel(runtime.GOOS, os.Stat)
	if err != nil {
		logger.Warn("qemu: accelerator selection fell back to software emulation (tcg) — VMs will be slow",
			"goos", runtime.GOOS, "err", err)
		accel = "tcg"
	}
	if accel == "tcg" {
		logger.Warn("qemu: using tcg software emulation — no hardware acceleration available; VMs will be SLOW",
			"goos", runtime.GOOS)
	}

	// Resolve the base image to an absolute path at construction.  qemu-img
	// create -b records the backing path relative to the OVERLAY's directory when
	// given a relative path, which would make real VMs fail to find their base
	// disk.  An empty base image (QEMU unavailable) is left empty.
	baseImage := cfg.BaseImage
	if baseImage != "" {
		if abs, err := filepath.Abs(baseImage); err == nil {
			baseImage = abs
		} else {
			logger.Warn("qemu: could not resolve base image to absolute path; using as-is",
				"base_image", baseImage, "err", err)
		}
	}

	return &QemuBackend{
		cfg:         cfg,
		baseImage:   baseImage,
		stateDir:    cfg.StateDir,
		accel:       accel,
		r:           execRunner{},
		qmpDialer:   realQMPDialer{},
		vsockDialer: realVsockDialer{},
		cidByID:     map[string]uint32{},
		idByCID:     map[uint32]string{},
		log:         logger,
	}
}

// newQemuBackendWithRunner is the constructor used by tests to inject a mock
// runner, fake QMP dialer, and fake vsock dialer.  Any of the injectables may be
// nil, in which case the real implementation is used.
func newQemuBackendWithRunner(r runner, logger *slog.Logger) *QemuBackend {
	if logger == nil {
		logger = slog.Default()
	}
	accel, err := selectAccel(runtime.GOOS, os.Stat)
	if err != nil {
		accel = "tcg"
	}
	return &QemuBackend{
		cfg:         Config{}.withDefaults(),
		stateDir:    filepath.Join(os.TempDir(), "qemu-test"),
		accel:       accel,
		r:           r,
		qmpDialer:   realQMPDialer{},
		vsockDialer: realVsockDialer{},
		cidByID:     map[string]uint32{},
		idByCID:     map[uint32]string{},
		log:         logger,
	}
}

// selectAccel picks the QEMU accelerator for the host OS.  It is pure (takes
// goos + a stat func) so the arg vector can be unit-tested for every platform.
//
//	linux  → "kvm"  if /dev/kvm exists, else "tcg"
//	darwin → "hvf"
//	windows→ "whpx"
//	other  → "tcg"
func selectAccel(goos string, stat func(string) (os.FileInfo, error)) (string, error) {
	switch goos {
	case "linux":
		if stat == nil {
			stat = os.Stat
		}
		if _, err := stat("/dev/kvm"); err == nil {
			return "kvm", nil
		}
		return "tcg", fmt.Errorf("/dev/kvm not present")
	case "darwin":
		return "hvf", nil
	case "windows":
		return "whpx", nil
	default:
		return "tcg", fmt.Errorf("no hardware accelerator known for GOOS=%s", goos)
	}
}

// guestCID derives a stable virtio-vsock guest context ID from the sandbox id.
// The result is always >= firstGuestCID and avoids the reserved low CIDs.
func guestCID(id string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	// Keep CIDs in a sane range [3, 2^31) to avoid the reserved space and any
	// platform quirks with very large CIDs.
	return firstGuestCID + (h.Sum32() % (1 << 31))
}

// allocateCID returns a guest CID for id, avoiding collisions with other live
// sandboxes.  It starts from the hashed candidate and linear-probes upward to the
// next free CID (>= firstGuestCID) when the candidate is already taken by a
// DIFFERENT id.  The chosen CID is recorded in the in-memory maps and persisted
// to <sandboxDir>/cid so it survives within the process and can be reloaded.
func (b *QemuBackend) allocateCID(id string) uint32 {
	b.cidMu.Lock()
	defer b.cidMu.Unlock()

	if cid, ok := b.cidByID[id]; ok {
		return cid
	}

	cid := guestCID(id)
	for {
		owner, taken := b.idByCID[cid]
		if !taken || owner == id {
			break
		}
		// Probe to the next CID, wrapping back to firstGuestCID on overflow.
		if cid == ^uint32(0) {
			cid = firstGuestCID
		} else {
			cid++
		}
		if cid < firstGuestCID {
			cid = firstGuestCID
		}
	}
	b.cidByID[id] = cid
	b.idByCID[cid] = id
	return cid
}

// cidFor returns the CID for id, preferring (in order) the in-memory allocation,
// the persisted cid file, then a fresh allocation.  Used by methods that may run
// after Create (Inspect/Exec/etc.) without a prior allocateCID this process.
func (b *QemuBackend) cidFor(id string) uint32 {
	b.cidMu.Lock()
	if cid, ok := b.cidByID[id]; ok {
		b.cidMu.Unlock()
		return cid
	}
	b.cidMu.Unlock()

	if data, err := os.ReadFile(b.cidFilePath(id)); err == nil {
		if n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); perr == nil && uint32(n) >= firstGuestCID {
			cid := uint32(n)
			b.cidMu.Lock()
			b.cidByID[id] = cid
			b.idByCID[cid] = id
			b.cidMu.Unlock()
			return cid
		}
	}
	return b.allocateCID(id)
}

// freeCID releases the CID allocation for id (called on Purge).
func (b *QemuBackend) freeCID(id string) {
	b.cidMu.Lock()
	defer b.cidMu.Unlock()
	if cid, ok := b.cidByID[id]; ok {
		delete(b.idByCID, cid)
		delete(b.cidByID, id)
	}
}

// sandboxDir returns the per-sandbox state directory.
func (b *QemuBackend) sandboxDir(id string) string {
	return filepath.Join(b.stateDir, id)
}

func (b *QemuBackend) cidFilePath(id string) string {
	return filepath.Join(b.sandboxDir(id), "cid")
}

func (b *QemuBackend) overlayPath(id string) string {
	return filepath.Join(b.sandboxDir(id), "overlay.qcow2")
}
func (b *QemuBackend) qmpSockPath(id string) string {
	return filepath.Join(b.sandboxDir(id), "qmp.sock")
}
func (b *QemuBackend) pidfilePath(id string) string {
	return filepath.Join(b.sandboxDir(id), "qemu.pid")
}

// run wraps the runner, mapping a missing qemu binary to ErrQemuUnavailable.
func (b *QemuBackend) run(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
	stdout, stderr, err := b.r.Run(ctx, args, stdin, nil)
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) && execErr.Err == exec.ErrNotFound {
			return nil, nil, fmt.Errorf("%w: %v", ErrQemuUnavailable, execErr.Err)
		}
		// Exit error — return a CommandError that keeps the *exec.ExitError in
		// the chain and carries stderr in Detail rather than in the error
		// string; see CommandError for why stderr is withheld from logs.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			sub := ""
			if len(args) > 1 {
				sub = args[1]
			}
			return stdout, stderr, &CommandError{
				Tool:       args[0],
				Subcommand: sub,
				ExitCode:   exitErr.ExitCode(),
				Stderr:     strings.TrimSpace(string(stderr)),
				Err:        exitErr,
			}
		}
		return stdout, stderr, fmt.Errorf("qemu %s: %w", args[0], err)
	}
	return stdout, stderr, nil
}

// Create implements Backend.Create.
//
// It requires a configured base image (else ErrQemuUnavailable), creates a
// per-sandbox copy-on-write overlay, then launches a daemonized qemu-system
// process with a QMP control socket and a virtio-vsock device for the
// out-of-band control bridge.
func (b *QemuBackend) Create(ctx context.Context, spec Spec) (Handle, error) {
	if b.baseImage == "" {
		return Handle{}, fmt.Errorf("%w: Config.BaseImage is not set", ErrQemuUnavailable)
	}

	id := spec.Name
	if err := validID(id); err != nil {
		return Handle{}, err
	}

	// A VM runs whatever its disk image boots, and file transfer needs the
	// in-guest bridge, which only exists after boot.  Both are the opposite of
	// what these fields promise, so fail loudly rather than hand back a VM
	// that silently ran the wrong thing or lacks a file it was promised.
	if len(spec.Command) > 0 {
		return Handle{}, fmt.Errorf("qemu create %s: Spec.Command: %w", id, ErrSpecUnsupported)
	}
	if len(spec.Files) > 0 {
		return Handle{}, fmt.Errorf("qemu create %s: Spec.Files: %w", id, ErrSpecUnsupported)
	}

	// Resolve the base image to an absolute path so qemu-img records an absolute
	// backing reference (a relative -b is recorded relative to the overlay's dir,
	// which would break boots).  Reject a comma — it is the qemu-img/qemu option
	// separator and would inject into the create/-drive option strings.
	baseImage, err := filepath.Abs(b.baseImage)
	if err != nil {
		return Handle{}, fmt.Errorf("qemu create: resolve base image %q: %w", b.baseImage, err)
	}
	if strings.ContainsRune(baseImage, ',') {
		return Handle{}, fmt.Errorf("qemu create: base image path %q contains a comma (qemu option separator)", baseImage)
	}

	dir := b.sandboxDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Handle{}, fmt.Errorf("qemu create: state dir: %w", err)
	}

	// On any failure after the state dir is created, remove it so a failed launch
	// does not leak the overlay/state dir.  Cleared once Create succeeds.
	success := false
	defer func() {
		if !success {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				b.log.Warn("qemu create: failed to clean up state dir after error",
					"sandbox", id, "dir", dir, "err", rmErr)
			}
			b.freeCID(id)
		}
	}()

	overlay := b.overlayPath(id)

	// Create the copy-on-write overlay backed by the (absolute) base image.
	imgArgs := []string{
		b.cfg.QemuImgBinary, "create",
		"-f", "qcow2",
		"-F", "qcow2",
		"-b", baseImage,
		overlay,
	}
	if _, _, err := b.run(ctx, imgArgs, nil); err != nil {
		return Handle{}, fmt.Errorf("qemu create overlay: %w", err)
	}

	cid := b.allocateCID(id)
	// Persist the chosen CID so Inspect/Exec can recover it after restart.
	if werr := os.WriteFile(b.cidFilePath(id), []byte(strconv.FormatUint(uint64(cid), 10)), 0o644); werr != nil {
		b.log.Warn("qemu create: failed to persist cid file", "sandbox", id, "err", werr)
	}
	args := b.buildQemuArgs(spec, id, overlay, cid)

	b.log.Debug("qemu: launching VM",
		"sandbox", id, "accel", b.accel, "cid", cid, "overlay", overlay)

	// qemu daemonizes via -daemonize; the launch call returns once the process
	// has detached and written its pidfile.
	if _, _, err := b.run(ctx, args, nil); err != nil {
		return Handle{}, fmt.Errorf("qemu create launch: %w", err)
	}

	b.log.Info("qemu: VM created", "sandbox", id, "cid", cid)

	success = true
	return Handle{
		ID:          id,
		ContainerID: fmt.Sprintf("vsock-cid:%d", cid),
		Endpoints:   map[string]string{},
	}, nil
}

// buildQemuArgs constructs the full qemu-system argument vector (args[0] is the
// binary).  Kept separate so tests can assert the vector without launching.
func (b *QemuBackend) buildQemuArgs(spec Spec, id, overlay string, cid uint32) []string {
	mem := spec.MemoryMB
	if mem <= 0 {
		mem = 2048
	}
	cpus := int(spec.CPUs)
	if cpus <= 0 {
		cpus = 2
	}

	args := []string{
		b.cfg.QemuBinary,
		"-machine", "accel=" + b.accel,
		"-m", strconv.Itoa(mem),
		"-smp", strconv.Itoa(cpus),
		"-drive", "file=" + overlay + ",if=virtio",
		// QMP control plane on a unix socket.
		"-qmp", "unix:" + b.qmpSockPath(id) + ",server,nowait",
		// virtio-vsock: out-of-band host↔guest control transport.
		"-device", fmt.Sprintf("vhost-vsock-pci,guest-cid=%d", cid),
		// Headless v1: no GUI; desktop/web endpoints are a follow-up.
		"-display", "none",
		// Daemonize so the launch call returns; pidfile lets Inspect/Purge find it.
		"-pidfile", b.pidfilePath(id),
		"-daemonize",
	}

	// Networking.  NetworkPolicyNone → no NIC at all.  Otherwise a user-mode NIC.
	//
	// NOTE: full egress nft-enforcement parity with PodmanBackend is a follow-up.
	// The VM's control plane is vsock (out-of-band from the NIC), so the guest NIC
	// can be locked down later (host-applied egress in the guest netns, or a
	// restricted -netdev) without touching the control path.
	switch effectivePolicy(spec.NetworkPolicy) {
	case NetworkPolicyNone:
		args = append(args, "-nic", "none")
	default:
		args = append(args, "-nic", "user")
	}

	return args
}

// Start implements Backend.Start.  For a stopped VM (qemu process gone), it
// relaunches from the existing overlay.  If the QMP socket answers, the VM is
// already running and Start is a no-op.
func (b *QemuBackend) Start(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	if b.vmRunning(ctx, id) {
		return nil
	}
	overlay := b.overlayPath(id)
	if _, err := os.Stat(overlay); err != nil {
		return fmt.Errorf("qemu start %s: %w", id, ErrSandboxNotFound)
	}
	// Relaunch with a minimal spec; resource limits are re-derived from defaults
	// because the backend keeps no stored Spec (mirrors PodmanBackend.Restore).
	args := b.buildQemuArgs(Spec{Name: id}, id, overlay, b.cidFor(id))
	if _, _, err := b.run(ctx, args, nil); err != nil {
		return fmt.Errorf("qemu start %s: %w", id, err)
	}
	return nil
}

// stopPollInterval and stopGraceTimeout bound how long Stop waits for an ACPI
// powerdown to take effect before escalating to a hard QMP quit.
const (
	stopPollInterval = 200 * time.Millisecond
	stopGraceTimeout = 3 * time.Second
)

// Stop implements Backend.Stop.  Best-effort-graceful: it asks the guest to power
// down via QMP system_powerdown (async ACPI), then polls query-status for up to
// stopGraceTimeout; if the VM is still running it escalates to a hard QMP quit so
// callers do not leave a VM running.  If QMP is
// unreachable the VM is treated as already stopped.
func (b *QemuBackend) Stop(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	conn, err := b.qmpDialer.Dial(ctx, b.qmpSockPath(id))
	if err != nil {
		b.log.Debug("qemu stop: QMP unreachable (may be already stopped)", "id", id, "err", err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.command("system_powerdown", nil); err != nil {
		// Powerdown command itself failed: go straight to a hard quit.
		b.log.Debug("qemu stop: system_powerdown failed, falling back to quit", "id", id, "err", err)
		_, _ = conn.command("quit", nil)
		return nil
	}

	// system_powerdown is async ACPI; poll until the VM stops or we give up.
	deadline := time.Now().Add(stopGraceTimeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		if !b.qmpReportsRunning(conn) {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(stopPollInterval):
		}
	}

	// Still running after the grace period: escalate to a hard quit.
	b.log.Debug("qemu stop: powerdown did not stop VM in time, escalating to quit", "id", id)
	_, _ = conn.command("quit", nil)
	return nil
}

// qmpReportsRunning queries VM status over an existing QMP conn.  A query-status
// error (e.g. the monitor closed because the VM exited) is treated as "not
// running".  An unparseable-but-successful reply is treated as running.
func (b *QemuBackend) qmpReportsRunning(conn qmpConn) bool {
	raw, err := conn.command("query-status", nil)
	if err != nil {
		return false
	}
	var qs struct {
		Return struct {
			Running bool `json:"running"`
		} `json:"return"`
	}
	if json.Unmarshal(raw, &qs) != nil {
		return true
	}
	return qs.Return.Running
}

// Recreate implements Backend.Recreate.  The qemu process is replaced with one
// launched from spec's resource settings; the per-sandbox overlay disk — where
// the sandbox's data lives — is preserved, and no path through this method
// removes the state directory.
//
// The disk cannot change here: an overlay is bound to the base image it was
// created from, so a non-empty spec.Image is rejected with ErrSpecUnsupported.
// Moving to a new base disk means Purge then Create, which deletes the data —
// a decision this method refuses to make implicitly.
func (b *QemuBackend) Recreate(ctx context.Context, spec Spec) (Handle, error) {
	id := spec.Name
	if err := validID(id); err != nil {
		return Handle{}, err
	}
	if len(spec.Command) > 0 {
		return Handle{}, fmt.Errorf("qemu recreate %s: Spec.Command: %w", id, ErrSpecUnsupported)
	}
	if len(spec.Files) > 0 {
		return Handle{}, fmt.Errorf("qemu recreate %s: Spec.Files: %w", id, ErrSpecUnsupported)
	}
	if spec.Image != "" {
		return Handle{}, fmt.Errorf("qemu recreate %s: Spec.Image: %w (an overlay is bound to its base image; a new disk requires Purge and Create, which deletes the data)", id, ErrSpecUnsupported)
	}
	overlay := b.overlayPath(id)
	if _, err := os.Stat(overlay); err != nil {
		return Handle{}, fmt.Errorf("qemu recreate %s: %w", id, ErrSandboxNotFound)
	}

	// Stop the running VM (tolerates already-stopped) and confirm it is down
	// before relaunching against the same overlay: two qemu processes writing
	// one overlay corrupt it.
	if err := b.Stop(ctx, id); err != nil {
		return Handle{}, fmt.Errorf("qemu recreate %s: stop: %w", id, err)
	}
	if b.vmRunning(ctx, id) {
		return Handle{}, fmt.Errorf("qemu recreate %s: VM still running after stop; refusing to launch a second process against the same overlay", id)
	}

	args := b.buildQemuArgs(spec, id, overlay, b.cidFor(id))
	if _, _, err := b.run(ctx, args, nil); err != nil {
		return Handle{}, fmt.Errorf("qemu recreate %s: relaunch: %w", id, err)
	}
	b.log.Info("qemu: VM recreated (overlay preserved)", "sandbox", id)
	return b.refreshedHandle(id), nil
}

// Purge implements Backend.Purge (named Destroy before v0.5.0).  Best-effort
// QMP quit, then removes the per-sandbox state directory — overlay, sockets,
// pidfile.  The overlay is where a QEMU sandbox's data lives, so this is the
// data-deleting operation; nothing else in this backend removes it.  A missing
// VM or directory is tolerated.
func (b *QemuBackend) Purge(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	if conn, err := b.qmpDialer.Dial(ctx, b.qmpSockPath(id)); err == nil {
		_, _ = conn.command("quit", nil)
		conn.Close()
	} else {
		b.log.Debug("qemu purge: QMP unreachable (may be already stopped)", "id", id, "err", err)
	}

	if err := os.RemoveAll(b.sandboxDir(id)); err != nil {
		return fmt.Errorf("qemu purge %s: remove state: %w", id, err)
	}
	b.freeCID(id)
	b.log.Info("qemu: VM purged (state directory and overlay removed)", "sandbox", id)
	return nil
}

// Exec implements Backend.Exec by sending a JSON-RPC "exec" request to the
// in-guest bridge over virtio-vsock.  When no guest bridge is reachable it
// returns ErrQemuGuestUnavailable (a built guest image is a follow-up).
func (b *QemuBackend) Exec(ctx context.Context, id string, cmd []string, opts ExecOpts) (ExecResult, error) {
	req := bridgeRequest{
		Op:      "exec",
		Cmd:     cmd,
		WorkDir: opts.WorkDir,
		Env:     opts.Env,
		User:    opts.RunAs,
		Timeout: opts.TimeoutSec,
	}
	resp, err := b.bridgeRoundTrip(ctx, id, req)
	if err != nil {
		return ExecResult{}, err
	}
	if resp.Error != "" {
		return ExecResult{}, fmt.Errorf("qemu exec %s: guest bridge: %s", id, resp.Error)
	}
	return ExecResult{
		ExitCode: resp.ExitCode,
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
	}, nil
}

// ExecStream implements Backend.ExecStream.  v1 runs the command via the
// non-streaming bridge round-trip and returns the collected stdout as a reader.
// True duplex streaming over vsock is a follow-up.
func (b *QemuBackend) ExecStream(ctx context.Context, id string, cmd []string, opts ExecOpts) (io.ReadCloser, error) {
	res, err := b.Exec(ctx, id, cmd, opts)
	if err != nil {
		return nil, err
	}
	combined := append(append([]byte{}, res.Stdout...), res.Stderr...)
	return io.NopCloser(bytes.NewReader(combined)), nil
}

// WriteFile implements Backend.WriteFile over the guest bridge.
func (b *QemuBackend) WriteFile(ctx context.Context, id string, path string, data []byte) error {
	req := bridgeRequest{Op: "writefile", Path: path, Data: data}
	resp, err := b.bridgeRoundTrip(ctx, id, req)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("qemu write-file %s: guest bridge: %s", path, resp.Error)
	}
	return nil
}

// ReadFile implements Backend.ReadFile over the guest bridge.
func (b *QemuBackend) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	req := bridgeRequest{Op: "readfile", Path: path}
	resp, err := b.bridgeRoundTrip(ctx, id, req)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("qemu read-file %s: guest bridge: %s", path, resp.Error)
	}
	return resp.Data, nil
}

// Snapshot implements Backend.Snapshot.  For a running VM it uses the QMP human
// monitor `savevm <tag>` (captures CPU/RAM + disk state).  If the VM is not
// running it falls back to `qemu-img snapshot -c <tag> <overlay>` on the disk.
func (b *QemuBackend) Snapshot(ctx context.Context, id string, label string) (SnapshotRef, error) {
	if err := validID(id); err != nil {
		return SnapshotRef{}, err
	}
	if label == "" {
		label = fmt.Sprintf("snap-%d", time.Now().UnixNano())
	}
	tag := snapshotTag(label)
	ref := SnapshotRef{Ref: fmt.Sprintf("qemu:%s:%s", id, tag), Label: label}

	conn, err := b.qmpDialer.Dial(ctx, b.qmpSockPath(id))
	if err == nil {
		defer conn.Close()
		// Use the human-monitor passthrough for savevm (no native QMP command).
		_, herr := conn.command("human-monitor-command", map[string]any{
			"command-line": "savevm " + tag,
		})
		if herr == nil {
			b.log.Info("qemu: snapshot created (live)", "sandbox", id, "ref", ref.Ref)
			return ref, nil
		}
		// A live savevm failed.  Running `qemu-img snapshot -c` against an overlay
		// that a live VM still has open risks image corruption, so only fall through
		// to the offline path when the VM is confirmed NOT running.
		if b.vmRunning(ctx, id) {
			return SnapshotRef{}, fmt.Errorf("qemu snapshot %s: live savevm failed on a running VM: %w", id, herr)
		}
		b.log.Debug("qemu snapshot: live savevm failed and VM not running, using offline qemu-img", "id", id, "err", herr)
	}

	// Offline path on the disk overlay (VM not running).
	if _, _, err := b.run(ctx, []string{b.cfg.QemuImgBinary, "snapshot", "-c", tag, b.overlayPath(id)}, nil); err != nil {
		return SnapshotRef{}, fmt.Errorf("qemu snapshot %s: %w", id, err)
	}
	b.log.Info("qemu: snapshot created (offline)", "sandbox", id, "ref", ref.Ref)
	return ref, nil
}

// RemoveSnapshot implements Backend.RemoveSnapshot.  It deletes the named qcow2
// internal snapshot from the overlay best-effort; a missing snapshot is not an
// error.
func (b *QemuBackend) RemoveSnapshot(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	id, tag, ok := parseSnapshotRef(ref)
	if !ok {
		return fmt.Errorf("qemu remove-snapshot: malformed ref %q", ref)
	}
	if _, _, err := b.run(ctx, []string{b.cfg.QemuImgBinary, "snapshot", "-d", tag, b.overlayPath(id)}, nil); err != nil {
		if isQemuSnapshotMissing(err) {
			b.log.Debug("qemu remove-snapshot: snapshot not found", "ref", ref, "err", err)
			return nil
		}
		return fmt.Errorf("qemu remove-snapshot %s: %w", ref, err)
	}
	b.log.Info("qemu: snapshot removed", "ref", ref)
	return nil
}

// Restore implements Backend.Restore.  For a running VM it uses QMP human
// monitor `loadvm <tag>`.  If QMP is unreachable it stops, applies the disk
// snapshot offline (`qemu-img snapshot -a`), and relaunches.  Returns a
// refreshed Handle.
func (b *QemuBackend) Restore(ctx context.Context, id string, ref SnapshotRef) (Handle, error) {
	if err := validID(id); err != nil {
		return Handle{}, err
	}
	refID, tag, ok := parseSnapshotRef(ref.Ref)
	if !ok {
		return Handle{}, fmt.Errorf("qemu restore: malformed ref %q", ref.Ref)
	}
	// The ref embeds the id of the sandbox it was taken from; applying it to a
	// different overlay would corrupt the wrong VM.  Reject a mismatch.
	if refID != id {
		return Handle{}, fmt.Errorf("qemu restore: ref %q belongs to sandbox %q, not %q", ref.Ref, refID, id)
	}

	conn, err := b.qmpDialer.Dial(ctx, b.qmpSockPath(id))
	if err == nil {
		defer conn.Close()
		if _, lerr := conn.command("human-monitor-command", map[string]any{
			"command-line": "loadvm " + tag,
		}); lerr == nil {
			b.log.Info("qemu: restored from snapshot (live)", "sandbox", id, "ref", ref.Ref)
			return b.refreshedHandle(id), nil
		} else {
			// A live loadvm failed.  Applying `qemu-img snapshot -a` to an overlay
			// a running VM still has open risks corruption: only take the offline
			// path after confirming the VM is stopped (Stop below escalates to quit).
			b.log.Debug("qemu restore: live loadvm failed, falling back to offline", "id", id, "err", lerr)
		}
	}

	// Offline path: ensure VM is down, confirm it, apply snapshot to disk, relaunch.
	_ = b.Stop(ctx, id)
	if b.vmRunning(ctx, id) {
		return Handle{}, fmt.Errorf("qemu restore %s: VM still running after stop; refusing offline qemu-img snapshot -a to avoid overlay corruption", id)
	}
	if _, _, err := b.run(ctx, []string{b.cfg.QemuImgBinary, "snapshot", "-a", tag, b.overlayPath(id)}, nil); err != nil {
		return Handle{}, fmt.Errorf("qemu restore %s: apply snapshot: %w", id, err)
	}
	if err := b.Start(ctx, id); err != nil {
		return Handle{}, fmt.Errorf("qemu restore %s: relaunch: %w", id, err)
	}
	b.log.Info("qemu: restored from snapshot (offline)", "sandbox", id, "ref", ref.Ref)
	return b.refreshedHandle(id), nil
}

func (b *QemuBackend) refreshedHandle(id string) Handle {
	return Handle{
		ID:          id,
		ContainerID: fmt.Sprintf("vsock-cid:%d", b.cidFor(id)),
		Endpoints:   map[string]string{},
	}
}

// Inspect implements Backend.Inspect.  It reports Running by querying VM status
// over QMP; if QMP is unreachable it falls back to the pidfile presence.
func (b *QemuBackend) Inspect(ctx context.Context, id string) (Status, error) {
	if err := validID(id); err != nil {
		return Status{}, err
	}
	// Existence: the per-sandbox dir must be present.
	if _, err := os.Stat(b.sandboxDir(id)); err != nil {
		return Status{}, fmt.Errorf("qemu inspect %s: %w", id, ErrSandboxNotFound)
	}

	running := b.vmRunning(ctx, id)
	return Status{
		Running:   running,
		Endpoints: map[string]string{},
	}, nil
}

// vmRunning reports whether the VM answers QMP query-status; if QMP cannot be
// dialed it falls back to checking the pidfile.
func (b *QemuBackend) vmRunning(ctx context.Context, id string) bool {
	conn, err := b.qmpDialer.Dial(ctx, b.qmpSockPath(id))
	if err == nil {
		defer conn.Close()
		if raw, qerr := conn.command("query-status", nil); qerr == nil {
			var qs struct {
				Return struct {
					Running bool `json:"running"`
				} `json:"return"`
			}
			if json.Unmarshal(raw, &qs) == nil {
				return qs.Return.Running
			}
			// QMP answered but we couldn't parse — treat as running.
			return true
		}
	}
	// Fallback: pidfile present and the process is alive.
	return pidfileAlive(b.pidfilePath(id))
}

// DesktopEndpoint implements Backend.DesktopEndpoint.  v1 VMs are headless;
// desktop streaming is a follow-up.
func (b *QemuBackend) DesktopEndpoint(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("qemu desktop endpoint: headless VM (v1); %w", ErrWrongProfile)
}

// WebEndpoint implements Backend.WebEndpoint.  v1 VMs are headless; web
// reverse-proxying is a follow-up.
func (b *QemuBackend) WebEndpoint(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("qemu web endpoint: headless VM (v1); %w", ErrWrongProfile)
}

// ContainerAddr implements Backend.ContainerAddr.  QEMU VMs have no host-routable
// bridge IP (the control plane is out-of-band over vsock), so on-demand port
// preview is unsupported for LevelIsolated sandboxes.
func (b *QemuBackend) ContainerAddr(_ context.Context, _ string, _ int) (string, error) {
	return "", fmt.Errorf("qemu container addr: not supported for isolated VMs; %w", ErrWrongProfile)
}

// ---- guest bridge protocol -------------------------------------------------

// bridgeRequest is the host→guest JSON-RPC envelope for the control bridge.
type bridgeRequest struct {
	Op      string            `json:"op"`            // "exec" | "readfile" | "writefile"
	Cmd     []string          `json:"cmd,omitempty"` // exec
	WorkDir string            `json:"workdir,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	User    string            `json:"user,omitempty"`
	Timeout int               `json:"timeout,omitempty"`
	Path    string            `json:"path,omitempty"` // readfile/writefile
	Data    []byte            `json:"data,omitempty"` // writefile (base64 via encoding/json)
}

// bridgeResponse is the guest→host JSON-RPC reply.
type bridgeResponse struct {
	ExitCode int    `json:"exitCode"`
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
	Data     []byte `json:"data,omitempty"` // readfile
	Error    string `json:"error,omitempty"`
}

// bridgeRoundTrip dials the in-guest bridge over vsock, sends one JSON request
// (newline-delimited), and reads one JSON response.  A dial failure is mapped to
// ErrQemuGuestUnavailable.
// bridgeDefaultTimeout bounds a bridge round-trip when neither the ctx nor the
// request carries a deadline, so a misbehaving / half-dead VM cannot hang the
// host indefinitely on the io.ReadAll below.
const bridgeDefaultTimeout = 60 * time.Second

func (b *QemuBackend) bridgeRoundTrip(ctx context.Context, id string, req bridgeRequest) (bridgeResponse, error) {
	if err := validID(id); err != nil {
		return bridgeResponse{}, err
	}
	conn, err := b.vsockDialer.Dial(ctx, b.cidFor(id), guestBridgePort)
	if err != nil {
		return bridgeResponse{}, fmt.Errorf("%w: %v", ErrQemuGuestUnavailable, err)
	}
	defer conn.Close()

	// Derive a deadline from (in priority order) the ctx deadline, the request's
	// own timeout, then bridgeDefaultTimeout, and apply it so reads/writes cannot
	// block forever on a misbehaving guest.
	deadline := time.Now().Add(bridgeDefaultTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	} else if req.Timeout > 0 {
		if t := time.Now().Add(time.Duration(req.Timeout) * time.Second); t.Before(deadline) {
			deadline = t
		}
	}
	if err := conn.SetDeadline(deadline); err != nil {
		b.log.Debug("qemu bridge: SetDeadline failed (continuing without)", "id", id, "err", err)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return bridgeResponse{}, fmt.Errorf("qemu bridge: marshal request: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := conn.Write(payload); err != nil {
		return bridgeResponse{}, fmt.Errorf("%w: write: %v", ErrQemuGuestUnavailable, err)
	}

	// Honor ctx cancellation: a goroutine closes the conn if ctx is done before
	// the read returns, unblocking io.ReadAll.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	raw, err := io.ReadAll(conn)
	if err != nil {
		return bridgeResponse{}, fmt.Errorf("%w: read: %v", ErrQemuGuestUnavailable, err)
	}
	var resp bridgeResponse
	if err := json.Unmarshal(bytes.TrimSpace(raw), &resp); err != nil {
		return bridgeResponse{}, fmt.Errorf("qemu bridge: parse response: %w", err)
	}
	return resp, nil
}

// ---- snapshot ref helpers --------------------------------------------------

// snapshotTag sanitizes a label into a qcow2-safe internal snapshot tag.  Any
// character outside [A-Za-z0-9_-] is replaced with '_', which neutralizes the
// qemu option separator (','), path separators ('/', '\\'), the ref separator
// (':'), whitespace, and '.' (so a ".." traversal cannot survive).  An empty
// result falls back to "snap".
func snapshotTag(label string) string {
	var b strings.Builder
	for _, r := range label {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "snap"
	}
	return out
}

// parseSnapshotRef decodes a "qemu:<id>:<tag>" ref.  The id may itself contain
// no colons (sandbox ids are colon-free); tag takes the remainder.
func parseSnapshotRef(ref string) (id, tag string, ok bool) {
	const prefix = "qemu:"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", false
	}
	rest := ref[len(prefix):]
	idx := strings.IndexByte(rest, ':')
	if idx < 0 {
		return "", "", false
	}
	return rest[:idx], rest[idx+1:], true
}

// isQemuSnapshotMissing reports whether a qemu-img error indicates the named
// snapshot simply does not exist.
func isQemuSnapshotMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := errText(err)
	return strings.Contains(msg, "can't find snapshot") ||
		strings.Contains(msg, "snapshot not found") ||
		strings.Contains(msg, "no such snapshot") ||
		strings.Contains(msg, "could not delete snapshot")
}

// pidfileAlive reports whether the pidfile exists and names a live process.
func pidfileAlive(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return false
	}
	return processAlive(pid)
}
