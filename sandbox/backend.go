// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// SandboxLevel describes the isolation level of a sandbox.
type SandboxLevel string

const (
	// LevelFast uses Podman containers: shared kernel, separate namespaces.
	LevelFast SandboxLevel = "fast"
	// LevelIsolated uses a QEMU VM for full kernel isolation.
	LevelIsolated SandboxLevel = "isolated"
)

// NetworkPolicy controls the egress firewall applied to a sandbox.
type NetworkPolicy string

const (
	// NetworkPolicyNone disables all networking interfaces in the container.
	// Use for pure compute sandboxes where the host drives everything.
	NetworkPolicyNone NetworkPolicy = "none"

	// NetworkPolicyInternalOnly is the default policy.  The sandbox can reach
	// the host (host.containers.internal / host-gateway) for services the host
	// exposes to it, DNS resolvers reachable through that gateway, and
	// loopback.  All other egress is blocked.
	NetworkPolicyInternalOnly NetworkPolicy = "internal-only"

	// NetworkPolicyFiltered extends internal-only with a host-side HTTP/HTTPS
	// forward proxy that enforces the AllowDomains list.  The container is given
	// HTTP_PROXY / HTTPS_PROXY pointing at that proxy.
	NetworkPolicyFiltered NetworkPolicy = "filtered"

	// NetworkPolicyOpen places no egress restrictions.  Flagged as risky; the
	// Spec field must be set explicitly — an empty NetworkPolicy is NOT treated
	// as open (it defaults to internal-only).
	NetworkPolicyOpen NetworkPolicy = "open"
)

// Profile shapes how the sandbox image is started.
type Profile string

const (
	// ProfileDesktop expects the image to start a graphical stack behind noVNC
	// on port 6080; the caller typically reverse-proxies that WebSocket to a
	// browser.
	ProfileDesktop Profile = "desktop"
	// ProfileWeb does not start a desktop stack; the workload serves HTTP on
	// ServePort and the caller proxies that to a browser.
	ProfileWeb Profile = "web"
	// ProfileHeadless starts no GUI and exposes no port; pure shell/batch use.
	ProfileHeadless Profile = "headless"
)

// Spec is the complete description of a sandbox to be created.
// All backend implementations derive their resource limits and networking
// configuration from this struct.
type Spec struct {
	// Name identifies the sandbox.  It must match [A-Za-z0-9_-]+, because it
	// becomes the container or VM name, the work volume name, a container
	// label, and a directory name.  It is the value passed back to every other
	// Backend method as id.
	//
	// The caller chooses it and the caller alone knows what it refers to; this
	// package attaches no ownership or tenancy meaning to it.
	Name string

	// Image is the fully-qualified OCI image reference.  Empty means the
	// backend's configured default (Config.Image); if that is empty too,
	// Create fails.
	Image string

	// Level selects the isolation runtime: LevelFast for PodmanBackend,
	// LevelIsolated for QemuBackend.  Each backend implements one level and
	// ignores this field.
	Level SandboxLevel

	// Profile shapes the entrypoint behaviour inside the container.
	Profile Profile

	// CPUs is the number of vCPU cores to assign.  0 means no limit.
	CPUs float64

	// MemoryMB is the memory cap in mebibytes.  0 means no limit.
	MemoryMB int

	// DiskGB is the maximum ephemeral overlay size in gibibytes.  0 means
	// unbounded (relies on the host's free space).
	// NOTE: Podman named-volume size limits require a storage driver that
	// supports quotas; enforcement is best-effort.
	DiskGB int

	// Env is a set of extra environment variables injected into the container
	// at creation time.
	Env map[string]string

	// Command overrides the arguments the image's entrypoint receives (in OCI
	// terms it replaces the image's CMD; the ENTRYPOINT still runs).  Empty
	// means the image decides, which is the behaviour before this field
	// existed.
	//
	// Each element is delivered to the runtime as exactly one argv entry with
	// no shell anywhere on the path: spaces, quotes, equals signs and non-ASCII
	// text arrive byte-identical, and no element can split into two arguments.
	//
	// Supported by PodmanBackend.  QemuBackend rejects a non-empty Command with
	// ErrSpecUnsupported: a VM runs whatever its disk image boots.
	Command []string

	// Files are provisioned into the sandbox filesystem at create time, before
	// the workload's entrypoint starts, so the process never observes a moment
	// in which an expected file is missing (WriteFile, by contrast, acts on a
	// sandbox that is already running).  See File for path and mode rules.
	//
	// Supported by PodmanBackend.  QemuBackend rejects non-empty Files with
	// ErrSpecUnsupported: its file transport is the in-guest bridge, which only
	// exists once the VM has booted.
	Files []File

	// ServePort is the in-container TCP port that the workload's web server
	// listens on (Profile=web only).  The backend picks a random host port
	// and records it in Handle.Endpoints["web"].
	ServePort int

	// NetworkPolicy controls the egress firewall applied to this sandbox.
	// Empty string is treated as NetworkPolicyInternalOnly (default-deny
	// external egress; the host gateway and DNS through it stay reachable).
	//
	// NetworkPolicyNone         → --network none (no NIC at all)
	// NetworkPolicyInternalOnly → default; host-applied nftables drop-external
	// NetworkPolicyFiltered     → internal + host egress proxy for AllowDomains
	// NetworkPolicyOpen         → no restrictions (flagged risky, explicit only)
	NetworkPolicy NetworkPolicy

	// AllowDomains is the set of domains the container may reach through the
	// host egress proxy when NetworkPolicy == NetworkPolicyFiltered.
	// Values must be plain hostnames or subdomain-wildcards ("*.example.com").
	// Ignored for all other policies.
	AllowDomains []string

	// EgressProxyAddr is the host:port address of a running HTTP forward proxy
	// supplied by the caller.  Required when
	// NetworkPolicy == NetworkPolicyFiltered; set before calling Create.
	// Example: "127.0.0.1:7070"
	EgressProxyAddr string
}

// File is one file provisioned into a sandbox at create time (Spec.Files).
type File struct {
	// Path is the absolute destination inside the sandbox, for example
	// "/etc/app/config.yaml".  It must be absolute, already clean (no "." or
	// ".." elements, no doubled or trailing slashes), and not "/" itself.
	// Parent directories that do not exist are created by the copy (0755,
	// root-owned); directories that already exist are left alone.
	Path string

	// Data is the file content.
	Data []byte

	// Mode is the file's permission bits inside the sandbox, and it is
	// required: a zero Mode fails Create rather than silently choosing one,
	// because the gap between 0600 and 0644 is the gap between a private
	// credential and a world-readable one.  Only permission bits are allowed;
	// file-type bits (fs.ModeDir and friends) are rejected.
	Mode fs.FileMode

	// UID and GID set the file's owner inside the sandbox, so a workload that
	// runs as a non-root account can be handed a file only it can read.  The
	// zero values mean uid 0 / gid 0 (root).  These are accounts in the guest,
	// not on the host, and mean nothing outside the sandbox.
	UID int
	GID int
}

// Handle is the opaque reference returned after Create.  Callers must store
// the ID (or ContainerID) to drive subsequent operations.
type Handle struct {
	// ID is the sandbox identifier: the Spec.Name it was created from, and the
	// value passed to every other Backend method.
	ID string

	// ContainerID is the OCI runtime's container identifier (podman ID or
	// full hash).  Empty for VM-level sandboxes where the concept differs.
	ContainerID string

	// Endpoints maps logical endpoint names to host URLs.
	//   "desktop" -> "http://127.0.0.1:<hostPort>" (noVNC, profile=desktop)
	//   "web"     -> "http://127.0.0.1:<hostPort>" (workload HTTP, profile=web)
	Endpoints map[string]string
}

// ExecOpts configures optional behaviour for Exec / ExecStream.
type ExecOpts struct {
	// WorkDir is the working directory inside the container.  Empty means
	// the image's default.
	WorkDir string

	// Env overrides or extends the container's environment for this exec.
	Env map[string]string

	// RunAs overrides the OS account the command runs under inside the
	// sandbox (e.g. "agent").  Empty means the image's default.  This is an
	// account in the guest, and has nothing to do with whoever asked for the
	// command to be run.
	RunAs string

	// TimeoutSec, if >0, cancels the exec after this many seconds.
	TimeoutSec int
}

// ExecResult holds the collected output of a completed Exec call.
type ExecResult struct {
	// ExitCode is the process exit status.
	ExitCode int

	// Stdout is the combined standard output.
	Stdout []byte

	// Stderr is the combined standard error.
	Stderr []byte
}

// SnapshotRef is an opaque reference to a persisted sandbox snapshot.
// For Podman, this is an OCI image tag; for QEMU it would be a qcow2
// internal snapshot name.
type SnapshotRef struct {
	// Ref is the backend-specific reference string.
	// Podman: "<Config.SnapshotRepo>-<id>:<label>".
	// QEMU:   "qemu:<id>:<label>".
	Ref string

	// Label is the human-readable name supplied at snapshot time.
	Label string
}

// Status describes the observed state of a sandbox at a point in time.
type Status struct {
	// Running is true when the container/VM process is actively running.
	Running bool

	// Endpoints mirrors Handle.Endpoints, refreshed from the live runtime.
	// The backend re-resolves host ports on every Inspect call because Podman
	// can remap them on restart.
	Endpoints map[string]string
}

// Backend is the runtime-agnostic interface for sandbox lifecycle, execution,
// file transfer, snapshotting, and endpoint discovery.
//
// All methods accept a context; callers should pass a request-scoped context
// with an appropriate timeout.  Methods that mutate container state (Create,
// Start, Stop, Recreate, Purge, Restore) should be treated as not concurrency-safe for
// the same sandbox ID — the caller must serialise them.
type Backend interface {
	// Create provisions a new sandbox from Spec and starts it (or leaves it
	// stopped — up to the implementation).  Returns a Handle on success.
	// In the Podman backend, Create also calls Start; the container is
	// running when Create returns.
	Create(ctx context.Context, spec Spec) (Handle, error)

	// Start starts a previously-stopped sandbox.
	Start(ctx context.Context, id string) error

	// Stop gracefully stops a running sandbox (SIGTERM → wait).  The
	// container's filesystem is preserved for a subsequent Start or Purge.
	Stop(ctx context.Context, id string) error

	// Recreate replaces the sandbox's runtime — the container or VM process —
	// with one built from spec, while preserving the sandbox's work volume and
	// everything on it.  spec.Name selects the sandbox; the other fields,
	// including a new Image, take effect as in Create.  This is the operation
	// a rolling image update needs: no path through Recreate deletes the
	// volume, structurally, so a caller cannot lose data to it.
	//
	// The volume surviving is this package's guarantee; whether the new image
	// can read what the old one wrote is the caller's compatibility problem.
	// keel owns the mechanism (the volume is still there); the consumer owns
	// its schema and any migration between versions of it.
	//
	// Recreate does no sequencing.  Rolling one sandbox at a time, draining
	// first, or stopping on the first failure is policy, and policy belongs to
	// the caller.
	//
	// On the QEMU backend the disk image cannot change: an overlay is bound to
	// the base image it was created from, so a non-empty spec.Image is
	// rejected with ErrSpecUnsupported (a new base disk requires Purge and
	// Create, which deletes the data — deliberately not reachable from here).
	Recreate(ctx context.Context, spec Spec) (Handle, error)

	// Purge stops (if running) and removes the sandbox INCLUDING its named
	// work volume — the caller's data.  Irreversible.  It is the only method
	// in this interface that deletes the volume; every other operation,
	// Recreate above in particular, leaves it in place.
	//
	// This method was named Destroy before v0.5.0.  It was renamed because
	// deleting a consumer's data must never hide behind a routine
	// infrastructure verb: a supervisor that means "remove the old container"
	// must not be able to reach for a name that also, silently, means "and
	// the data".  If you are migrating a Destroy call, decide which you meant:
	// container replacement is Recreate, retiring the sandbox and its data is
	// Purge.
	Purge(ctx context.Context, id string) error

	// Exec runs cmd inside the sandbox and returns the collected result.
	// stdin is not supported; use ExecStream for interactive use.
	Exec(ctx context.Context, id string, cmd []string, opts ExecOpts) (ExecResult, error)

	// ExecStream runs cmd inside the sandbox and returns a ReadCloser backed
	// by the combined stdout+stderr stream.  The caller must close the reader
	// to release resources.  Useful for long-running commands (builds, tests).
	ExecStream(ctx context.Context, id string, cmd []string, opts ExecOpts) (io.ReadCloser, error)

	// WriteFile writes data to path inside the sandbox, creating parent
	// directories as needed.  Equivalent to `podman exec -i sh -c 'cat > path'`.
	//
	// The sandbox is already running when WriteFile acts, so a file the
	// workload needs at startup would arrive after the race is lost.  For
	// those, use Spec.Files at Create, which lands before the entrypoint runs.
	WriteFile(ctx context.Context, id string, path string, data []byte) error

	// ReadFile reads the content of path from inside the sandbox.
	ReadFile(ctx context.Context, id string, path string) ([]byte, error)

	// Snapshot commits the current container state to an OCI image and
	// returns a SnapshotRef.  The container continues running.
	Snapshot(ctx context.Context, id string, label string) (SnapshotRef, error)

	// RemoveSnapshot deletes a previously-created snapshot image identified by
	// ref (SnapshotRef.Ref).  It is best-effort: a missing image is not an
	// error.  Callers use it to reclaim disk when a sandbox is retired.
	RemoveSnapshot(ctx context.Context, ref string) error

	// Restore recreates the sandbox from a previously-taken snapshot.
	// The current container is stopped and removed; a new container is
	// created from the snapshot image and started.
	// The Handle.ContainerID in the returned Handle reflects the new container.
	Restore(ctx context.Context, id string, ref SnapshotRef) (Handle, error)

	// Inspect returns the live status of the sandbox, including running state
	// and current host-port mappings.
	Inspect(ctx context.Context, id string) (Status, error)

	// DesktopEndpoint returns the http://127.0.0.1:<port> URL of the noVNC
	// websocket endpoint for profile=desktop sandboxes.
	// Returns an error if the sandbox is not running or profile≠desktop.
	DesktopEndpoint(ctx context.Context, id string) (string, error)

	// WebEndpoint returns the http://127.0.0.1:<port> URL of the agent's
	// HTTP server for profile=web sandboxes.
	// Returns an error if the sandbox is not running or profile≠web.
	WebEndpoint(ctx context.Context, id string) (string, error)

	// ContainerAddr returns the "<ip>:<port>" dial address of an in-container
	// service so the host can reach ANY port a server is listening on inside the
	// sandbox (the host can reach the container bridge IP directly; egress rules
	// only restrict the container's OUTBOUND traffic, not inbound from the host).
	// Used by the on-demand port-preview reverse proxy.
	// Returns ErrSandboxNotFound if the container is gone, or an unsupported
	// error for backends that cannot expose container IPs (e.g. QEMU VMs).
	ContainerAddr(ctx context.Context, id string, port int) (string, error)
}

// CommandError reports that a host tool this package shells out to (podman,
// qemu-system, qemu-img) ran and exited non-zero.
//
// # What Error does not say
//
// Error renders only the tool, its subcommand, and the exit code — never the
// tool's stderr. An error string is the one part of a failure that reaches a
// log by default, and a tool's stderr is whatever the tool chose to print,
// which can include fragments of its own invocation. Sandbox invocations carry
// caller configuration, so rendering stderr by default would make every
// consumer responsible for scrubbing it. The text is not lost, only unlisted:
// read [CommandError.Detail] when deliberately debugging, at which point
// disclosing it is a decision rather than an accident. (llm.APIError withholds
// provider error bodies for the same reason; this is the same pattern.)
type CommandError struct {
	// Tool is the binary that ran, for example "podman".
	Tool string

	// Subcommand is the tool's first argument, for example "run". Empty when
	// the tool was invoked without one.
	Subcommand string

	// ExitCode is the tool's exit status.
	ExitCode int

	// Stderr is the tool's standard error, trimmed. It is retained for
	// Detail and never rendered by Error.
	Stderr string

	// Err is the underlying error, an *exec.ExitError, kept so errors.As
	// still reaches it.
	Err error
}

// Error implements error. It renders the tool, subcommand, and exit code —
// never stderr. See the type documentation for why, and [CommandError.Detail]
// for how to get the text.
func (e *CommandError) Error() string {
	if e.Subcommand == "" {
		return fmt.Sprintf("%s: exit %d", e.Tool, e.ExitCode)
	}
	return fmt.Sprintf("%s %s: exit %d", e.Tool, e.Subcommand, e.ExitCode)
}

// Unwrap returns the underlying failure so errors.Is and errors.As reach it.
func (e *CommandError) Unwrap() error { return e.Err }

// Detail returns the tool's stderr. It is a method rather than part of Error
// so that disclosing it is a decision: treat the result as potentially
// sensitive diagnostics, and log it where such text is allowed to go, or not
// at all.
func (e *CommandError) Detail() string { return e.Stderr }

// ErrPodmanUnavailable is returned when the podman binary cannot be found or
// exits with a status that indicates it is not installed/configured.
// Callers should check errors.Is(err, ErrPodmanUnavailable) and surface a
// clear "install Podman" message rather than crashing.
var ErrPodmanUnavailable = errors.New("podman unavailable: ensure Podman is installed and accessible in PATH")

// ErrSandboxNotFound is returned when an operation targets a sandbox ID that
// does not map to a known container.
var ErrSandboxNotFound = errors.New("sandbox not found")

// ErrWrongProfile is returned when DesktopEndpoint is called on a non-desktop
// sandbox or WebEndpoint on a non-web sandbox.
var ErrWrongProfile = errors.New("operation not supported for this sandbox profile")

// ErrSpecUnsupported is returned by Create when a Spec asks for something the
// chosen backend cannot deliver (for example Spec.Command or Spec.Files on the
// QEMU backend).  Failing loudly is deliberate: silently ignoring a command
// vector or a config file would hand the caller a sandbox that runs the wrong
// thing, or runs without the file it was promised.
var ErrSpecUnsupported = errors.New("spec field not supported by this backend")
