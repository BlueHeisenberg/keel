// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// effectivePolicy returns the policy to apply, treating the empty string as
// NetworkPolicyInternalOnly (the safe default).
func effectivePolicy(p NetworkPolicy) NetworkPolicy {
	if p == "" {
		return NetworkPolicyInternalOnly
	}
	return p
}

// Compile-time assertion: PodmanBackend must implement Backend.
var _ Backend = (*PodmanBackend)(nil)

// runner is the interface through which PodmanBackend shells out.
// The default implementation uses os/exec; tests inject a mock.
type runner interface {
	// Run executes args as a command (args[0] is the program).
	// stdin is written to the process's stdin if non-nil.
	// extraEnv entries ("K=V") are appended to the process's inherited
	// environment; nil means inherit unchanged.  This is how secret values
	// reach a tool WITHOUT appearing on its argv, where any local user could
	// read them out of the host's process list.
	// Returns stdout, stderr, and any execution error.
	// A non-zero exit code is surfaced as an *exec.ExitError inside err.
	Run(ctx context.Context, args []string, stdin []byte, extraEnv []string) (stdout, stderr []byte, err error)
}

// execRunner is the production runner backed by os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, args []string, stdin []byte, extraEnv []string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, errors.New("runner: empty args")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), err
}

// PodmanBackend implements Backend by shelling out to the podman CLI.
// Container names follow the pattern "<Config.NamePrefix><Spec.Name>" and the
// work volume is "<Config.NamePrefix><Spec.Name>-work".
//
// The backend persists no state of its own: the caller is responsible for
// keeping Handle.ContainerID and Handle.Endpoints if it needs them.
//
// It works only on a Linux host — see the package documentation.
type PodmanBackend struct {
	// cfg holds binary paths and resource naming, with defaults applied.
	cfg Config

	// r is the command runner.
	r runner

	// log is the structured logger.
	log *slog.Logger

	// lookPath resolves host binaries (nft, nsenter).  Defaults to
	// exec.LookPath; tests override it to simulate host tooling availability.
	lookPath func(string) (string, error)
}

// NewPodmanBackend returns a PodmanBackend configured by cfg. The zero Config
// is usable; see Config for the defaults it implies. Pass logger from the
// application; if nil, slog.Default() is used.
//
// Construction never touches the host: nothing checks for podman, and no
// sandbox exists until Create is called.
func NewPodmanBackend(cfg Config, log *slog.Logger) *PodmanBackend {
	if log == nil {
		log = slog.Default()
	}
	return &PodmanBackend{
		cfg:      cfg.withDefaults(),
		r:        execRunner{},
		log:      log,
		lookPath: exec.LookPath,
	}
}

// newPodmanBackendWithRunner is the constructor used by tests to inject a mock runner.
func newPodmanBackendWithRunner(r runner, log *slog.Logger) *PodmanBackend {
	if log == nil {
		log = slog.Default()
	}
	return &PodmanBackend{
		cfg:      Config{}.withDefaults(),
		r:        r,
		log:      log,
		lookPath: exec.LookPath,
	}
}

// containerName returns the deterministic container name for a sandbox name:
// Config.NamePrefix + name.
func (b *PodmanBackend) containerName(name string) string {
	return b.cfg.NamePrefix + name
}

// volumeName returns the deterministic work-volume name for a sandbox name:
// Config.NamePrefix + name + "-work".
func (b *PodmanBackend) volumeName(name string) string {
	return b.cfg.NamePrefix + name + "-work"
}

// pickFreePort asks the OS for a free TCP port on the loopback interface.
// It binds briefly, records the port, and closes; there is a brief TOCTOU
// window; it is the same approach the standard test helpers use.
func pickFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("pick free port: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

// podman wraps the run method so callers don't repeat the binary name.
func (b *PodmanBackend) podman(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
	return b.podmanEnv(ctx, args, stdin, nil)
}

// podmanEnv is podman with extra process environment for the tool (see
// runner.Run).  Used where a value must reach podman without touching argv.
func (b *PodmanBackend) podmanEnv(ctx context.Context, args []string, stdin []byte, extraEnv []string) ([]byte, []byte, error) {
	full := append([]string{b.cfg.PodmanBinary}, args...)
	stdout, stderr, err := b.r.Run(ctx, full, stdin, extraEnv)
	if err != nil {
		// Detect "not found" from exec.LookPath or PATH execution errors.
		var execErr *exec.Error
		if errors.As(err, &execErr) && execErr.Err == exec.ErrNotFound {
			return nil, nil, fmt.Errorf("%w: %s", ErrPodmanUnavailable, execErr.Err)
		}
		// Exit error — return a CommandError that keeps the *exec.ExitError in
		// the chain (Exec unwraps it for the exit code) and carries stderr in
		// Detail rather than in the error string, so a log line cannot echo
		// whatever the tool chose to print.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout, stderr, &CommandError{
				Tool:       "podman",
				Subcommand: args[0],
				ExitCode:   exitErr.ExitCode(),
				Stderr:     strings.TrimSpace(string(stderr)),
				Err:        exitErr,
			}
		}
		return nil, nil, fmt.Errorf("podman %s: %w", args[0], err)
	}
	return stdout, stderr, nil
}

// validSpec runs the per-spec validations shared by Create and Recreate,
// before anything on the host is touched.
func validSpec(spec Spec) error {
	// Validate the id before it reaches container/volume names or podman args.
	if err := validID(spec.Name); err != nil {
		return err
	}
	// Validate the provisioned files and environment before anything is
	// created, so a bad Files or Env entry cannot leave an orphaned volume or
	// container behind.
	if err := validFiles(spec.Files); err != nil {
		return fmt.Errorf("sandbox %s: %w", spec.Name, err)
	}
	if err := validEnv(spec.Env); err != nil {
		return fmt.Errorf("sandbox %s: %w", spec.Name, err)
	}
	return nil
}

// resolveImage picks the image for a spec, falling back to Config.Image.
// Resolved before anything is created, so a misconfigured backend does not
// leave an orphaned volume or a half-replaced sandbox behind.
func (b *PodmanBackend) resolveImage(spec Spec) (string, error) {
	image := spec.Image
	if image == "" {
		image = b.cfg.Image
	}
	if image == "" {
		return "", fmt.Errorf("sandbox %s: no image: set Spec.Image or Config.Image", spec.Name)
	}
	return image, nil
}

// Create implements Backend.Create.
//
// The function:
//  1. Creates a named volume for /work.
//  2. Runs `podman run -d` with the resource limits and labels from Spec
//     (or create → copy files in → start, when Spec.Files is non-empty).
//  3. Returns a Handle with the resolved ContainerID and Endpoints.
//
// The container is running when Create returns.
func (b *PodmanBackend) Create(ctx context.Context, spec Spec) (Handle, error) {
	if err := validSpec(spec); err != nil {
		return Handle{}, err
	}
	image, err := b.resolveImage(spec)
	if err != nil {
		return Handle{}, err
	}

	// Ensure the named volume exists (idempotent).
	vol := b.volumeName(spec.Name)
	if _, _, err := b.podman(ctx, []string{"volume", "create", vol}, nil); err != nil {
		return Handle{}, fmt.Errorf("sandbox create volume: %w", err)
	}

	// Create made the volume, so Create's failure cleanup is Purge: a spec
	// that cannot launch must not leak a container-less volume.
	return b.launch(ctx, spec, image, "create", b.Purge)
}

// Recreate implements Backend.Recreate: the container is replaced from spec —
// a new image included — while the named work volume, and the caller's data on
// it, survive.  The volume-deleting code (Purge) is not reachable from here:
// no volume command runs on this path, and every failure cleanup is
// removeContainer, which cannot touch a volume by construction.
func (b *PodmanBackend) Recreate(ctx context.Context, spec Spec) (Handle, error) {
	if err := validSpec(spec); err != nil {
		return Handle{}, err
	}
	image, err := b.resolveImage(spec)
	if err != nil {
		return Handle{}, err
	}

	// Remove the existing container.  An absent container is tolerated so
	// Recreate can also repair a sandbox whose container was lost.
	if err := b.removeContainer(ctx, spec.Name); err != nil {
		return Handle{}, fmt.Errorf("sandbox recreate %s: %w", spec.Name, err)
	}

	// `--volume <name>:/work` in the launch args reattaches the existing
	// volume; podman only creates it if it is missing.
	return b.launch(ctx, spec, image, "recreate", b.removeContainer)
}

// launch is the shared container-creation flow behind Create and Recreate:
// argument construction, run/create, file provisioning, host-applied egress,
// endpoint discovery.  verb names the calling operation in errors and logs.
// cleanup is invoked with the sandbox id when a step fails after the container
// exists: Create passes Purge (it owns the volume it just made); Recreate
// passes removeContainer (the volume predates the call and holds the caller's
// data, so it must survive every failure path).
func (b *PodmanBackend) launch(ctx context.Context, spec Spec, image, verb string, cleanup func(context.Context, string) error) (Handle, error) {
	// Determine which container port to expose and under what logical name.
	var (
		containerPort int
		endpointKey   string
	)
	switch spec.Profile {
	case ProfileDesktop:
		containerPort = 6080 // noVNC websockify port, by convention
		endpointKey = "desktop"
	case ProfileWeb:
		if spec.ServePort == 0 {
			spec.ServePort = 8080
		}
		containerPort = spec.ServePort
		endpointKey = "web"
	case ProfileHeadless:
		// no published port
	default:
		// treat unknown profiles as headless
		b.log.Warn("sandbox: unknown profile, treating as headless", "profile", spec.Profile)
	}

	var hostPort int
	if containerPort > 0 {
		var err error
		hostPort, err = pickFreePort()
		if err != nil {
			return Handle{}, fmt.Errorf("sandbox %s: %w", verb, err)
		}
	}

	// The sandbox is identified by the caller-supplied name.
	sandboxID := spec.Name
	vol := b.volumeName(sandboxID)
	cname := b.containerName(sandboxID)

	policy := effectivePolicy(spec.NetworkPolicy)

	// When files must be provisioned they have to land BEFORE the workload's
	// entrypoint starts, so the container is created stopped (`podman create`),
	// the files are copied in, and only then is it started.  With no files,
	// `podman run -d` is used exactly as before.
	provision := len(spec.Files) > 0

	// Build the `podman run`/`podman create` arguments.
	args := []string{"run", "-d"}
	if provision {
		args = []string{"create"}
	}
	args = append(args,
		"--name", cname,
		"--label", b.cfg.LabelKey+"="+spec.Name,
		"--volume", vol+":/work",
		"--env", "PROFILE="+string(spec.Profile),
	)

	// ── Egress policy ────────────────────────────────────────────────────────
	//
	// "none" → no network interface at all; skip --add-host entirely.
	//
	// "open" → unrestricted; keep the host-gateway alias so host services stay
	//          reachable by name.
	//
	// "internal-only" (default) / "filtered" → the egress lockdown is applied
	//          from the HOST into the container's network namespace AFTER start
	//          (see applyHostEgress below).  The container is NOT granted
	//          NET_ADMIN and the entrypoint applies no rules — this removes the
	//          in-guest self-flush risk (a compromised workload with NET_ADMIN
	//          could otherwise delete its own egress table).
	//          host.containers.internal resolves to the host-gateway IP; the
	//          host-applied nftables ruleset allows that specific IP so host
	//          services stay reachable.  For "filtered" we also set
	//          HTTP_PROXY/HTTPS_PROXY so the container routes through the host
	//          egress proxy.
	switch policy {
	case NetworkPolicyNone:
		args = append(args, "--network", "none")

	case NetworkPolicyOpen:
		// Keep the host alias; no firewall applied.
		args = append(args, "--add-host", "host.containers.internal:host-gateway")
		b.log.Warn("sandbox: NetworkPolicyOpen in use — unrestricted egress", "sandbox", spec.Name)

	case NetworkPolicyInternalOnly:
		args = append(args, "--add-host", "host.containers.internal:host-gateway")

	case NetworkPolicyFiltered:
		args = append(args, "--add-host", "host.containers.internal:host-gateway")
		if spec.EgressProxyAddr != "" {
			proxyURL := "http://" + spec.EgressProxyAddr
			args = append(args,
				"--env", "HTTP_PROXY="+proxyURL,
				"--env", "HTTPS_PROXY="+proxyURL,
				"--env", "http_proxy="+proxyURL,
				"--env", "https_proxy="+proxyURL,
			)
		}
	}
	// ── end egress policy ────────────────────────────────────────────────────

	// Resource limits.
	if spec.CPUs > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.2f", spec.CPUs))
	}
	if spec.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", spec.MemoryMB))
	}

	// Extra environment variables.  The VALUES are deliberately kept off the
	// argv: `--env K=V` would render V in the host's process list, where any
	// local user can read it via ps while podman runs, and callers put
	// credentials in Env.  Instead each variable is passed as `--env K` — a
	// form podman resolves from its own process environment — and the value
	// travels through that environment (runner extraEnv), which the kernel
	// exposes only to the same user and root.  Only the NAME appears on the
	// argv.  The variables this package composes itself (PROFILE, the proxy
	// vars above) stay in K=V form: they are non-secret by construction.
	envArgs, extraEnv := splitEnv(spec.Env)
	args = append(args, envArgs...)

	// Port mapping — bind to loopback only.
	if containerPort > 0 {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d", hostPort, containerPort))
	}

	// Image ends podman's own flag parsing; everything after it is the
	// container command.  Spec.Command therefore goes AFTER the image, each
	// element as one argv entry.  No shell sits anywhere on this path — the
	// runner passes an argv slice to podman, and podman hands it to the OCI
	// runtime as the process args — so an element containing spaces, quotes,
	// or equals signs arrives intact and cannot become a second argument.
	args = append(args, image)
	args = append(args, spec.Command...)

	b.log.Debug("sandbox: creating container",
		"sandbox", spec.Name,
		"op", verb,
		"profile", spec.Profile,
		"image", image,
	)

	stdout, _, err := b.podmanEnv(ctx, args, nil, extraEnv)
	if err != nil {
		return Handle{}, fmt.Errorf("sandbox %s container: %w", verb, err)
	}

	// stdout is the full container ID (64-hex chars + newline).
	containerID := strings.TrimSpace(string(stdout))

	// ── File provisioning (create-time) ──────────────────────────────────────
	// The container exists but has not started, so the files land before the
	// entrypoint can look for them.  Fail-closed on any error: clean up the
	// container rather than leave one running without the files it was
	// promised.
	if provision {
		if err := b.copyFilesIn(ctx, sandboxID, spec.Files); err != nil {
			if derr := cleanup(ctx, sandboxID); derr != nil {
				b.log.Warn("sandbox: file provisioning failed and cleanup also failed",
					"sandbox", spec.Name, "provision_err", err, "cleanup_err", derr)
			}
			return Handle{}, fmt.Errorf("sandbox %s: provision files: %w", verb, err)
		}
		if _, _, err := b.podman(ctx, []string{"start", cname}, nil); err != nil {
			if derr := cleanup(ctx, sandboxID); derr != nil {
				b.log.Warn("sandbox: start after provisioning failed and cleanup also failed",
					"sandbox", spec.Name, "start_err", err, "cleanup_err", derr)
			}
			return Handle{}, fmt.Errorf("sandbox %s: start after provisioning: %w", verb, err)
		}
	}
	// ── end file provisioning ────────────────────────────────────────────────

	// ── Host-applied egress lockdown (H3/H4) ─────────────────────────────────
	// For internal-only/filtered, apply the nftables ruleset from the HOST into
	// the container's netns and then VERIFY it is active.  This is fail-closed:
	// any failure removes the container and returns an error so we never run a
	// sandbox with unconfirmed egress restrictions.
	if policy == NetworkPolicyInternalOnly || policy == NetworkPolicyFiltered {
		if err := b.applyHostEgress(ctx, sandboxID, containerID, policy, spec.AllowDomains); err != nil {
			// Best-effort teardown; surface the original error.
			if derr := cleanup(ctx, sandboxID); derr != nil {
				b.log.Warn("sandbox: egress lockdown failed and cleanup also failed",
					"sandbox", spec.Name, "egress_err", err, "cleanup_err", derr)
			}
			return Handle{}, fmt.Errorf("sandbox %s: egress lockdown: %w", verb, err)
		}
	}
	// ── end host-applied egress ──────────────────────────────────────────────

	endpoints := make(map[string]string)
	if containerPort > 0 && hostPort > 0 {
		endpoints[endpointKey] = fmt.Sprintf("http://127.0.0.1:%d", hostPort)
	}

	b.log.Info("sandbox: container created",
		"sandbox", spec.Name,
		"op", verb,
		"container", containerID,
		"endpoints", endpoints,
	)

	return Handle{
		ID:          sandboxID,
		ContainerID: containerID,
		Endpoints:   endpoints,
	}, nil
}

// ErrEgressUnavailable is returned by Create when an internal-only/filtered
// sandbox cannot have its host-applied egress lockdown installed or verified
// (e.g. the host lacks nft/nsenter, or the rules did not take effect).  Create
// fails closed in this case: it never returns a running sandbox with
// unconfirmed egress restrictions.
var ErrEgressUnavailable = errors.New("egress lockdown unavailable: host nftables/nsenter missing or rules failed to apply")

// applyHostEgress installs the egress nftables ruleset from the HOST into the
// container's network namespace via `nsenter -t <pid> -n nft -f -`, then
// verifies the table is present.  It returns an error (fail-closed) if the host
// tooling is unavailable or the lockdown cannot be confirmed.
//
// The container is NOT granted NET_ADMIN; the host (running as root) owns the
// netns manipulation.  This defeats in-guest self-flush by a compromised agent.
func (b *PodmanBackend) applyHostEgress(ctx context.Context, sandboxID, containerID string, policy NetworkPolicy, allowDomains []string) error {
	// Host tooling must be present — otherwise fail closed.
	lookPath := b.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if _, err := lookPath("nft"); err != nil {
		return fmt.Errorf("%w: nft not found on host", ErrEgressUnavailable)
	}
	if _, err := lookPath("nsenter"); err != nil {
		return fmt.Errorf("%w: nsenter not found on host", ErrEgressUnavailable)
	}

	// Resolve the container PID for nsenter.
	pid, err := b.containerPID(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("%w: get container pid: %v", ErrEgressUnavailable, err)
	}

	// Determine the host-gateway IP the container reaches the host through.
	hostGW, err := b.containerGateway(ctx, sandboxID)
	if err != nil || hostGW == "" {
		return fmt.Errorf("%w: determine host-gateway IP: %v", ErrEgressUnavailable, err)
	}

	ruleset := buildEgressRuleset(b.cfg.EgressTable, policy, hostGW, allowDomains)

	// Apply the ruleset from the host into the container netns.
	// nsenter -t <pid> -n nft -f -   (ruleset piped on stdin)
	nsArgs := []string{"nsenter", "-t", pid, "-n", "nft", "-f", "-"}
	if _, stderr, err := b.r.Run(ctx, nsArgs, []byte(ruleset), nil); err != nil {
		return fmt.Errorf("%w: nsenter nft load: %v: %s", ErrEgressUnavailable, err, strings.TrimSpace(string(stderr)))
	}

	// VERIFY the lockdown is active: the ip <EgressTable> table must exist in
	// the container netns.  Check via `podman exec` so we observe what the
	// container actually sees.
	if _, _, err := b.podman(ctx, []string{"exec", b.containerName(sandboxID), "nft", "list", "table", "ip", b.cfg.EgressTable}, nil); err != nil {
		// Fall back to checking from the host netns in case the container image
		// lacks the nft binary; the host check is authoritative.
		hostCheck := []string{"nsenter", "-t", pid, "-n", "nft", "list", "table", "ip", b.cfg.EgressTable}
		if _, _, herr := b.r.Run(ctx, hostCheck, nil, nil); herr != nil {
			return fmt.Errorf("%w: egress table not present after load (container: %v; host: %v)",
				ErrEgressUnavailable, err, herr)
		}
	}

	b.log.Info("sandbox: host-applied egress lockdown active",
		"sandbox", sandboxID, "container", containerID, "policy", policy, "host_gw", hostGW)
	return nil
}

// containerPID returns the host PID of the container's init process.
func (b *PodmanBackend) containerPID(ctx context.Context, sandboxID string) (string, error) {
	stdout, _, err := b.podman(ctx, []string{"inspect", "--type", "container", "--format", "{{.State.Pid}}", b.containerName(sandboxID)}, nil)
	if err != nil {
		return "", err
	}
	pid := strings.TrimSpace(string(stdout))
	if pid == "" || pid == "0" {
		return "", fmt.Errorf("container has no pid (not running?)")
	}
	return pid, nil
}

// containerGateway returns the host-gateway IP the container uses to reach the
// host (host.containers.internal / default-route gateway).
func (b *PodmanBackend) containerGateway(ctx context.Context, sandboxID string) (string, error) {
	stdout, _, err := b.podman(ctx, []string{"inspect", "--type", "container", "--format", "{{.NetworkSettings.Gateway}}", b.containerName(sandboxID)}, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(stdout)), nil
}

// buildEgressRuleset generates the nftables ruleset applied into the container
// netns, under the table name table (Config.EgressTable).  It default-drops
// OUTPUT for both IPv4 and IPv6, allowing only:
//   - loopback
//   - established/related return traffic
//   - DNS (udp/tcp 53) ONLY to the host-gateway (forces DNS through the host;
//     prevents DNS-based exfiltration to arbitrary resolvers)
//   - all traffic to the host-gateway IP (host services)
//   - for "filtered": each resolved allow-domain IP (v4 and v6)
//
// IPv6 is default-dropped with no host-gw allowance unless the host-gw itself is
// a v6 address (covered by the v4/v6 split below).
func buildEgressRuleset(table string, policy NetworkPolicy, hostGW string, allowDomains []string) string {
	gwIsV6 := strings.Contains(hostGW, ":")

	var v4Extra, v6Extra strings.Builder
	if !gwIsV6 {
		v4Extra.WriteString("        ip daddr " + hostGW + " accept\n")
		v4Extra.WriteString("        udp dport 53 ip daddr " + hostGW + " accept\n")
		v4Extra.WriteString("        tcp dport 53 ip daddr " + hostGW + " accept\n")
	} else {
		v6Extra.WriteString("        ip6 daddr " + hostGW + " accept\n")
		v6Extra.WriteString("        udp dport 53 ip6 daddr " + hostGW + " accept\n")
		v6Extra.WriteString("        tcp dport 53 ip6 daddr " + hostGW + " accept\n")
	}

	if policy == NetworkPolicyFiltered {
		for _, domain := range allowDomains {
			bare := strings.TrimPrefix(domain, "*.")
			ips, err := net.LookupIP(bare)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					v4Extra.WriteString("        ip daddr " + ip4.String() + " accept\n")
				} else {
					v6Extra.WriteString("        ip6 daddr " + ip.String() + " accept\n")
				}
			}
		}
	}

	var sb strings.Builder
	// IPv4 table.
	sb.WriteString("table ip " + table + " {\n")
	sb.WriteString("    chain output {\n")
	sb.WriteString("        type filter hook output priority 0; policy drop;\n")
	sb.WriteString("        oifname \"lo\" accept\n")
	sb.WriteString("        ct state established,related accept\n")
	sb.WriteString(v4Extra.String())
	sb.WriteString("    }\n")
	sb.WriteString("}\n")
	// IPv6 table — default-drop so IPv6 egress can't bypass the v4 rules.
	sb.WriteString("table ip6 " + table + " {\n")
	sb.WriteString("    chain output {\n")
	sb.WriteString("        type filter hook output priority 0; policy drop;\n")
	sb.WriteString("        oifname \"lo\" accept\n")
	sb.WriteString("        ct state established,related accept\n")
	sb.WriteString(v6Extra.String())
	sb.WriteString("    }\n")
	sb.WriteString("}\n")
	return sb.String()
}

// Start implements Backend.Start.
// A missing container is reported as ErrSandboxNotFound, matching Inspect and
// ContainerAddr: podman's message for a missing name on `start` is
// `Error: no container with name or ID "…" found: no such container`, which
// isNoSuchContainer already recognises (verified against real podman 4.9.3).
func (b *PodmanBackend) Start(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	_, _, err := b.podman(ctx, []string{"start", b.containerName(id)}, nil)
	if err != nil {
		if isNoSuchContainer(err) {
			return fmt.Errorf("sandbox start %s: %w", id, ErrSandboxNotFound)
		}
		return fmt.Errorf("sandbox start %s: %w", id, err)
	}
	return nil
}

// Stop implements Backend.Stop.
// A missing container is reported as ErrSandboxNotFound, matching Inspect and
// ContainerAddr (see Start).  Note this is a real error, not tolerated as a
// no-op: unlike removeContainer/Purge, whose goal state is "gone" and so treat
// an absent container as success, Stop is asked to act on a specific sandbox
// the caller believes exists, and the caller (kenward's rollOne and shutdown,
// among others) branches on ErrSandboxNotFound to tell that apart from a real
// stop failure.
func (b *PodmanBackend) Stop(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	_, _, err := b.podman(ctx, []string{"stop", b.containerName(id)}, nil)
	if err != nil {
		if isNoSuchContainer(err) {
			return fmt.Errorf("sandbox stop %s: %w", id, ErrSandboxNotFound)
		}
		return fmt.Errorf("sandbox stop %s: %w", id, err)
	}
	return nil
}

// removeContainer stops and removes the container for id and touches nothing
// else: it issues no volume command of any kind, so the sandbox's work volume
// — the caller's data — survives it by construction.  It is the teardown used
// by Recreate and by every failure path reachable from Recreate.  A missing or
// already-stopped container is tolerated.
func (b *PodmanBackend) removeContainer(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	cname := b.containerName(id)

	// Stop — tolerate "already stopped" errors.
	if _, _, err := b.podman(ctx, []string{"stop", cname}, nil); err != nil {
		b.log.Debug("sandbox remove-container: stop error (may be already stopped)", "id", id, "err", err)
	}

	// Remove container.  Tolerate a missing container ("no such container").
	if _, _, err := b.podman(ctx, []string{"rm", "--force", cname}, nil); err != nil {
		if isNotFoundErr(err) {
			b.log.Debug("sandbox remove-container: container not found", "id", id, "err", err)
		} else {
			return fmt.Errorf("sandbox remove container %s: %w", id, err)
		}
	}
	return nil
}

// Purge implements Backend.Purge (named Destroy before v0.5.0).
// Stops the container (tolerates already-stopped), removes it, then removes
// the named work volume — the caller's data.  This is the only method on the
// backend that deletes the volume.
func (b *PodmanBackend) Purge(ctx context.Context, id string) error {
	if err := b.removeContainer(ctx, id); err != nil {
		return fmt.Errorf("sandbox purge: %w", err)
	}

	// Remove work volume.  Tolerate a missing volume so a partially
	// provisioned sandbox is still fully reaped.
	vol := b.volumeName(id)
	if _, _, err := b.podman(ctx, []string{"volume", "rm", "--force", vol}, nil); err != nil {
		if isNotFoundErr(err) {
			b.log.Debug("sandbox purge: volume not found", "id", id, "err", err)
		} else {
			return fmt.Errorf("sandbox purge volume rm %s: %w", id, err)
		}
	}

	b.log.Info("sandbox: purged (container and work volume removed)", "sandbox", id)
	return nil
}

// Exec implements Backend.Exec.
func (b *PodmanBackend) Exec(ctx context.Context, id string, cmd []string, opts ExecOpts) (ExecResult, error) {
	if err := validID(id); err != nil {
		return ExecResult{}, err
	}
	args, extraEnv, err := b.buildExecArgs(id, cmd, opts)
	if err != nil {
		return ExecResult{}, fmt.Errorf("sandbox exec %s: %w", id, err)
	}
	stdout, stderr, err := b.podmanEnv(ctx, args, nil, extraEnv)

	// Collect exit code from ExitError; a non-zero exit is not a Go error —
	// the caller reads ExitResult.ExitCode.
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			// Clear the Go error — the caller will inspect ExitCode.
			err = nil
		} else {
			return ExecResult{}, fmt.Errorf("sandbox exec %s: %w", id, err)
		}
	}

	return ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
	}, nil
}

// ExecStream implements Backend.ExecStream.
// It starts `podman exec` and returns the stdout pipe.  The caller must close
// the returned ReadCloser to free the process.
func (b *PodmanBackend) ExecStream(ctx context.Context, id string, cmd []string, opts ExecOpts) (io.ReadCloser, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	argSlice, extraEnv, err := b.buildExecArgs(id, cmd, opts)
	if err != nil {
		return nil, fmt.Errorf("sandbox exec-stream %s: %w", id, err)
	}
	// prepend the binary name
	full := append([]string{b.cfg.PodmanBinary}, argSlice...)
	osCmd := exec.CommandContext(ctx, full[0], full[1:]...)
	if len(extraEnv) > 0 {
		osCmd.Env = append(os.Environ(), extraEnv...)
	}

	pr, err := osCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("sandbox exec-stream stdout pipe: %w", err)
	}
	if err := osCmd.Start(); err != nil {
		// Start failed: the stdout pipe was created by StdoutPipe but the
		// process never ran.  Close the read end so the os.Pipe fds are not
		// leaked, then map the error.  (cmd.Wait is not called/needed: the
		// process was never started, and per os/exec docs StdoutPipe's pipe is
		// closed by Wait — which we must not call after a failed Start; closing
		// the reader here releases our half.)
		_ = pr.Close()
		var execErr *exec.Error
		if errors.As(err, &execErr) && execErr.Err == exec.ErrNotFound {
			return nil, fmt.Errorf("%w: %s", ErrPodmanUnavailable, execErr.Err)
		}
		return nil, fmt.Errorf("sandbox exec-stream start: %w", err)
	}

	// Wrap the pipe in a closer that also waits for the command to exit.
	return &streamCloser{ReadCloser: pr, cmd: osCmd}, nil
}

// streamCloser wraps a ReadCloser and waits for the underlying command to
// finish when Close is called.
type streamCloser struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (s *streamCloser) Close() error {
	err := s.ReadCloser.Close()
	_ = s.cmd.Wait()
	return err
}

// buildExecArgs constructs the `exec` subcommand arguments (without the binary
// prefix) for both Exec and ExecStream.  Environment values are returned
// separately as extraEnv rather than placed on the argv — see splitEnv.
func (b *PodmanBackend) buildExecArgs(id string, cmd []string, opts ExecOpts) (args, extraEnv []string, err error) {
	if err := validEnv(opts.Env); err != nil {
		return nil, nil, err
	}
	args = []string{"exec"}
	if opts.WorkDir != "" {
		args = append(args, "--workdir", opts.WorkDir)
	}
	if opts.RunAs != "" {
		args = append(args, "--user", opts.RunAs)
	}
	envArgs, extraEnv := splitEnv(opts.Env)
	args = append(args, envArgs...)
	args = append(args, b.containerName(id))
	args = append(args, cmd...)
	return args, extraEnv, nil
}

// envKeyRe is the allowed shape of an environment variable name.  Restricting
// to the POSIX portable set is load-bearing: podman expands `--env K*` as a
// glob importing every matching variable from its own environment, and '='
// or NUL would corrupt the K=V entry handed to the kernel.
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validEnv rejects environment maps whose keys could act as podman globs or
// break the K=V form, and values that cannot cross an execve boundary.
func validEnv(env map[string]string) error {
	for k, v := range env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("env %q: name must match [A-Za-z_][A-Za-z0-9_]*", k)
		}
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("env %q: value contains NUL", k)
		}
	}
	return nil
}

// splitEnv turns an environment map into the argv fragment and the process
// environment that together deliver it to the container: `--env K` on the argv
// (name only — podman resolves the value from its own environment) and "K=V"
// in extraEnv for the runner to place in that environment.  Keeping values off
// the argv keeps them out of the host's process list, which any local user can
// read; a process's environment is readable only by its own user and root.
// Keys are sorted so the argv is deterministic.
func splitEnv(env map[string]string) (envArgs, extraEnv []string) {
	if len(env) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		envArgs = append(envArgs, "--env", k)
		extraEnv = append(extraEnv, k+"="+env[k])
	}
	return envArgs, extraEnv
}

// WriteFile implements Backend.WriteFile.
// Uses `podman exec -i sh -c 'cat > <path>'` with the data as stdin.
// Parent directories are created with mkdir -p first.
func (b *PodmanBackend) WriteFile(ctx context.Context, id string, path string, data []byte) error {
	if err := validID(id); err != nil {
		return err
	}
	// Ensure parent directory exists.
	// Use sh -c to avoid separate exec round-trips.
	mkdirCmd := []string{"exec", b.containerName(id), "sh", "-c", "mkdir -p -- \"$(dirname " + shellQuote(path) + ")\""}
	if _, _, err := b.podman(ctx, mkdirCmd, nil); err != nil {
		return fmt.Errorf("sandbox write-file mkdir %s: %w", path, err)
	}

	// Write data via stdin.
	writeArgs := []string{"exec", "-i", b.containerName(id), "sh", "-c", "cat > " + shellQuote(path)}
	if _, _, err := b.podman(ctx, writeArgs, data); err != nil {
		return fmt.Errorf("sandbox write-file %s: %w", path, err)
	}
	return nil
}

// ReadFile implements Backend.ReadFile.
func (b *PodmanBackend) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	args := []string{"exec", b.containerName(id), "cat", path}
	stdout, _, err := b.podman(ctx, args, nil)
	if err != nil {
		return nil, fmt.Errorf("sandbox read-file %s: %w", path, err)
	}
	return stdout, nil
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes.
// Suitable for use in sh -c strings.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// errText returns the searchable text of err for classification: the error
// string, plus the withheld stderr when a CommandError is in the chain.
// Classifiers must use this rather than err.Error(), because CommandError
// deliberately keeps the tool's stderr — where podman says "no such
// container" — out of the error string.
func errText(err error) string {
	text := err.Error()
	var ce *CommandError
	if errors.As(err, &ce) {
		text += " " + ce.Stderr
	}
	return strings.ToLower(text)
}

// isNotFoundErr reports whether err (from a podman rm / volume rm / rmi call)
// indicates the target container, volume, or image simply does not exist.
// Such "not found" failures are tolerated during best-effort cleanup so a
// partially-provisioned sandbox does not orphan its other resources.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := errText(err)
	return strings.Contains(msg, "no such container") ||
		strings.Contains(msg, "no container with name") ||
		strings.Contains(msg, "no such volume") ||
		strings.Contains(msg, "no volume with name") ||
		strings.Contains(msg, "no such image") ||
		strings.Contains(msg, "image not known")
}

// isNoSuchContainer reports whether err indicates the container does not
// exist, for mapping to ErrSandboxNotFound.
func isNoSuchContainer(err error) bool {
	if err == nil {
		return false
	}
	msg := errText(err)
	return strings.Contains(msg, "no such container") ||
		strings.Contains(msg, "no container with name or id")
}

// ---- create-time file provisioning ------------------------------------------

// validFiles rejects Spec.Files entries whose path could escape or alias
// (relative, unclean, or the root itself), whose mode is missing or carries
// file-type bits, or whose ownership is negative.  Duplicated paths are
// rejected rather than letting the last write win silently.
func validFiles(files []File) error {
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "/") {
			return fmt.Errorf("file %q: path must be absolute", f.Path)
		}
		if f.Path == "/" || path.Clean(f.Path) != f.Path {
			return fmt.Errorf("file %q: path must be a clean absolute file path (no \".\", \"..\", doubled or trailing slashes)", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("file %q: duplicate path", f.Path)
		}
		seen[f.Path] = true
		if f.Mode == 0 {
			return fmt.Errorf("file %q: explicit mode bits are required (for example 0o600); refusing to choose one silently", f.Path)
		}
		if f.Mode != f.Mode.Perm() {
			return fmt.Errorf("file %q: mode %v carries file-type bits; only permission bits are allowed", f.Path, f.Mode)
		}
		if f.UID < 0 || f.GID < 0 {
			return fmt.Errorf("file %q: negative uid/gid", f.Path)
		}
	}
	return nil
}

// copyFilesIn lands Spec.Files in the (created, not yet started) container via
// `podman cp --archive=false - <ctr>:/` with a tar stream on stdin.  Copy-in
// rather than a mount keeps the sandbox self-contained: nothing on the host
// filesystem has to exist, persist, or stay in sync for the sandbox to run.
// --archive=false makes podman preserve the ownership recorded in the tar
// headers (File.UID/GID) instead of chowning to the container's primary user.
func (b *PodmanBackend) copyFilesIn(ctx context.Context, id string, files []File) error {
	archive, err := filesArchive(files)
	if err != nil {
		return err
	}
	cpArgs := []string{"cp", "--archive=false", "-", b.containerName(id) + ":/"}
	if _, _, err := b.podman(ctx, cpArgs, archive); err != nil {
		return fmt.Errorf("copy files in: %w", err)
	}
	return nil
}

// filesArchive builds the tar stream podman extracts at the container root.
// Each entry carries the exact mode and ownership from its File.  Parent
// directories are not emitted as entries: the extraction creates missing ones
// itself (0755, root-owned) and — unlike an explicit directory entry — leaves
// the permissions of directories that already exist untouched.  Timestamps are
// pinned to the epoch so the archive is deterministic.
func filesArchive(files []File) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	epoch := time.Unix(0, 0)
	for _, f := range files {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     strings.TrimPrefix(f.Path, "/"),
			Mode:     int64(f.Mode.Perm()),
			Uid:      f.UID,
			Gid:      f.GID,
			Size:     int64(len(f.Data)),
			ModTime:  epoch,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("tar %q: %w", f.Path, err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, fmt.Errorf("tar %q: %w", f.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	return buf.Bytes(), nil
}

// Snapshot implements Backend.Snapshot.
// Commits the running container to a new image:
//
//	podman commit <container> <SnapshotRepo>-<id>:<label>
//
// If label is empty a short random suffix is used.
func (b *PodmanBackend) Snapshot(ctx context.Context, id string, label string) (SnapshotRef, error) {
	if err := validID(id); err != nil {
		return SnapshotRef{}, err
	}
	if label == "" {
		label = fmt.Sprintf("snap-%d", rand.IntN(1_000_000))
	}
	// Namespace the image repository by sandbox id so snapshots of different
	// sandboxes cannot collide / overwrite one another.
	tag := fmt.Sprintf("%s-%s:%s", b.cfg.SnapshotRepo, id, label)
	args := []string{"commit", b.containerName(id), tag}
	if _, _, err := b.podman(ctx, args, nil); err != nil {
		return SnapshotRef{}, fmt.Errorf("sandbox snapshot %s: %w", id, err)
	}
	b.log.Info("sandbox: snapshot created", "sandbox", id, "ref", tag)
	return SnapshotRef{Ref: tag, Label: label}, nil
}

// RemoveSnapshot implements Backend.RemoveSnapshot.
// It removes the snapshot image (`podman rmi <ref>`), tolerating a missing
// image so callers can use it best-effort when retiring a sandbox.
func (b *PodmanBackend) RemoveSnapshot(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if _, _, err := b.podman(ctx, []string{"rmi", ref}, nil); err != nil {
		if isNotFoundErr(err) {
			b.log.Debug("sandbox remove-snapshot: image not found", "ref", ref, "err", err)
			return nil
		}
		return fmt.Errorf("sandbox remove-snapshot %s: %w", ref, err)
	}
	b.log.Info("sandbox: snapshot image removed", "ref", ref)
	return nil
}

// Restore implements Backend.Restore.
// Stops and removes the current container, then re-creates it from the
// snapshot image, preserving the existing work volume and resource settings.
//
// NOTE: Because PodmanBackend is stateless (no stored Spec), Restore re-creates
// the container with minimal flags (just volume, label, and image).  Call
// Create with the original Spec if you need the full resource limits back
// after a Restore.
func (b *PodmanBackend) Restore(ctx context.Context, id string, ref SnapshotRef) (Handle, error) {
	if err := validID(id); err != nil {
		return Handle{}, err
	}
	cname := b.containerName(id)
	vol := b.volumeName(id)

	// Stop and remove current container.
	if _, _, err := b.podman(ctx, []string{"stop", cname}, nil); err != nil {
		b.log.Debug("sandbox restore: stop error (may be already stopped)", "id", id)
	}
	if _, _, err := b.podman(ctx, []string{"rm", "--force", cname}, nil); err != nil {
		return Handle{}, fmt.Errorf("sandbox restore rm %s: %w", id, err)
	}

	// Re-create from the snapshot image.
	args := []string{
		"run", "-d",
		"--name", cname,
		"--label", b.cfg.LabelKey + "=" + id,
		"--volume", vol + ":/work",
		ref.Ref,
	}
	stdout, _, err := b.podman(ctx, args, nil)
	if err != nil {
		return Handle{}, fmt.Errorf("sandbox restore run %s: %w", id, err)
	}

	containerID := strings.TrimSpace(string(stdout))
	b.log.Info("sandbox: restored from snapshot", "sandbox", id, "ref", ref.Ref)

	return Handle{
		ID:          id,
		ContainerID: containerID,
		Endpoints:   map[string]string{},
	}, nil
}

// ---- podman inspect JSON structures ----------------------------------------

// podmanInspect is the minimal subset of `podman inspect` JSON that we need.
// The full output is much larger; we only decode what we use to avoid fragility.
type podmanInspect struct {
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// Inspect implements Backend.Inspect.
// Parses `podman inspect --type container --format json <container>` to
// determine running state and the current host-port mappings.
//
// `--type container` is load-bearing and every inspect on this backend carries
// it.  Bare `podman inspect NAME` searches containers *and* images, which breaks
// this method twice over on a sandbox that does not exist: podman reports
// `no such object: "NAME"` — a phrase no classifier here matches, so the absence
// never becomes ErrSandboxNotFound and the caller sees an opaque exit 125
// forever — and if an image happens to answer to that name it succeeds instead,
// returning image JSON whose State.Running is false, so a missing sandbox reads
// as a stopped one. With the type pinned podman says `no such container NAME`,
// which isNoSuchContainer does match, and nothing but a container can answer.
func (b *PodmanBackend) Inspect(ctx context.Context, id string) (Status, error) {
	if err := validID(id); err != nil {
		return Status{}, err
	}
	stdout, _, err := b.podman(ctx, []string{"inspect", "--type", "container", "--format", "json", b.containerName(id)}, nil)
	if err != nil {
		// If the container doesn't exist, surface ErrSandboxNotFound.
		if isNoSuchContainer(err) {
			return Status{}, fmt.Errorf("sandbox inspect %s: %w", id, ErrSandboxNotFound)
		}
		return Status{}, fmt.Errorf("sandbox inspect %s: %w", id, err)
	}

	// podman inspect returns a JSON array even for a single container.
	var inspects []podmanInspect
	if err := json.Unmarshal(stdout, &inspects); err != nil {
		return Status{}, fmt.Errorf("sandbox inspect %s: parse JSON: %w", id, err)
	}
	if len(inspects) == 0 {
		return Status{}, fmt.Errorf("sandbox inspect %s: %w", id, ErrSandboxNotFound)
	}

	info := inspects[0]
	endpoints := make(map[string]string)
	for portProto, bindings := range info.NetworkSettings.Ports {
		if len(bindings) == 0 {
			continue
		}
		// portProto is e.g. "6080/tcp" or "8080/tcp".
		// Map to known endpoint keys by container port number.
		containerPortStr := strings.SplitN(portProto, "/", 2)[0]
		hp := bindings[0].HostPort
		if hp == "" {
			continue
		}
		host := bindings[0].HostIP
		if host == "" {
			host = "127.0.0.1"
		}
		key := containerPortStr // use the container port as key if unrecognised
		switch containerPortStr {
		case "6080":
			key = "desktop"
		default:
			key = "web" // any other published port is assumed to be the web endpoint
		}
		endpoints[key] = fmt.Sprintf("http://%s:%s", host, hp)
	}

	return Status{
		Running:   info.State.Running,
		Endpoints: endpoints,
	}, nil
}

// DesktopEndpoint implements Backend.DesktopEndpoint.
func (b *PodmanBackend) DesktopEndpoint(ctx context.Context, id string) (string, error) {
	status, err := b.Inspect(ctx, id)
	if err != nil {
		return "", err
	}
	if !status.Running {
		return "", fmt.Errorf("sandbox desktop endpoint %s: container not running", id)
	}
	ep, ok := status.Endpoints["desktop"]
	if !ok {
		return "", fmt.Errorf("sandbox desktop endpoint %s: %w", id, ErrWrongProfile)
	}
	return ep, nil
}

// WebEndpoint implements Backend.WebEndpoint.
func (b *PodmanBackend) WebEndpoint(ctx context.Context, id string) (string, error) {
	status, err := b.Inspect(ctx, id)
	if err != nil {
		return "", err
	}
	if !status.Running {
		return "", fmt.Errorf("sandbox web endpoint %s: container not running", id)
	}
	ep, ok := status.Endpoints["web"]
	if !ok {
		return "", fmt.Errorf("sandbox web endpoint %s: %w", id, ErrWrongProfile)
	}
	return ep, nil
}

// ContainerAddr implements Backend.ContainerAddr.
// It resolves the container's bridge IP via
// `podman inspect --format '{{.NetworkSettings.IPAddress}}'` and returns
// "<ip>:<port>" for the host to dial directly.  A missing container is mapped
// to ErrSandboxNotFound; an empty IP (container stopped / no NIC) is a clear
// error so the proxy can surface a 502 rather than crash.
func (b *PodmanBackend) ContainerAddr(ctx context.Context, id string, port int) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	stdout, _, err := b.podman(ctx, []string{"inspect", "--type", "container", "--format", "{{.NetworkSettings.IPAddress}}", b.containerName(id)}, nil)
	if err != nil {
		if isNoSuchContainer(err) {
			return "", fmt.Errorf("sandbox container addr %s: %w", id, ErrSandboxNotFound)
		}
		return "", fmt.Errorf("sandbox container addr %s: %w", id, err)
	}
	ip := strings.TrimSpace(string(stdout))
	if ip == "" {
		return "", fmt.Errorf("sandbox container addr %s: container has no IP address (not running or no network)", id)
	}
	return net.JoinHostPort(ip, strconv.Itoa(port)), nil
}
