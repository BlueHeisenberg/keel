// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os/exec"
	"strconv"
	"strings"
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
	// Returns stdout, stderr, and any execution error.
	// A non-zero exit code is surfaced as an *exec.ExitError inside err.
	Run(ctx context.Context, args []string, stdin []byte) (stdout, stderr []byte, err error)
}

// execRunner is the production runner backed by os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, errors.New("runner: empty args")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
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
	full := append([]string{b.cfg.PodmanBinary}, args...)
	stdout, stderr, err := b.r.Run(ctx, full, stdin)
	if err != nil {
		// Detect "not found" from exec.LookPath or PATH execution errors.
		var execErr *exec.Error
		if errors.As(err, &execErr) && execErr.Err == exec.ErrNotFound {
			return nil, nil, fmt.Errorf("%w: %s", ErrPodmanUnavailable, execErr.Err)
		}
		// Exit error — wrap with %w to preserve the *exec.ExitError in the chain
		// so that Exec() can unwrap it for the exit code, while still embedding
		// stderr text for human-readable log/error messages.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout, stderr, fmt.Errorf("podman %s: exit %d: %s: %w",
				args[0], exitErr.ExitCode(), strings.TrimSpace(string(stderr)), exitErr)
		}
		return nil, nil, fmt.Errorf("podman %s: %w", args[0], err)
	}
	return stdout, stderr, nil
}

// Create implements Backend.Create.
//
// The function:
//  1. Picks a random host port for the noVNC or web endpoint.
//  2. Creates a named volume for /work.
//  3. Runs `podman run -d` with the resource limits and labels from Spec.
//  4. Returns a Handle with the resolved ContainerID and Endpoints.
//
// The container is started immediately (podman run -d).
func (b *PodmanBackend) Create(ctx context.Context, spec Spec) (Handle, error) {
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
			return Handle{}, fmt.Errorf("sandbox create: %w", err)
		}
	}

	// The sandbox is identified by the caller-supplied name.
	sandboxID := spec.Name

	// Validate the id before it reaches container/volume names or podman args.
	if err := validID(sandboxID); err != nil {
		return Handle{}, err
	}

	// Resolve the image before creating anything, so a misconfigured backend
	// does not leave an orphaned volume behind.
	image := spec.Image
	if image == "" {
		image = b.cfg.Image
	}
	if image == "" {
		return Handle{}, fmt.Errorf("sandbox create %s: no image: set Spec.Image or Config.Image", sandboxID)
	}

	vol := b.volumeName(sandboxID)
	cname := b.containerName(sandboxID)

	// Ensure the named volume exists (idempotent).
	if _, _, err := b.podman(ctx, []string{"volume", "create", vol}, nil); err != nil {
		return Handle{}, fmt.Errorf("sandbox create volume: %w", err)
	}

	policy := effectivePolicy(spec.NetworkPolicy)

	// Build `podman run` arguments.
	args := []string{
		"run", "-d",
		"--name", cname,
		"--label", b.cfg.LabelKey + "=" + spec.Name,
		"--volume", vol + ":/work",
		"--env", "PROFILE=" + string(spec.Profile),
	}

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

	// Extra environment variables.
	for k, v := range spec.Env {
		args = append(args, "--env", k+"="+v)
	}

	// Port mapping — bind to loopback only.
	if containerPort > 0 {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d", hostPort, containerPort))
	}

	// Image must be last.
	args = append(args, image)

	b.log.Debug("sandbox: creating container",
		"sandbox", spec.Name,
		"profile", spec.Profile,
		"image", image,
	)

	stdout, _, err := b.podman(ctx, args, nil)
	if err != nil {
		return Handle{}, fmt.Errorf("sandbox create container: %w", err)
	}

	// stdout is the full container ID (64-hex chars + newline).
	containerID := strings.TrimSpace(string(stdout))

	// ── Host-applied egress lockdown (H3/H4) ─────────────────────────────────
	// For internal-only/filtered, apply the nftables ruleset from the HOST into
	// the container's netns and then VERIFY it is active.  This is fail-closed:
	// any failure destroys the container and returns an error so we never run a
	// sandbox with unconfirmed egress restrictions.
	if policy == NetworkPolicyInternalOnly || policy == NetworkPolicyFiltered {
		if err := b.applyHostEgress(ctx, sandboxID, containerID, policy, spec.AllowDomains); err != nil {
			// Best-effort teardown; surface the original error.
			if derr := b.Destroy(ctx, sandboxID); derr != nil {
				b.log.Warn("sandbox: egress lockdown failed and cleanup also failed",
					"sandbox", spec.Name, "egress_err", err, "cleanup_err", derr)
			}
			return Handle{}, fmt.Errorf("sandbox create: egress lockdown: %w", err)
		}
	}
	// ── end host-applied egress ──────────────────────────────────────────────

	endpoints := make(map[string]string)
	if containerPort > 0 && hostPort > 0 {
		endpoints[endpointKey] = fmt.Sprintf("http://127.0.0.1:%d", hostPort)
	}

	b.log.Info("sandbox: container created",
		"sandbox", spec.Name,
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
	if _, stderr, err := b.r.Run(ctx, nsArgs, []byte(ruleset)); err != nil {
		return fmt.Errorf("%w: nsenter nft load: %v: %s", ErrEgressUnavailable, err, strings.TrimSpace(string(stderr)))
	}

	// VERIFY the lockdown is active: the ip <EgressTable> table must exist in
	// the container netns.  Check via `podman exec` so we observe what the
	// container actually sees.
	if _, _, err := b.podman(ctx, []string{"exec", b.containerName(sandboxID), "nft", "list", "table", "ip", b.cfg.EgressTable}, nil); err != nil {
		// Fall back to checking from the host netns in case the container image
		// lacks the nft binary; the host check is authoritative.
		hostCheck := []string{"nsenter", "-t", pid, "-n", "nft", "list", "table", "ip", b.cfg.EgressTable}
		if _, _, herr := b.r.Run(ctx, hostCheck, nil); herr != nil {
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
	stdout, _, err := b.podman(ctx, []string{"inspect", "--format", "{{.State.Pid}}", b.containerName(sandboxID)}, nil)
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
	stdout, _, err := b.podman(ctx, []string{"inspect", "--format", "{{.NetworkSettings.Gateway}}", b.containerName(sandboxID)}, nil)
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
func (b *PodmanBackend) Start(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	_, _, err := b.podman(ctx, []string{"start", b.containerName(id)}, nil)
	if err != nil {
		return fmt.Errorf("sandbox start %s: %w", id, err)
	}
	return nil
}

// Stop implements Backend.Stop.
func (b *PodmanBackend) Stop(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	_, _, err := b.podman(ctx, []string{"stop", b.containerName(id)}, nil)
	if err != nil {
		return fmt.Errorf("sandbox stop %s: %w", id, err)
	}
	return nil
}

// Destroy implements Backend.Destroy.
// Stops the container (tolerates already-stopped), removes it, then removes
// the named work volume.
func (b *PodmanBackend) Destroy(ctx context.Context, id string) error {
	if err := validID(id); err != nil {
		return err
	}
	cname := b.containerName(id)
	vol := b.volumeName(id)

	// Stop — tolerate "already stopped" errors.
	if _, _, err := b.podman(ctx, []string{"stop", cname}, nil); err != nil {
		b.log.Debug("sandbox destroy: stop error (may be already stopped)", "id", id, "err", err)
	}

	// Remove container.  Tolerate a missing container ("no such container") so a
	// partially-provisioned sandbox still has its named volume reaped below.
	if _, _, err := b.podman(ctx, []string{"rm", "--force", cname}, nil); err != nil {
		if isNotFoundErr(err) {
			b.log.Debug("sandbox destroy: container not found, continuing to volume rm", "id", id, "err", err)
		} else {
			return fmt.Errorf("sandbox destroy rm %s: %w", id, err)
		}
	}

	// Remove work volume.  Tolerate a missing volume.
	if _, _, err := b.podman(ctx, []string{"volume", "rm", "--force", vol}, nil); err != nil {
		if isNotFoundErr(err) {
			b.log.Debug("sandbox destroy: volume not found", "id", id, "err", err)
		} else {
			return fmt.Errorf("sandbox destroy volume rm %s: %w", id, err)
		}
	}

	b.log.Info("sandbox: container destroyed", "sandbox", id)
	return nil
}

// Exec implements Backend.Exec.
func (b *PodmanBackend) Exec(ctx context.Context, id string, cmd []string, opts ExecOpts) (ExecResult, error) {
	if err := validID(id); err != nil {
		return ExecResult{}, err
	}
	args := b.buildExecArgs(id, cmd, opts)
	stdout, stderr, err := b.podman(ctx, args, nil)

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
	argSlice := b.buildExecArgs(id, cmd, opts)
	// prepend the binary name
	full := append([]string{b.cfg.PodmanBinary}, argSlice...)
	osCmd := exec.CommandContext(ctx, full[0], full[1:]...)

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
// prefix) for both Exec and ExecStream.
func (b *PodmanBackend) buildExecArgs(id string, cmd []string, opts ExecOpts) []string {
	args := []string{"exec"}
	if opts.WorkDir != "" {
		args = append(args, "--workdir", opts.WorkDir)
	}
	if opts.RunAs != "" {
		args = append(args, "--user", opts.RunAs)
	}
	for k, v := range opts.Env {
		args = append(args, "--env", k+"="+v)
	}
	args = append(args, b.containerName(id))
	args = append(args, cmd...)
	return args
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

// isNotFoundErr reports whether err (from a podman rm / volume rm / rmi call)
// indicates the target container, volume, or image simply does not exist.
// Such "not found" failures are tolerated during best-effort cleanup so a
// partially-provisioned sandbox does not orphan its other resources.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such container") ||
		strings.Contains(msg, "no container with name") ||
		strings.Contains(msg, "no such volume") ||
		strings.Contains(msg, "no volume with name") ||
		strings.Contains(msg, "no such image") ||
		strings.Contains(msg, "image not known")
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
// Parses `podman inspect --format json <container>` to determine running state
// and the current host-port mappings.
func (b *PodmanBackend) Inspect(ctx context.Context, id string) (Status, error) {
	if err := validID(id); err != nil {
		return Status{}, err
	}
	stdout, _, err := b.podman(ctx, []string{"inspect", "--format", "json", b.containerName(id)}, nil)
	if err != nil {
		// If the container doesn't exist, surface ErrSandboxNotFound.
		if strings.Contains(err.Error(), "no such container") ||
			strings.Contains(err.Error(), "no container with name or id") {
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
	stdout, _, err := b.podman(ctx, []string{"inspect", "--format", "{{.NetworkSettings.IPAddress}}", b.containerName(id)}, nil)
	if err != nil {
		if strings.Contains(err.Error(), "no such container") ||
			strings.Contains(err.Error(), "no container with name or id") {
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
