// SPDX-License-Identifier: Apache-2.0

// Package sandbox runs untrusted workloads in an isolated environment behind a
// single Backend interface.
//
// Two backends ship with it. PodmanBackend starts one container per sandbox:
// fast, cheap, and sharing the host kernel. QemuBackend starts one virtual
// machine per sandbox: slower, and isolated at the hardware boundary. Both
// shell out to their tool (podman, qemu-system) through an injectable runner,
// so the entire host-side surface — argument vectors, QMP control, vsock
// dialling — is testable without either tool installed.
//
// # Identity
//
// A sandbox is identified by Spec.Name, a string the caller chooses. It becomes
// the container or VM name, the work volume name, a container label, and the
// per-sandbox state directory, so it must match [A-Za-z0-9_-]+. Beyond that,
// sandbox attaches no meaning to it: what a name refers to, and whether two
// sandboxes belong to the same anything, is the caller's model, not this
// package's.
//
// # Configuration
//
// Backends take a Config. Its zero value is usable, every field has a neutral
// default, and nothing is read from the environment unless the caller asks for
// it with ConfigFromEnv. Naming — container prefix, label key, snapshot
// repository, firewall table — is configurable so that a product can brand its
// own resources without this package knowing the brand.
//
// # Data lifetime
//
// A sandbox's work volume (its overlay disk, for QEMU) is where the caller's
// data lives, and exactly one method deletes it: Purge. Recreate replaces the
// container — new image included — against the existing volume, and is built
// so the volume-deleting code is not reachable from it; use it for rolling
// image updates. The split is deliberate after a consumer nearly lost data to
// the old Destroy, whose name said "infrastructure" and whose effect included
// "and the data" (it was renamed to Purge in v0.5.0 so migrating callers must
// decide which operation they meant).
//
// The guarantee is mechanical: the volume survives Recreate. Whether the new
// image can read what the old image wrote is the consumer's compatibility
// problem — this package owns the mechanism, the consumer owns its schema and
// any migration between versions of it. Recreate also does no sequencing:
// rolling sandboxes one at a time is the caller's policy, not this package's.
//
// # What reaches the host's process list
//
// Everything on a tool's argv is world-readable on the host for as long as the
// tool runs (ps, /proc/<pid>/cmdline), and callers put credentials in Spec.Env.
// This package therefore never places an environment VALUE on an argv: Spec.Env
// and ExecOpts.Env travel as name-only "--env K" flags, with the values passed
// through the tool's own process environment, which the kernel exposes only to
// the same user and root. Spec.Files content travels on stdin. Error strings
// keep the same discipline: a tool's stderr — which can quote fragments of its
// invocation — is withheld from Error and available through
// [CommandError.Detail] for whoever deliberately asks.
//
// # Portability
//
// This package compiles on every platform Go supports, and is functionally
// Linux-only. Cross-platform programs can import it, reference its types, and
// decide at runtime whether to construct a backend; nothing fails at build or
// init time. Off Linux, three things do not work:
//
//   - Egress lockdown needs the host's nft and nsenter. Since an empty
//     Spec.NetworkPolicy means NetworkPolicyInternalOnly, the default
//     configuration cannot create a Podman sandbox anywhere else: Create fails
//     closed with ErrEgressUnavailable rather than running a workload with
//     unconfirmed egress restrictions. Only NetworkPolicyNone and
//     NetworkPolicyOpen skip that step.
//   - The QEMU guest control bridge rides on AF_VSOCK, which exists only on
//     Linux. VMs may still boot under hvf (macOS) or whpx (Windows), but Exec,
//     WriteFile, and ReadFile return ErrQemuGuestUnavailable.
//   - QEMU pidfile liveness checks degrade to "assume running".
//
// The failures are all typed errors returned from method calls. Callers meant
// to run everywhere should gate construction on runtime.GOOS == "linux" and say
// "sandboxing requires Linux" in their own words, rather than letting one of
// these errors surface to a user who cannot act on it.
package sandbox
