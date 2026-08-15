// SPDX-License-Identifier: Apache-2.0

// Package update implements signed, atomic, self-rolling-back binary
// self-updates for long-running, unattended processes.
//
// The pipeline is: fetch a signed release manifest, verify its Ed25519
// signature against public keys compiled into the consuming binary, select
// the release for the configured channel, download the artifact next to the
// running binary, verify its digest against the signed manifest, obtain
// human consent when required, drain in-flight work, swap the binary while
// retaining the previous one, restart, health-check the new build, and
// either commit or automatically roll back to the retained binary. A failed
// update must leave a working system; that property dominates every other
// design decision in this package.
//
// # Threat model
//
// An auto-update channel is, by construction, a remote code execution
// channel into the consuming process. This package assumes the update host
// is hostile.
//
// An attacker who fully controls the update host, or the network path to
// it, can:
//
//   - withhold updates entirely (denial of service against updating, never
//     against the running product);
//   - replay an old, still-correctly-signed manifest — bounded by
//     Config.MaxManifestAge when set, and never resulting in a version below
//     the one already running;
//   - observe check-in metadata: the requesting IP and which platform
//     artifact is downloaded. The client sends no identity and no version
//     information.
//
// The same attacker cannot:
//
//   - execute code on any deployment: every manifest must carry a valid
//     Ed25519 signature from a release key the update host never holds, and
//     the artifact digest is part of the signed payload, so neither the
//     manifest nor the artifact can be forged or tampered with;
//   - downgrade a deployment below its running version;
//   - apply a major version bump, or any release flagged SecuritySensitive,
//     without a human agreeing through the consumer's Consent hook.
//
// An attacker who obtains a release signing private key owns every
// deployment that updates. Key custody is the root of trust; nothing in
// this package can compensate for a leaked signing key. Multiple trusted
// public keys are supported so that keys can be rotated: ship a build
// trusting both the old and new key, start signing with the new key, then
// drop the old key in a later release.
//
// # Health checks
//
// The health check supplied in Config.Health decides whether a freshly
// swapped binary is kept or rolled back. It must test only what the process
// itself controls: that it started, that its own dependencies loaded, that
// its local services respond. Availability of external resources must NOT
// be part of health: a household's inference machines are legitimately
// powered off much of the time, and treating an unreachable endpoint as
// "unhealthy" would roll back a perfectly good update, re-apply it on the
// next check, and roll it back again — an endless loop that ends with a
// wedged installation. Health means "this binary works", not "the world is
// reachable".
//
// # The swap, exactly
//
// Staging, the previous-binary copy, and the final rename all happen inside
// the directory of the target binary, so every step is a same-filesystem
// operation and the install itself is a rename, never a cross-device copy.
//
// On POSIX the final step is a single atomic rename over the target: there
// is no instant at which the target path lacks a complete binary. On
// Windows a running executable cannot be replaced in place, but it can be
// renamed, so the sequence is rename-running-aside then place-new; the
// window between those two renames is unavoidable there and is covered by
// the journal plus the retained copy, which Resume uses to repair.
//
// A journal file written next to the target records every update in flight.
// Call (*Updater).Resume early at startup, every startup: it is what
// completes, commits, rolls back, or repairs an update after the restart —
// including after a crash at any point in the sequence.
package update
