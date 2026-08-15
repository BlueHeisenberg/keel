# keel

**Domain-free Go mechanisms for self-hosted agent systems.**

keel is the structural core shared by [kenward](https://github.com/BlueHeisenberg/kenward)
and its ancestor [the-harness](https://github.com/BlueHeisenberg/the-harness): process
isolation, sealed secret storage, an OpenAI-compatible model client, and seamless
self-update. It is deliberately small, deliberately boring, and deliberately knows
nothing about whatever product is using it.

## The rule

**keel owns mechanisms. Consuming products own their domain model and their schema.**

The enforceable version: keel imports nothing from its consumers, and no exported keel
function signature contains a **product** domain noun — no `Org`, `User`, `Workspace`,
`Space`, `Member` or `Role`. The moment a function needs one of those, it belongs in the
product instead.

That single constraint is what stops a shared core from accreting into a framework.

**One carve-out, because two extractions ran into it.** Where a term is the vocabulary of
an external protocol or tool that keel is wrapping, keel uses that term. `ChatMessage.Role`
stays `Role` because that is what the field is called in every provider's API, in the JSON
on the wire, and in the head of anyone who will use the package; renaming it would satisfy
the letter of the rule by making the library surprising to its entire audience. The rule
exists to keep *someone else's product model* out of keel, not to make keel invent private
names for public protocols.

The carve-out is permissive, not mandatory. Where an equally clear alternative exists,
prefer it — `sandbox.ExecOpts.RunAs` reads at least as well as `User` and removes the
ambiguity, so it stays renamed.

## Packages

| Package | What it is |
| --- | --- |
| `sandbox` | Process isolation with pluggable backends (Podman, QEMU) behind one `Backend` interface. Linux hosts |
| `vault` | Passphrase-sealed secret storage with argon2-derived keys. Persistence is an interface the caller supplies |
| `llm` | OpenAI-compatible provider client: completions, streaming, sanitisation |
| `update` | Self-updating binaries: signed manifests verified against multiple trusted keys, a preflight run of the staged binary before it is swapped in, an atomic swap with automatic rollback, a cross-process lock, channels including `off`, and an exported signing surface (`SignPayload`, `Envelope`, `ParseEnvelope`, `VerifyPayload`, `SignerIDs`, `ManifestSchema`) for release tooling |
| `ids` | Identifier generation |
| `log` | `slog` helpers, including secret redaction |

Dependencies are kept near zero by design — a module you import into everything must
not drag a tree behind it. As of v0.2.0 that is two direct dependencies,
`golang.org/x/crypto` (Argon2id, in `vault`) and `golang.org/x/sys` (vsock and
signal handling, in `sandbox`), both from the Go team and each used narrowly. A CI
dependency budget checks `go.mod` stays tidy and reports the direct dependency list
on every build, so a new one can't be added silently.

## Known limitations

Recorded here rather than only in package docs, because each one is the kind of thing a
caller could reasonably assume the opposite of.

**`sandbox` — the two backends do not have equivalent network isolation.** The Podman
backend enforces egress policy and fails closed. The QEMU backend currently does not
enforce it at all: both `NetworkPolicyFiltered` and `NetworkPolicyInternalOnly` produce
plain user-mode networking. A caller assuming parity between backends is wrong today, so
choose Podman where egress policy is load-bearing.

**`sandbox` — `AllowDomains` pins IP addresses at creation time** via a single lookup.
DNS rotation silently breaks the allowlist, and a lookup that fails is skipped rather
than raised.

**`sandbox` — QEMU guest context IDs are allocated per-process and in-memory.** Two
backend instances, or a restart, can hand the same CID to different sandboxes.

**`sandbox` — liveness detection is Linux-only in practice.** Off Linux, QEMU's
pidfile liveness check degrades to assuming the VM is still running; only the Linux
path does a real check, probing the recorded pid with signal 0.

**`vault` — AAD is anti-confusion, not authorization.** An open vault will decrypt any
record whose AAD the caller supplies. The confused-deputy hole is closed only if callers
pass the identity they were *asked for*, never one read out of the record they just
fetched. Passing an id taken from stored data reconstructs the hole with extra steps,
and every test still passes.

**`vault` — the key record has no freshness or monotonicity.** Anyone who can write it
can roll it back to an earlier version and re-enable a passphrase that was rotated away.
Treat keyring writes with the same care as data writes.

**`vault` — every unlock allocates 64 MiB for Argon2id.** An unlock path reachable from
untrusted input is a memory-exhaustion lever. Bound derivation concurrency and rate-limit
attempts in the caller; the package deliberately has no opinion about who is allowed to
try.

**`vault` — there is no DEK rotation.** `Rotate` changes the passphrase, not the data
key. A leaked data key means re-sealing everything.

## Versions

**v0.1.0** — first release. All six packages extracted from the-harness, where
they were built and tested against real Podman, real QEMU and real providers;
extraction preserved the test suites, so if a package is here, its tests came
with it. `update` landed already hardened: signed manifests, preflight, atomic
swap with rollback, and cross-process locking.

**v0.2.0** — `update` gained an exported signing surface (`SignPayload`,
`Envelope`, `ParseEnvelope`, `VerifyPayload`, `SignerIDs`, `ManifestSchema`) so
release tooling can add a signature to an existing manifest, including for key
rotation, without re-encoding or invalidating the signatures already on it. CI
now enforces the dependency budget on every build.

## Status

Extraction from the-harness is complete: every package in the table above has
been pulled out, hardened on its own, and released. That does not make the
module finished — it makes it a foundation other things can now be built on.

The API is not stable before `v1.0.0`.

## Licence

Apache License 2.0. Permissive on purpose: there is no product moat in a sandbox
wrapper or a key-sealing routine, and permissive licensing means these packages can be
imported by anything without anyone having to think about it.

Products built on keel are licensed separately and may not be permissive.
