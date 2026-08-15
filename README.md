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
function signature contains a domain noun — no `Org`, `User`, `Workspace`, `Space`,
`Member` or `Role`. The moment a function needs one of those, it belongs in the product
instead.

That single constraint is what stops a shared core from accreting into a framework.

## Packages

| Package | What it is |
| --- | --- |
| `sandbox` | Process isolation with pluggable backends (Podman, QEMU) behind one `Backend` interface. Linux hosts |
| `vault` | Passphrase-sealed secret storage with argon2-derived keys. Persistence is an interface the caller supplies |
| `llm` | OpenAI-compatible provider client: completions, streaming, sanitisation |
| `update` | Signed, atomic, self-rolling-back binary updates |
| `ids` | Identifier generation |
| `log` | `slog` helpers |

Dependencies are kept near zero by design — a module you import into everything must
not drag a tree behind it.

## Status

Early. Packages are being extracted from the-harness, where they were built and
tested against real Podman, real QEMU and real providers. Extraction preserves the
test suites; if a package is here, its tests came with it.

The API is not stable before `v1.0.0`.

## Licence

Apache License 2.0. Permissive on purpose: there is no product moat in a sandbox
wrapper or a key-sealing routine, and permissive licensing means these packages can be
imported by anything without anyone having to think about it.

Products built on keel are licensed separately and may not be permissive.
