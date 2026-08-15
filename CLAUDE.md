# keel — project instructions

Read `README.md` first, particularly "The rule". keel is a shared core for a family of
self-hosted projects; its value comes entirely from staying small and staying free of
anyone's domain model.

## The rule, restated because it is the whole point

**keel owns mechanisms. Consuming products own their domain model and their schema.**

Enforceable form:

- keel imports nothing from its consumers.
- **No exported keel identifier contains or accepts a product domain noun** — no `Org`,
  `User`, `Workspace`, `Space`, `Member`, `Role`.

When a function needs one of those, it belongs in the product instead. This constraint
is what stops a shared core from accreting into a framework, which is the normal fate of
these. Enforce it on every change; a single exception is how it starts.

**The carve-out** — where a term is the vocabulary of an external protocol or tool keel
wraps, keel uses that term. `llm.ChatMessage.Role` keeps its name because that is the
field's name in every provider API and in the JSON on the wire. The rule keeps someone
else's *product model* out of keel; it does not require inventing private names for
public protocols. Permissive, not mandatory: where an equally clear alternative exists,
prefer it (`sandbox.ExecOpts.RunAs` over `User`).

Before adding a package, ask whether it has two real consumers. A shared library
designed against one consumer is a guess.

## Ground rules

- **Git identity**: commit as `BlueHeisenberg <2033896+BlueHeisenberg@users.noreply.github.com>`.
  The global git config on this machine is a work identity, so set it locally.
- **Remotes** use the SSH host alias `github-personal`.
- **Apache-2.0.** Every file starts `// SPDX-License-Identifier: Apache-2.0`. Permissive
  is deliberate: there is no product moat in a sandbox wrapper or a key-sealing routine,
  and permissive means these packages can be imported by anything later without a
  licence conversation.
- **Sole copyright.** No outside contribution before a CLA exists.
- **Dependencies stay near zero.** A module imported into everything must not drag a
  tree behind it. Adding a third-party dependency needs a reason written in the commit.

## Provenance

Most packages were extracted from `the-harness`, where they were built and tested
against real Podman, real QEMU and real providers. Extraction preserved the test suites
deliberately: that testing is the expensive part, and it is why these packages were
inherited rather than rewritten.

Where a defect was found during extraction it was fixed at the time — while there was no
deployed data to migrate — rather than carried across. The vault's envelope format is
the example: the extraction added AAD binding and a version byte because doing it later
would have meant a data migration.

## Working style

- Tests come with the code and run under `-race`.
- `sandbox` is Linux-only in behaviour but must **compile** on Windows and macOS;
  consumers gate construction on `runtime.GOOS`. Where a backend cannot work, return a
  typed error, never panic.
- Public API is not stable before `v1.0.0`, but breaking it still costs a consumer a
  day, so break it on purpose.
- Package docs state plainly what a package does and does not defend against. The
  `vault` and `update` package docs carry threat models; keep them honest.
