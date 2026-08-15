// SPDX-License-Identifier: Apache-2.0

// Package vault provides passphrase-gated envelope encryption over opaque
// byte slices.
//
// A single random 32-byte data-encryption key (DEK) seals every value with
// AES-256-GCM. The DEK itself is wrapped under a key-encryption key (KEK)
// derived from an operator passphrase with Argon2id; the salt, the KDF
// parameters and the wrapped DEK are persisted through a caller-supplied
// [Keyring]. The DEK and KEK are never persisted.
//
// vault owns no schema and does no I/O on the data path. [Init] creates key
// material, [Open] unlocks it, and [Vault.Seal] / [Vault.Open] transform
// bytes in memory; where sealed values are stored is entirely the caller's
// business.
//
// # Envelope format
//
// Every sealed value (including the wrapped DEK inside the [KeyRecord]) is a
// self-describing envelope:
//
//	version(1 byte) || nonce(12 bytes) || AES-256-GCM ciphertext+tag
//
// Version 0x01 is the only version defined today. The version byte is
// authenticated: it is prepended to the additional authenticated data, so it
// cannot be altered without failing the GCM tag. A future algorithm change is
// a new version byte and a new code path, not a data migration; envelopes
// with an unknown version are rejected with [UnknownVersionError].
//
// # Additional authenticated data
//
// Seal and Open take an explicit, mandatory AAD parameter. The AAD is bound
// into the GCM tag: an envelope sealed under one AAD cannot be opened under
// another. Callers must pass the identity of the record the ciphertext
// belongs to (a record ID, a filename, a column key), which defeats
// ciphertext relocation — copying a sealed blob from record A into record B
// and having the system decrypt it as B. AAD is authenticated, not encrypted,
// and must never contain secrets.
//
// # Threat model
//
// vault defends against:
//
//   - Offline theft of the keyring and ciphertexts: recovering plaintext
//     requires the passphrase; Argon2id (64 MiB, by default) makes guessing
//     expensive. The protection is only as strong as the passphrase.
//   - Ciphertext tampering and truncation: AES-GCM authentication.
//   - Ciphertext relocation between records: mandatory AAD binding.
//   - Keyring-existence probing through the unlock path: a wrong passphrase
//     and an absent keyring return the identical [ErrBadPassphrase] value,
//     and the absent-keyring path performs a decoy key derivation so the two
//     take comparable time (best effort; see [Open]).
//
// vault does NOT defend against:
//
//   - An attacker who can read the process's memory while the vault is open:
//     the DEK is in memory by construction, as is any plaintext in flight.
//   - A compromised host that observes passphrase entry or patches this code.
//   - Weak passphrases: Argon2id slows brute force; it cannot repair a
//     guessable passphrase.
//   - Complete key erasure. Close and the internal helpers overwrite key
//     buffers when finished, but Go's runtime gives no guarantee: the
//     compiler may keep copies in registers, stack growth and the garbage
//     collector may have copied buffers, and passphrase strings cannot be
//     zeroed at all. Erasure narrows the window in which a memory dump
//     captures key material; it does not close it.
//
// There is no path to retire a compromised DEK short of re-encrypting every
// stored value under a new vault; [Vault.Rotate] rotates the passphrase
// (the KEK), never the DEK. Products that need DEK rotation must enumerate
// and re-seal their own records.
package vault
