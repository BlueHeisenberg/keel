// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"fmt"
)

// Sentinel errors. None of them ever carry key material, passphrase content
// or plaintext; they are safe to log.
var (
	// ErrNoKey is returned by Keyring.Load when no key record has been
	// persisted yet. Keyring implementations must map their store's
	// not-found condition to this value (wrapping is fine; errors.Is must
	// hold).
	ErrNoKey = errors.New("vault: no key record")

	// ErrBadPassphrase is returned by Open and Rotate when the supplied
	// passphrase cannot unwrap the stored data key. It deliberately covers
	// three indistinguishable cases: a wrong passphrase, a corrupted key
	// record, and an absent key record. Callers who need to know whether a
	// vault has been initialised must ask their own Keyring, not this error.
	ErrBadPassphrase = errors.New("vault: bad passphrase")

	// ErrClosed is returned by Seal, Open and Rotate after Close has been
	// called. A closed Vault cannot be reused; call the package-level Open
	// again with the passphrase.
	ErrClosed = errors.New("vault: closed")

	// ErrKeyringExists is returned by Init when the keyring already holds a
	// key record. Use Open to unlock an existing vault.
	ErrKeyringExists = errors.New("vault: keyring already initialised")

	// ErrDecryptionFailed is returned by Vault.Open when an envelope is
	// structurally valid but fails authenticated decryption. It deliberately
	// does not distinguish a wrong key, a mismatched AAD, or a tampered or
	// truncated ciphertext.
	ErrDecryptionFailed = errors.New("vault: decryption failed")

	// ErrInvalidEnvelope is returned by Vault.Open when a blob is too short
	// to be an envelope at all.
	ErrInvalidEnvelope = errors.New("vault: invalid envelope")

	// ErrEmptyAAD is returned by Seal and Open when the additional
	// authenticated data is empty. AAD is mandatory: it binds a ciphertext to
	// the record it belongs to, and an empty binding defeats that purpose.
	ErrEmptyAAD = errors.New("vault: empty additional authenticated data")

	// ErrEmptyPassphrase is returned by Init and Rotate when asked to protect
	// key material under an empty passphrase.
	ErrEmptyPassphrase = errors.New("vault: empty passphrase")
)

// UnknownVersionError is returned by Vault.Open (and by the package-level
// Open, folded into ErrBadPassphrase, when the wrapped key itself is
// affected) for an envelope whose version byte this build does not
// understand. It usually means the data was written by a newer version of
// this package.
type UnknownVersionError struct {
	// Version is the unrecognised version byte.
	Version byte
}

// Error implements the error interface.
func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("vault: unknown envelope version 0x%02x", e.Version)
}
