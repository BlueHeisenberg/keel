// SPDX-License-Identifier: Apache-2.0

package vault

import "context"

// KeyRecord is the persisted wrapped-key material for one vault. All fields
// are opaque to the caller; only this package interprets them. A KeyRecord
// contains no secrets in the clear — it is safe to store anywhere the sealed
// data itself is stored — but anyone who can replace it can deny access, so
// treat it with the same write protection as the data.
type KeyRecord struct {
	// ID is a stable record identity chosen at Init (currently always
	// "default") and preserved across Rotate. Keyring implementations may
	// use it as a storage key or ignore it.
	ID string

	// Salt is the KDF salt. Regenerated on every Rotate.
	Salt []byte

	// Params is the JSON-encoded key-derivation configuration. It travels
	// with the record so parameters can be raised over time without breaking
	// existing vaults.
	Params []byte

	// WrappedKey is the data-encryption key sealed under the
	// passphrase-derived key-encryption key, in the same versioned envelope
	// format as Vault.Seal output.
	WrappedKey []byte
}

// Keyring persists exactly one KeyRecord. It is the only storage dependency
// of this package; the consuming product implements it against its own
// schema (a database row, a file, an OS keystore entry).
//
// Implementations must be safe for concurrent use if the Vault is shared
// across goroutines that call Rotate.
type Keyring interface {
	// Load returns the persisted record, or an error satisfying
	// errors.Is(err, ErrNoKey) if none exists.
	Load(ctx context.Context) (KeyRecord, error)

	// Save writes the record, replacing any existing one.
	Save(ctx context.Context, rec KeyRecord) error
}
