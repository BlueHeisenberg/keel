// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Vault holds the in-memory data-encryption key and seals/opens opaque byte
// slices. It is safe for concurrent use. Obtain one from Init (first run) or
// Open (existing keyring); a Vault whose Close has been called is dead and
// must be replaced by calling Open again.
type Vault struct {
	// mu guards dek. Readers (Seal, Open, Closed) take the read lock only
	// long enough to copy the key bytes into a private buffer; writers
	// (Close, Rotate) may therefore zero and replace the shared array in
	// place under the write lock without corrupting an in-flight operation.
	mu  sync.RWMutex
	dek []byte // nil once closed

	// rotateMu serialises Rotate end to end. Without it, two concurrent
	// rotations interleave their read-verify-rewrap-save sequences and the
	// persisted record can come from the loser, leaving one of the two new
	// passphrases silently non-functional.
	rotateMu sync.Mutex

	kr Keyring
}

// Option configures Init or Rotate.
type Option func(*options)

type options struct {
	params *KDFParams
}

// WithKDFParams overrides the key-derivation cost. For Init the default is
// DefaultKDFParams; for Rotate the default is whatever the existing record
// uses, so rotating a vault never silently downgrades an upgraded cost.
func WithKDFParams(p KDFParams) Option {
	return func(o *options) {
		cp := p
		o.params = &cp
	}
}

func applyOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Init creates key material for a keyring that has none: it generates a
// random salt and data key, derives the key-encryption key from the
// passphrase, wraps the data key, persists the record through kr, and
// returns the vault open.
//
// If the keyring already holds a record, Init returns ErrKeyringExists and
// changes nothing. The passphrase must be non-empty; it cannot be zeroed
// from memory afterwards (Go strings are immutable), so callers should avoid
// keeping additional copies.
func Init(ctx context.Context, kr Keyring, passphrase string, opts ...Option) (*Vault, error) {
	if passphrase == "" {
		return nil, ErrEmptyPassphrase
	}
	params := DefaultKDFParams()
	if o := applyOptions(opts); o.params != nil {
		params = *o.params
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	if _, err := kr.Load(ctx); err == nil {
		return nil, ErrKeyringExists
	} else if !errors.Is(err, ErrNoKey) {
		return nil, fmt.Errorf("vault: read keyring: %w", err)
	}

	salt, err := randomBytes(saltSize)
	if err != nil {
		return nil, err
	}
	dek, err := randomBytes(dekSize)
	if err != nil {
		return nil, err
	}

	kek := deriveKEK(passphrase, salt, params)
	wrapped, err := sealEnvelope(kek, dekWrapAAD, dek)
	zeroBytes(kek)
	if err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("vault: wrap data key: %w", err)
	}

	paramsJSON, err := marshalParams(params)
	if err != nil {
		zeroBytes(dek)
		return nil, err
	}

	rec := KeyRecord{ID: "default", Salt: salt, Params: paramsJSON, WrappedKey: wrapped}
	if err := kr.Save(ctx, rec); err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("vault: persist key record: %w", err)
	}
	return &Vault{dek: dek, kr: kr}, nil
}

// Open unlocks an existing vault: it loads the key record from kr, derives
// the key-encryption key from the passphrase using the record's persisted
// KDF parameters, and unwraps the data key.
//
// Open never creates key material; use Init for the first run. A wrong
// passphrase, a corrupted record and an absent record all return the same
// ErrBadPassphrase value, and the absent-record path performs a decoy
// derivation at default cost so its duration resembles a real attempt. The
// timing equivalence is best effort — a keyring whose record uses
// non-default KDF parameters takes correspondingly different time — and no
// error or log output distinguishes the cases.
func Open(ctx context.Context, kr Keyring, passphrase string) (*Vault, error) {
	rec, err := kr.Load(ctx)
	if errors.Is(err, ErrNoKey) {
		decoyDerive(passphrase)
		return nil, ErrBadPassphrase
	}
	if err != nil {
		return nil, fmt.Errorf("vault: read keyring: %w", err)
	}

	params, err := parseParams(rec.Params)
	if err != nil {
		return nil, err
	}

	kek := deriveKEK(passphrase, rec.Salt, params)
	dek, err := openEnvelope(kek, dekWrapAAD, rec.WrappedKey)
	zeroBytes(kek)
	if err != nil || len(dek) != dekSize {
		zeroBytes(dek)
		return nil, ErrBadPassphrase
	}
	return &Vault{dek: dek, kr: kr}, nil
}

// decoyDerive burns approximately the work of a real unlock attempt —
// one Argon2id derivation at default cost and one failed unwrap — so that
// Open's absent-keyring path is not trivially distinguishable by timing
// from its wrong-passphrase path. The result is discarded.
func decoyDerive(passphrase string) {
	salt := make([]byte, saltSize)
	// A zero salt is acceptable here: the derived key is never used or
	// compared, only timed.
	kek := deriveKEK(passphrase, salt, DefaultKDFParams())
	var decoy [minEnvelopeLen + dekSize]byte
	decoy[0] = envelopeV1
	if pt, err := openEnvelope(kek, dekWrapAAD, decoy[:]); err == nil {
		// Unreachable: the decoy cannot authenticate. Guard anyway.
		zeroBytes(pt)
	}
	zeroBytes(kek)
}

// Seal encrypts plaintext under the vault's data key and returns a
// self-describing envelope (see the package documentation for the byte
// layout). aad is mandatory: pass the identity of the record this ciphertext
// will be stored under — Open must be given the same bytes, and a ciphertext
// cannot be moved to a different identity undetected. aad is authenticated,
// not encrypted; never put secrets in it.
//
// Seal does no I/O and returns ErrClosed after Close.
func (v *Vault) Seal(aad, plaintext []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrEmptyAAD
	}
	dek, err := v.dekCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	return sealEnvelope(dek, aad, plaintext)
}

// Open authenticates and decrypts an envelope produced by Seal with the same
// aad. It returns ErrClosed after Close, ErrEmptyAAD for an empty aad,
// ErrInvalidEnvelope or *UnknownVersionError for structurally invalid input,
// and ErrDecryptionFailed for any cryptographic failure — wrong key, wrong
// aad, or tampering — without distinguishing which.
//
// The returned plaintext is the caller's responsibility: never log it, and
// zero it when a copy is no longer needed.
func (v *Vault) Open(aad, envelope []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrEmptyAAD
	}
	dek, err := v.dekCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	return openEnvelope(dek, aad, envelope)
}

// dekCopy returns a private copy of the data key, or ErrClosed. Copying the
// bytes (not the slice header) under the read lock is what allows Close and
// Rotate to zero the shared array in place under the write lock.
func (v *Vault) dekCopy() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.dek == nil {
		return nil, ErrClosed
	}
	return append([]byte(nil), v.dek...), nil
}

// Close erases the in-memory data key: subsequent Seal, Open and Rotate
// calls return ErrClosed. The shared key buffer is overwritten in place
// under the write lock — safe because concurrent Seal/Open take private
// copies of the bytes under the read lock and never retain the shared array
// — and then dropped. Erasure is best effort: Go's runtime may have made
// copies this code cannot reach (see the package documentation).
//
// Close is idempotent. A closed Vault cannot be reopened; call Open again.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	zeroBytes(v.dek)
	v.dek = nil
}

// Closed reports whether Close has been called.
func (v *Vault) Closed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dek == nil
}

// Rotate re-wraps the data key under a new passphrase. The current
// passphrase must be supplied to authenticate the operation; a wrong one
// returns ErrBadPassphrase and changes nothing. Rotation generates a fresh
// salt, keeps the record's existing KDF parameters unless WithKDFParams
// overrides them (this is the cost-upgrade path), and persists the new
// record through the Keyring before publishing anything.
//
// The data key itself never changes, so previously sealed envelopes keep
// opening. Rotations are serialised; concurrent calls run one at a time and
// a loser whose "old" passphrase has just been retired fails cleanly with
// ErrBadPassphrase. If Close runs concurrently, the persisted rotation still
// takes effect but the vault stays closed.
func (v *Vault) Rotate(ctx context.Context, oldPassphrase, newPassphrase string, opts ...Option) error {
	if newPassphrase == "" {
		return ErrEmptyPassphrase
	}
	o := applyOptions(opts)
	if o.params != nil {
		if err := o.params.validate(); err != nil {
			return err
		}
	}

	v.rotateMu.Lock()
	defer v.rotateMu.Unlock()

	if v.Closed() {
		return ErrClosed
	}

	rec, err := v.kr.Load(ctx)
	if errors.Is(err, ErrNoKey) {
		decoyDerive(oldPassphrase)
		return ErrBadPassphrase
	}
	if err != nil {
		return fmt.Errorf("vault: read keyring: %w", err)
	}

	params, err := parseParams(rec.Params)
	if err != nil {
		return err
	}

	// Authenticate the old passphrase by unwrapping the data key.
	oldKEK := deriveKEK(oldPassphrase, rec.Salt, params)
	dek, err := openEnvelope(oldKEK, dekWrapAAD, rec.WrappedKey)
	zeroBytes(oldKEK)
	if err != nil || len(dek) != dekSize {
		zeroBytes(dek)
		return ErrBadPassphrase
	}

	newSalt, err := randomBytes(saltSize)
	if err != nil {
		zeroBytes(dek)
		return err
	}
	newParams := params
	if o.params != nil {
		newParams = *o.params
	}

	newKEK := deriveKEK(newPassphrase, newSalt, newParams)
	wrapped, err := sealEnvelope(newKEK, dekWrapAAD, dek)
	zeroBytes(newKEK)
	if err != nil {
		zeroBytes(dek)
		return fmt.Errorf("vault: re-wrap data key: %w", err)
	}

	paramsJSON, err := marshalParams(newParams)
	if err != nil {
		zeroBytes(dek)
		return err
	}

	if err := v.kr.Save(ctx, KeyRecord{ID: rec.ID, Salt: newSalt, Params: paramsJSON, WrappedKey: wrapped}); err != nil {
		zeroBytes(dek)
		return fmt.Errorf("vault: persist key record: %w", err)
	}

	// Publish the freshly unwrapped key. Zeroing the outgoing array in place
	// is safe: readers copy the bytes under the read lock and we hold the
	// write lock. If the vault was closed while we rotated, do not resurrect
	// it — the persisted rotation stands, the process keeps no key.
	v.mu.Lock()
	if v.dek == nil {
		v.mu.Unlock()
		zeroBytes(dek)
		return nil
	}
	zeroBytes(v.dek)
	v.dek = dek
	v.mu.Unlock()
	return nil
}
