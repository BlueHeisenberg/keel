// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"runtime"
)

const (
	// envelopeV1 is version 0x01: AES-256-GCM, 12-byte random nonce, the
	// version byte authenticated by prepending it to the caller AAD.
	envelopeV1 = 0x01

	dekSize   = 32 // AES-256 data-encryption key length in bytes
	saltSize  = 32 // KDF salt length in bytes
	nonceSize = 12 // AES-GCM standard nonce length in bytes
	tagSize   = 16 // AES-GCM authentication tag length in bytes

	// minEnvelopeLen is the shortest structurally valid envelope: the
	// version byte, the nonce, and the tag of an empty plaintext.
	minEnvelopeLen = 1 + nonceSize + tagSize
)

// dekWrapAAD is the associated data under which the data key itself is
// wrapped inside the KeyRecord. The constant separates the key-wrap domain
// from the data domain: a wrapped key cannot be passed off as sealed data or
// vice versa, even to code holding the right key.
var dekWrapAAD = []byte("keel/vault: wrapped data key")

// fullAAD prepends the envelope version to the caller AAD so the version
// byte is covered by the GCM tag. The version is a single fixed-width byte,
// so the concatenation is unambiguous.
func fullAAD(version byte, aad []byte) []byte {
	out := make([]byte, 1+len(aad))
	out[0] = version
	copy(out[1:], aad)
	return out
}

// sealEnvelope encrypts plaintext under key with AES-256-GCM and a fresh
// random nonce, binding aad (and the version byte) as associated data.
// Output layout: version(1) || nonce(12) || ciphertext+tag.
func sealEnvelope(key, aad, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+tagSize)
	out[0] = envelopeV1
	if _, err := io.ReadFull(rand.Reader, out[1:1+nonceSize]); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	return gcm.Seal(out, out[1:1+nonceSize], plaintext, fullAAD(envelopeV1, aad)), nil
}

// openEnvelope authenticates and decrypts an envelope produced by
// sealEnvelope with the same key and aad. Structural failures return
// ErrInvalidEnvelope or *UnknownVersionError; every cryptographic failure —
// wrong key, wrong AAD, tampering, truncation past the header — returns the
// bare ErrDecryptionFailed with no detail, so error content cannot serve as
// a decryption oracle. GCM tag verification is constant-time inside
// crypto/cipher.
func openEnvelope(key, aad, envelope []byte) ([]byte, error) {
	if len(envelope) == 0 {
		return nil, ErrInvalidEnvelope
	}
	if envelope[0] != envelopeV1 {
		return nil, &UnknownVersionError{Version: envelope[0]}
	}
	if len(envelope) < minEnvelopeLen {
		return nil, ErrInvalidEnvelope
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := envelope[1 : 1+nonceSize]
	ct := envelope[1+nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, fullAAD(envelope[0], aad))
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// newGCM builds the AEAD. key must be 32 bytes; anything else is an internal
// invariant violation, reported without echoing the key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: new gcm: %w", err)
	}
	return gcm, nil
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("vault: read random: %w", err)
	}
	return b, nil
}

// zeroBytes best-effort erases key material. The runtime.KeepAlive
// discourages the compiler from treating the writes as dead stores, but Go
// makes no guarantee: copies may survive in registers, in buffers moved by
// stack growth, or in memory the GC has not reused. This narrows the
// exposure window of a later memory dump; it is not guaranteed erasure (see
// the package documentation's threat model).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
