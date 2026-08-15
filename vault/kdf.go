// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFParams configures the Argon2id derivation of the key-encryption key
// from the passphrase. The derived key length is fixed at 32 bytes
// (AES-256) and is not configurable.
//
// Raising the cost of an existing vault is a passphrase rotation:
// Rotate(..., WithKDFParams(p)) re-wraps the data key under the new
// parameters, and previously sealed data keeps opening because the data key
// itself is unchanged.
type KDFParams struct {
	// Time is the number of Argon2 passes. Must be at least 1.
	Time uint32

	// MemoryKiB is the Argon2 memory cost in KiB. Must be at least
	// 8*Threads and at most 4 GiB.
	MemoryKiB uint32

	// Threads is the Argon2 parallelism. Must be at least 1.
	Threads uint8
}

// DefaultKDFParams returns the parameters used when none are supplied:
// Argon2id with time=1, memory=64 MiB, threads=4 (RFC 9106's second
// recommended profile).
func DefaultKDFParams() KDFParams {
	return KDFParams{Time: 1, MemoryKiB: 64 * 1024, Threads: 4}
}

const (
	// kekLen is the derived key length: AES-256.
	kekLen = 32

	// maxMemoryKiB caps the memory cost accepted from options or from a
	// loaded record (4 GiB), so a corrupted or hostile record cannot demand
	// an absurd allocation at unlock time.
	maxMemoryKiB = 4 * 1024 * 1024

	// kdfAlgo is the only key-derivation algorithm this version understands.
	kdfAlgo = "argon2id"
)

// validate rejects parameter sets that Argon2 would panic on or that are
// operationally unsafe. The returned error describes the parameters only —
// never key material.
func (p KDFParams) validate() error {
	switch {
	case p.Time == 0:
		return errors.New("vault: kdf time must be at least 1")
	case p.Threads == 0:
		return errors.New("vault: kdf threads must be at least 1")
	case p.MemoryKiB < 8*uint32(p.Threads):
		return errors.New("vault: kdf memory must be at least 8 KiB per thread")
	case p.MemoryKiB > maxMemoryKiB:
		return errors.New("vault: kdf memory exceeds 4 GiB cap")
	}
	return nil
}

// kdfParamsJSON is the persisted wire form. Algo makes a future KDF change a
// code path (like the envelope version byte does for the cipher); KeyLen is
// recorded for auditability and must be 32.
type kdfParamsJSON struct {
	Algo    string `json:"algo"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB — Argon2 memory is expressed in KiB
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keyLen"`
}

// marshalParams encodes p for persistence in a KeyRecord.
func marshalParams(p KDFParams) ([]byte, error) {
	b, err := json.Marshal(kdfParamsJSON{
		Algo:    kdfAlgo,
		Time:    p.Time,
		Memory:  p.MemoryKiB,
		Threads: p.Threads,
		KeyLen:  kekLen,
	})
	if err != nil {
		return nil, fmt.Errorf("vault: marshal kdf params: %w", err)
	}
	return b, nil
}

// parseParams decodes and validates persisted parameters. An empty Algo is
// accepted as argon2id for records written before the field existed.
func parseParams(raw []byte) (KDFParams, error) {
	var w kdfParamsJSON
	if err := json.Unmarshal(raw, &w); err != nil {
		return KDFParams{}, fmt.Errorf("vault: parse kdf params: %w", err)
	}
	if w.Algo != "" && w.Algo != kdfAlgo {
		return KDFParams{}, fmt.Errorf("vault: unsupported kdf %q", w.Algo)
	}
	if w.KeyLen != kekLen {
		return KDFParams{}, fmt.Errorf("vault: unsupported kdf key length %d", w.KeyLen)
	}
	p := KDFParams{Time: w.Time, MemoryKiB: w.Memory, Threads: w.Threads}
	if err := p.validate(); err != nil {
		return KDFParams{}, err
	}
	return p, nil
}

// deriveKEK runs Argon2id to produce the 32-byte key-encryption key. The
// caller owns the result and must zero it with zeroBytes when finished.
func deriveKEK(passphrase string, salt []byte, p KDFParams) []byte {
	return argon2.IDKey([]byte(passphrase), salt, p.Time, p.MemoryKiB, p.Threads, kekLen)
}
