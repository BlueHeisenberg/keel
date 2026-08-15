// SPDX-License-Identifier: Apache-2.0

package vault_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/BlueHeisenberg/keel/vault"
)

// TestAADMismatchRejected is the ciphertext-relocation attack: an envelope
// sealed under record A's identity must not open under record B's identity,
// even by code holding the right key.
func TestAADMismatchRejected(t *testing.T) {
	v, _ := newTestVault(t, "relocation-test")
	secretA := []byte("value-for-record-a")
	aadA := []byte("secret:record-a")
	aadB := []byte("secret:record-b")

	envA, err := v.Seal(aadA, secretA)
	if err != nil {
		t.Fatalf("Seal A: %v", err)
	}

	// The attack: envA is copied into record B's storage slot and the system
	// asks to open it as B. It must fail, indistinguishably from tampering.
	if _, err := v.Open(aadB, envA); !errors.Is(err, vault.ErrDecryptionFailed) {
		t.Fatalf("relocated ciphertext: expected ErrDecryptionFailed, got %v", err)
	}

	// Under the right identity it still opens.
	got, err := v.Open(aadA, envA)
	if err != nil {
		t.Fatalf("Open under correct AAD: %v", err)
	}
	if !bytes.Equal(got, secretA) {
		t.Errorf("mismatch: got %q, want %q", got, secretA)
	}

	// A prefix/suffix of the right AAD must also fail: binding is exact.
	if _, err := v.Open([]byte("secret:record-"), envA); !errors.Is(err, vault.ErrDecryptionFailed) {
		t.Errorf("AAD prefix: expected ErrDecryptionFailed, got %v", err)
	}
	if _, err := v.Open([]byte("secret:record-a2"), envA); !errors.Is(err, vault.ErrDecryptionFailed) {
		t.Errorf("AAD superstring: expected ErrDecryptionFailed, got %v", err)
	}
}

// TestUnknownVersionRejected verifies that an envelope with an unrecognised
// version byte is rejected with the typed error before any decryption is
// attempted.
func TestUnknownVersionRejected(t *testing.T) {
	v, _ := newTestVault(t, "version-test")
	aad := []byte("secret:versioned")

	env, err := v.Seal(aad, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if env[0] != 0x01 {
		t.Fatalf("expected version byte 0x01, got 0x%02x", env[0])
	}

	for _, ver := range []byte{0x00, 0x02, 0x7f, 0xff} {
		mutated := append([]byte(nil), env...)
		mutated[0] = ver

		_, err := v.Open(aad, mutated)
		var uve *vault.UnknownVersionError
		if !errors.As(err, &uve) {
			t.Errorf("version 0x%02x: expected UnknownVersionError, got %v", ver, err)
			continue
		}
		if uve.Version != ver {
			t.Errorf("UnknownVersionError.Version = 0x%02x, want 0x%02x", uve.Version, ver)
		}
	}
}

// TestTamperedEnvelopeRejected flips one bit in each region of the envelope
// (nonce, ciphertext, tag) and expects authentication to fail.
func TestTamperedEnvelopeRejected(t *testing.T) {
	v, _ := newTestVault(t, "tamper-test")
	aad := []byte("secret:tamper")

	env, err := v.Seal(aad, []byte("integrity-protected"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Byte 1 is in the nonce, a middle byte is in the ciphertext, the last
	// byte is in the tag.
	for _, idx := range []int{1, len(env) / 2, len(env) - 1} {
		mutated := append([]byte(nil), env...)
		mutated[idx] ^= 0x01
		if _, err := v.Open(aad, mutated); !errors.Is(err, vault.ErrDecryptionFailed) {
			t.Errorf("flip at %d: expected ErrDecryptionFailed, got %v", idx, err)
		}
	}
}

// TestMalformedEnvelopeRejected covers structurally invalid inputs: empty,
// too short, and truncated below the minimum envelope length.
func TestMalformedEnvelopeRejected(t *testing.T) {
	v, _ := newTestVault(t, "malformed-test")
	aad := []byte("secret:malformed")

	if _, err := v.Open(aad, nil); !errors.Is(err, vault.ErrInvalidEnvelope) {
		t.Errorf("nil envelope: expected ErrInvalidEnvelope, got %v", err)
	}
	if _, err := v.Open(aad, []byte{}); !errors.Is(err, vault.ErrInvalidEnvelope) {
		t.Errorf("empty envelope: expected ErrInvalidEnvelope, got %v", err)
	}
	// Version byte alone, and version plus a partial nonce.
	for _, n := range []int{1, 5, 13, 28} {
		blob := make([]byte, n)
		blob[0] = 0x01
		if _, err := v.Open(aad, blob); !errors.Is(err, vault.ErrInvalidEnvelope) {
			t.Errorf("length %d: expected ErrInvalidEnvelope, got %v", n, err)
		}
	}
	// A full-length envelope of garbage past the version byte fails
	// authentication, not structure.
	blob := make([]byte, 64)
	blob[0] = 0x01
	if _, err := v.Open(aad, blob); !errors.Is(err, vault.ErrDecryptionFailed) {
		t.Errorf("garbage envelope: expected ErrDecryptionFailed, got %v", err)
	}
}

// TestEmptyAADRejected verifies Seal and Open both refuse an empty AAD; the
// binding is mandatory, not optional.
func TestEmptyAADRejected(t *testing.T) {
	v, _ := newTestVault(t, "empty-aad-test")

	if _, err := v.Seal(nil, []byte("x")); !errors.Is(err, vault.ErrEmptyAAD) {
		t.Errorf("Seal(nil aad): expected ErrEmptyAAD, got %v", err)
	}
	if _, err := v.Seal([]byte{}, []byte("x")); !errors.Is(err, vault.ErrEmptyAAD) {
		t.Errorf("Seal(empty aad): expected ErrEmptyAAD, got %v", err)
	}

	env, err := v.Seal([]byte("secret:id"), []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := v.Open(nil, env); !errors.Is(err, vault.ErrEmptyAAD) {
		t.Errorf("Open(nil aad): expected ErrEmptyAAD, got %v", err)
	}
}

// TestEmptyPlaintextRoundTrip: sealing an empty value is legal and
// round-trips; the envelope still authenticates its AAD.
func TestEmptyPlaintextRoundTrip(t *testing.T) {
	v, _ := newTestVault(t, "empty-plaintext-test")
	aad := []byte("secret:empty")

	env, err := v.Seal(aad, nil)
	if err != nil {
		t.Fatalf("Seal(nil plaintext): %v", err)
	}
	got, err := v.Open(aad, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %q", got)
	}
	if _, err := v.Open([]byte("secret:other"), env); !errors.Is(err, vault.ErrDecryptionFailed) {
		t.Errorf("empty plaintext under wrong AAD: expected ErrDecryptionFailed, got %v", err)
	}
}

// FuzzOpen throws arbitrary AADs and envelopes at Vault.Open. It must never
// panic; any outcome other than a clean error or a correct round-trip
// re-open is a bug. Seeds cover the valid envelope, truncations, version
// mutations and garbage; testdata/fuzz/FuzzOpen holds the committed corpus.
func FuzzOpen(f *testing.F) {
	kr := &memKeyring{}
	v, err := vault.Init(context.Background(), kr, "fuzz-pass", vault.WithKDFParams(testKDF))
	if err != nil {
		f.Fatalf("Init: %v", err)
	}
	valid, err := v.Seal([]byte("secret:fuzz"), []byte("fuzz-payload"))
	if err != nil {
		f.Fatalf("Seal: %v", err)
	}

	f.Add([]byte("secret:fuzz"), valid)
	f.Add([]byte("secret:other"), valid)
	f.Add([]byte("secret:fuzz"), valid[:len(valid)-1])
	f.Add([]byte("a"), []byte{})
	f.Add([]byte("a"), []byte{0x00})
	f.Add([]byte("a"), []byte{0x01})
	f.Add([]byte("a"), []byte{0xff, 0x01, 0x02})
	f.Add([]byte{}, append([]byte{0x01}, make([]byte, 40)...))

	f.Fuzz(func(t *testing.T, aad, envelope []byte) {
		got, err := v.Open(aad, envelope)
		if err != nil {
			if got != nil {
				t.Errorf("non-nil plaintext alongside error %v", err)
			}
			return
		}
		// The only envelopes that can authenticate are ones sealed under
		// this vault's key. Re-seal/open to confirm consistency.
		env2, serr := v.Seal(aad, got)
		if serr != nil {
			t.Fatalf("re-Seal of opened plaintext: %v", serr)
		}
		got2, oerr := v.Open(aad, env2)
		if oerr != nil || !bytes.Equal(got, got2) {
			t.Errorf("re-open mismatch: %v", oerr)
		}
	})
}
