// SPDX-License-Identifier: Apache-2.0

package vault_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/BlueHeisenberg/keel/vault"
)

// testKDF keeps Argon2 cheap in tests. Correctness is independent of cost;
// TestInitCreatesKeyRecord exercises the default parameters once.
var testKDF = vault.KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

// newTestVault initialises a fresh vault over an empty in-memory keyring
// using cheap KDF parameters.
func newTestVault(t *testing.T, passphrase string) (*vault.Vault, *memKeyring) {
	t.Helper()
	kr := &memKeyring{}
	v, err := vault.Init(context.Background(), kr, passphrase, vault.WithKDFParams(testKDF))
	if err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	return v, kr
}

// TestInitCreatesKeyRecord verifies that initialising a fresh vault persists
// a key record with non-empty salt, parameters and wrapped key, using the
// default KDF parameters. (Was TestFirstRunCreatesVaultMeta.)
func TestInitCreatesKeyRecord(t *testing.T) {
	ctx := context.Background()
	kr := &memKeyring{}

	if _, err := kr.Load(ctx); !errors.Is(err, vault.ErrNoKey) {
		t.Fatalf("expected ErrNoKey before Init, got %v", err)
	}

	v, err := vault.Init(ctx, kr, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	if v.Closed() {
		t.Fatal("vault should not be closed after Init")
	}

	rec, ok := kr.snapshot()
	if !ok {
		t.Fatal("no key record persisted by Init")
	}
	if rec.ID == "" {
		t.Error("record ID is empty")
	}
	if len(rec.Salt) == 0 {
		t.Error("Salt is empty")
	}
	if len(rec.WrappedKey) == 0 {
		t.Error("WrappedKey is empty")
	}
	if len(rec.Params) == 0 {
		t.Error("Params is empty")
	}
}

// TestInitWhenKeyringExists verifies Init refuses to overwrite an existing
// key record.
func TestInitWhenKeyringExists(t *testing.T) {
	ctx := context.Background()
	_, kr := newTestVault(t, "pass-one")

	if _, err := vault.Init(ctx, kr, "pass-two", vault.WithKDFParams(testKDF)); !errors.Is(err, vault.ErrKeyringExists) {
		t.Fatalf("expected ErrKeyringExists, got %v", err)
	}
	if kr.saves != 1 {
		t.Errorf("Save called %d times, want 1", kr.saves)
	}
}

// TestEmptyPassphraseRejected verifies Init and Rotate refuse an empty
// passphrase.
func TestEmptyPassphraseRejected(t *testing.T) {
	ctx := context.Background()
	if _, err := vault.Init(ctx, &memKeyring{}, ""); !errors.Is(err, vault.ErrEmptyPassphrase) {
		t.Fatalf("Init: expected ErrEmptyPassphrase, got %v", err)
	}

	v, _ := newTestVault(t, "real-pass")
	if err := v.Rotate(ctx, "real-pass", ""); !errors.Is(err, vault.ErrEmptyPassphrase) {
		t.Fatalf("Rotate: expected ErrEmptyPassphrase, got %v", err)
	}
}

// TestSealOpenRoundTrip seals a value and opens it, asserting the plaintext
// matches. (Was TestPutGetRoundTrip.)
func TestSealOpenRoundTrip(t *testing.T) {
	v, _ := newTestVault(t, "hunter2")
	want := []byte("sk-supersecretapikey-12345")
	aad := []byte("secret:prod-key")

	env, err := v.Seal(aad, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(env) == 0 {
		t.Fatal("envelope is empty")
	}

	got, err := v.Open(aad, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, want)
	}
}

// TestReopenSamePassphrase seals a value, closes the vault, re-opens it with
// the same passphrase (re-deriving the KEK from the persisted record), and
// verifies the value still opens. This is the round-trip-across-a-re-derived-
// keyring guarantee.
func TestReopenSamePassphrase(t *testing.T) {
	ctx := context.Background()
	const pass = "correct-horse-battery-staple"
	want := []byte("my-github-token")
	aad := []byte("secret:github-personal")

	v1, kr := newTestVault(t, pass)
	env, err := v1.Seal(aad, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	v1.Close()

	v2, err := vault.Open(ctx, kr, pass)
	if err != nil {
		t.Fatalf("vault.Open after Close: %v", err)
	}
	got, err := v2.Open(aad, env)
	if err != nil {
		t.Fatalf("Open after reopen: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("plaintext mismatch after reopen: got %q, want %q", got, want)
	}
}

// TestWrongPassphraseReturnsErrBadPassphrase verifies that a wrong
// passphrase against an existing keyring returns ErrBadPassphrase and not an
// opaque decryption error.
func TestWrongPassphraseReturnsErrBadPassphrase(t *testing.T) {
	ctx := context.Background()
	v, kr := newTestVault(t, "correct-passphrase")
	v.Close()

	if _, err := vault.Open(ctx, kr, "wrong-passphrase"); !errors.Is(err, vault.ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}
}

// TestWrongPassphraseIndistinguishableFromMissingKeyring verifies that Open
// returns the identical error value for a wrong passphrase and for a keyring
// with no record, so the unlock path cannot be used to probe whether a vault
// exists.
func TestWrongPassphraseIndistinguishableFromMissingKeyring(t *testing.T) {
	ctx := context.Background()

	v, kr := newTestVault(t, "the-real-passphrase")
	v.Close()
	_, errWrong := vault.Open(ctx, kr, "not-the-passphrase")

	_, errMissing := vault.Open(ctx, &memKeyring{}, "not-the-passphrase")

	if !errors.Is(errWrong, vault.ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: expected ErrBadPassphrase, got %v", errWrong)
	}
	if !errors.Is(errMissing, vault.ErrBadPassphrase) {
		t.Fatalf("missing keyring: expected ErrBadPassphrase, got %v", errMissing)
	}
	// Stronger than errors.Is: the two paths must return the same value, so
	// not even the error text differs.
	if errWrong != errMissing {
		t.Errorf("errors are distinguishable: wrong=%q missing=%q", errWrong, errMissing)
	}
}

// TestOpenAfterCloseReturnsErrClosed verifies that Close makes Seal and Open
// fail with ErrClosed. (Was TestGetAfterSealReturnsErrSealed.)
func TestOpenAfterCloseReturnsErrClosed(t *testing.T) {
	v, _ := newTestVault(t, "pass")
	aad := []byte("secret:webhook-key")

	env, err := v.Seal(aad, []byte("whsec_abc123"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	v.Close()
	if !v.Closed() {
		t.Error("Closed() should report true after Close()")
	}

	if _, err := v.Open(aad, env); !errors.Is(err, vault.ErrClosed) {
		t.Fatalf("Open: expected ErrClosed, got %v", err)
	}
	if _, err := v.Seal(aad, []byte("x")); !errors.Is(err, vault.ErrClosed) {
		t.Fatalf("Seal: expected ErrClosed, got %v", err)
	}
	// Close is idempotent.
	v.Close()
}

// TestDifferentSealsProduceDifferentCiphertexts ensures sealing the same
// plaintext twice produces distinct envelopes, confirming per-encryption
// nonce randomness.
func TestDifferentSealsProduceDifferentCiphertexts(t *testing.T) {
	v, _ := newTestVault(t, "nonce-randomness-test")
	plaintext := []byte("identical-plaintext")
	aad := []byte("secret:same-record")

	env1, err := v.Seal(aad, plaintext)
	if err != nil {
		t.Fatalf("Seal 1: %v", err)
	}
	env2, err := v.Seal(aad, plaintext)
	if err != nil {
		t.Fatalf("Seal 2: %v", err)
	}
	if bytes.Equal(env1, env2) {
		t.Error("two seals of the same plaintext produced identical envelopes — nonce is not random")
	}

	for i, env := range [][]byte{env1, env2} {
		got, err := v.Open(aad, env)
		if err != nil {
			t.Fatalf("Open %d: %v", i+1, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("Open %d mismatch: got %q, want %q", i+1, got, plaintext)
		}
	}
}

// TestConcurrentOpenDuringClose stresses the DEK race fixed in the original
// implementation: many goroutines call Open while another goroutine Closes
// the vault. Open must either succeed with the correct plaintext or return
// ErrClosed — never panic, never fail authentication, never return a torn
// value from a key being erased mid-decrypt. Run with -race. (Was
// TestConcurrentGetDuringSeal.)
func TestConcurrentOpenDuringClose(t *testing.T) {
	ctx := context.Background()
	const pass = "race-test-passphrase"
	want := []byte("sk-concurrent-secret")
	aad := []byte("secret:race-key")

	v, kr := newTestVault(t, pass)
	env, err := v.Seal(aad, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	const readers = 32
	const itersPerReader = 50

	var wg sync.WaitGroup
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < itersPerReader; j++ {
				got, gerr := v.Open(aad, env)
				switch {
				case gerr == nil:
					if !bytes.Equal(got, want) {
						t.Errorf("torn read: got %q, want %q", got, want)
						return
					}
				case errors.Is(gerr, vault.ErrClosed):
					// Acceptable: vault was closed concurrently.
				default:
					t.Errorf("unexpected Open error during concurrent close: %v", gerr)
					return
				}
			}
		}()
	}

	// Close partway through the readers' run to maximise the overlap window.
	v.Close()
	wg.Wait()

	// Re-open (Close cannot be undone on the same instance) and confirm the
	// envelope is still readable.
	v2, err := vault.Open(ctx, kr, pass)
	if err != nil {
		t.Fatalf("vault.Open after close: %v", err)
	}
	got, err := v2.Open(aad, env)
	if err != nil {
		t.Fatalf("Open after re-open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("plaintext mismatch after re-open: got %q, want %q", got, want)
	}
}

// TestConcurrentOpenDuringRotate stresses Open against a concurrent Rotate,
// which republishes the data key. Open must never observe a half-replaced or
// zeroed key: the data key is unchanged by rotation, so every Open must
// succeed with the correct plaintext. Run with -race. (Was
// TestConcurrentGetDuringRotate.)
func TestConcurrentOpenDuringRotate(t *testing.T) {
	ctx := context.Background()
	const oldPass = "rotate-old"
	const newPass = "rotate-new"
	want := []byte("sk-rotate-secret")
	aad := []byte("secret:rotate-key")

	v, _ := newTestVault(t, oldPass)
	env, err := v.Seal(aad, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	const readers = 16
	const itersPerReader = 50

	var wg sync.WaitGroup
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < itersPerReader; j++ {
				got, gerr := v.Open(aad, env)
				switch {
				case gerr == nil:
					if !bytes.Equal(got, want) {
						t.Errorf("torn read during rotate: got %q, want %q", got, want)
						return
					}
				case errors.Is(gerr, vault.ErrClosed):
					// Tolerated for future variants that seal during rotation.
				default:
					t.Errorf("unexpected Open error during concurrent rotate: %v", gerr)
					return
				}
			}
		}()
	}

	if err := v.Rotate(ctx, oldPass, newPass); err != nil {
		t.Errorf("Rotate: %v", err)
	}
	wg.Wait()

	// Vault stays open after rotation; Open must still succeed.
	got, err := v.Open(aad, env)
	if err != nil {
		t.Fatalf("Open after rotate: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("plaintext mismatch after rotate: got %q, want %q", got, want)
	}
}

// TestConcurrentSealAndOpen runs Seal and Open simultaneously from many
// goroutines. Run with -race.
func TestConcurrentSealAndOpen(t *testing.T) {
	v, _ := newTestVault(t, "seal-open-race")
	want := []byte("payload")
	aad := []byte("secret:concurrent")

	env, err := v.Seal(aad, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	const workers = 16
	const iters = 50

	var wg sync.WaitGroup
	wg.Add(2 * workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				e, serr := v.Seal(aad, want)
				if serr != nil {
					t.Errorf("concurrent Seal: %v", serr)
					return
				}
				got, oerr := v.Open(aad, e)
				if oerr != nil {
					t.Errorf("open own seal: %v", oerr)
					return
				}
				if !bytes.Equal(got, want) {
					t.Errorf("round-trip mismatch: got %q", got)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				got, oerr := v.Open(aad, env)
				if oerr != nil {
					t.Errorf("concurrent Open: %v", oerr)
					return
				}
				if !bytes.Equal(got, want) {
					t.Errorf("concurrent Open mismatch: got %q", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestConcurrentRotate verifies rotations are serialised: of two concurrent
// rotations from the same old passphrase, exactly one wins and the other
// fails cleanly with ErrBadPassphrase (its "old" passphrase was retired by
// the winner). The persisted record must open under the winner's passphrase.
func TestConcurrentRotate(t *testing.T) {
	ctx := context.Background()
	const oldPass = "shared-old"
	v, kr := newTestVault(t, oldPass)
	aad := []byte("secret:rotate-race")
	env, err := v.Seal(aad, []byte("value"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	newPasses := [2]string{"winner-a", "winner-b"}
	var errs [2]error
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = v.Rotate(ctx, oldPass, newPasses[i])
		}(i)
	}
	wg.Wait()

	var winner string
	switch {
	case errs[0] == nil && errors.Is(errs[1], vault.ErrBadPassphrase):
		winner = newPasses[0]
	case errs[1] == nil && errors.Is(errs[0], vault.ErrBadPassphrase):
		winner = newPasses[1]
	default:
		t.Fatalf("expected exactly one winner, got errs=%v", errs)
	}

	v.Close()
	if _, err := vault.Open(ctx, kr, oldPass); !errors.Is(err, vault.ErrBadPassphrase) {
		t.Fatalf("old passphrase should be retired, got %v", err)
	}
	v2, err := vault.Open(ctx, kr, winner)
	if err != nil {
		t.Fatalf("vault.Open with winning passphrase %q: %v", winner, err)
	}
	if _, err := v2.Open(aad, env); err != nil {
		t.Fatalf("Open sealed data after concurrent rotate: %v", err)
	}
}

// TestRotatePassphrase verifies that after rotation the old passphrase is
// rejected, the new one unlocks the vault, and previously sealed data still
// opens.
func TestRotatePassphrase(t *testing.T) {
	ctx := context.Background()
	const oldPass = "old-passphrase"
	const newPass = "new-passphrase"
	want := []byte("rotate-me")
	aad := []byte("secret:rotatable-key")

	v, kr := newTestVault(t, oldPass)
	env, err := v.Seal(aad, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	oldRec, _ := kr.snapshot()
	if err := v.Rotate(ctx, oldPass, newPass); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	newRec, _ := kr.snapshot()
	if bytes.Equal(oldRec.Salt, newRec.Salt) {
		t.Error("rotation did not generate a fresh salt")
	}
	if newRec.ID != oldRec.ID {
		t.Errorf("rotation changed record ID: %q -> %q", oldRec.ID, newRec.ID)
	}

	v.Close()
	if _, err := vault.Open(ctx, kr, oldPass); !errors.Is(err, vault.ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase for old pass after rotation, got %v", err)
	}

	v2, err := vault.Open(ctx, kr, newPass)
	if err != nil {
		t.Fatalf("vault.Open with new pass: %v", err)
	}
	got, err := v2.Open(aad, env)
	if err != nil {
		t.Fatalf("Open after rotation: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("plaintext mismatch after rotation: got %q, want %q", got, want)
	}
}

// TestRotateWrongOldPassphrase ensures Rotate rejects a wrong old passphrase
// without modifying the key record.
func TestRotateWrongOldPassphrase(t *testing.T) {
	ctx := context.Background()
	v, kr := newTestVault(t, "real-pass")
	before, _ := kr.snapshot()

	if err := v.Rotate(ctx, "wrong-old-pass", "new-pass"); !errors.Is(err, vault.ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase for wrong old pass in Rotate, got %v", err)
	}
	after, _ := kr.snapshot()
	if !bytes.Equal(before.WrappedKey, after.WrappedKey) || !bytes.Equal(before.Salt, after.Salt) {
		t.Error("failed rotation modified the key record")
	}

	// Vault must still open with the original passphrase.
	v.Close()
	v2, err := vault.Open(ctx, kr, "real-pass")
	if err != nil {
		t.Fatalf("vault.Open with original pass after failed Rotate: %v", err)
	}
	if v2.Closed() {
		t.Error("vault should be open")
	}
}

// TestRotateOnClosedVault verifies rotation is refused after Close so a
// closed vault cannot be resurrected through the rotation path.
func TestRotateOnClosedVault(t *testing.T) {
	v, _ := newTestVault(t, "pass")
	v.Close()
	if err := v.Rotate(context.Background(), "pass", "new-pass"); !errors.Is(err, vault.ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

// TestKDFParamsRoundTrip verifies custom KDF parameters are persisted with
// the record and honoured on reopen.
func TestKDFParamsRoundTrip(t *testing.T) {
	ctx := context.Background()
	kr := &memKeyring{}
	custom := vault.KDFParams{Time: 2, MemoryKiB: 128, Threads: 2}

	v, err := vault.Init(ctx, kr, "params-pass", vault.WithKDFParams(custom))
	if err != nil {
		t.Fatalf("Init with custom params: %v", err)
	}
	aad := []byte("secret:params")
	env, err := v.Seal(aad, []byte("value"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	v.Close()

	rec, _ := kr.snapshot()
	for _, want := range []string{`"algo":"argon2id"`, `"time":2`, `"memory":128`, `"threads":2`, `"keyLen":32`} {
		if !bytes.Contains(rec.Params, []byte(want)) {
			t.Errorf("persisted params %s missing %s", rec.Params, want)
		}
	}

	v2, err := vault.Open(ctx, kr, "params-pass")
	if err != nil {
		t.Fatalf("vault.Open with custom params: %v", err)
	}
	if _, err := v2.Open(aad, env); err != nil {
		t.Fatalf("Open sealed data: %v", err)
	}
}

// TestUpgradedKDFCostStillOpensOldData raises the KDF cost through Rotate
// and verifies data sealed before the upgrade still opens: the data key is
// unchanged, only its wrapping got more expensive.
func TestUpgradedKDFCostStillOpensOldData(t *testing.T) {
	ctx := context.Background()
	const oldPass = "cheap-pass"
	const newPass = "costly-pass"
	want := []byte("sealed-before-upgrade")
	aad := []byte("secret:upgrade")

	v, kr := newTestVault(t, oldPass) // testKDF: time=1, 64 KiB, 1 thread
	env, err := v.Seal(aad, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	upgraded := vault.KDFParams{Time: 3, MemoryKiB: 1024, Threads: 2}
	if err := v.Rotate(ctx, oldPass, newPass, vault.WithKDFParams(upgraded)); err != nil {
		t.Fatalf("Rotate with upgraded params: %v", err)
	}

	rec, _ := kr.snapshot()
	for _, wantFrag := range []string{`"time":3`, `"memory":1024`, `"threads":2`} {
		if !bytes.Contains(rec.Params, []byte(wantFrag)) {
			t.Errorf("upgraded params not persisted: %s missing %s", rec.Params, wantFrag)
		}
	}

	// Both on the live vault and across a full reopen.
	got, err := v.Open(aad, env)
	if err != nil {
		t.Fatalf("Open on live vault after upgrade: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("mismatch on live vault: got %q", got)
	}

	v.Close()
	v2, err := vault.Open(ctx, kr, newPass)
	if err != nil {
		t.Fatalf("vault.Open after upgrade: %v", err)
	}
	got, err = v2.Open(aad, env)
	if err != nil {
		t.Fatalf("Open old data after upgrade: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("mismatch after upgrade: got %q, want %q", got, want)
	}
}

// TestRotatePreservesExistingKDFParams pins the no-silent-downgrade rule:
// rotating without WithKDFParams keeps the record's current cost instead of
// resetting to the defaults.
func TestRotatePreservesExistingKDFParams(t *testing.T) {
	ctx := context.Background()
	kr := &memKeyring{}
	custom := vault.KDFParams{Time: 2, MemoryKiB: 256, Threads: 1}
	v, err := vault.Init(ctx, kr, "keep-pass", vault.WithKDFParams(custom))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := v.Rotate(ctx, "keep-pass", "next-pass"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	rec, _ := kr.snapshot()
	for _, want := range []string{`"time":2`, `"memory":256`, `"threads":1`} {
		if !bytes.Contains(rec.Params, []byte(want)) {
			t.Errorf("rotation changed KDF params: %s missing %s", rec.Params, want)
		}
	}
}
