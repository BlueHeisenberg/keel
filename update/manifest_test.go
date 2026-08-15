// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func testManifest() Manifest {
	return Manifest{
		Schema:      manifestSchema,
		GeneratedAt: time.Now().UTC(),
		Channels: map[string]Release{
			"edge": {
				Version: "v1.1.0",
				Notes:   "test release",
				Artifacts: map[string]Artifact{
					Platform(): {URL: "https://example.invalid/a", SHA256: "00"},
				},
			},
		},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := genKey(t)
	data, err := SignManifest(testManifest(), Signer{KeyID: "k1", Key: priv})
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	m, err := VerifyManifest(data, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if m.Channels["edge"].Version != "v1.1.0" {
		t.Errorf("round-tripped manifest lost data: %+v", m)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pub, priv := genKey(t)
	data, err := SignManifest(testManifest(), Signer{KeyID: "k1", Key: priv})
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	env.Payload = bytes.Replace(env.Payload, []byte("v1.1.0"), []byte("v9.9.9"), 1)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if _, err := VerifyManifest(tampered, []ed25519.PublicKey{pub}); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered payload: got %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	pub, _ := genKey(t)
	_, attackerPriv := genKey(t)
	data, err := SignManifest(testManifest(), Signer{KeyID: "k1", Key: attackerPriv})
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if _, err := VerifyManifest(data, []ed25519.PublicKey{pub}); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: got %v, want ErrSignature", err)
	}
}

func TestVerifyKeyRotation(t *testing.T) {
	oldPub, _ := genKey(t)
	newPub, newPriv := genKey(t)
	data, err := SignManifest(testManifest(), Signer{KeyID: "2026-b", Key: newPriv})
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	// A build trusting both the retiring and the new key accepts a manifest
	// signed only with the new one.
	if _, err := VerifyManifest(data, []ed25519.PublicKey{oldPub, newPub}); err != nil {
		t.Fatalf("rotation: %v", err)
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	pub, _ := genKey(t)

	// A bare manifest with no envelope at all.
	raw, err := json.Marshal(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(raw, []ed25519.PublicKey{pub}); !errors.Is(err, ErrSignature) {
		t.Fatalf("bare manifest: got %v, want ErrSignature", err)
	}

	// An envelope with an empty signature list.
	payload, err := json.Marshal(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(envelope{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(env, []ed25519.PublicKey{pub}); !errors.Is(err, ErrSignature) {
		t.Fatalf("empty signatures: got %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsMalformedSignature(t *testing.T) {
	pub, _ := genKey(t)
	payload, err := json.Marshal(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(envelope{
		Payload:    payload,
		Signatures: []envelopeSignature{{KeyID: "k1", Sig: []byte("too short")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(env, []ed25519.PublicKey{pub}); !errors.Is(err, ErrSignature) {
		t.Fatalf("malformed signature: got %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsNoTrustedKeys(t *testing.T) {
	_, priv := genKey(t)
	data, err := SignManifest(testManifest(), Signer{KeyID: "k1", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(data, nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("no trusted keys: got %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsUnknownSchema(t *testing.T) {
	pub, priv := genKey(t)
	m := testManifest()
	m.Schema = 2
	data, err := SignManifest(m, Signer{KeyID: "k1", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(data, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("schema 2 accepted; a build must refuse manifests it does not understand")
	}
}
