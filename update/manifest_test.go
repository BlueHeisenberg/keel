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
		Schema:      ManifestSchema,
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
	var env Envelope
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
	env, err := json.Marshal(Envelope{Payload: payload})
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
	env, err := json.Marshal(Envelope{
		Payload:    payload,
		Signatures: []Signature{{KeyID: "k1", Sig: []byte("too short")}},
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

func TestSignPayloadVerifyPayload(t *testing.T) {
	pub, priv := genKey(t)
	otherPub, _ := genKey(t)
	payload := []byte(`{"exact":"bytes, never re-encoded"}`)

	sig, err := SignPayload(payload, priv, "k1")
	if err != nil {
		t.Fatalf("SignPayload: %v", err)
	}
	if sig.KeyID != "k1" || len(sig.Sig) != ed25519.SignatureSize {
		t.Fatalf("signature shape wrong: %+v", sig)
	}
	if !VerifyPayload(payload, sig, pub) {
		t.Fatal("signature does not verify under the signing key")
	}
	if VerifyPayload(payload, sig, otherPub) {
		t.Fatal("signature verifies under an unrelated key")
	}
	tampered := append([]byte{'x'}, payload...)
	if VerifyPayload(tampered, sig, pub) {
		t.Fatal("signature verifies over different bytes")
	}
	if _, err := SignPayload(nil, priv, "k1"); err == nil {
		t.Fatal("SignPayload accepted an empty payload")
	}
	if _, err := SignPayload(payload, []byte("short"), "k1"); err == nil {
		t.Fatal("SignPayload accepted a malformed private key")
	}
}

// TestAddSignatureToForeignEnvelope is the rotation-safety test: the payload
// is deliberately formatted in a way Go's JSON encoder would never produce
// (indentation, unusual key ordering, stray whitespace). A second signature
// is added by parsing the envelope and signing the original bytes — never by
// re-encoding a decoded manifest — and both signatures must remain valid.
// If this passes, rotation works for any manifest anyone can produce, not
// only for manifests this codebase happened to write.
func TestAddSignatureToForeignEnvelope(t *testing.T) {
	pub1, priv1 := genKey(t)
	pub2, priv2 := genKey(t)

	payload := []byte("{\n\t\"channels\": {\"edge\": {\"artifacts\": {\"linux/amd64\": {\"sha256\": \"00\",   \"url\": \"https://example.invalid/a\"}}, \"version\": \"v1.1.0\"}},\n    \"generatedAt\": \"2026-08-15T00:00:00Z\",\n\t\"schema\": 1   \n}\n")

	// Prove the payload does NOT round-trip through Go's encoder: this is
	// what makes the test mean something.
	var decoded Manifest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("test payload is not valid manifest JSON: %v", err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reencoded, payload) {
		t.Fatal("test payload round-trips byte-for-byte; it does not exercise the foreign-producer case")
	}

	// Release 1: signed by the original key, by some external tool.
	sig1, err := SignPayload(payload, priv1, "2026-a")
	if err != nil {
		t.Fatal(err)
	}
	envBytes, err := Envelope{Payload: payload, Signatures: []Signature{sig1}}.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Rotation: a later invocation parses the published envelope and adds a
	// signature from the new key, without touching the payload.
	parsed, err := ParseEnvelope(envBytes)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatal("ParseEnvelope did not preserve the payload bytes verbatim")
	}
	sig2, err := SignPayload(parsed.Payload, priv2, "2026-b")
	if err != nil {
		t.Fatal(err)
	}
	parsed.Signatures = append(parsed.Signatures, sig2)
	rotated, err := parsed.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip once more and confirm the payload still survived verbatim.
	reparsed, err := ParseEnvelope(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reparsed.Payload, payload) {
		t.Fatal("Encode re-encoded the payload; existing signatures would be invalidated")
	}

	// Both signatures verify independently: a deployment trusting only the
	// old key and one trusting only the new key both accept the rotated
	// envelope.
	for name, key := range map[string]ed25519.PublicKey{"old key only": pub1, "new key only": pub2} {
		m, err := VerifyManifest(rotated, []ed25519.PublicKey{key})
		if err != nil {
			t.Fatalf("VerifyManifest (%s): %v", name, err)
		}
		if m.Channels["edge"].Version != "v1.1.0" {
			t.Fatalf("decoded manifest wrong (%s): %+v", name, m)
		}
	}
}

func TestSignerIDs(t *testing.T) {
	_, priv1 := genKey(t)
	_, priv2 := genKey(t)
	payload := []byte(`{"schema":1}`)
	sig1, err := SignPayload(payload, priv1, "2026-a")
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := SignPayload(payload, priv2, "2026-b")
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{Payload: payload, Signatures: []Signature{sig1, sig2}}
	data, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	ids := parsed.SignerIDs()
	if len(ids) != 2 || ids[0] != "2026-a" || ids[1] != "2026-b" {
		t.Fatalf("SignerIDs = %v, want [2026-a 2026-b] in order", ids)
	}
}

func TestParseEnvelopeStructuralChecks(t *testing.T) {
	if _, err := ParseEnvelope([]byte("not json")); err == nil {
		t.Error("ParseEnvelope accepted non-JSON")
	}
	if _, err := ParseEnvelope([]byte(`{"signatures":[]}`)); err == nil {
		t.Error("ParseEnvelope accepted an empty payload")
	}
	if _, err := ParseEnvelope([]byte(`{"payload":"AAAA","signatures":[{"keyId":"k","signature":"AAAA"}]}`)); err == nil {
		t.Error("ParseEnvelope accepted a malformed (wrong-length) signature")
	}
	if _, err := (Envelope{}).Encode(); err == nil {
		t.Error("Encode accepted an empty payload")
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
