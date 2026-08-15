// SPDX-License-Identifier: Apache-2.0

package update

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrSignature is wrapped by every manifest verification failure: missing,
// malformed, or non-matching signatures, an empty payload, or no trusted
// keys. It is a refusal, never a warning.
var ErrSignature = errors.New("update: manifest signature verification failed")

// ManifestSchema is the manifest payload schema this build understands and
// the value producers stamp into Manifest.Schema. An unknown schema is
// refused: failing closed costs an update, never a deployment.
const ManifestSchema = 1

// maxManifestBytes caps the manifest envelope (and its decoded payload) to
// avoid unbounded reads from a hostile host.
const maxManifestBytes = 1 << 20 // 1 MiB

// signingContext domain-separates manifest signatures from any other use of
// the same Ed25519 key.
const signingContext = "keel/update/manifest/v1\n"

// Artifact describes one downloadable build for one platform. Because the
// manifest is signed, SHA256 authenticates the artifact itself: the artifact
// host can serve anything it likes and the mismatch is detected locally.
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size,omitempty"`
}

// Release is one channel entry in a manifest. Artifacts are keyed by
// "GOOS/GOARCH" (see Platform).
type Release struct {
	Version     string    `json:"version"`
	Notes       string    `json:"notes,omitempty"`
	PublishedAt time.Time `json:"publishedAt,omitzero"`

	// SecuritySensitive marks a release that changes security-relevant
	// defaults or behaviour. Such a release is never auto-applied,
	// regardless of how small the version bump is: it requires the same
	// explicit consent as a major version. Publishers must set it for any
	// release that could, for example, alter routing or privacy defaults.
	SecuritySensitive bool `json:"securitySensitive,omitempty"`

	Artifacts map[string]Artifact `json:"artifacts"`
}

// Manifest is the signed payload describing the current releases per
// channel. It is transported inside a signature envelope; consumers never
// fetch or trust a bare Manifest.
type Manifest struct {
	Schema      int                `json:"schema"`
	GeneratedAt time.Time          `json:"generatedAt,omitzero"`
	Channels    map[string]Release `json:"channels"`
}

// Envelope is the wire format served at the manifest URL:
//
//	{
//	  "payload":    "<base64 of the Manifest JSON>",
//	  "signatures": [{"keyId": "2026-a", "signature": "<base64 Ed25519>"}]
//	}
//
// Signatures are computed over signingContext || payload bytes, so there is
// no canonicalisation step to get wrong: the exact bytes that were signed
// are the exact bytes that are verified and then decoded.
//
// Payload is opaque to the envelope: ParseEnvelope and Encode carry it
// verbatim and never re-encode it. That is what makes key rotation safe —
// a second signature can be added to any correctly signed envelope,
// regardless of who produced the payload bytes or how they were formatted,
// without invalidating the first signature.
type Envelope struct {
	Payload    []byte      `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

// Signature is one signature entry in an Envelope. KeyID is advisory, for
// operator diagnostics; verification never trusts it.
type Signature struct {
	KeyID string `json:"keyId,omitempty"`
	Sig   []byte `json:"signature"`
}

// SignPayload signs the exact bytes given, applying the signing context
// internally. It is the signing primitive: SignManifest is a thin wrapper
// that serialises a Manifest and calls this. Release tooling that needs to
// add a signature to an existing envelope must sign the envelope's original
// payload bytes with SignPayload — never a re-encoded manifest.
func SignPayload(payload []byte, key ed25519.PrivateKey, keyID string) (Signature, error) {
	if len(payload) == 0 {
		return Signature{}, errors.New("update: SignPayload requires a non-empty payload")
	}
	if len(key) != ed25519.PrivateKeySize {
		return Signature{}, fmt.Errorf("update: signer %q: invalid Ed25519 private key size %d", keyID, len(key))
	}
	return Signature{KeyID: keyID, Sig: ed25519.Sign(key, signingMessage(payload))}, nil
}

// VerifyPayload reports whether sig verifies payload under key, applying the
// signing context internally. It lets a verifier attribute results per key
// without re-running whole-envelope verification once per candidate.
func VerifyPayload(payload []byte, sig Signature, key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize || len(sig.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(key, signingMessage(payload), sig.Sig)
}

// ParseEnvelope decodes a signed envelope structurally — payload present and
// within bounds, every signature entry well-formed — without verifying any
// signature. Use it in tooling that inspects or extends an envelope;
// consumers deciding whether to trust one use VerifyManifest.
func ParseEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, fmt.Errorf("update: parse envelope: %w", err)
	}
	if len(env.Payload) == 0 {
		return Envelope{}, errors.New("update: envelope has an empty payload")
	}
	if len(env.Payload) > maxManifestBytes {
		return Envelope{}, fmt.Errorf("update: envelope payload exceeds %d bytes", maxManifestBytes)
	}
	for _, s := range env.Signatures {
		if len(s.Sig) != ed25519.SignatureSize {
			return Envelope{}, fmt.Errorf("update: envelope carries a malformed signature (keyId %q)", s.KeyID)
		}
	}
	return env, nil
}

// Encode serialises the envelope, carrying Payload verbatim: the base64 in
// the output decodes to exactly the bytes that were parsed or signed, so
// existing signatures remain valid.
func (e Envelope) Encode() ([]byte, error) {
	if len(e.Payload) == 0 {
		return nil, errors.New("update: refusing to encode an envelope with an empty payload")
	}
	return json.Marshal(e)
}

// SignerIDs returns the advisory key ids of the signatures present, in
// order. IDs are producer-supplied labels: use them for reporting, never as
// proof of who signed — VerifyPayload against a trusted key is the proof.
func (e Envelope) SignerIDs() []string {
	ids := make([]string, len(e.Signatures))
	for i, s := range e.Signatures {
		ids[i] = s.KeyID
	}
	return ids
}

// Signer pairs a release signing key with an advisory identifier. The KeyID
// travels in the envelope for operator diagnostics only; verification tries
// every trusted key regardless, so a mislabelled KeyID cannot cause a wrong
// accept or a wrong reject.
type Signer struct {
	KeyID string
	Key   ed25519.PrivateKey
}

// SignManifest serialises m and wraps it in a signature envelope carrying
// one signature per signer. It is intended for release tooling; the output
// is what gets served at the manifest URL.
func SignManifest(m Manifest, signers ...Signer) ([]byte, error) {
	if len(signers) == 0 {
		return nil, errors.New("update: SignManifest requires at least one signer")
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("update: marshal manifest: %w", err)
	}
	env := Envelope{Payload: payload}
	for _, s := range signers {
		sig, err := SignPayload(payload, s.Key, s.KeyID)
		if err != nil {
			return nil, err
		}
		env.Signatures = append(env.Signatures, sig)
	}
	return env.Encode()
}

// VerifyManifest parses a signature envelope and verifies it against the
// trusted public keys. It returns the decoded Manifest only when at least
// one signature verifies against at least one trusted key. Any malformed
// signature entry rejects the whole envelope. Unsigned data, an empty
// trusted key set, and an unknown payload schema are all refusals.
func VerifyManifest(data []byte, trusted []ed25519.PublicKey) (Manifest, error) {
	if len(trusted) == 0 {
		return Manifest{}, fmt.Errorf("%w: no trusted keys configured", ErrSignature)
	}
	for i, k := range trusted {
		if len(k) != ed25519.PublicKeySize {
			return Manifest{}, fmt.Errorf("%w: trusted key %d has invalid size %d", ErrSignature, i, len(k))
		}
	}
	env, err := ParseEnvelope(data)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if len(env.Signatures) == 0 {
		return Manifest{}, fmt.Errorf("%w: manifest is unsigned", ErrSignature)
	}
	verified := false
	for _, s := range env.Signatures {
		for _, k := range trusted {
			if VerifyPayload(env.Payload, s, k) {
				verified = true
			}
		}
	}
	if !verified {
		return Manifest{}, fmt.Errorf("%w: no signature matches a trusted key", ErrSignature)
	}
	var m Manifest
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		return Manifest{}, fmt.Errorf("update: decode verified manifest: %w", err)
	}
	if m.Schema != ManifestSchema {
		return Manifest{}, fmt.Errorf("update: manifest schema %d not supported (want %d); refusing", m.Schema, ManifestSchema)
	}
	return m, nil
}

func signingMessage(payload []byte) []byte {
	msg := make([]byte, 0, len(signingContext)+len(payload))
	msg = append(msg, signingContext...)
	return append(msg, payload...)
}
