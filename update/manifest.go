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

// manifestSchema is the manifest payload schema this build understands. An
// unknown schema is refused: failing closed costs an update, never a
// deployment.
const manifestSchema = 1

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

// envelope is the wire format served at the manifest URL:
//
//	{
//	  "payload":    "<base64 of the Manifest JSON>",
//	  "signatures": [{"keyId": "2026-a", "signature": "<base64 Ed25519>"}]
//	}
//
// The signature is computed over signingContext || payload bytes, so there
// is no canonicalisation step to get wrong: the exact bytes that were signed
// are the exact bytes that are verified and then decoded.
type envelope struct {
	Payload    []byte              `json:"payload"`
	Signatures []envelopeSignature `json:"signatures"`
}

type envelopeSignature struct {
	KeyID string `json:"keyId,omitempty"`
	Sig   []byte `json:"signature"`
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
	msg := signingMessage(payload)
	env := envelope{Payload: payload}
	for _, s := range signers {
		if len(s.Key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("update: signer %q: invalid Ed25519 private key size %d", s.KeyID, len(s.Key))
		}
		env.Signatures = append(env.Signatures, envelopeSignature{
			KeyID: s.KeyID,
			Sig:   ed25519.Sign(s.Key, msg),
		})
	}
	return json.Marshal(env)
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
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Manifest{}, fmt.Errorf("%w: parse envelope: %v", ErrSignature, err)
	}
	if len(env.Payload) == 0 {
		return Manifest{}, fmt.Errorf("%w: empty payload", ErrSignature)
	}
	if len(env.Payload) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: payload exceeds %d bytes", ErrSignature, maxManifestBytes)
	}
	if len(env.Signatures) == 0 {
		return Manifest{}, fmt.Errorf("%w: manifest is unsigned", ErrSignature)
	}
	msg := signingMessage(env.Payload)
	verified := false
	for _, s := range env.Signatures {
		if len(s.Sig) != ed25519.SignatureSize {
			return Manifest{}, fmt.Errorf("%w: malformed signature (keyId %q)", ErrSignature, s.KeyID)
		}
		for _, k := range trusted {
			if ed25519.Verify(k, msg, s.Sig) {
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
	if m.Schema != manifestSchema {
		return Manifest{}, fmt.Errorf("update: manifest schema %d not supported (want %d); refusing", m.Schema, manifestSchema)
	}
	return m, nil
}

func signingMessage(payload []byte) []byte {
	msg := make([]byte, 0, len(signingContext)+len(payload))
	msg = append(msg, signingContext...)
	return append(msg, payload...)
}
