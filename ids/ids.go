// SPDX-License-Identifier: Apache-2.0

// Package ids generates prefixed, URL-safe unique identifiers.
//
// The format is "<prefix>_<32 lowercase hex characters>": 128 bits from
// crypto/rand, rendered as hex. Prefixes are chosen by the caller and ids
// assigns no meaning to them — an identifier is an opaque string, and what it
// identifies is the caller's business.
//
//	ids.New("sbx") // "sbx_9f1c0b0d4a7e4f0e8c2d3b6a5e4f1027"
package ids

import (
	"crypto/rand"
	"encoding/hex"
)

// randomBytes is the number of random bytes behind every identifier. Sixteen
// bytes is 128 bits, the same entropy budget as a random UUID and enough that
// collisions are not worth reasoning about.
const randomBytes = 16

// New returns an identifier with the given prefix, in the form
// "<prefix>_<32 hex characters>". The prefix is used verbatim; it is not
// validated, and an empty prefix yields a leading underscore.
//
// New panics if the system random source fails, which on any supported
// platform means the process is already in an unrecoverable state.
func New(prefix string) string {
	var b [randomBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("keel/ids: crypto/rand unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
