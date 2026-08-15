// SPDX-License-Identifier: Apache-2.0

package vault_test

import (
	"context"
	"sync"

	"github.com/BlueHeisenberg/keel/vault"
)

// memKeyring is an in-memory vault.Keyring for tests. It is safe for
// concurrent use and deep-copies records on the way in and out so tests
// cannot accidentally alias its internal state.
type memKeyring struct {
	mu    sync.Mutex
	rec   vault.KeyRecord
	has   bool
	saves int // number of successful Save calls
}

func (k *memKeyring) Load(_ context.Context) (vault.KeyRecord, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.has {
		return vault.KeyRecord{}, vault.ErrNoKey
	}
	return copyRecord(k.rec), nil
}

func (k *memKeyring) Save(_ context.Context, rec vault.KeyRecord) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rec = copyRecord(rec)
	k.has = true
	k.saves++
	return nil
}

// snapshot returns the stored record and whether one exists.
func (k *memKeyring) snapshot() (vault.KeyRecord, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return copyRecord(k.rec), k.has
}

func copyRecord(rec vault.KeyRecord) vault.KeyRecord {
	return vault.KeyRecord{
		ID:         rec.ID,
		Salt:       append([]byte(nil), rec.Salt...),
		Params:     append([]byte(nil), rec.Params...),
		WrappedKey: append([]byte(nil), rec.WrappedKey...),
	}
}
