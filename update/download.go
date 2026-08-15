// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// maxArtifactBytes caps an artifact download (256 MiB) to avoid unbounded
// disk use from a malicious or misconfigured manifest.
const maxArtifactBytes int64 = 256 << 20

// downloadArtifact fetches art.URL into a freshly created staging file
// inside destDir, streaming the body through a SHA-256 hasher. destDir is
// always the directory of the binary being replaced, so the eventual install
// is a same-filesystem rename, never a cross-device copy.
//
// The digest comes from the signed manifest, so a mismatch means the
// artifact host served something other than what was signed; the partial
// file is removed and an error returned. On success the staged path is
// returned.
func downloadArtifact(ctx context.Context, client *http.Client, art Artifact, destDir, base string) (stagedPath string, err error) {
	if art.URL == "" {
		return "", fmt.Errorf("update: artifact has no URL")
	}
	if art.SHA256 == "" {
		return "", fmt.Errorf("update: artifact has no sha256 digest in the signed manifest")
	}
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, art.URL, nil)
	if err != nil {
		return "", fmt.Errorf("update: build artifact request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("update: download artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("update: artifact fetch returned status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(destDir, base+".staged-*")
	if err != nil {
		return "", fmt.Errorf("update: create staging file: %w", err)
	}
	tmpPath := tmp.Name()

	// Never leave a partial or unverified file behind on any error path.
	cleanup := true
	defer func() {
		if cleanup {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	limited := io.LimitReader(resp.Body, maxArtifactBytes+1)
	written, err := io.Copy(io.MultiWriter(tmp, hasher), limited)
	if err != nil {
		return "", fmt.Errorf("update: stream artifact: %w", err)
	}
	if written > maxArtifactBytes {
		return "", fmt.Errorf("update: artifact exceeds max size of %d bytes", maxArtifactBytes)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("update: sync staging file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("update: flush staging file: %w", err)
	}

	got := hex.EncodeToString(hasher.Sum(nil))
	want := strings.ToLower(strings.TrimSpace(art.SHA256))
	if got != want {
		return "", fmt.Errorf("update: artifact digest mismatch: got %s, signed manifest says %s", got, want)
	}

	cleanup = false
	return tmpPath, nil
}
