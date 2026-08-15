// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// env is a signed-release test harness: an httptest server carrying a
// manifest endpoint plus artifact endpoints, a release key pair, and a fake
// target binary on disk.
type env struct {
	t        *testing.T
	mux      *http.ServeMux
	srv      *httptest.Server
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	dir      string
	target   string
	manifest atomic.Value // []byte: envelope served at /manifest.json
	requests atomic.Int64
	nextArt  atomic.Int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pub, priv := genKey(t)
	e := &env{t: t, mux: http.NewServeMux(), pub: pub, priv: priv}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		e.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(e.srv.Close)
	e.mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		body, _ := e.manifest.Load().([]byte)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	e.dir = t.TempDir()
	e.target = filepath.Join(e.dir, "app")
	writeBinary(t, e.target, oldBinary)
	return e
}

// artifact registers an endpoint serving `served` and returns an Artifact
// whose signed digest is that of `digestOf` — pass different slices to model
// an artifact host serving something other than what was signed.
func (e *env) artifact(served, digestOf []byte) Artifact {
	path := fmt.Sprintf("/artifact-%d", e.nextArt.Add(1))
	e.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(served)
	})
	sum := sha256.Sum256(digestOf)
	return Artifact{URL: e.srv.URL + path, SHA256: hex.EncodeToString(sum[:])}
}

// release builds a Release for the running platform serving `artifact`.
func (e *env) release(version string, artifact []byte, mut func(*Release)) Release {
	rel := Release{
		Version:     version,
		Notes:       "notes for " + version,
		PublishedAt: time.Now().UTC(),
		Artifacts:   map[string]Artifact{Platform(): e.artifact(artifact, artifact)},
	}
	if mut != nil {
		mut(&rel)
	}
	return rel
}

// serveManifest signs and publishes a manifest carrying rel on both the edge
// and stable channels.
func (e *env) serveManifest(rel Release, signers ...Signer) {
	e.t.Helper()
	m := Manifest{
		Schema:      manifestSchema,
		GeneratedAt: time.Now().UTC(),
		Channels:    map[string]Release{"edge": rel, "stable": rel},
	}
	if len(signers) == 0 {
		signers = []Signer{{KeyID: "k1", Key: e.priv}}
	}
	data, err := SignManifest(m, signers...)
	if err != nil {
		e.t.Fatalf("SignManifest: %v", err)
	}
	e.manifest.Store(data)
}

// serveRaw publishes arbitrary bytes at the manifest URL.
func (e *env) serveRaw(data []byte) { e.manifest.Store(data) }

func (e *env) updater(mod func(*Config)) *Updater {
	e.t.Helper()
	cfg := Config{
		ManifestURL:   e.srv.URL + "/manifest.json",
		Keys:          []ed25519.PublicKey{e.pub},
		Channel:       ChannelEdge,
		Current:       "v1.0.0",
		TargetPath:    e.target,
		HTTPClient:    e.srv.Client(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		HealthTimeout: 2 * time.Second,
		// Most tests install non-executable fake binaries; preflight is
		// exercised explicitly by the TestPreflight* tests.
		SkipPreflight: true,
	}
	if mod != nil {
		mod(&cfg)
	}
	u, err := New(cfg)
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	return u
}

func TestCheckSignedManifestAccepted(t *testing.T) {
	e := newEnv(t)
	e.serveManifest(e.release("v1.1.0", newBinary, nil))
	u := e.updater(nil)
	st, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !st.Available || st.Release == nil {
		t.Fatalf("expected available update, got %+v", st)
	}
	if st.Latest != "v1.1.0" || st.Current != "v1.0.0" || st.Platform != Platform() {
		t.Errorf("status fields wrong: %+v", st)
	}
}

func TestCheckUpToDate(t *testing.T) {
	e := newEnv(t)
	e.serveManifest(e.release("v1.0.0", newBinary, nil))
	st, err := e.updater(nil).Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.Available {
		t.Fatalf("equal version reported as available: %+v", st)
	}
}

func TestCheckDowngradeNotAvailable(t *testing.T) {
	e := newEnv(t)
	e.serveManifest(e.release("v0.9.0", newBinary, nil))
	st, err := e.updater(nil).Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.Available {
		t.Fatalf("older version reported as available: %+v", st)
	}
}

func TestApplyDowngradeRejected(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v0.9.0", newBinary, nil)
	err := e.updater(nil).Apply(context.Background(), rel)
	if !errors.Is(err, ErrDowngrade) {
		t.Fatalf("Apply(older) = %v, want ErrDowngrade", err)
	}
	assertTargetUntouched(t, e)
}

func TestCheckRejectsTamperedManifest(t *testing.T) {
	e := newEnv(t)
	e.serveManifest(e.release("v1.1.0", newBinary, nil))
	data, _ := e.manifest.Load().([]byte)
	var env2 envelope
	if err := json.Unmarshal(data, &env2); err != nil {
		t.Fatal(err)
	}
	env2.Payload = bytes.Replace(env2.Payload, []byte("v1.1.0"), []byte("v9.9.9"), 1)
	tampered, err := json.Marshal(env2)
	if err != nil {
		t.Fatal(err)
	}
	e.serveRaw(tampered)
	if _, err := e.updater(nil).Check(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered manifest: got %v, want ErrSignature", err)
	}
}

func TestCheckRejectsWrongKey(t *testing.T) {
	e := newEnv(t)
	_, attackerPriv := genKey(t)
	e.serveManifest(e.release("v1.1.0", newBinary, nil), Signer{KeyID: "evil", Key: attackerPriv})
	if _, err := e.updater(nil).Check(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: got %v, want ErrSignature", err)
	}
}

func TestCheckRejectsUnsignedManifest(t *testing.T) {
	e := newEnv(t)
	raw, err := json.Marshal(Manifest{
		Schema:   manifestSchema,
		Channels: map[string]Release{"edge": e.release("v1.1.0", newBinary, nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.serveRaw(raw)
	if _, err := e.updater(nil).Check(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("unsigned manifest: got %v, want ErrSignature", err)
	}
}

func TestCheckAcceptsRotatedKey(t *testing.T) {
	e := newEnv(t)
	newPub, newPriv := genKey(t)
	e.serveManifest(e.release("v1.1.0", newBinary, nil), Signer{KeyID: "2026-b", Key: newPriv})
	u := e.updater(func(c *Config) {
		c.Keys = []ed25519.PublicKey{e.pub, newPub} // old key retained, new key added
	})
	st, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check with rotated key: %v", err)
	}
	if !st.Available {
		t.Fatalf("rotated key manifest not available: %+v", st)
	}
}

func TestApplyRejectsTamperedArtifact(t *testing.T) {
	e := newEnv(t)
	evil := []byte("EVIL bytes the host serves instead of what was signed")
	rel := Release{
		Version:     "v1.1.0",
		PublishedAt: time.Now().UTC(),
		Artifacts:   map[string]Artifact{Platform(): e.artifact(evil, newBinary)},
	}
	e.serveManifest(rel)
	err := e.updater(nil).Apply(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered artifact: got %v, want digest mismatch", err)
	}
	assertTargetUntouched(t, e)
}

func TestApplySwapAndCommit(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)

	var restarted atomic.Bool
	u := e.updater(func(c *Config) {
		c.Restart = func(context.Context) error { restarted.Store(true); return nil }
	})
	if err := u.Apply(context.Background(), rel); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !restarted.Load() {
		t.Fatal("Restart hook not invoked")
	}
	got, err := os.ReadFile(e.target)
	if err != nil || !bytes.Equal(got, newBinary) {
		t.Fatalf("target after apply: %q err=%v", got, err)
	}
	prev, err := os.ReadFile(e.target + ".prev")
	if err != nil || !bytes.Equal(prev, oldBinary) {
		t.Fatalf("retained previous: %q err=%v", prev, err)
	}

	// A second Apply while the journal is pending is refused.
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("second Apply = %v, want ErrUpdateInProgress", err)
	}

	// "Restart": the new binary boots, passes health, commits.
	u2 := e.updater(func(c *Config) {
		c.Current = "v1.1.0"
		c.Health = func(context.Context) error { return nil }
	})
	rep, err := u2.Resume(context.Background())
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rep.Outcome != OutcomeCommitted {
		t.Fatalf("Outcome = %v, want OutcomeCommitted", rep.Outcome)
	}
	if fileExists(journalPath(e.target)) {
		t.Fatal("journal not removed after commit")
	}
	if !fileExists(e.target + ".prev") {
		t.Fatal("previous binary not retained after commit")
	}
	assertOnlyExpectedFiles(t, e.dir, e.target)
}

func TestHealthFailureTriggersRollback(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)
	if err := e.updater(nil).Apply(context.Background(), rel); !errors.Is(err, ErrRestartPending) {
		t.Fatalf("Apply = %v, want ErrRestartPending with no Restart hook", err)
	}

	var restarted atomic.Bool
	u2 := e.updater(func(c *Config) {
		c.Current = "v1.1.0"
		c.Health = func(context.Context) error { return errors.New("lore MCP did not respond") }
		c.Restart = func(context.Context) error { restarted.Store(true); return nil }
	})
	rep, err := u2.Resume(context.Background())
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rep.Outcome != OutcomeRolledBack || !strings.Contains(rep.Reason, "lore MCP") {
		t.Fatalf("report = %+v, want rollback carrying the health failure", rep)
	}
	if !restarted.Load() {
		t.Fatal("Restart not invoked after rollback; the process would keep running the bad binary")
	}
	got, err := os.ReadFile(e.target)
	if err != nil || !bytes.Equal(got, oldBinary) {
		t.Fatalf("target after rollback: %q err=%v, want the old binary byte-identical", got, err)
	}
}

func TestHealthTimeoutTriggersRollback(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)
	if err := e.updater(nil).Apply(context.Background(), rel); !errors.Is(err, ErrRestartPending) {
		t.Fatalf("Apply = %v", err)
	}
	u2 := e.updater(func(c *Config) {
		c.Current = "v1.1.0"
		c.HealthTimeout = 50 * time.Millisecond
		c.Health = func(ctx context.Context) error {
			<-ctx.Done() // a hung health check
			return ctx.Err()
		}
	})
	rep, err := u2.Resume(context.Background())
	if !errors.Is(err, ErrRestartPending) {
		t.Fatalf("Resume err = %v, want ErrRestartPending", err)
	}
	if rep.Outcome != OutcomeRolledBack || !strings.Contains(rep.Reason, "health check") {
		t.Fatalf("report = %+v, want rollback on health timeout", rep)
	}
	got, _ := os.ReadFile(e.target)
	if !bytes.Equal(got, oldBinary) {
		t.Fatalf("target after timeout rollback: %q", got)
	}
}

func TestDrainRunsBeforeRestartAndSwap(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)

	var mu sync.Mutex
	var events []string
	record := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, name)
	}
	u := e.updater(func(c *Config) {
		c.Drain = func(context.Context) error {
			// The swap must not have happened yet: no turn may be lost.
			if data, err := os.ReadFile(e.target); err != nil || !bytes.Equal(data, oldBinary) {
				t.Errorf("swap ran before drain completed")
			}
			record("drain")
			return nil
		}
		c.Restart = func(context.Context) error { record("restart"); return nil }
	})
	if err := u.Apply(context.Background(), rel); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0] != "drain" || events[1] != "restart" {
		t.Fatalf("events = %v, want [drain restart]", events)
	}
}

func TestDrainErrorAbortsWithNothingChanged(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)
	u := e.updater(func(c *Config) {
		c.Drain = func(context.Context) error { return errors.New("turns still in flight") }
	})
	err := u.Apply(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "drain") {
		t.Fatalf("Apply = %v, want drain error", err)
	}
	assertTargetUntouched(t, e)
}

func TestMajorVersionRequiresConsent(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v2.0.0", newBinary, nil)
	e.serveManifest(rel)

	// No Consent hook configured: refusal.
	if err := e.updater(nil).Apply(context.Background(), rel); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("no hook: got %v, want ErrConsentRequired", err)
	}
	assertTargetUntouched(t, e)

	// Consent declined: refusal, and nothing was downloaded (consent is
	// asked before any bytes move).
	preRequests := e.requests.Load()
	u := e.updater(func(c *Config) {
		c.Consent = func(ctx context.Context, from, to Version, notes string) (bool, error) {
			if from.String() != "v1.0.0" || to.String() != "v2.0.0" || !strings.Contains(notes, "v2.0.0") {
				t.Errorf("consent args: from=%s to=%s notes=%q", from, to, notes)
			}
			return false, nil
		}
	})
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrConsentDeclined) {
		t.Fatalf("declined: got %v, want ErrConsentDeclined", err)
	}
	if e.requests.Load() != preRequests {
		t.Error("artifact was downloaded before consent was granted")
	}
	assertTargetUntouched(t, e)

	// Consent granted: the major version applies.
	u2 := e.updater(func(c *Config) {
		c.Consent = func(context.Context, Version, Version, string) (bool, error) { return true, nil }
	})
	if err := u2.Apply(context.Background(), rel); !errors.Is(err, ErrRestartPending) {
		t.Fatalf("granted: got %v, want ErrRestartPending", err)
	}
	got, _ := os.ReadFile(e.target)
	if !bytes.Equal(got, newBinary) {
		t.Fatalf("target after consented major update: %q", got)
	}
}

func TestSecuritySensitiveRequiresConsentEvenForPatch(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.0.1", newBinary, func(r *Release) { r.SecuritySensitive = true })
	e.serveManifest(rel)

	if err := e.updater(nil).Apply(context.Background(), rel); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("security-sensitive patch without hook: got %v, want ErrConsentRequired", err)
	}
	assertTargetUntouched(t, e)

	u := e.updater(func(c *Config) {
		c.Consent = func(context.Context, Version, Version, string) (bool, error) { return false, nil }
	})
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrConsentDeclined) {
		t.Fatalf("security-sensitive declined: got %v, want ErrConsentDeclined", err)
	}
	assertTargetUntouched(t, e)
}

func TestOffChannelNeverFetches(t *testing.T) {
	e := newEnv(t)
	e.serveManifest(e.release("v9.9.9", newBinary, nil))
	u := e.updater(func(c *Config) {
		c.Channel = ChannelOff
		c.Keys = nil // off requires neither keys nor a reachable manifest
	})
	if _, err := u.Check(context.Background()); !errors.Is(err, ErrChannelOff) {
		t.Fatalf("Check = %v, want ErrChannelOff", err)
	}
	if err := u.Apply(context.Background(), e.release("v9.9.9", newBinary, nil)); !errors.Is(err, ErrChannelOff) {
		t.Fatalf("Apply = %v, want ErrChannelOff", err)
	}
	if err := u.Run(context.Background()); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if n := e.requests.Load(); n != 0 {
		t.Fatalf("off channel made %d HTTP requests; must make none", n)
	}
	assertTargetUntouched(t, e)
}

func TestStableChannelLagsByDelay(t *testing.T) {
	e := newEnv(t)
	t0 := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	rel := e.release("v1.1.0", newBinary, func(r *Release) { r.PublishedAt = t0 })
	e.serveManifest(rel)

	u := e.updater(func(c *Config) {
		c.Channel = ChannelStable
		c.StableDelay = 24 * time.Hour
	})

	u.now = func() time.Time { return t0.Add(1 * time.Hour) }
	st, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.Available {
		t.Fatalf("release available 1h after publish with a 24h stable delay: %+v", st)
	}
	if !strings.Contains(st.Reason, "stable delay") {
		t.Errorf("Reason = %q, want stable delay explanation", st.Reason)
	}

	u.now = func() time.Time { return t0.Add(25 * time.Hour) }
	st, err = u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !st.Available {
		t.Fatalf("release not available after the delay elapsed: %+v", st)
	}
}

func TestStableDelayFailsClosedWithoutPublishedAt(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, func(r *Release) { r.PublishedAt = time.Time{} })
	e.serveManifest(rel)
	u := e.updater(func(c *Config) {
		c.Channel = ChannelStable
		c.StableDelay = 24 * time.Hour
	})
	st, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.Available {
		t.Fatal("release without publishedAt must not satisfy a stable delay")
	}
}

func TestStaleManifestRejected(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	m := Manifest{
		Schema:      manifestSchema,
		GeneratedAt: time.Now().Add(-48 * time.Hour).UTC(),
		Channels:    map[string]Release{"edge": rel, "stable": rel},
	}
	data, err := SignManifest(m, Signer{KeyID: "k1", Key: e.priv})
	if err != nil {
		t.Fatal(err)
	}
	e.serveRaw(data)
	u := e.updater(func(c *Config) { c.MaxManifestAge = 24 * time.Hour })
	if _, err := u.Check(context.Background()); !errors.Is(err, ErrStale) {
		t.Fatalf("stale manifest: got %v, want ErrStale", err)
	}
}

func TestRunAppliesEligibleRelease(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)
	u := e.updater(func(c *Config) { c.CheckInterval = 10 * time.Millisecond })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := u.Run(ctx)
	if !errors.Is(err, ErrRestartPending) {
		t.Fatalf("Run = %v, want ErrRestartPending after the swap", err)
	}
	got, _ := os.ReadFile(e.target)
	if !bytes.Equal(got, newBinary) {
		t.Fatalf("target after Run: %q", got)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{Channel: ChannelEdge}); err == nil {
		t.Error("New without ManifestURL must fail when updating is on")
	}
	if _, err := New(Config{Channel: ChannelEdge, ManifestURL: "https://x"}); err == nil {
		t.Error("New without trusted keys must fail when updating is on")
	}
	if _, err := New(Config{Channel: ChannelEdge, ManifestURL: "https://x", Keys: []ed25519.PublicKey{[]byte("short")}}); err == nil {
		t.Error("New with a malformed trusted key must fail")
	}
	if _, err := New(Config{Channel: "weekly"}); err == nil {
		t.Error("New with an unknown channel must fail")
	}
	if _, err := New(Config{Channel: ChannelOff}); err != nil {
		t.Errorf("New with channel off needs no URL or keys: %v", err)
	}
	if _, err := New(Config{Channel: ChannelOff, Current: "not-a-version"}); err == nil {
		t.Error("New with an unparseable current version must fail")
	}

	pub, _ := genKey(t)
	base := Config{Channel: ChannelEdge, ManifestURL: "https://x", Keys: []ed25519.PublicKey{pub}}
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "Preflight") {
		t.Errorf("New without preflight configuration must fail explicitly, got %v", err)
	}
	withArgs := base
	withArgs.PreflightArgs = []string{"version"}
	if _, err := New(withArgs); err != nil {
		t.Errorf("New with PreflightArgs: %v", err)
	}
	withSkip := base
	withSkip.SkipPreflight = true
	if _, err := New(withSkip); err != nil {
		t.Errorf("New with explicit SkipPreflight: %v", err)
	}
}

// assertTargetUntouched verifies the fake binary is byte-identical to the
// original and that no staging, journal, or backup files were left behind.
func assertTargetUntouched(t *testing.T, e *env) {
	t.Helper()
	got, err := os.ReadFile(e.target)
	if err != nil || !bytes.Equal(got, oldBinary) {
		t.Fatalf("target modified: %q err=%v", got, err)
	}
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if en.Name() != filepath.Base(e.target) {
			t.Errorf("leftover file %q after a refused update", en.Name())
		}
	}
}
