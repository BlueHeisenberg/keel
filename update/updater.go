// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Channel selects which release stream a deployment follows.
type Channel string

const (
	// ChannelStable lags ChannelEdge: a stable release is eligible only
	// once it has been published for at least Config.StableDelay, so edge
	// households find breakage first.
	ChannelStable Channel = "stable"
	// ChannelEdge applies eligible releases as soon as they are published.
	ChannelEdge Channel = "edge"
	// ChannelOff disables updating entirely. Nothing is ever fetched and
	// the product works forever without updating; this is a supported
	// permanent state, not a degraded one.
	ChannelOff Channel = "off"
)

// HealthCheck reports whether the freshly restarted binary is healthy. It
// is supplied by the consumer and must cover only what the process itself
// controls (it started, its own services respond). External resources that
// are legitimately unavailable — a powered-off household machine, a
// sleeping endpoint — must NOT be part of health, or a good update will be
// rolled back, re-applied, and rolled back again forever.
type HealthCheck func(context.Context) error

// Drain blocks until it is safe to restart — for a conversational product,
// until no participant has a turn in flight. It runs after the artifact is
// verified and before the binary swap; returning an error aborts the update
// with nothing changed on disk.
type Drain func(context.Context) error

// ConsentRequest carries everything a human needs to decide on an update:
// the version pair, the release notes, and — critically — whether the
// release is flagged SecuritySensitive, so the consumer can ask "this
// release changes security-relevant behaviour — approve?" rather than only
// "there is a new version".
type ConsentRequest struct {
	From              Version
	To                Version
	Notes             string
	SecuritySensitive bool
}

// Decision is a consent hook's answer. The zero value is DecisionUnanswered
// on purpose: a hook that returns without deciding re-asks next cycle
// rather than silently approving or permanently suppressing a release.
type Decision int

const (
	// DecisionUnanswered: nobody answered (a timed-out question, an
	// unavailable channel). Not a decision — the update is not applied
	// now, and the same release is asked about again on the next cycle.
	DecisionUnanswered Decision = iota
	// DecisionApproved: a human approved; the update proceeds.
	DecisionApproved
	// DecisionDeclined: a human said no. Run remembers the declined
	// version and does not re-ask until a different version appears.
	DecisionDeclined
)

// Consent asks a human whether the update described by req may proceed. It
// is required for a major version bump and for any release flagged
// SecuritySensitive. Any error, and any Decision other than
// DecisionApproved, means the update is not applied; the distinction
// between DecisionDeclined and DecisionUnanswered controls only whether the
// question is asked again.
type Consent func(ctx context.Context, req ConsentRequest) (Decision, error)

// Restart restarts the process after a swap or a rollback: exit and let a
// supervisor bring the process back up, or re-exec in place. When nil,
// Apply and Resume return ErrRestartPending instead and the caller owns the
// restart.
type Restart func(context.Context) error

// Sentinel errors callers must be able to distinguish.
var (
	ErrChannelOff      = errors.New("update: updates are disabled (channel off)")
	ErrConsentRequired = errors.New("update: release requires consent but no Consent hook is configured")
	ErrConsentDeclined = errors.New("update: consent declined")
	// ErrConsentUnanswered: the consent question got no answer. Silence is
	// not a decision — the release stays eligible and is asked about again
	// on the next cycle, unlike ErrConsentDeclined which Run remembers.
	ErrConsentUnanswered = errors.New("update: consent question unanswered; will ask again")
	ErrDowngrade         = errors.New("update: refusing to apply a version that is not newer than the running one")
	ErrNoArtifact        = errors.New("update: release has no artifact for this platform")
	ErrUpdateInProgress  = errors.New("update: an update is already pending; call Resume first")
	ErrRestartPending    = errors.New("update: binary swapped; restart the process to continue")
	ErrStale             = errors.New("update: manifest is older than the configured maximum age")
	// ErrPreflight: the staged binary could not be executed successfully
	// before the swap. The update is refused and the running system is left
	// untouched — a binary that cannot even start would never reach Resume,
	// so it must never reach the target path either.
	ErrPreflight = errors.New("update: staged binary failed preflight; update refused")
)

// Config wires an Updater. ManifestURL and at least one trusted key are
// required unless Channel is ChannelOff.
type Config struct {
	// ManifestURL serves the signed manifest envelope.
	ManifestURL string
	// Keys are the trusted Ed25519 release public keys, compiled into the
	// consuming binary. More than one key may be trusted so keys can be
	// rotated without stranding deployments.
	Keys []ed25519.PublicKey
	// Channel is stable, edge, or off. Empty defaults to stable.
	Channel Channel
	// Current is the running build's version ("v1.2.3"). "" and "dev"
	// sort below every real version.
	Current string
	// TargetPath is the binary to replace. Empty means the running
	// executable, resolved through symlinks.
	TargetPath string
	// StableDelay is how long a release must have been published before
	// the stable channel will apply it. Ignored on other channels. If a
	// release carries no publishedAt and StableDelay > 0, it is refused
	// (fail closed).
	StableDelay time.Duration
	// CheckInterval is the Run polling period. Defaults to 6h.
	CheckInterval time.Duration
	// MaxManifestAge, when > 0, refuses manifests whose generatedAt is
	// older than this, bounding replay of stale signed manifests. Zero
	// disables the check.
	MaxManifestAge time.Duration
	// HealthTimeout bounds the post-restart health check. Defaults to 30s.
	HealthTimeout time.Duration

	// PreflightArgs are the arguments the staged binary is executed with
	// before the swap (kenward uses ["version"]). The staged binary must
	// exit 0 within PreflightTimeout or the update is refused with
	// ErrPreflight and nothing on disk changes. This is the only guard
	// against a build broken enough that it would never start — such a
	// binary can never be rolled back by Resume, because Resume runs
	// inside it. Required unless SkipPreflight is set or the channel is
	// off: a deployment that cannot exec the staged file is exactly the
	// deployment that most needs this check.
	PreflightArgs []string
	// PreflightTimeout bounds the preflight execution. Defaults to 10s.
	// A hang is a failure.
	PreflightTimeout time.Duration
	// SkipPreflight disables the preflight check. It must be an explicit
	// decision; there is no implicit default that skips it.
	SkipPreflight bool

	// LockStaleAfter is how old the cross-process lock file may be before
	// it is presumed abandoned by a crashed updater and broken. Defaults
	// to 10 minutes. The lock serialises processes sharing one install
	// path; the loser receives ErrLocked, skips the cycle quietly, and
	// retries on its next check. The lock is held across the drain, whose
	// timestamp it refreshes on completion — configure LockStaleAfter
	// comfortably longer than the worst-case drain.
	LockStaleAfter time.Duration

	// Now is the clock used for every time-based policy decision: the
	// stable-channel delay, manifest freshness, lock staleness, and
	// journal timestamps. Nil means time.Now. It exists so consumers can
	// test scheduling behaviour against this package rather than around
	// it; Run's tick interval still elapses in wall-clock time.
	Now func() time.Time

	HTTPClient *http.Client
	Logger     *slog.Logger

	Health  HealthCheck
	Drain   Drain
	Consent Consent
	Restart Restart
}

// Status is the outcome of a Check.
type Status struct {
	Current   string
	Latest    string
	Platform  string
	Available bool
	// Reason explains why no update is available (up to date, stable
	// delay, missing artifact). Informational only.
	Reason string
	// Release is the eligible release when Available is true.
	Release *Release
}

// Outcome describes what Resume did.
type Outcome int

const (
	// OutcomeNone: no update was in flight.
	OutcomeNone Outcome = iota
	// OutcomeCommitted: the new binary passed its health check and was kept.
	OutcomeCommitted
	// OutcomeRolledBack: the update failed and the previous binary was
	// (or already had been) restored.
	OutcomeRolledBack
	// OutcomeAborted: a swap never took effect (crash mid-sequence); the
	// previous state was restored or confirmed and leftovers were removed.
	OutcomeAborted
)

// ResumeReport describes the update Resume found and what it did about it.
type ResumeReport struct {
	Outcome Outcome
	From    string
	To      string
	Reason  string
}

// Updater checks for, applies, and verifies signed binary updates.
type Updater struct {
	cfg     Config
	current Version
	target  string
	client  *http.Client
	log     *slog.Logger

	// seams, overridden in tests
	now     func() time.Time
	fs      fsOps
	winSwap bool

	mu       sync.Mutex
	declined map[string]bool
}

// New validates cfg and builds an Updater.
func New(cfg Config) (*Updater, error) {
	if cfg.Channel == "" {
		cfg.Channel = ChannelStable
	}
	switch cfg.Channel {
	case ChannelStable, ChannelEdge, ChannelOff:
	default:
		return nil, fmt.Errorf("update: unknown channel %q (want stable, edge, or off)", cfg.Channel)
	}
	if cfg.Channel != ChannelOff {
		if cfg.ManifestURL == "" {
			return nil, errors.New("update: ManifestURL is required unless the channel is off")
		}
		if len(cfg.Keys) == 0 {
			return nil, errors.New("update: at least one trusted release key is required unless the channel is off")
		}
		for i, k := range cfg.Keys {
			if len(k) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("update: trusted key %d has invalid size %d", i, len(k))
			}
		}
	}
	current, err := parseVersionAllowDev(cfg.Current)
	if err != nil {
		return nil, fmt.Errorf("update: invalid current version: %w", err)
	}
	if cfg.Channel != ChannelOff && !cfg.SkipPreflight && len(cfg.PreflightArgs) == 0 {
		return nil, errors.New("update: PreflightArgs is required (e.g. [\"version\"]); set SkipPreflight explicitly to run without a preflight check")
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = 30 * time.Second
	}
	if cfg.PreflightTimeout <= 0 {
		cfg.PreflightTimeout = 10 * time.Second
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 6 * time.Hour
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	target := cfg.TargetPath
	if target == "" {
		exe, err := os.Executable()
		if err != nil {
			if cfg.Channel != ChannelOff {
				return nil, fmt.Errorf("update: resolve running executable: %w", err)
			}
		} else {
			if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
				exe = resolved
			}
			target = exe
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Updater{
		cfg:      cfg,
		current:  current,
		target:   target,
		client:   client,
		log:      logger,
		now:      now,
		fs:       osFS{},
		winSwap:  runtime.GOOS == "windows",
		declined: make(map[string]bool),
	}, nil
}

// Platform returns the "GOOS/GOARCH" artifact key for the running process.
func Platform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// Check fetches and verifies the manifest and reports whether an eligible
// update exists for this platform and channel. On ChannelOff it performs no
// network activity at all and returns ErrChannelOff.
func (u *Updater) Check(ctx context.Context) (Status, error) {
	if u.cfg.Channel == ChannelOff {
		return Status{}, ErrChannelOff
	}
	st := Status{Current: u.current.String(), Platform: Platform()}

	m, err := u.fetchManifest(ctx)
	if err != nil {
		return st, err
	}
	rel, ok := m.Channels[string(u.cfg.Channel)]
	if !ok {
		return st, fmt.Errorf("update: channel %q not present in manifest", u.cfg.Channel)
	}
	to, err := ParseVersion(rel.Version)
	if err != nil {
		return st, fmt.Errorf("update: manifest advertises unparseable version: %w", err)
	}
	st.Latest = rel.Version
	if to.Compare(u.current) <= 0 {
		st.Reason = "up to date"
		return st, nil
	}
	art, ok := rel.Artifacts[Platform()]
	if !ok || art.URL == "" || art.SHA256 == "" {
		st.Reason = "no artifact for " + Platform()
		return st, nil
	}
	if u.cfg.Channel == ChannelStable && u.cfg.StableDelay > 0 {
		if rel.PublishedAt.IsZero() {
			st.Reason = "release has no publishedAt; the stable delay cannot be evaluated"
			return st, nil
		}
		if ready := rel.PublishedAt.Add(u.cfg.StableDelay); u.now().Before(ready) {
			st.Reason = fmt.Sprintf("stable delay: eligible at %s", ready.UTC().Format(time.RFC3339))
			return st, nil
		}
	}
	relCopy := rel
	st.Available = true
	st.Release = &relCopy
	return st, nil
}

func (u *Updater) fetchManifest(ctx context.Context) (Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.cfg.ManifestURL, nil)
	if err != nil {
		return Manifest{}, fmt.Errorf("update: build manifest request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := u.client.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("update: fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("update: manifest fetch returned status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("update: read manifest: %w", err)
	}
	if len(data) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("update: manifest exceeds %d bytes", maxManifestBytes)
	}
	m, err := VerifyManifest(data, u.cfg.Keys)
	if err != nil {
		return Manifest{}, err
	}
	if u.cfg.MaxManifestAge > 0 {
		if m.GeneratedAt.IsZero() {
			return Manifest{}, fmt.Errorf("%w: manifest carries no generatedAt", ErrStale)
		}
		if age := u.now().Sub(m.GeneratedAt); age > u.cfg.MaxManifestAge {
			return Manifest{}, fmt.Errorf("%w: generated %s ago", ErrStale, age.Round(time.Second))
		}
	}
	return m, nil
}

// Apply downloads, verifies, and installs rel — a Release obtained from
// Check, whose digests come from the signed manifest. The sequence is:
// downgrade guard, consent gate (major version or SecuritySensitive),
// download + digest verification into the target's directory, drain, swap,
// restart. If Config.Restart is nil it returns ErrRestartPending after a
// successful swap; the update is then finished by Resume after the caller
// restarts the process.
func (u *Updater) Apply(ctx context.Context, rel Release) error {
	if u.cfg.Channel == ChannelOff {
		return ErrChannelOff
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.target == "" {
		return errors.New("update: no target path resolved")
	}
	if _, err := u.fs.Stat(journalPath(u.target)); err == nil {
		return ErrUpdateInProgress
	}
	to, err := ParseVersion(rel.Version)
	if err != nil {
		return fmt.Errorf("update: release version: %w", err)
	}
	if to.Compare(u.current) <= 0 {
		return fmt.Errorf("%w: running %s, offered %s", ErrDowngrade, u.current, to)
	}
	art, ok := rel.Artifacts[Platform()]
	if !ok || art.URL == "" || art.SHA256 == "" {
		return fmt.Errorf("%w (%s)", ErrNoArtifact, Platform())
	}

	if to.Major > u.current.Major || rel.SecuritySensitive {
		if u.cfg.Consent == nil {
			return fmt.Errorf("%w (from %s to %s, securitySensitive=%t)", ErrConsentRequired, u.current, to, rel.SecuritySensitive)
		}
		dec, err := u.cfg.Consent(ctx, ConsentRequest{
			From:              u.current,
			To:                to,
			Notes:             rel.Notes,
			SecuritySensitive: rel.SecuritySensitive,
		})
		if err != nil {
			return fmt.Errorf("update: consent hook: %w", err)
		}
		switch dec {
		case DecisionApproved:
		case DecisionDeclined:
			return fmt.Errorf("%w (from %s to %s)", ErrConsentDeclined, u.current, to)
		default:
			// DecisionUnanswered, or an unrecognised value: not a decision.
			// Fail closed for this cycle, stay eligible for the next.
			return fmt.Errorf("%w (from %s to %s)", ErrConsentUnanswered, u.current, to)
		}
	}

	staged, err := downloadArtifact(ctx, u.client, art, filepath.Dir(u.target), filepath.Base(u.target))
	if err != nil {
		return err
	}
	mode := os.FileMode(0o755)
	if fi, err := u.fs.Stat(u.target); err == nil && fi.Mode().Perm() != 0 {
		mode = fi.Mode().Perm()
	}
	if err := os.Chmod(staged, mode); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("update: chmod staged binary: %w", err)
	}

	// Preflight: the staged binary must prove it can execute BEFORE it is
	// installed. A build that cannot start would never reach Resume, so
	// post-swap rollback cannot save it — this check runs while the old
	// binary is still safely in place.
	if !u.cfg.SkipPreflight {
		if perr := u.preflight(ctx, staged); perr != nil {
			_ = os.Remove(staged)
			return fmt.Errorf("%w: %v", ErrPreflight, perr)
		}
	}

	// Cross-process lock BEFORE the drain: draining silences the household,
	// so it must only ever happen for an update that is actually going to
	// proceed. Taking the lock first means a process that loses it skips
	// quietly WITHOUT having drained anyone. The loser removes its own
	// staged download and retries next cycle.
	rel0, lerr := acquireLock(u.target, u.cfg.LockStaleAfter, u.now)
	if lerr != nil {
		_ = os.Remove(staged)
		return lerr
	}
	locked := true
	release := func() {
		if locked {
			locked = false
			rel0()
		}
	}
	defer release()

	// Re-check the journal under the lock — before draining: another
	// process may have swapped while this one was downloading, and nobody
	// should be drained for an update that is already done.
	if _, err := u.fs.Stat(journalPath(u.target)); err == nil {
		_ = os.Remove(staged)
		return ErrUpdateInProgress
	}

	// Drain while holding the lock. A drain may legitimately take a long
	// time (waiting for conversations to finish), so refresh the lock's
	// timestamp afterwards: LockStaleAfter is measured against the last
	// activity, and consumers must configure it longer than their worst-
	// case drain.
	if u.cfg.Drain != nil {
		if err := u.cfg.Drain(ctx); err != nil {
			_ = os.Remove(staged)
			return fmt.Errorf("update: drain before swap: %w", err)
		}
		touchLock(u.target, u.now())
	}

	j := journal{
		From:      u.current.String(),
		To:        rel.Version,
		Target:    u.target,
		Staged:    staged,
		StartedAt: u.now(),
	}
	if err := performSwap(u.fs, j, u.winSwap); err != nil {
		_ = os.Remove(staged)
		return err
	}
	u.log.Info("update: binary swapped", "from", u.current.String(), "to", rel.Version, "target", u.target)

	// Release before restarting: a Restart hook that exits or re-execs the
	// process would otherwise strand the lock file until it went stale.
	release()
	if u.cfg.Restart == nil {
		return ErrRestartPending
	}
	return u.cfg.Restart(ctx)
}

// preflight executes the staged binary with the configured arguments and
// requires a clean exit within PreflightTimeout. Any failure to start, a
// non-zero exit, or a hang refuses the update.
func (u *Updater) preflight(ctx context.Context, staged string) error {
	pctx, cancel := context.WithTimeout(ctx, u.cfg.PreflightTimeout)
	defer cancel()
	cmd := exec.CommandContext(pctx, staged, u.cfg.PreflightArgs...)
	out, err := cmd.CombinedOutput()
	if pctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("staged binary did not exit within %s running %q", u.cfg.PreflightTimeout, u.cfg.PreflightArgs)
	}
	if err != nil {
		return fmt.Errorf("staged binary failed running %q: %v (output: %s)", u.cfg.PreflightArgs, err, truncateOutput(out, 512))
	}
	return nil
}

func truncateOutput(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Resume finishes whatever update was in flight when the process last
// stopped. Call it early on every startup, before serving traffic.
//
//   - No journal: OutcomeNone.
//   - Running the new version: health-check it (Config.HealthTimeout);
//     commit on success, roll back to the retained previous binary and
//     restart on failure or timeout. An attempt counter bounds crash loops.
//   - Running the previous version with a completed rollback recorded:
//     report OutcomeRolledBack (so the failure can be surfaced to a human)
//     and clean up.
//   - Crash mid-swap: repair the target from the moved-aside original or
//     the retained copy, then abort the update cleanly.
func (u *Updater) Resume(ctx context.Context) (ResumeReport, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.target == "" {
		return ResumeReport{Outcome: OutcomeNone}, nil
	}
	// Resume mutates the same files as a swap, so it takes the same
	// cross-process lock. A sibling holding it returns ErrLocked; the
	// caller retries shortly rather than treating it as a failure.
	rel0, lerr := acquireLock(u.target, u.cfg.LockStaleAfter, u.now)
	if lerr != nil {
		return ResumeReport{}, lerr
	}
	locked := true
	release := func() {
		if locked {
			locked = false
			rel0()
		}
	}
	defer release()

	j, err := readJournal(u.fs, u.target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No update in flight. Sweep files a crash could have orphaned
			// before the journal existed (a staged download, atomic-write
			// temp files, a .old/.failed image whose removal was skipped).
			// The retained .prev is deliberately NOT swept.
			u.sweepStale()
			return ResumeReport{Outcome: OutcomeNone}, nil
		}
		return ResumeReport{}, err
	}
	rep := ResumeReport{From: j.From, To: j.To}

	// Crash inside the Windows swap window: no binary at the target path.
	if _, serr := u.fs.Stat(u.target); errors.Is(serr, fs.ErrNotExist) {
		if err := performRepair(u.fs, j); err != nil {
			return rep, err
		}
		if err := performAbort(u.fs, j); err != nil {
			return rep, err
		}
		rep.Outcome = OutcomeAborted
		rep.Reason = "crash during swap; previous binary restored"
		u.log.Warn("update: repaired interrupted swap", "from", j.From, "to", j.To)
		return rep, nil
	}

	to, terr := parseVersionAllowDev(j.To)
	from, ferr := parseVersionAllowDev(j.From)

	switch {
	case terr == nil && u.current.Compare(to) == 0:
		// We are the new binary.
		if j.State == stateRolledBack {
			// A rollback was decided but did not complete before the
			// process stopped; finish it.
			if err := performRollback(u.fs, j, j.Reason, u.winSwap); err != nil {
				return rep, err
			}
			rep.Outcome = OutcomeRolledBack
			rep.Reason = j.Reason
			return rep, u.restartOrPending(ctx, release)
		}
		j.Attempts++
		if j.Attempts > maxResumeAttempts {
			reason := fmt.Sprintf("update: %d verification attempts without a passing health check", j.Attempts-1)
			return u.rollback(ctx, rep, j, reason, release)
		}
		if err := writeJournal(u.fs, j); err != nil {
			return rep, err
		}
		if herr := u.runHealth(ctx); herr != nil {
			return u.rollback(ctx, rep, j, "health check failed: "+herr.Error(), release)
		}
		if err := performCommit(u.fs, j); err != nil {
			return rep, err
		}
		rep.Outcome = OutcomeCommitted
		u.log.Info("update: committed", "from", j.From, "to", j.To)
		return rep, nil

	case ferr == nil && u.current.Compare(from) == 0:
		// We are the previous binary again.
		if j.State == stateRolledBack {
			if err := performRollbackCleanup(u.fs, j); err != nil {
				return rep, err
			}
			rep.Outcome = OutcomeRolledBack
			rep.Reason = j.Reason
			u.log.Warn("update: rolled back", "from", j.From, "to", j.To, "reason", j.Reason)
			return rep, nil
		}
		// Pending, but the swap never took effect (crash before the final
		// rename, or a restart that never happened).
		if err := performAbort(u.fs, j); err != nil {
			return rep, err
		}
		rep.Outcome = OutcomeAborted
		rep.Reason = "update never took effect; leftovers removed"
		return rep, nil

	default:
		// The running version matches neither side of the journal — the
		// binary was replaced out of band. Do not touch any binary; just
		// retire the journal so updating can proceed.
		if err := u.fs.Remove(journalPath(u.target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return rep, err
		}
		rep.Outcome = OutcomeAborted
		rep.Reason = fmt.Sprintf("running version %s matches neither %q nor %q; journal removed, files left in place", u.current, j.From, j.To)
		u.log.Warn("update: journal did not match running version", "running", u.current.String(), "from", j.From, "to", j.To)
		return rep, nil
	}
}

func (u *Updater) rollback(ctx context.Context, rep ResumeReport, j journal, reason string, release func()) (ResumeReport, error) {
	if err := performRollback(u.fs, j, reason, u.winSwap); err != nil {
		return rep, fmt.Errorf("update: rollback after %q: %w", reason, err)
	}
	rep.Outcome = OutcomeRolledBack
	rep.Reason = reason
	u.log.Warn("update: rolling back", "from", j.From, "to", j.To, "reason", reason)
	return rep, u.restartOrPending(ctx, release)
}

// sweepStale removes best-effort the debris a crash can orphan when no
// journal references it. It never touches the target or the retained
// previous binary.
func (u *Updater) sweepStale() {
	if matches, err := filepath.Glob(u.target + ".staged-*"); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
	for _, p := range []string{
		journalPath(u.target) + ".tmp",
		u.target + ".prev.tmp",
		u.target + ".old",
		u.target + ".failed",
	} {
		_ = os.Remove(p)
	}
}

// restartOrPending releases the cross-process lock (the journal now owns the
// state) and then restarts, or reports that a restart is the caller's job.
// Releasing first matters: a Restart hook that exits or re-execs would strand
// the lock file until it went stale.
func (u *Updater) restartOrPending(ctx context.Context, release func()) error {
	release()
	if u.cfg.Restart == nil {
		return ErrRestartPending
	}
	return u.cfg.Restart(ctx)
}

// runHealth executes the configured health check under HealthTimeout. A nil
// HealthCheck passes vacuously (documented: no health check means the swap
// is trusted). A check that ignores its context is still bounded here.
func (u *Updater) runHealth(ctx context.Context) error {
	if u.cfg.Health == nil {
		return nil
	}
	hctx, cancel := context.WithTimeout(ctx, u.cfg.HealthTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.cfg.Health(hctx) }()
	select {
	case err := <-done:
		return err
	case <-hctx.Done():
		return fmt.Errorf("health check did not complete within %s: %w", u.cfg.HealthTimeout, hctx.Err())
	}
}

// Run polls Check every CheckInterval (first check immediately) and applies
// eligible releases according to policy. On ChannelOff it returns nil at
// once without any network activity. A release declined via Consent is
// remembered and not re-asked until a different version appears. Run
// returns ErrRestartPending when a swap completed and no Restart hook is
// configured, and ctx.Err() on cancellation.
func (u *Updater) Run(ctx context.Context) error {
	if u.cfg.Channel == ChannelOff {
		return nil
	}
	timer := time.NewTimer(0) // first check immediately
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		st, err := u.Check(ctx)
		switch {
		case err != nil:
			u.log.Warn("update: check failed", "err", err)
		case st.Available:
			ver := st.Release.Version
			if !u.declined[ver] {
				err := u.Apply(ctx, *st.Release)
				switch {
				case err == nil:
					// Restart hook ran; if it returns, keep looping. The
					// journal blocks a second Apply until Resume runs.
				case errors.Is(err, ErrRestartPending):
					return ErrRestartPending
				case errors.Is(err, ErrConsentDeclined):
					u.declined[ver] = true
					u.log.Info("update: declined by consent; will not re-ask for this version", "version", ver)
				case errors.Is(err, ErrConsentUnanswered):
					// Silence is not a decision: the release stays eligible
					// and the question is asked again next cycle.
					u.log.Info("update: consent question unanswered; will ask again next cycle", "version", ver)
				case errors.Is(err, ErrLocked), errors.Is(err, ErrUpdateInProgress):
					// A sibling process is handling it. Nothing is wrong;
					// skip quietly and look again next cycle.
					u.log.Debug("update: skipped this cycle", "reason", err)
				default:
					u.log.Warn("update: apply failed", "version", ver, "err", err)
				}
			}
		}
		timer.Reset(u.cfg.CheckInterval)
	}
}
