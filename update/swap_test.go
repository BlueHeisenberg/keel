// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	oldBinary = []byte("OLD binary image v1.0.0 ................")
	newBinary = []byte("NEW binary image v1.1.0 -- different bytes")
)

// errInjectedCrash simulates the process dying: once a crashFS trips, every
// subsequent operation fails, exactly as if no further code ran.
var errInjectedCrash = errors.New("injected crash")

// crashFS delegates to the real filesystem for the first `remaining`
// mutating operations, then fails everything forever.
type crashFS struct {
	real      fsOps
	remaining int
	crashed   bool
}

func (c *crashFS) gate() error {
	if c.remaining <= 0 {
		c.crashed = true
	}
	if c.crashed {
		return errInjectedCrash
	}
	c.remaining--
	return nil
}

func (c *crashFS) Rename(o, n string) error {
	if err := c.gate(); err != nil {
		return err
	}
	return c.real.Rename(o, n)
}
func (c *crashFS) Remove(n string) error {
	if err := c.gate(); err != nil {
		return err
	}
	return c.real.Remove(n)
}
func (c *crashFS) WriteFileAtomic(n string, d []byte) error {
	if err := c.gate(); err != nil {
		return err
	}
	return c.real.WriteFileAtomic(n, d)
}
func (c *crashFS) CopyFile(s, d string) error {
	if err := c.gate(); err != nil {
		return err
	}
	return c.real.CopyFile(s, d)
}
func (c *crashFS) ReadFile(n string) ([]byte, error) {
	if c.crashed {
		return nil, errInjectedCrash
	}
	return c.real.ReadFile(n)
}
func (c *crashFS) Stat(n string) (fs.FileInfo, error) {
	if c.crashed {
		return nil, errInjectedCrash
	}
	return c.real.Stat(n)
}

func writeBinary(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// bareUpdater builds an Updater directly against a target file, bypassing
// New's network configuration requirements. Tests live in-package, so this
// is the sanctioned way to exercise Resume against arbitrary disk states.
func bareUpdater(t *testing.T, target, current string, winStyle bool, health HealthCheck) *Updater {
	t.Helper()
	cur, err := parseVersionAllowDev(current)
	if err != nil {
		t.Fatalf("parse current %q: %v", current, err)
	}
	cfg := Config{HealthTimeout: 2 * time.Second, Health: health}
	return &Updater{
		cfg:      cfg,
		current:  cur,
		target:   target,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      time.Now,
		fs:       osFS{},
		winSwap:  winStyle,
		declined: map[string]bool{},
	}
}

// rebootUntilSettled simulates the restart loop after a crash: as long as a
// journal exists, "boot" whichever binary is at the target (or invoke Resume
// with the previous version if the target is missing — the repair path) and
// let Resume act. healthErr is what the new binary's health check reports.
func rebootUntilSettled(t *testing.T, target string, winStyle bool, healthErr error) {
	t.Helper()
	for i := 0; i < 6; i++ {
		cur := "v1.0.0"
		if data, err := os.ReadFile(target); err == nil {
			switch {
			case bytes.Equal(data, oldBinary):
				cur = "v1.0.0"
			case bytes.Equal(data, newBinary):
				cur = "v1.1.0"
			default:
				t.Fatalf("target contains neither old nor new binary bytes: %q", data)
			}
		}
		u := bareUpdater(t, target, cur, winStyle, func(context.Context) error { return healthErr })
		if _, err := u.Resume(context.Background()); err != nil && !errors.Is(err, ErrRestartPending) {
			t.Fatalf("Resume (boot %d): %v", i, err)
		}
		if !fileExists(journalPath(target)) {
			return // settled; every boot runs Resume, so the sweep has run too
		}
	}
	t.Fatalf("journal never settled after 6 reboots")
}

// assertOnlyExpectedFiles fails if the target directory holds anything
// beyond the binary and (optionally) the retained previous binary.
func assertOnlyExpectedFiles(t *testing.T, dir, target string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		filepath.Base(target):           true,
		filepath.Base(target) + ".prev": true,
	}
	for _, e := range entries {
		if !allowed[e.Name()] {
			t.Errorf("unexpected leftover file %q", e.Name())
		}
	}
}

// TestSwapRealFilesystem exercises the real swap sequences end to end on a
// real filesystem, in both the POSIX and the Windows style.
func TestSwapRealFilesystem(t *testing.T) {
	for _, winStyle := range []bool{false, true} {
		name := "posix"
		if winStyle {
			name = "windows"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "app")
			staged := filepath.Join(dir, "app.staged-test")
			writeBinary(t, target, oldBinary)
			writeBinary(t, staged, newBinary)

			j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
			if err := performSwap(osFS{}, j, winStyle); err != nil {
				t.Fatalf("performSwap: %v", err)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, newBinary) {
				t.Fatalf("target after swap: %q err=%v, want new binary", got, err)
			}
			prev, err := os.ReadFile(target + ".prev")
			if err != nil || !bytes.Equal(prev, oldBinary) {
				t.Fatalf("retained previous binary: %q err=%v, want old binary byte-identical", prev, err)
			}
			if !fileExists(journalPath(target)) {
				t.Fatal("journal missing after swap; Resume would have nothing to verify")
			}
		})
	}
}

// TestRollbackRestoresByteIdenticalBinary verifies the single most important
// property in the package: after a rollback, the binary at the target path
// is byte-identical to what ran before the update.
func TestRollbackRestoresByteIdenticalBinary(t *testing.T) {
	for _, winStyle := range []bool{false, true} {
		name := "posix"
		if winStyle {
			name = "windows"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "app")
			staged := filepath.Join(dir, "app.staged-test")
			writeBinary(t, target, oldBinary)
			writeBinary(t, staged, newBinary)

			j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
			if err := performSwap(osFS{}, j, winStyle); err != nil {
				t.Fatalf("performSwap: %v", err)
			}
			// Health check fails in the new binary; Resume rolls back.
			u := bareUpdater(t, target, "v1.1.0", winStyle, func(context.Context) error {
				return errors.New("synthetic failure")
			})
			rep, err := u.Resume(context.Background())
			if !errors.Is(err, ErrRestartPending) {
				t.Fatalf("Resume: err=%v, want ErrRestartPending (no Restart hook)", err)
			}
			if rep.Outcome != OutcomeRolledBack {
				t.Fatalf("Outcome = %v, want OutcomeRolledBack", rep.Outcome)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, oldBinary) {
				t.Fatalf("target after rollback: %q err=%v, want old binary byte-identical", got, err)
			}
			// The restored previous binary boots and reports the failure.
			u2 := bareUpdater(t, target, "v1.0.0", winStyle, nil)
			rep2, err := u2.Resume(context.Background())
			if err != nil {
				t.Fatalf("Resume on restored binary: %v", err)
			}
			if rep2.Outcome != OutcomeRolledBack || rep2.Reason == "" {
				t.Fatalf("restored binary report = %+v, want OutcomeRolledBack with a reason", rep2)
			}
			assertOnlyExpectedFiles(t, dir, target)
			// Third start: nothing in flight.
			rep3, err := u2.Resume(context.Background())
			if err != nil || rep3.Outcome != OutcomeNone {
				t.Fatalf("third Resume = %+v err=%v, want OutcomeNone", rep3, err)
			}
		})
	}
}

// TestSwapCrashMatrix injects a crash between every pair of filesystem
// mutations in the swap sequence, in both styles, and asserts that a working
// binary survives in every case: after simulated reboots the target holds
// either the old or the new binary bytes, and the journal is settled.
func TestSwapCrashMatrix(t *testing.T) {
	for _, winStyle := range []bool{false, true} {
		name := "posix"
		if winStyle {
			name = "windows"
		}
		t.Run(name, func(t *testing.T) {
			for k := 0; k < 8; k++ {
				dir := t.TempDir()
				target := filepath.Join(dir, "app")
				staged := filepath.Join(dir, "app.staged-test")
				writeBinary(t, target, oldBinary)
				writeBinary(t, staged, newBinary)

				cfs := &crashFS{real: osFS{}, remaining: k}
				j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
				err := performSwap(cfs, j, winStyle)

				if err == nil {
					// k covered the whole sequence; the swap completed.
					got, rerr := os.ReadFile(target)
					if rerr != nil || !bytes.Equal(got, newBinary) {
						t.Fatalf("k=%d: completed swap left target %q err=%v", k, got, rerr)
					}
				} else if !errors.Is(err, errInjectedCrash) {
					t.Fatalf("k=%d: unexpected error %v", k, err)
				}

				// Invariant at the instant of the crash: a complete binary
				// image exists somewhere on disk.
				if !fileExists(target) && !fileExists(target+".old") && !fileExists(target+".prev") {
					t.Fatalf("k=%d style=%s: no binary image survives anywhere", k, name)
				}
				if data, rerr := os.ReadFile(target); rerr == nil {
					if !bytes.Equal(data, oldBinary) && !bytes.Equal(data, newBinary) {
						t.Fatalf("k=%d: target holds a torn image: %q", k, data)
					}
				} else if !winStyle {
					t.Fatalf("k=%d: POSIX swap must never leave the target path empty: %v", k, rerr)
				}

				// Reboot with a passing health check until settled, then the
				// system must hold a complete old or new binary and no
				// journal.
				rebootUntilSettled(t, target, winStyle, nil)
				final, rerr := os.ReadFile(target)
				if rerr != nil {
					t.Fatalf("k=%d: no binary at target after recovery: %v", k, rerr)
				}
				if !bytes.Equal(final, oldBinary) && !bytes.Equal(final, newBinary) {
					t.Fatalf("k=%d: recovered target is neither old nor new: %q", k, final)
				}
				if err == nil && !bytes.Equal(final, newBinary) {
					t.Fatalf("k=%d: completed swap with passing health must commit the new binary", k)
				}
				assertOnlyExpectedFiles(t, dir, target)
			}
		})
	}
}

// TestRollbackCrashMatrix injects a crash between every pair of filesystem
// mutations in the rollback sequence and asserts the system always converges
// back to the byte-identical previous binary.
func TestRollbackCrashMatrix(t *testing.T) {
	for _, winStyle := range []bool{false, true} {
		name := "posix"
		if winStyle {
			name = "windows"
		}
		t.Run(name, func(t *testing.T) {
			for k := 0; k < 7; k++ {
				dir := t.TempDir()
				target := filepath.Join(dir, "app")
				staged := filepath.Join(dir, "app.staged-test")
				writeBinary(t, target, oldBinary)
				writeBinary(t, staged, newBinary)

				// Complete the swap for real first.
				j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
				if err := performSwap(osFS{}, j, winStyle); err != nil {
					t.Fatalf("setup swap: %v", err)
				}
				jd, err := readJournal(osFS{}, target)
				if err != nil {
					t.Fatalf("read journal: %v", err)
				}

				// The rollback crashes after k mutations.
				cfs := &crashFS{real: osFS{}, remaining: k}
				rerr := performRollback(cfs, jd, "health check failed: synthetic", winStyle)
				if rerr != nil && !errors.Is(rerr, errInjectedCrash) {
					t.Fatalf("k=%d: unexpected rollback error %v", k, rerr)
				}

				// Reboot loop with a failing health check: whatever state the
				// crash left, the system must converge to the old binary.
				rebootUntilSettled(t, target, winStyle, errors.New("still failing"))
				final, err := os.ReadFile(target)
				if err != nil {
					t.Fatalf("k=%d: no binary at target after recovery: %v", k, err)
				}
				if !bytes.Equal(final, oldBinary) {
					t.Fatalf("k=%d: rollback recovery must restore the old binary byte-identical, got %q", k, final)
				}
				assertOnlyExpectedFiles(t, dir, target)
			}
		})
	}
}

// TestRepairFromWindowsCrashWindow reproduces the one unavoidable Windows
// state — a crash between rename-aside and place-new leaves no file at the
// target — and asserts Resume restores the previous binary.
func TestRepairFromWindowsCrashWindow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app")
	staged := filepath.Join(dir, "app.staged-test")
	writeBinary(t, target, oldBinary)
	writeBinary(t, staged, newBinary)

	// Steps: journal, copy prev, remove stale old, rename aside = 4 ops,
	// then crash before the final rename.
	cfs := &crashFS{real: osFS{}, remaining: 4}
	j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
	err := performSwap(cfs, j, true)
	if !errors.Is(err, errInjectedCrash) {
		t.Fatalf("expected injected crash, got %v", err)
	}
	if fileExists(target) {
		t.Fatal("test setup: expected the target to be missing (the Windows window)")
	}

	u := bareUpdater(t, target, "v1.0.0", true, nil)
	rep, err := u.Resume(context.Background())
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rep.Outcome != OutcomeAborted {
		t.Fatalf("Outcome = %v, want OutcomeAborted", rep.Outcome)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, oldBinary) {
		t.Fatalf("repaired target: %q err=%v, want old binary byte-identical", got, err)
	}
	assertOnlyExpectedFiles(t, dir, target)
}

// TestResumeAttemptsExhausted: if the new binary restarts repeatedly without
// ever passing health, the attempt counter forces a rollback instead of an
// infinite verification loop — and the health check is not even attempted.
func TestResumeAttemptsExhausted(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app")
	staged := filepath.Join(dir, "app.staged-test")
	writeBinary(t, target, oldBinary)
	writeBinary(t, staged, newBinary)

	j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
	if err := performSwap(osFS{}, j, false); err != nil {
		t.Fatalf("setup swap: %v", err)
	}
	jd, err := readJournal(osFS{}, target)
	if err != nil {
		t.Fatal(err)
	}
	jd.Attempts = maxResumeAttempts
	if err := writeJournal(osFS{}, jd); err != nil {
		t.Fatal(err)
	}

	healthCalled := false
	u := bareUpdater(t, target, "v1.1.0", false, func(context.Context) error {
		healthCalled = true
		return nil
	})
	rep, err := u.Resume(context.Background())
	if !errors.Is(err, ErrRestartPending) {
		t.Fatalf("Resume err = %v, want ErrRestartPending", err)
	}
	if rep.Outcome != OutcomeRolledBack {
		t.Fatalf("Outcome = %v, want OutcomeRolledBack", rep.Outcome)
	}
	if healthCalled {
		t.Fatal("health check ran despite exhausted attempts; a crash-looping binary would never get here")
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, oldBinary) {
		t.Fatalf("target = %q err=%v, want old binary", got, err)
	}
}
