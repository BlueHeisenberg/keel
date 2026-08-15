// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLockContention(t *testing.T) {
	target := filepath.Join(t.TempDir(), "app")

	release1, err := acquireLock(target, 0, time.Now)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := acquireLock(target, 0, time.Now); !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire = %v, want ErrLocked", err)
	}
	release1()
	release1() // idempotent

	release2, err := acquireLock(target, 0, time.Now)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()
	if fileExists(lockPath(target)) {
		t.Fatal("lock file left behind after release")
	}
}

func TestStaleLockIsBroken(t *testing.T) {
	target := filepath.Join(t.TempDir(), "app")
	lp := lockPath(target)
	if err := os.WriteFile(lp, []byte("{\"pid\":999999}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lp, stale, stale); err != nil {
		t.Fatal(err)
	}
	release, err := acquireLock(target, 10*time.Minute, time.Now)
	if err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
	release()

	// A fresh lock is NOT broken.
	if err := os.WriteFile(lp, []byte("{\"pid\":999999}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(target, 10*time.Minute, time.Now); !errors.Is(err, ErrLocked) {
		t.Fatalf("fresh lock was stolen: %v", err)
	}
}

// TestApplySkipsQuietlyWhenLocked: a sibling process holding the lock means
// this process skips the cycle with ErrLocked, leaving the target untouched
// and no staged download behind.
func TestApplySkipsQuietlyWhenLocked(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)
	if err := os.WriteFile(lockPath(e.target), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := e.updater(nil).Apply(context.Background(), rel)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("Apply under sibling lock = %v, want ErrLocked", err)
	}
	got, rerr := os.ReadFile(e.target)
	if rerr != nil || !bytes.Equal(got, oldBinary) {
		t.Fatalf("target modified while locked: %q err=%v", got, rerr)
	}
	if staged, _ := filepath.Glob(e.target + ".staged-*"); len(staged) != 0 {
		t.Fatalf("staged leftovers under lock: %v", staged)
	}
	if fileExists(journalPath(e.target)) {
		t.Fatal("journal written while locked")
	}

	// The sibling finishes; the retry succeeds.
	if err := os.Remove(lockPath(e.target)); err != nil {
		t.Fatal(err)
	}
	if err := e.updater(nil).Apply(context.Background(), rel); !errors.Is(err, ErrRestartPending) {
		t.Fatalf("Apply after lock release = %v, want ErrRestartPending", err)
	}
}

// TestResumeSkipsWhenLocked: Resume mutates the same files, so it honours
// the same lock, and proceeds normally once the sibling releases it.
func TestResumeSkipsWhenLocked(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app")
	staged := filepath.Join(dir, "app.staged-test")
	writeBinary(t, target, oldBinary)
	writeBinary(t, staged, newBinary)
	j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
	if err := performSwap(osFS{}, j, false); err != nil {
		t.Fatalf("setup swap: %v", err)
	}
	if err := os.WriteFile(lockPath(target), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	u := bareUpdater(t, target, "v1.1.0", false, func(context.Context) error { return nil })
	if _, err := u.Resume(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("Resume under sibling lock = %v, want ErrLocked", err)
	}
	if err := os.Remove(lockPath(target)); err != nil {
		t.Fatal(err)
	}
	rep, err := u.Resume(context.Background())
	if err != nil || rep.Outcome != OutcomeCommitted {
		t.Fatalf("Resume after release = %+v err=%v, want OutcomeCommitted", rep, err)
	}
	if fileExists(lockPath(target)) {
		t.Fatal("Resume left its lock behind")
	}
}

// TestConcurrentAppliesExactlyOneProceeds models isolated mode: two
// processes sharing one install path decide to update at the same moment.
// Exactly one must perform the swap; the other must lose quietly via
// ErrLocked or ErrUpdateInProgress.
func TestConcurrentAppliesExactlyOneProceeds(t *testing.T) {
	e := newEnv(t)
	rel := e.release("v1.1.0", newBinary, nil)
	e.serveManifest(rel)

	// Two Updater instances = two processes: they share no in-process state.
	u1 := e.updater(nil)
	u2 := e.updater(nil)

	errs := make(chan error, 2)
	for _, u := range []*Updater{u1, u2} {
		go func(u *Updater) { errs <- u.Apply(context.Background(), rel) }(u)
	}
	var winners, losers int
	for i := 0; i < 2; i++ {
		err := <-errs
		switch {
		case errors.Is(err, ErrRestartPending):
			winners++
		case errors.Is(err, ErrLocked), errors.Is(err, ErrUpdateInProgress):
			losers++
		default:
			t.Fatalf("unexpected concurrent Apply outcome: %v", err)
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("winners=%d losers=%d, want exactly one of each", winners, losers)
	}
	got, err := os.ReadFile(e.target)
	if err != nil || !bytes.Equal(got, newBinary) {
		t.Fatalf("target after concurrent applies: %q err=%v", got, err)
	}
	if !fileExists(journalPath(e.target)) {
		t.Fatal("journal missing; the winner's swap should be pending verification")
	}
	if staged, _ := filepath.Glob(e.target + ".staged-*"); len(staged) != 0 {
		t.Fatalf("loser left staged files behind: %v", staged)
	}
	if fileExists(lockPath(e.target)) {
		t.Fatal("lock file left behind")
	}
}
