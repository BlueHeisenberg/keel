// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestMain doubles as a helper process: when re-invoked with
// KEEL_UPDATE_TEST_HELPER=1 the binary just blocks on stdin, standing in for
// a running production process whose executable is being swapped.
func TestMain(m *testing.M) {
	if os.Getenv("KEEL_UPDATE_TEST_HELPER") == "1" {
		if len(os.Args) > 1 {
			switch os.Args[1] {
			case "preflight-ok":
				return // exit 0: a healthy staged binary
			case "preflight-fail":
				os.Exit(3) // a binary that starts but reports itself broken
			case "preflight-hang":
				time.Sleep(time.Minute) // a binary that never exits
				return
			}
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	os.Exit(m.Run())
}

// copyWithMarker copies the current test binary to dst with a distinguishing
// trailer appended. ELF and PE loaders both ignore trailing overlay data, so
// the copy still executes; the trailer makes old and new images
// distinguishable by content.
func copyWithMarker(t *testing.T, src, dst string, marker string) []byte {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	data = append(data, []byte("\n"+marker)...)
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	return data
}

func startHelper(t *testing.T, path string) (*exec.Cmd, io.WriteCloser) {
	t.Helper()
	cmd := exec.Command(path)
	cmd.Env = append(os.Environ(), "KEEL_UPDATE_TEST_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper %s: %v", path, err)
	}
	return cmd, stdin
}

func stopHelper(t *testing.T, cmd *exec.Cmd, stdin io.WriteCloser) {
	t.Helper()
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

// preflightEnv builds a signed-release environment whose artifact is a real
// executable: this test binary itself, which reacts to the preflight
// arguments via TestMain's helper mode.
func preflightEnv(t *testing.T) (*env, Release) {
	t.Helper()
	t.Setenv("KEEL_UPDATE_TEST_HELPER", "1") // inherited by the exec'd staged binary
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	selfBytes, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	e := newEnv(t)
	rel := e.release("v1.1.0", selfBytes, nil)
	e.serveManifest(rel)
	return e, rel
}

// TestPreflightFailureRefusesUpdate: a staged binary that starts but exits
// non-zero must never be installed — the old binary keeps running, nothing
// on disk changes, and no participant was drained for it.
func TestPreflightFailureRefusesUpdate(t *testing.T) {
	e, rel := preflightEnv(t)
	drainCalled := false
	u := e.updater(func(c *Config) {
		c.SkipPreflight = false
		c.PreflightArgs = []string{"preflight-fail"}
		c.Drain = func(context.Context) error { drainCalled = true; return nil }
	})
	err := u.Apply(t.Context(), rel)
	if !errors.Is(err, ErrPreflight) {
		t.Fatalf("Apply = %v, want ErrPreflight", err)
	}
	if drainCalled {
		t.Error("drain ran for an update that preflight was going to refuse")
	}
	assertTargetUntouched(t, e)
}

// TestPreflightTimeoutIsFailure: a staged binary that hangs is as broken as
// one that crashes; the hang is bounded and treated as refusal.
func TestPreflightTimeoutIsFailure(t *testing.T) {
	e, rel := preflightEnv(t)
	u := e.updater(func(c *Config) {
		c.SkipPreflight = false
		c.PreflightArgs = []string{"preflight-hang"}
		c.PreflightTimeout = 300 * time.Millisecond
	})
	err := u.Apply(t.Context(), rel)
	if !errors.Is(err, ErrPreflight) {
		t.Fatalf("Apply = %v, want ErrPreflight on timeout", err)
	}
	assertTargetUntouched(t, e)
}

// TestPreflightPassAllowsUpdate: a staged binary that execs cleanly proceeds
// through the normal swap.
func TestPreflightPassAllowsUpdate(t *testing.T) {
	e, rel := preflightEnv(t)
	u := e.updater(func(c *Config) {
		c.SkipPreflight = false
		c.PreflightArgs = []string{"preflight-ok"}
	})
	err := u.Apply(t.Context(), rel)
	if !errors.Is(err, ErrRestartPending) {
		t.Fatalf("Apply = %v, want ErrRestartPending after a passing preflight", err)
	}
	got, rerr := os.ReadFile(e.target)
	if rerr != nil {
		t.Fatal(rerr)
	}
	prev, rerr := os.ReadFile(e.target + ".prev")
	if rerr != nil || !bytes.Equal(prev, oldBinary) {
		t.Fatalf("previous binary not retained: err=%v", rerr)
	}
	if len(got) == len(oldBinary) {
		t.Fatal("target does not look like the swapped test binary")
	}
}

// TestSwapAndRollbackWhileTargetRunning exercises the real swap and rollback
// sequences against a genuinely executing binary. On Windows this is the
// test of the rename-running-then-place-new pattern: the running image
// cannot be replaced in place, only renamed aside.
func TestSwapAndRollbackWhileTargetRunning(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	target := filepath.Join(dir, "app"+suffix)
	staged := filepath.Join(dir, "app.staged"+suffix)

	oldImage := copyWithMarker(t, self, target, "MARKER-OLD-IMAGE")
	newImage := copyWithMarker(t, self, staged, "MARKER-NEW-IMAGE")

	// Executing a modified copy is verified on Windows and Linux. On macOS
	// an appended trailer invalidates the ad-hoc code signature, so there
	// the sequences run against a non-executing target — the POSIX rename
	// semantics do not depend on the file being executed anyway.
	canRun := runtime.GOOS == "windows" || runtime.GOOS == "linux"
	winStyle := runtime.GOOS == "windows"

	var child1 *exec.Cmd
	var stdin1 io.WriteCloser
	if canRun {
		child1, stdin1 = startHelper(t, target)
	}

	if runtime.GOOS == "windows" && canRun {
		// Prove the constraint that motivates the rename-aside pattern:
		// a running .exe cannot be replaced in place.
		probe := filepath.Join(dir, "probe.bin")
		if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(probe, target); err == nil {
			t.Fatal("rename over a running executable unexpectedly succeeded; the Windows swap pattern rests on this failing")
		}
		_ = os.Remove(probe)
	}

	j := journal{From: "v1.0.0", To: "v1.1.0", Target: target, Staged: staged, StartedAt: time.Now()}
	if err := performSwap(osFS{}, j, winStyle); err != nil {
		t.Fatalf("performSwap while target running: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, newImage) {
		t.Fatalf("target after swap is not the new image (err=%v)", err)
	}
	prev, err := os.ReadFile(target + ".prev")
	if err != nil || !bytes.Equal(prev, oldImage) {
		t.Fatalf("retained previous image mismatch (err=%v)", err)
	}

	// The old process exits (the restart) ...
	if child1 != nil {
		stopHelper(t, child1, stdin1)
	}
	// ... and the NEW binary starts. Roll back while it is executing —
	// exactly what a failed health check does.
	var child2 *exec.Cmd
	var stdin2 io.WriteCloser
	if canRun {
		child2, stdin2 = startHelper(t, target)
	}
	j2, err := readJournal(osFS{}, target)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if err := performRollback(osFS{}, j2, "test rollback", winStyle); err != nil {
		t.Fatalf("performRollback while new binary running: %v", err)
	}
	restored, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(restored, oldImage) {
		t.Fatalf("rollback did not restore the old image byte-identical (err=%v)", err)
	}
	if child2 != nil {
		stopHelper(t, child2, stdin2)
	}
}
