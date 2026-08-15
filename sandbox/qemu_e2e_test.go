// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// QEMU Isolated-backend live boot test.  It exercises the real VM lifecycle
// (create → inspect(running) → destroy) against an actual qemu-system process.
//
// Run:
//
//	KEEL_QEMU_BASE_IMAGE=/path/to/base.qcow2 //	  go test -tags e2e ./sandbox -run TestQemuLifecycle -v -timeout 120s
//
// The test skips cleanly when:
//   - KEEL_QEMU_BASE_IMAGE is not set, or
//   - the qemu-system binary is not in PATH.
//
// It asserts lifecycle only; in-guest exec/file ops require a guest image
// carrying the vsock bridge daemon, which is a follow-up.
package sandbox

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestQemuLifecycle(t *testing.T) {
	cfg := ConfigFromEnv("KEEL")
	if cfg.BaseImage == "" {
		t.Skip("KEEL_QEMU_BASE_IMAGE not set — skipping QEMU lifecycle e2e")
	}
	cfg = cfg.withDefaults()
	if _, err := exec.LookPath(cfg.QemuBinary); err != nil {
		t.Skipf("%s not in PATH — skipping QEMU lifecycle e2e", cfg.QemuBinary)
	}
	cfg.StateDir = t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	b := NewQemuBackend(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	id := "qemu-e2e"
	h, err := b.Create(ctx, Spec{
		Name:          id,
		Level:         LevelIsolated,
		Profile:       ProfileHeadless,
		MemoryMB:      1024,
		CPUs:          1,
		NetworkPolicy: NetworkPolicyNone,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if h.ID != id {
		t.Errorf("Handle.ID = %q, want %q", h.ID, id)
	}
	t.Cleanup(func() { _ = b.Purge(context.Background(), id) })

	// Give the VM a moment to come up, then confirm it's running.
	deadline := time.Now().Add(20 * time.Second)
	running := false
	for time.Now().Before(deadline) {
		st, err := b.Inspect(ctx, id)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if st.Running {
			running = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !running {
		t.Fatalf("VM did not report running within deadline")
	}

	if err := b.Purge(ctx, id); err != nil {
		t.Fatalf("Purge: %v", err)
	}
}
