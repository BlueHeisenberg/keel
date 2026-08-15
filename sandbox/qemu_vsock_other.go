// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import (
	"context"
	"os"
)

// realVsockDialer on non-Linux build hosts cannot speak AF_VSOCK to a guest
// bridge, so it always reports the guest as unavailable.  The QEMU VM itself
// still runs (HVF on macOS, WHPX on Windows); only the in-guest control bridge
// transport is unimplemented off Linux.  This keeps the package buildable on all
// dev hosts, which is why this package still compiles there.
type realVsockDialer struct{}

func (realVsockDialer) Dial(_ context.Context, _ uint32, _ uint32) (vsockConn, error) {
	return nil, ErrQemuGuestUnavailable
}

// processAlive reports whether pid names a live process.  On Windows,
// os.FindProcess only succeeds for processes it can open, so a failure is a good
// proxy for "not alive"; this is best-effort.
func processAlive(pid int) bool {
	if _, err := os.FindProcess(pid); err != nil {
		return false
	}
	// FindProcess always succeeds on Unix-like systems; on Windows it opens a
	// handle and fails for dead PIDs.  We treat a successful lookup as alive.
	return true
}
