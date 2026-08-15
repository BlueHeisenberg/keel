// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// vsockConnectTimeout bounds a blocking AF_VSOCK connect when the ctx carries no
// deadline, so a guest that never accepts cannot hang Dial forever.
const vsockConnectTimeout = 10 * time.Second

// realVsockDialer dials the in-guest bridge over AF_VSOCK on Linux.
type realVsockDialer struct{}

func (realVsockDialer) Dial(ctx context.Context, cid uint32, port uint32) (vsockConn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}

	// Best-effort bounded connect: do a non-blocking connect and wait for
	// writability with a deadline derived from ctx (else vsockConnectTimeout).
	// This prevents a guest that never answers from hanging the host; the
	// per-round-trip read deadline (see bridgeRoundTrip) bounds the rest.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock set nonblock: %w", err)
	}
	sa := &unix.SockaddrVM{CID: cid, Port: port}
	if cerr := unix.Connect(fd, sa); cerr != nil && cerr != unix.EINPROGRESS {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock connect cid=%d port=%d: %w", cid, port, cerr)
	} else if cerr == unix.EINPROGRESS {
		timeout := vsockConnectTimeout
		if dl, ok := ctx.Deadline(); ok {
			if d := time.Until(dl); d < timeout {
				timeout = d
			}
		}
		if err := waitWritable(fd, timeout); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("vsock connect cid=%d port=%d: %w", cid, port, err)
		}
		// Surface any asynchronous connect error (SO_ERROR).
		if soErr, gerr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); gerr != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("vsock connect cid=%d port=%d: getsockopt: %w", cid, port, gerr)
		} else if soErr != 0 {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("vsock connect cid=%d port=%d: %w", cid, port, unix.Errno(soErr))
		}
	}

	// Restore blocking mode; *os.File deadlines (SetDeadline) handle timeouts from
	// here on via the runtime poller.
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock clear nonblock: %w", err)
	}

	// Wrap the raw fd in an *os.File so we get io.ReadWriteCloser + SetDeadline.
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d:%d", cid, port))
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock: os.NewFile failed for fd %d", fd)
	}
	return f, nil
}

// waitWritable blocks until fd is writable (connect completed) or timeout elapses.
func waitWritable(fd int, timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("vsock connect timed out")
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	ms := int(timeout / time.Millisecond)
	if ms <= 0 {
		ms = 1
	}
	for {
		n, err := unix.Poll(fds, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("vsock connect poll: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("vsock connect timed out after %s", timeout)
		}
		return nil
	}
}

// processAlive reports whether pid names a live process (signal-0 probe).
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
