// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"io"
	"time"
)

// vsockConn is a bidirectional connection to the in-guest control bridge.
// SetDeadline bounds reads/writes so a misbehaving guest cannot hang the host;
// the linux *os.File-backed conn supports it, and the non-linux stub never
// returns a conn.
type vsockConn interface {
	io.ReadWriteCloser
	// SetDeadline sets the read/write deadline (mirrors net.Conn.SetDeadline).
	SetDeadline(t time.Time) error
}

// vsockDialer dials the in-guest bridge daemon over virtio-vsock at
// (guestCID, port).  The real implementation uses AF_VSOCK on Linux; on other
// build hosts it returns ErrQemuGuestUnavailable.  Tests inject a fake.
type vsockDialer interface {
	Dial(ctx context.Context, cid uint32, port uint32) (vsockConn, error)
}
