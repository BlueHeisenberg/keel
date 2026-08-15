// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// qmpConn is one live QMP control connection to a running VM.  The handshake
// (greeting + qmp_capabilities) is performed by the dialer before the connection
// is handed back, so callers can issue commands immediately.
type qmpConn interface {
	// command issues a QMP command and returns the raw JSON reply object.
	command(cmd string, args map[string]any) (json.RawMessage, error)
	// Close releases the underlying transport.
	Close() error
}

// qmpDialer opens a qmpConn to a QMP unix socket.  The real implementation dials
// the socket and completes the capabilities handshake; tests inject a fake that
// records issued commands.
type qmpDialer interface {
	Dial(ctx context.Context, sockPath string) (qmpConn, error)
}

// realQMPDialer dials the QMP unix socket and performs the negotiation handshake.
type realQMPDialer struct{}

func (realQMPDialer) Dial(ctx context.Context, sockPath string) (qmpConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("qmp dial %s: %w", sockPath, err)
	}
	conn := &realQMPConn{c: c, br: bufio.NewReader(c)}
	if err := conn.handshake(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("qmp handshake: %w", err)
	}
	return conn, nil
}

// realQMPConn implements qmpConn over a net.Conn.
type realQMPConn struct {
	c  net.Conn
	br *bufio.Reader
}

// handshake reads the QMP greeting then enters command mode with
// qmp_capabilities, as required by the QMP protocol.
func (q *realQMPConn) handshake() error {
	// Bound the handshake so a wedged socket cannot hang Create/Inspect.
	_ = q.c.SetDeadline(time.Now().Add(5 * time.Second))

	// Read and discard the greeting object ({"QMP": {...}}).
	if _, err := q.br.ReadBytes('\n'); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if _, err := q.command("qmp_capabilities", nil); err != nil {
		return fmt.Errorf("qmp_capabilities: %w", err)
	}
	// Clear the deadline for subsequent commands; callers carry their own ctx.
	_ = q.c.SetDeadline(time.Time{})
	return nil
}

// qmpCommandTimeout bounds a single QMP command's write+read so a chatty or
// half-dead QMP socket cannot hang Stop/Purge/Snapshot/Restore/Inspect.
// Fixed (not ctx-derived) for simplicity; documented here.
const qmpCommandTimeout = 10 * time.Second

// qmpMaxEventSkip caps how many asynchronous {"event":...} objects command()
// will skip while waiting for a command response, so a flood of events cannot
// keep the loop spinning indefinitely (the deadline is the backstop; this is a
// secondary bound).
const qmpMaxEventSkip = 1000

// command sends one QMP command and returns the raw reply.  A reply carrying an
// {"error": ...} object is surfaced as a Go error.  A per-command deadline is set
// before the write and cleared afterward.
func (q *realQMPConn) command(cmd string, args map[string]any) (json.RawMessage, error) {
	// Bound this command; clear the deadline on return so a later command starts
	// fresh (and a long-lived conn isn't left with a stale deadline).
	_ = q.c.SetDeadline(time.Now().Add(qmpCommandTimeout))
	defer func() { _ = q.c.SetDeadline(time.Time{}) }()

	req := map[string]any{"execute": cmd}
	if len(args) > 0 {
		req["arguments"] = args
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if _, err := q.c.Write(payload); err != nil {
		return nil, fmt.Errorf("write %s: %w", cmd, err)
	}

	// Read replies until we see one that is a command response (has "return" or
	// "error"); skip asynchronous events ({"event": ...}), bounded by both the
	// deadline above and qmpMaxEventSkip.
	for skipped := 0; ; skipped++ {
		if skipped > qmpMaxEventSkip {
			return nil, fmt.Errorf("qmp %s: exceeded %d async events without a response", cmd, qmpMaxEventSkip)
		}
		line, err := q.br.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("read reply for %s: %w", cmd, err)
		}
		var probe struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("parse reply for %s: %w", cmd, err)
		}
		if probe.Event != "" {
			continue // async event; keep reading for the command response
		}
		if probe.Error != nil {
			return nil, fmt.Errorf("qmp %s error: %s: %s", cmd, probe.Error.Class, probe.Error.Desc)
		}
		return json.RawMessage(line), nil
	}
}

func (q *realQMPConn) Close() error { return q.c.Close() }
