// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// ErrLocked reports that another process on the same machine is currently
// updating the same target. It is a routine coordination outcome, not a
// failure: the loser skips this cycle quietly and retries on its next check.
var ErrLocked = errors.New("update: another process is updating this binary; skipping this cycle")

// defaultLockStaleAfter is how old a lock file may be before it is presumed
// abandoned by a crashed updater and broken. The lock is held only across
// the swap or a Resume — seconds of work — so this is very generous.
const defaultLockStaleAfter = 10 * time.Minute

func lockPath(target string) string { return target + ".update.lock" }

// acquireLock takes the cross-process update lock for target using
// O_CREATE|O_EXCL, which is atomic on every supported platform. A lock file
// older than staleAfter is presumed left behind by a crashed process,
// removed, and re-contended: after breaking a stale lock the acquisition is
// retried, and O_EXCL guarantees at most one contender wins the recreate.
//
// Known smallness: between observing a stale lock and recreating it there is
// a window in which two processes can each remove-and-create; O_EXCL still
// admits only one, but the loser may have deleted the winner's
// microseconds-old file first. The lock guards a seconds-long critical
// section against a ten-minute staleness horizon, so hitting this requires
// two processes breaking the same abandoned lock in the same instant; the
// journal check inside the critical section remains the final arbiter.
//
// The returned release function is idempotent.
func acquireLock(target string, staleAfter time.Duration, now func() time.Time) (release func(), err error) {
	if staleAfter <= 0 {
		staleAfter = defaultLockStaleAfter
	}
	path := lockPath(target)
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "{\"pid\":%d,\"acquiredAt\":%q}\n", os.Getpid(), now().UTC().Format(time.RFC3339))
			f.Close()
			released := false
			return func() {
				if !released {
					released = true
					_ = os.Remove(path)
				}
			}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("update: create lock file: %w", err)
		}
		fi, serr := os.Stat(path)
		if serr != nil {
			continue // it vanished between attempts; retry
		}
		if now().Sub(fi.ModTime()) > staleAfter {
			_ = os.Remove(path) // abandoned by a crashed updater; break it
			continue
		}
		return nil, ErrLocked
	}
	return nil, ErrLocked
}
