// SPDX-License-Identifier: Apache-2.0

package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// fsOps is the filesystem seam for the swap, rollback, repair, and commit
// sequences. Production uses osFS; the crash-injection tests substitute an
// implementation that dies between any two mutations. Keeping the seam this
// narrow is deliberate: everything that can brick an installation goes
// through it and nothing else does.
type fsOps interface {
	Rename(oldpath, newpath string) error
	Remove(name string) error
	// WriteFileAtomic writes data to name via a temp file, fsync, and
	// rename, so name is only ever absent, the old content, or the new
	// content — never a partial write.
	WriteFileAtomic(name string, data []byte) error
	// CopyFile copies src to dst atomically (temp + rename), preserving
	// src's permission bits, so dst is only ever absent or complete.
	CopyFile(src, dst string) error
	ReadFile(name string) ([]byte, error)
	Stat(name string) (fs.FileInfo, error)
}

// osFS is the real-filesystem implementation of fsOps.
type osFS struct{}

func (osFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }
func (osFS) Remove(name string) error             { return os.Remove(name) }
func (osFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (osFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(name)
}

func (osFS) WriteFileAtomic(name string, data []byte) error {
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (osFS) CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Journal states.
const (
	statePending    = "pending"    // swap in progress or awaiting post-restart verification
	stateRolledBack = "rolledback" // rollback decided; may or may not have completed
)

const journalSchema = 1

// maxResumeAttempts bounds how many times a pending update may be
// re-verified after restarts. If the new binary keeps crashing before its
// health check completes, the attempt counter — incremented before each
// check — eventually forces a rollback instead of a crash loop.
const maxResumeAttempts = 3

// journal is the crash-recovery record written next to the target binary
// before the first mutating step of a swap and removed on commit or after a
// completed rollback has been reported.
type journal struct {
	Schema    int       `json:"schema"`
	State     string    `json:"state"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Target    string    `json:"target"`
	Prev      string    `json:"prev"`
	Old       string    `json:"old,omitempty"`
	Staged    string    `json:"staged"`
	Attempts  int       `json:"attempts"`
	Reason    string    `json:"reason,omitempty"`
	StartedAt time.Time `json:"startedAt,omitzero"`
}

func journalPath(target string) string { return target + ".update.json" }

func writeJournal(fsys fsOps, j journal) error {
	j.Schema = journalSchema
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return fsys.WriteFileAtomic(journalPath(j.Target), data)
}

func readJournal(fsys fsOps, target string) (journal, error) {
	data, err := fsys.ReadFile(journalPath(target))
	if err != nil {
		return journal{}, err
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil {
		return journal{}, fmt.Errorf("update: corrupt journal at %s: %w", journalPath(target), err)
	}
	return j, nil
}

// performSwap installs j.Staged at j.Target, retaining the previous binary
// at "<target>.prev". The caller sets Target, Staged, From, To, StartedAt;
// performSwap fills State, Prev and (on Windows) Old.
//
// POSIX sequence (each numbered step is one filesystem mutation):
//
//  1. write journal (atomic)                — nothing changed yet
//  2. copy target -> target.prev (atomic)   — target untouched
//  3. rename staged -> target               — atomic replace
//
// There is no instant on POSIX at which the target path lacks a complete,
// executable binary: before step 3 it is the old build, after step 3 the
// new one.
//
// Windows sequence (a running .exe can be renamed but not replaced):
//
//  1. write journal (atomic)
//  2. copy target -> target.prev (atomic)
//  3. remove stale target.old, if any
//  4. rename target -> target.old           — allowed while executing
//  5. rename staged -> target
//
// Between 4 and 5 no file exists at the target path. That window cannot be
// closed on Windows; the journal (step 1) plus the retained copy (step 2)
// make it repairable — see performRepair, invoked from Resume.
func performSwap(fsys fsOps, j journal, windowsStyle bool) error {
	if j.Target == "" || j.Staged == "" {
		return errors.New("update: swap requires target and staged paths")
	}
	j.State = statePending
	j.Prev = j.Target + ".prev"
	if windowsStyle {
		j.Old = j.Target + ".old"
	}

	if err := writeJournal(fsys, j); err != nil {
		return fmt.Errorf("update: write journal: %w", err)
	}
	if err := fsys.CopyFile(j.Target, j.Prev); err != nil {
		_ = fsys.Remove(journalPath(j.Target))
		return fmt.Errorf("update: retain previous binary: %w", err)
	}
	if windowsStyle {
		if err := fsys.Remove(j.Old); err != nil && !errors.Is(err, fs.ErrNotExist) {
			_ = fsys.Remove(j.Prev)
			_ = fsys.Remove(journalPath(j.Target))
			return fmt.Errorf("update: clear stale %s: %w", j.Old, err)
		}
		if err := fsys.Rename(j.Target, j.Old); err != nil {
			_ = fsys.Remove(j.Prev)
			_ = fsys.Remove(journalPath(j.Target))
			return fmt.Errorf("update: move running executable aside: %w", err)
		}
	}
	if err := fsys.Rename(j.Staged, j.Target); err != nil {
		if windowsStyle {
			if rerr := fsys.Rename(j.Old, j.Target); rerr != nil {
				// Target is missing and could not be restored in-process.
				// The journal stays on disk so Resume/repair can fix it.
				return fmt.Errorf("update: install new binary failed (%w) and restoring the previous one failed (%v); journal retained for repair", err, rerr)
			}
		}
		_ = fsys.Remove(j.Prev)
		_ = fsys.Remove(journalPath(j.Target))
		return fmt.Errorf("update: install new binary: %w", err)
	}
	return nil
}

// performRollback restores the retained previous binary over the target.
// It is called from the (running) new binary after a failed health check,
// and again from Resume if a previous rollback was interrupted; it is
// idempotent given the journal.
//
// POSIX: write journal(state=rolledback), then a single atomic
// rename(prev -> target). The failed build is discarded.
//
// Windows: write journal, rename the running new binary target -> target.failed
// (renaming the executing image is allowed), then rename(prev -> target).
func performRollback(fsys fsOps, j journal, reason string, windowsStyle bool) error {
	j.State = stateRolledBack
	j.Reason = reason
	if err := writeJournal(fsys, j); err != nil {
		return fmt.Errorf("update: write rollback journal: %w", err)
	}
	if windowsStyle {
		failed := j.Target + ".failed"
		if err := fsys.Remove(failed); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("update: clear stale %s: %w", failed, err)
		}
		if err := fsys.Rename(j.Target, failed); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("update: move failed binary aside: %w", err)
		}
	}
	if err := fsys.Rename(j.Prev, j.Target); err != nil {
		return fmt.Errorf("update: restore previous binary: %w", err)
	}
	return nil
}

// performCommit finalises a verified update: the Windows .old image and any
// stale staged file are removed best-effort, the previous binary is
// retained at target.prev, and the journal is deleted last so an
// interrupted commit is simply re-run on the next start.
func performCommit(fsys fsOps, j journal) error {
	if j.Old != "" {
		_ = fsys.Remove(j.Old) // may still be held briefly by the exiting old process
	}
	if j.Staged != "" {
		_ = fsys.Remove(j.Staged) // already renamed away; stale-file safety only
	}
	if err := fsys.Remove(journalPath(j.Target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("update: remove journal: %w", err)
	}
	return nil
}

// performRepair restores a binary at the target path after a crash inside
// the Windows swap window (between rename-aside and place-new), preferring
// the moved-aside original over the retained copy.
func performRepair(fsys fsOps, j journal) error {
	if _, err := fsys.Stat(j.Target); err == nil {
		return nil
	}
	if j.Old != "" {
		if _, err := fsys.Stat(j.Old); err == nil {
			if err := fsys.Rename(j.Old, j.Target); err != nil {
				return fmt.Errorf("update: repair from %s: %w", j.Old, err)
			}
			return nil
		}
	}
	if j.Prev != "" {
		if _, err := fsys.Stat(j.Prev); err == nil {
			if err := fsys.Rename(j.Prev, j.Target); err != nil {
				return fmt.Errorf("update: repair from %s: %w", j.Prev, err)
			}
			return nil
		}
	}
	return errors.New("update: no binary available to restore at target")
}

// performAbort returns the installation to its pre-update state after a
// swap that never took effect (crash before the final rename). The target
// must already exist — run performRepair first when it does not.
func performAbort(fsys fsOps, j journal) error {
	for _, p := range []string{j.Staged, j.Prev, j.Old, j.Target + ".failed"} {
		if p == "" {
			continue
		}
		if err := fsys.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("update: abort cleanup %s: %w", p, err)
		}
	}
	if err := fsys.Remove(journalPath(j.Target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("update: abort cleanup journal: %w", err)
	}
	return nil
}

// performRollbackCleanup runs on the restored previous binary after a
// completed rollback: it removes the failed build, the Windows .old image,
// any stale staged file, and finally the journal.
func performRollbackCleanup(fsys fsOps, j journal) error {
	for _, p := range []string{j.Target + ".failed", j.Old, j.Staged} {
		if p == "" {
			continue
		}
		_ = fsys.Remove(p) // best effort; stale files are harmless
	}
	if err := fsys.Remove(journalPath(j.Target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("update: remove journal after rollback: %w", err)
	}
	return nil
}
