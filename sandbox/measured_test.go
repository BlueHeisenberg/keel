// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// ---- measured external-tool output ------------------------------------------
//
// This file is the evidence locker for every string this package matches
// against an external tool's output, and the enforcement that keeps it honest.
//
// THE RULE.  A classifier here may only match a string that some sample in
// measuredToolOutput below actually contains, copied byte-for-byte off a real
// run of the real tool.  TestEveryMatchedStringIsMeasured reads the classifier
// source and fails the build for any literal with no sample behind it, so
// "I measured this" is checkable rather than claimed.
//
// WHY.  Three bugs in one day, all the same shape: a string nobody had run the
// tool to confirm.
//
//   - Inspect matched "no such container" while bare `podman inspect` answers
//     "no such object", so ErrSandboxNotFound never fired and isolated mode
//     created zero sandboxes on any host, ever (v0.5.1).
//   - Stop and Start never classified at all, so every consumer branch on
//     ErrSandboxNotFound was dead code (v0.5.2).
//   - The not-found test asserted the stderr the package hoped for against an
//     argv that cannot produce it: a test that could not fail.
//
// A hoped-for string and a measured one are indistinguishable in a diff. The
// only difference a reviewer can see is whether a sample sits next to it.
//
// HOW TO ADD ONE.  Run the command against the real tool, paste the exit code
// and the stderr verbatim — warnings, quoting, punctuation and all — and record
// the tool version you ran. Then set the classification fields to what the
// classifiers must say about it, including the falses: a sample that must NOT
// classify is worth as much as one that must, and pins the bug above.
//
// Samples that no classifier matches are not waste — they are the negative
// space that shows what the tool says on paths this package deliberately does
// not treat as absences.

// toolSample is one observed invocation of an external tool: what was run, what
// it exited with, what it printed, and what this package's classifiers must
// conclude from it.
type toolSample struct {
	// Tool is the binary and its exact version, e.g. "podman 4.9.3".
	Tool string
	// Cmd is the command as run, so a reader can reproduce the sample.
	Cmd string
	// Exit is the observed exit status.
	Exit int
	// Stderr is the observed standard error, verbatim.
	Stderr string

	// The classification each predicate must return for this sample.
	NotFound        bool // isNotFoundErr
	NoSuchContainer bool // isNoSuchContainer
	SnapshotMissing bool // isQemuSnapshotMissing
}

// measuredToolOutput holds every observed sample.  Captured 2026-08-16 on
// theharness-dev (Ubuntu 24.04, root) with podman 4.9.3 and qemu-img 8.2.2.
var measuredToolOutput = []toolSample{
	// ── podman: the container is missing ─────────────────────────────────────
	//
	// The leading clause is worded differently per subcommand — note `stop`
	// says "name or ID" and `rm` says "ID or name" — so only the trailing
	// ": no such container" is common to all of them.  That is why
	// isNoSuchContainer leans on it rather than on the leading clause.
	{
		Tool: "podman 4.9.3", Cmd: `podman stop keel-missing`, Exit: 125,
		Stderr:          `Error: no container with name or ID "keel-missing" found: no such container`,
		NotFound:        true,
		NoSuchContainer: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman start keel-missing`, Exit: 125,
		Stderr:          `Error: no container with name or ID "keel-missing" found: no such container`,
		NotFound:        true,
		NoSuchContainer: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman exec keel-missing echo hi`, Exit: 125,
		Stderr:          `Error: no container with name or ID "keel-missing" found: no such container`,
		NotFound:        true,
		NoSuchContainer: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman commit keel-missing foo:bar`, Exit: 125,
		Stderr:          `Error: no container with name or ID "keel-missing" found: no such container`,
		NotFound:        true,
		NoSuchContainer: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman rm keel-missing`, Exit: 1,
		Stderr:          `Error: no container with ID or name "keel-missing" found: no such container`,
		NotFound:        true,
		NoSuchContainer: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman inspect --type container --format json keel-missing`, Exit: 125,
		Stderr:          `Error: no such container keel-missing`,
		NotFound:        true,
		NoSuchContainer: true,
	},

	// The v0.5.1 bug, pinned as a negative.  Bare `inspect` resolves containers
	// AND images, and says "object" — a word no classifier here matches, and
	// none should: the fix is `--type container` on the argv, not a wider match
	// that would also swallow a missing image as a missing sandbox.
	{
		Tool: "podman 4.9.3", Cmd: `podman inspect keel-missing`, Exit: 125,
		Stderr: `Error: no such object: "keel-missing"`,
	},

	// ── podman: the volume is missing ────────────────────────────────────────
	//
	// `volume rm --force` and `rm --force` both exit 0 on an absent target, so
	// the tolerated-cleanup paths mostly never reach isNotFoundErr at all.
	// These two are what the non-forced forms say when they do.
	{
		Tool: "podman 4.9.3", Cmd: `podman volume rm keel-nope-work`, Exit: 1,
		Stderr:   `Error: no volume with name "keel-nope-work" found: no such volume`,
		NotFound: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman volume inspect keel-missing-work`, Exit: 125,
		Stderr:   `Error: no such volume keel-missing-work`,
		NotFound: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman volume rm --force keel-missing-work`, Exit: 0,
		Stderr: ``,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman rm --force keel-missing`, Exit: 0,
		Stderr: ``,
	},

	// ── podman: `rm --volumes` says nothing new ──────────────────────────────
	//
	// Every container rm in podman.go carries `--volumes`, so that the
	// anonymous volume an image's `VOLUME` instruction gives each container is
	// reaped with it instead of stranded.  Recorded here so the next reader can
	// see that the flag changes what podman DOES and not what it SAYS: the
	// forced form still exits 0 in silence on an absent container, the
	// non-forced form still produces the exact "no such container" wording of
	// the plain `podman rm` sample above, and every classifier's verdict is
	// unchanged.  Nothing on this path needed a new match, which is why none
	// was added.
	{
		Tool: "podman 4.9.3", Cmd: `podman rm --force --volumes keel-missing`, Exit: 0,
		Stderr: ``,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman rm --volumes keel-missing`, Exit: 1,
		Stderr:          `Error: no container with ID or name "keel-missing" found: no such container`,
		NotFound:        true,
		NoSuchContainer: true,
	},

	// ── podman: the image is missing ─────────────────────────────────────────
	//
	// Every missing-image path answers with "image not known".  "no such image"
	// — the Docker phrasing isNotFoundErr used to also match — is produced by
	// none of them, which is why it is gone.
	{
		Tool: "podman 4.9.3", Cmd: `podman rmi keel-snap-missing:tag`, Exit: 1,
		Stderr:   `Error: keel-snap-missing:tag: image not known`,
		NotFound: true,
	},
	{
		Tool: "podman 4.9.3", Cmd: `podman inspect --type image keel-missing-img`, Exit: 125,
		Stderr:   `Error: keel-missing-img: image not known`,
		NotFound: true,
	},

	// ── podman: the volume already exists ────────────────────────────────────
	//
	// The reason Create passes `--ignore`.  Deliberately matched by nothing:
	// the fix is the flag, not a classifier.  `podman volume create --ignore X`
	// on an existing volume exits 0, prints the name and leaves the volume's
	// CreatedAt untouched (also measured), and `podman volume exists X` answers
	// 0/1 with empty output — so nothing on this path reads a message.
	{
		Tool: "podman 4.9.3", Cmd: `podman volume create keel-ok-vol   # already exists`, Exit: 125,
		Stderr: `Error: volume with name keel-ok-vol already exists: volume already exists`,
	},

	// ── qemu-img: the snapshot is missing ────────────────────────────────────
	{
		Tool: "qemu-img 8.2.2", Cmd: `qemu-img snapshot -d nosuchsnap disk.qcow2`, Exit: 1,
		Stderr:          `qemu-img: Could not delete snapshot 'nosuchsnap': snapshot not found`,
		SnapshotMissing: true,
	},

	// Same message on a file that is not a disk image at all: qemu-img probes
	// it as raw, finds no snapshots, and reports the absence.  Indistinguishable
	// from a genuinely missing snapshot, and treating it as one is correct for
	// RemoveSnapshot, whose goal state is "the snapshot is gone".
	{
		Tool: "qemu-img 8.2.2", Cmd: `qemu-img snapshot -d anysnap notdisk.txt`, Exit: 1,
		Stderr: `WARNING: Image format was not specified for 'notdisk.txt' and probing guessed raw.
         Automatically detecting the format is dangerous for raw images, write operations on block 0 will be restricted.
         Specify the 'raw' format explicitly to remove the restrictions.
qemu-img: Could not delete snapshot 'anysnap': snapshot not found`,
		SnapshotMissing: true,
	},

	// A missing image file is NOT a missing snapshot: qemu-img never gets far
	// enough to look.  RemoveSnapshot surfaces this rather than reporting
	// success, because "I could not open the disk" is a different fact from
	// "the snapshot is not on the disk".
	{
		Tool: "qemu-img 8.2.2", Cmd: `qemu-img snapshot -d anysnap /tmp/qt/nosuchimage.qcow2`, Exit: 1,
		Stderr: `qemu-img: Could not open '/tmp/qt/nosuchimage.qcow2': Could not open '/tmp/qt/nosuchimage.qcow2': No such file or directory`,
	},
	{
		Tool: "qemu-img 8.2.2", Cmd: `qemu-img snapshot -d keepme /tmp/qt/adir`, Exit: 1,
		Stderr: `qemu-img: Could not open '/tmp/qt/adir': Could not open '/tmp/qt/adir': Is a directory`,
	},
	{
		Tool: "qemu-img 8.2.2", Cmd: `su -s /bin/sh nobody -c "qemu-img snapshot -d s1 /tmp/qt/ro.qcow2"`, Exit: 1,
		Stderr: `qemu-img: Could not open '/tmp/qt/ro.qcow2': Could not open '/tmp/qt/ro.qcow2': Permission denied`,
	},

	// `snapshot -a` on a missing snapshot, for contrast: a different verb and a
	// different message, and Restore does not tolerate it.  Recorded so the next
	// person widening isQemuSnapshotMissing can see that "Could not ... snapshot"
	// is a prefix qemu-img reuses across verbs and causes, not an absence.
	{
		Tool: "qemu-img 8.2.2", Cmd: `qemu-img snapshot -a nosuchsnap disk.qcow2`, Exit: 1,
		Stderr: `qemu-img: Could not apply snapshot 'nosuchsnap': Failed to load snapshot: No such file or directory`,
	},
}

// asCommandError wraps a sample the way podmanEnv and QemuBackend.run wrap a
// real failure: the stderr is carried in CommandError.Stderr, deliberately kept
// out of Error(), which is exactly why classifiers must read it through
// errText.  A classifier that used err.Error() would see none of this.
func (s toolSample) asCommandError() error {
	if s.Exit == 0 {
		return nil
	}
	return &CommandError{
		Tool:     strings.Fields(s.Tool)[0],
		ExitCode: s.Exit,
		Stderr:   strings.TrimSpace(s.Stderr),
		Err:      &exec.ExitError{ProcessState: &os.ProcessState{}},
	}
}

// sampleFor returns the sample whose Cmd is cmd, so a behaviour test can drive
// a backend method with the exact bytes the tool produced instead of a
// paraphrase of them.  An unknown cmd fails rather than silently substituting
// nothing — a test fed an empty stderr is a test that cannot fail.
func sampleFor(t *testing.T, cmd string) toolSample {
	t.Helper()
	for _, s := range measuredToolOutput {
		if s.Cmd == cmd {
			return s
		}
	}
	t.Fatalf("no measured sample for %q; add one to measuredToolOutput", cmd)
	return toolSample{}
}

// TestMeasuredToolOutput_Classification runs every classifier over every
// measured sample.  The falses matter as much as the trues: they are what
// stops a future widening from turning "no such object" into a missing sandbox
// or "Could not open" into a missing snapshot.
func TestMeasuredToolOutput_Classification(t *testing.T) {
	for _, s := range measuredToolOutput {
		err := s.asCommandError()
		if err == nil {
			// An exit-0 sample is not an error at all; the classifiers must say
			// so, which is the nil guard each of them opens with.
			if isNotFoundErr(nil) || isNoSuchContainer(nil) || isQemuSnapshotMissing(nil) {
				t.Errorf("%s: a nil error must classify as nothing", s.Cmd)
			}
			continue
		}
		if got := isNotFoundErr(err); got != s.NotFound {
			t.Errorf("isNotFoundErr(%s) = %v, want %v\nstderr: %s", s.Cmd, got, s.NotFound, s.Stderr)
		}
		if got := isNoSuchContainer(err); got != s.NoSuchContainer {
			t.Errorf("isNoSuchContainer(%s) = %v, want %v\nstderr: %s", s.Cmd, got, s.NoSuchContainer, s.Stderr)
		}
		if got := isQemuSnapshotMissing(err); got != s.SnapshotMissing {
			t.Errorf("isQemuSnapshotMissing(%s) = %v, want %v\nstderr: %s", s.Cmd, got, s.SnapshotMissing, s.Stderr)
		}
	}
}

// classifierSources are the files whose external-tool string matches must be
// backed by a sample.  Add a file here when it starts classifying tool output.
var classifierSources = []string{"podman.go", "qemu.go"}

// matchedLiteralRe finds the string matches this rule governs.  It keys off the
// variable name `msg`, which is the convention every classifier in this package
// follows: `msg := errText(err)` and then match against msg.  That is the whole
// naming rule — text that came out of an external tool is called msg, and
// anything matched against msg needs a sample.  It deliberately does not match
// strings.Contains against anything else (hostGW, a caller's path), which are
// this package's own values and not a tool's wording.
var matchedLiteralRe = regexp.MustCompile(`strings\.Contains\(msg, "([^"]*)"\)`)

// TestEveryMatchedStringIsMeasured is the enforcement behind the rule at the
// top of this file: it reads the classifier source and fails for any literal
// matched against external-tool output that no measured sample contains.
//
// This is the test that would have caught all of it. isQemuSnapshotMissing
// shipped four strings of which two ("can't find snapshot", "no such snapshot")
// no version of qemu-img has ever printed, and isNotFoundErr shipped
// "no such image", which podman does not say either. None of the three had a
// sample, and none could have got one, because running the tool is how you
// find out that it does not say that.
func TestEveryMatchedStringIsMeasured(t *testing.T) {
	var haystack []string
	for _, s := range measuredToolOutput {
		haystack = append(haystack, strings.ToLower(s.Stderr))
	}

	measured := func(literal string) bool {
		for _, h := range haystack {
			if strings.Contains(h, literal) {
				return true
			}
		}
		return false
	}

	found := 0
	for _, name := range classifierSources {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range matchedLiteralRe.FindAllStringSubmatch(string(src), -1) {
			found++
			if !measured(m[1]) {
				t.Errorf("%s matches %q against external tool output, but no sample in "+
					"measuredToolOutput contains it.\n"+
					"Run the tool, paste the verbatim stderr into measuredToolOutput, or "+
					"delete the match — an unmeasured string is the bug this test exists to stop.",
					name, m[1])
			}
		}
	}

	// A regex that silently stops matching would turn this test green and
	// useless, which is the "test that cannot fail" failure mode all over
	// again.  Require it to have found something.
	if found == 0 {
		t.Fatal("matchedLiteralRe found no string matches in " + strings.Join(classifierSources, ", ") +
			"; either the classifiers stopped naming their variable msg, or this test has stopped working")
	}
}
