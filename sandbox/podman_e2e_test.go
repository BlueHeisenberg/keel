// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Podman anonymous-volume lifecycle test.  It exercises the real thing a unit
// test cannot: what `podman rm --volumes` actually removes.
//
// Run:
//
//	KEEL_PODMAN_E2E_IMAGE=localhost/volprobe:test \
//	  go test -tags e2e ./sandbox -run TestPodmanAnonymousVolumeLifecycle -v -timeout 180s
//
// The image must declare at least one `VOLUME`, because that is what makes
// podman attach an anonymous volume to every container built from it — the
// condition the leak needs.  Any long-running base will do:
//
//	FROM docker.io/library/busybox:latest
//	VOLUME ["/var/lib/app"]
//	CMD ["sleep", "600"]
//
// The test skips cleanly when KEEL_PODMAN_E2E_IMAGE is unset or podman is not
// in PATH.
package sandbox

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// podmanE2EPrefix keeps every object this test creates identifiable and out of
// the way of anything else on the host.
const podmanE2EPrefix = "keel-e2e-"

// anonVolumeOf returns the name of the single anonymous volume attached to the
// container, and fails if there is not exactly one.  An anonymous volume is one
// podman named itself: a 64-character hex id rather than a name a caller chose.
func anonVolumeOf(t *testing.T, container, workVol string) string {
	t.Helper()
	out, err := exec.Command("podman", "inspect", "--type", "container",
		"--format", "json", container).Output()
	if err != nil {
		t.Fatalf("podman inspect %s: %v", container, err)
	}
	var inspected []struct {
		Mounts []struct {
			Type string `json:"Type"`
			Name string `json:"Name"`
		} `json:"Mounts"`
	}
	if err := json.Unmarshal(out, &inspected); err != nil {
		t.Fatalf("decode inspect json: %v", err)
	}
	if len(inspected) != 1 {
		t.Fatalf("podman inspect returned %d objects, want 1", len(inspected))
	}

	var anon []string
	for _, m := range inspected[0].Mounts {
		if m.Type == "volume" && m.Name != workVol {
			anon = append(anon, m.Name)
		}
	}
	if len(anon) != 1 {
		t.Fatalf("want exactly 1 anonymous volume on %s, got %d (%v).\n"+
			"KEEL_PODMAN_E2E_IMAGE must declare exactly one VOLUME, or this test "+
			"is measuring something other than the leak.", container, len(anon), anon)
	}
	return anon[0]
}

// volumeExistsOnHost asks podman directly.  `podman volume exists` answers by
// exit status alone — 0 present, 1 absent, nothing on either stream — so this
// reads no message that a future podman could reword.
func volumeExistsOnHost(name string) bool {
	return exec.Command("podman", "volume", "exists", name).Run() == nil
}

// TestPodmanAnonymousVolumeLifecycle is the measurement behind the `--volumes`
// flag on every container rm in podman.go.  It asserts the two facts that flag
// depends on, in the same removal:
//
//  1. the container's ANONYMOUS volume is gone afterwards — without this,
//     every recreate strands one and a long-lived host fills its disk;
//  2. the NAMED work volume is still there AND still holds its data — this is
//     the regression a careless fix would cause, and the whole basis of
//     Recreate as a rolling-update mechanism.
//
// Run it against the unfixed code and (1) fails; run a fix that reaches for
// `podman volume prune` or an unqualified volume rm instead and (2) fails.
func TestPodmanAnonymousVolumeLifecycle(t *testing.T) {
	image := os.Getenv("KEEL_PODMAN_E2E_IMAGE")
	if image == "" {
		t.Skip("KEEL_PODMAN_E2E_IMAGE not set — skipping podman anonymous-volume e2e")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not in PATH — skipping podman anonymous-volume e2e")
	}

	b := NewPodmanBackend(Config{NamePrefix: podmanE2EPrefix},
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	id := "anonvol"
	spec := Spec{
		Name:          id,
		Image:         image,
		Level:         LevelFast,
		Profile:       ProfileHeadless,
		NetworkPolicy: NetworkPolicyOpen,
	}
	workVol := b.volumeName(id)
	cname := b.containerName(id)

	// Purge unconditionally at the end so a failure mid-test does not leave the
	// host dirty; Purge tolerates everything already being gone.
	t.Cleanup(func() {
		_ = b.Purge(context.Background(), id)
	})

	if _, err := b.Create(ctx, spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	firstAnon := anonVolumeOf(t, cname, workVol)
	if !volumeExistsOnHost(firstAnon) {
		t.Fatalf("podman reported anonymous volume %s on the container but it does not exist", firstAnon)
	}

	// Put the caller's data on the named work volume, so "the volume survived"
	// means the data survived and not merely that a volume of that name exists.
	const marker = "/work/marker"
	want := []byte("data the roll must not lose\n")
	if err := b.WriteFile(ctx, id, marker, want); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The rolling update: same spec, new container.  This is the removal under
	// test — Recreate's teardown is removeContainer, the shared path Purge and
	// every launch-failure cleanup also use.
	if _, err := b.Recreate(ctx, spec); err != nil {
		t.Fatalf("Recreate: %v", err)
	}

	// (1) The outgoing container's anonymous volume must be gone.  This is the
	//     assertion that fails against `podman rm --force` with no --volumes.
	if volumeExistsOnHost(firstAnon) {
		t.Errorf("anonymous volume %s survived container removal — every recreate "+
			"strands one and nothing ever collects them", firstAnon)
	}

	// (2) The named work volume must be untouched, data and all.  This is the
	//     half that matters: it is the regression that would break a consumer's
	//     rolling update.
	if !volumeExistsOnHost(workVol) {
		t.Fatalf("named work volume %s was removed — --volumes must reap anonymous "+
			"volumes ONLY", workVol)
	}
	got, err := b.ReadFile(ctx, id, marker)
	if err != nil {
		t.Fatalf("ReadFile after Recreate: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("work volume content after Recreate = %q, want %q", got, want)
	}

	// The new container has its own anonymous volume, and it is a different
	// one — i.e. the reap did not simply stop podman creating them.
	secondAnon := anonVolumeOf(t, cname, workVol)
	if secondAnon == firstAnon {
		t.Errorf("new container reused anonymous volume %s; the test is not "+
			"observing what it thinks it is", firstAnon)
	}

	// Purge is the only thing allowed to take the named volume with it.
	if err := b.Purge(ctx, id); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	for _, v := range []string{workVol, secondAnon} {
		if volumeExistsOnHost(v) {
			t.Errorf("Purge left volume %s behind", v)
		}
	}

	// And nothing of ours is left on the host at all.
	out, err := exec.Command("podman", "volume", "ls", "--format", "{{.Name}}").Output()
	if err != nil {
		t.Fatalf("podman volume ls: %v", err)
	}
	for _, line := range strings.Fields(string(out)) {
		if strings.HasPrefix(line, podmanE2EPrefix) {
			t.Errorf("leftover volume after Purge: %s", line)
		}
	}
}
