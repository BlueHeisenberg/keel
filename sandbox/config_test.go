// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigWithDefaults(t *testing.T) {
	got := Config{}.withDefaults()

	if got.NamePrefix != "sbx-" {
		t.Errorf("NamePrefix = %q, want sbx-", got.NamePrefix)
	}
	if got.LabelKey != "keel.sandbox" {
		t.Errorf("LabelKey = %q, want keel.sandbox", got.LabelKey)
	}
	if got.PodmanBinary != "podman" || got.QemuBinary != "qemu-system-x86_64" || got.QemuImgBinary != "qemu-img" {
		t.Errorf("unexpected binaries: %+v", got)
	}
	if got.SnapshotRepo != "keel/snap" || got.EgressTable != "keel_egress" {
		t.Errorf("unexpected naming defaults: %+v", got)
	}
	if !filepath.IsAbs(got.StateDir) || !strings.Contains(got.StateDir, "keel-sandbox") {
		t.Errorf("StateDir = %q, want an absolute path under keel-sandbox", got.StateDir)
	}
	// There is deliberately no default image.
	if got.Image != "" {
		t.Errorf("Image = %q, want empty (no built-in default image)", got.Image)
	}

	// Explicit values survive.
	set := Config{NamePrefix: "acme-", LabelKey: "acme.box", Image: "acme/desktop:1"}.withDefaults()
	if set.NamePrefix != "acme-" || set.LabelKey != "acme.box" || set.Image != "acme/desktop:1" {
		t.Errorf("withDefaults overwrote explicit values: %+v", set)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("ACME_SANDBOX_IMAGE", "acme/desktop:2")
	t.Setenv("ACME_QEMU_BINARY", "qemu-system-aarch64")
	t.Setenv("ACME_QEMU_BASE_IMAGE", "/disks/base.qcow2")
	t.Setenv("ACME_DATA_DIR", filepath.Join("var", "acme"))

	cfg := ConfigFromEnv("ACME")
	if cfg.Image != "acme/desktop:2" {
		t.Errorf("Image = %q", cfg.Image)
	}
	if cfg.QemuBinary != "qemu-system-aarch64" {
		t.Errorf("QemuBinary = %q", cfg.QemuBinary)
	}
	if cfg.BaseImage != "/disks/base.qcow2" {
		t.Errorf("BaseImage = %q", cfg.BaseImage)
	}
	// DATA_DIR is only consulted when the state dir is unset.
	if want := filepath.Join("var", "acme", "qemu"); cfg.StateDir != want {
		t.Errorf("StateDir = %q, want %q", cfg.StateDir, want)
	}
	t.Setenv("ACME_QEMU_STATE_DIR", filepath.Join("srv", "vms"))
	if got := ConfigFromEnv("ACME").StateDir; got != filepath.Join("srv", "vms") {
		t.Errorf("explicit state dir = %q", got)
	}

	// A different prefix sees none of it.
	if other := ConfigFromEnv("OTHER"); other != (Config{}) {
		t.Errorf("ConfigFromEnv(\"OTHER\") = %+v, want zero Config", other)
	}
	// Unset variables stay empty rather than being invented.
	if os.Getenv("ACME_PODMAN_BINARY") == "" && ConfigFromEnv("ACME").PodmanBinary != "" {
		t.Error("ConfigFromEnv invented a podman binary")
	}
}

// Config drives every name the Podman backend puts on the host.
func TestConfigNamesResources(t *testing.T) {
	r := &mockRunner{}
	b := newPodmanBackendWithRunner(r, slog.Default())
	b.cfg = Config{NamePrefix: "acme-", LabelKey: "acme.box", Image: "acme/desktop:1"}.withDefaults()
	r.responses = []mockResponse{ok(""), ok("cid\n")}

	if _, err := b.Create(context.Background(), Spec{Name: "one", Profile: ProfileHeadless, NetworkPolicy: NetworkPolicyOpen}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := b.containerName("one"); got != "acme-one" {
		t.Errorf("containerName = %q", got)
	}
	if got := b.volumeName("one"); got != "acme-one-work" {
		t.Errorf("volumeName = %q", got)
	}
	runArgs := r.calls[1].args
	if !containsArg(runArgs, "acme.box=one") {
		t.Errorf("missing configured label: %s", argString(runArgs))
	}
	if runArgs[len(runArgs)-1] != "acme/desktop:1" {
		t.Errorf("last arg = %q, want the configured default image", runArgs[len(runArgs)-1])
	}
	if runArgs[0] != "podman" {
		t.Errorf("args[0] = %q, want the configured podman binary", runArgs[0])
	}
}

// With no image on the Spec and none in the Config, Create fails before it
// creates anything on the host rather than guessing at a registry reference.
func TestCreate_NoImageConfigured(t *testing.T) {
	r := &mockRunner{}
	b := newTestBackend(r)

	_, err := b.Create(context.Background(), Spec{Name: "no-image", Profile: ProfileHeadless})
	if err == nil {
		t.Fatal("expected an error when no image is configured")
	}
	if !strings.Contains(err.Error(), "no image") {
		t.Errorf("error = %v, want it to mention the missing image", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("expected no runner calls, got %v", r.calls)
	}
}

// The egress ruleset is written under the configured table name, in both
// address families.
func TestEgressRulesetUsesConfiguredTable(t *testing.T) {
	rs := buildEgressRuleset("acme_egress", NetworkPolicyInternalOnly, "10.88.0.1", nil)
	if !strings.Contains(rs, "table ip acme_egress {") || !strings.Contains(rs, "table ip6 acme_egress {") {
		t.Errorf("ruleset does not use the configured table name:\n%s", rs)
	}
	if strings.Contains(rs, "keel_egress") {
		t.Errorf("ruleset leaked the default table name:\n%s", rs)
	}
}
