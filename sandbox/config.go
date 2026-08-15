// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

// Default values applied to a Config's zero fields. They are neutral on
// purpose: a sandbox library should not name anything after the product that
// happens to be using it.
const (
	defaultNamePrefix   = "sbx-"
	defaultLabelKey     = "keel.sandbox"
	defaultSnapshotRepo = "keel/snap"
	defaultEgressTable  = "keel_egress"
	defaultPodmanBinary = "podman"
	defaultQemuBinary   = "qemu-system-x86_64"
	defaultQemuImgBin   = "qemu-img"
	defaultStateDirName = "keel-sandbox"
)

// Config holds everything a backend needs that is not per-sandbox: which
// binaries to run, what to call the resources it creates, and where to keep
// state.
//
// The zero value is usable and reads nothing from the environment — a library
// that consults os.Getenv behind the caller's back is a library that behaves
// differently in production than in the test that passed. Callers who do want
// environment configuration ask for it explicitly with ConfigFromEnv.
//
// The naming fields exist so that a product can brand the containers, volumes,
// images, and firewall tables it creates without this package having to know
// the brand.
type Config struct {
	// NamePrefix is prepended to Spec.Name to form container and volume names.
	// Default "sbx-", producing "sbx-<name>" and "sbx-<name>-work".
	NamePrefix string

	// LabelKey is the container label key carrying Spec.Name.
	// Default "keel.sandbox", producing "--label keel.sandbox=<name>".
	LabelKey string

	// Image is the OCI image used when Spec.Image is empty. There is no
	// built-in default image: if both are empty, Create fails rather than
	// guessing at a registry reference.
	Image string

	// SnapshotRepo is the image repository prefix for Podman snapshots.
	// Default "keel/snap", producing "keel/snap-<name>:<label>".
	SnapshotRepo string

	// EgressTable is the nftables table name used for the host-applied egress
	// lockdown. Default "keel_egress". Change it only if it collides with
	// another table on the host.
	EgressTable string

	// PodmanBinary is the podman executable. Default "podman", resolved
	// through PATH.
	PodmanBinary string

	// QemuBinary is the qemu-system executable.
	// Default "qemu-system-x86_64", resolved through PATH.
	QemuBinary string

	// QemuImgBinary is the qemu-img executable. Default "qemu-img", resolved
	// through PATH.
	QemuImgBinary string

	// BaseImage is the qcow2 disk that per-sandbox QEMU overlays are backed
	// by. It is resolved to an absolute path at Create time. Required by
	// QemuBackend: with no base image, Create returns ErrQemuUnavailable.
	BaseImage string

	// StateDir is the root directory for per-sandbox QEMU state (one
	// subdirectory per sandbox, holding the overlay, QMP socket, pidfile, and
	// CID file). Default <os.TempDir()>/keel-sandbox/qemu, which is fine for
	// throwaway VMs and wrong for anything you want to survive a reboot.
	StateDir string
}

// withDefaults returns c with every empty field replaced by its default.
func (c Config) withDefaults() Config {
	if c.NamePrefix == "" {
		c.NamePrefix = defaultNamePrefix
	}
	if c.LabelKey == "" {
		c.LabelKey = defaultLabelKey
	}
	if c.SnapshotRepo == "" {
		c.SnapshotRepo = defaultSnapshotRepo
	}
	if c.EgressTable == "" {
		c.EgressTable = defaultEgressTable
	}
	if c.PodmanBinary == "" {
		c.PodmanBinary = defaultPodmanBinary
	}
	if c.QemuBinary == "" {
		c.QemuBinary = defaultQemuBinary
	}
	if c.QemuImgBinary == "" {
		c.QemuImgBinary = defaultQemuImgBin
	}
	if c.StateDir == "" {
		c.StateDir = filepath.Join(os.TempDir(), defaultStateDirName, "qemu")
	}
	return c
}

// ConfigFromEnv reads a Config from the environment, looking up each variable
// under the given prefix. A prefix of "ACME" reads ACME_SANDBOX_IMAGE,
// ACME_QEMU_BINARY, and so on; an empty prefix reads the bare names.
//
// The variables are:
//
//	<PREFIX>_SANDBOX_IMAGE      Config.Image
//	<PREFIX>_SANDBOX_NAME_PREFIX Config.NamePrefix
//	<PREFIX>_PODMAN_BINARY      Config.PodmanBinary
//	<PREFIX>_QEMU_BINARY        Config.QemuBinary
//	<PREFIX>_QEMU_IMG           Config.QemuImgBinary
//	<PREFIX>_QEMU_BASE_IMAGE    Config.BaseImage
//	<PREFIX>_QEMU_STATE_DIR     Config.StateDir
//	<PREFIX>_DATA_DIR           parent of the state dir, used only when
//	                            <PREFIX>_QEMU_STATE_DIR is unset
//
// Unset variables are left empty, so the defaults in withDefaults still apply.
// Fields with no environment variable (LabelKey, SnapshotRepo, EgressTable) are
// set in code or not at all: they change the shape of resources this package
// creates and manages, and letting the environment move them invites a
// half-renamed host.
func ConfigFromEnv(prefix string) Config {
	get := func(suffix string) string {
		if prefix == "" {
			return os.Getenv(suffix)
		}
		return os.Getenv(strings.ToUpper(prefix) + "_" + suffix)
	}

	cfg := Config{
		Image:         get("SANDBOX_IMAGE"),
		NamePrefix:    get("SANDBOX_NAME_PREFIX"),
		PodmanBinary:  get("PODMAN_BINARY"),
		QemuBinary:    get("QEMU_BINARY"),
		QemuImgBinary: get("QEMU_IMG"),
		BaseImage:     get("QEMU_BASE_IMAGE"),
		StateDir:      get("QEMU_STATE_DIR"),
	}
	if cfg.StateDir == "" {
		if dataDir := get("DATA_DIR"); dataDir != "" {
			cfg.StateDir = filepath.Join(dataDir, "qemu")
		}
	}
	return cfg
}
