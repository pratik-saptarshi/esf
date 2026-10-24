package podman

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- resolveInRootfs: pinned behavior + chained-symlink regression ---

func usrmergeRootfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestResolveInRootfsUsrmergeRelative(t *testing.T) {
	root := usrmergeRootfs(t)
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	got, err := resolveInRootfs(root, "/bin/sh")
	if err != nil {
		t.Fatalf("resolveInRootfs(/bin/sh) = %v, want nil", err)
	}
	if want := filepath.Join(root, "usr", "bin", "sh"); got != want {
		t.Fatalf("resolveInRootfs(/bin/sh) = %q, want %q", got, want)
	}
}

func TestResolveInRootfsUsrmergeAbsolute(t *testing.T) {
	root := usrmergeRootfs(t)
	if err := os.Symlink("/usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	got, err := resolveInRootfs(root, "/bin/sh")
	if err != nil {
		t.Fatalf("resolveInRootfs(/bin/sh) = %v, want nil", err)
	}
	if want := filepath.Join(root, "usr", "bin", "sh"); got != want {
		t.Fatalf("resolveInRootfs(/bin/sh) = %q, want %q", got, want)
	}
}

func TestResolveInRootfsSymlinkEscapeRejected(t *testing.T) {
	root := usrmergeRootfs(t)
	if err := os.Symlink("../outside", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveInRootfs(root, "/escape/passwd"); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("resolveInRootfs(/escape/passwd) = %v, want ErrInvalidSpec", err)
	}
}

// TestResolveInRootfsChainedSymlinkEscape is the regression test for the
// un-walked relative symlink target: x -> y/data looks contained when
// joined lexically, but y is itself a symlink escaping the rootfs, so a
// caller opening the returned path would be resolved by the host kernel
// through y, outside the rootfs. Every component of a symlink target
// must be re-walked from the rootfs.
func TestResolveInRootfsChainedSymlinkEscape(t *testing.T) {
	root := usrmergeRootfs(t)
	if err := os.Symlink("../../outside", filepath.Join(root, "y")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("y/data", filepath.Join(root, "x")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveInRootfs(root, "/x/secret"); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("resolveInRootfs(/x/secret) via x->y/data, y->../../outside = %v, want ErrInvalidSpec", err)
	}
}

// TestResolveInRootfsChainedSymlinkContained guards the fix against
// over-rejecting: a chain whose links all stay inside the rootfs still
// resolves, with each hop re-walked.
func TestResolveInRootfsChainedSymlinkContained(t *testing.T) {
	root := usrmergeRootfs(t)
	if err := os.MkdirAll(filepath.Join(root, "real", "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real", "data", "f.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "y")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("y/data", filepath.Join(root, "x")); err != nil {
		t.Fatal(err)
	}
	got, err := resolveInRootfs(root, "/x/f.txt")
	if err != nil {
		t.Fatalf("resolveInRootfs(/x/f.txt) = %v, want nil", err)
	}
	if want := filepath.Join(root, "real", "data", "f.txt"); got != want {
		t.Fatalf("resolveInRootfs(/x/f.txt) = %q, want %q", got, want)
	}
}

// --- extractRootfs: symlink-then-file regression ---

type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	body     string
}

func buildTar(t *testing.T, entries []tarEntry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typeflag, Linkname: e.linkname}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if e.typeflag == tar.TypeDir {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// TestExtractRootfsSymlinkThenFileEscape is the regression test for
// extraction following a planted symlink: the tar plants a symlink with
// an absolute target outside dest (allowed, recorded as-is for
// usrmerge), then writes a regular file through it. Extraction must not
// let the host kernel follow the planted symlink — nothing may be
// written to the outside directory.
func TestExtractRootfsSymlinkThenFileEscape(t *testing.T) {
	outside := t.TempDir()
	dest := t.TempDir()
	tarBytes := buildTar(t, []tarEntry{
		{name: "bin", typeflag: tar.TypeSymlink, linkname: outside},
		{name: "bin/pwned.txt", typeflag: tar.TypeReg, body: "pwned\n"},
	})
	if err := extractRootfs(tarBytes, dest); err != nil {
		t.Fatalf("extractRootfs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("file written outside rootfs through planted symlink: %v", err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside dir polluted by extraction: %v, %v", entries, err)
	}
	// The absolute target is reinterpreted rootfs-relative (usrmerge
	// semantics), so the payload lands inside dest.
	inside := filepath.Join(dest, strings.TrimPrefix(outside, "/"), "pwned.txt")
	data, err := os.ReadFile(inside)
	if err != nil || string(data) != "pwned\n" {
		t.Fatalf("contained payload = %q, %v (want %q inside dest)", data, err, inside)
	}
}

// TestExtractRootfsPlantedSymlinkFileName covers the second half of the
// finding: a regular entry whose very name was previously planted as a
// symlink to a host file. The write must land at the rootfs-relative
// interpretation inside dest; the host file stays untouched.
func TestExtractRootfsPlantedSymlinkFileName(t *testing.T) {
	outside := t.TempDir()
	hostFile := filepath.Join(outside, "host.txt")
	if err := os.WriteFile(hostFile, []byte("host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	tarBytes := buildTar(t, []tarEntry{
		{name: "planted", typeflag: tar.TypeSymlink, linkname: hostFile},
		{name: "planted", typeflag: tar.TypeReg, body: "pwned\n"},
	})
	if err := extractRootfs(tarBytes, dest); err != nil {
		t.Fatalf("extractRootfs: %v", err)
	}
	data, err := os.ReadFile(hostFile)
	if err != nil || string(data) != "host\n" {
		t.Fatalf("host file through planted symlink = %q, %v; want untouched \"host\\n\"", data, err)
	}
	inside := filepath.Join(dest, strings.TrimPrefix(hostFile, "/"))
	data, err = os.ReadFile(inside)
	if err != nil || string(data) != "pwned\n" {
		t.Fatalf("contained payload = %q, %v (want %q inside dest)", data, err, inside)
	}
}

// TestExtractRootfsUsrmergePreserved pins the legitimate image shape:
// a usrmerge symlink followed by files under the real directory still
// extracts, and the symlink is recorded as-is.
func TestExtractRootfsUsrmergePreserved(t *testing.T) {
	dest := t.TempDir()
	tarBytes := buildTar(t, []tarEntry{
		{name: "usr/bin/sh", typeflag: tar.TypeReg, body: "#!/bin/sh\n"},
		{name: "bin", typeflag: tar.TypeSymlink, linkname: "/usr/bin"},
		{name: "lib", typeflag: tar.TypeSymlink, linkname: "usr/lib"},
	})
	if err := extractRootfs(tarBytes, dest); err != nil {
		t.Fatalf("extractRootfs: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "usr", "bin", "sh"))
	if err != nil || string(data) != "#!/bin/sh\n" {
		t.Fatalf("usr/bin/sh = %q, %v", data, err)
	}
	for link, want := range map[string]string{"bin": "/usr/bin", "lib": "usr/lib"} {
		got, err := os.Readlink(filepath.Join(dest, link))
		if err != nil || got != want {
			t.Fatalf("symlink %s = %q, %v; want %q", link, got, err, want)
		}
	}
}

// TestExtractRootfsHardlinkThroughSymlink pins hardlink protection: the
// source is resolved with the same walked expansion, so a hardlink
// cannot pull content in through a planted symlink from outside dest —
// the source simply does not exist under its rootfs interpretation.
func TestExtractRootfsHardlinkThroughSymlink(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "host.txt"), []byte("host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	tarBytes := buildTar(t, []tarEntry{
		{name: "s", typeflag: tar.TypeSymlink, linkname: outside},
		{name: "stolen.txt", typeflag: tar.TypeLink, linkname: "s/host.txt"},
	})
	if err := extractRootfs(tarBytes, dest); err == nil {
		t.Fatal("extractRootfs succeeded on hardlink through planted symlink, want error")
	}
	if _, err := os.Stat(filepath.Join(dest, "stolen.txt")); !os.IsNotExist(err) {
		t.Fatalf("hardlink created from outside content: %v", err)
	}
}
