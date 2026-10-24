package podman

import (
	"archive/tar"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

const stateFileName = "spec.json"

var sandboxIDPattern = regexp.MustCompile(`^podman-[0-9a-f]{32}$`)

// validSandboxID reports whether id is a provider-issued sandbox ID. IDs
// are validated before ANY filesystem use: an unvalidated ID is a path
// traversal vector into the state dir.
func validSandboxID(id string) bool { return sandboxIDPattern.MatchString(id) }

func newSandboxID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate sandbox id: %w", err)
	}
	return "podman-" + hex.EncodeToString(b[:]), nil
}

// sandboxState is the persisted spec for one sandbox. Env is stored so a
// reattached sandbox executes with the same environment it was created
// with; the file is mode 0600 inside a 0700 tree for that reason.
type sandboxState struct {
	ID        string            `json:"id"`
	Image     string            `json:"image"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

func stateFromSpec(id, image string, spec sandbox.Spec) sandboxState {
	return sandboxState{ID: id, Image: image, Metadata: spec.Metadata, Env: spec.Env, CreatedAt: time.Now().UTC()}
}

func writeState(dir string, st sandboxState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sandbox state: %w", err)
	}
	tmp := filepath.Join(dir, stateFileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write sandbox state: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, stateFileName)); err != nil {
		return fmt.Errorf("commit sandbox state: %w", err)
	}
	return nil
}

func readState(dir string) (sandboxState, error) {
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return sandboxState{}, fmt.Errorf("%w: %s", ErrSandboxNotFound, filepath.Base(dir))
		}
		return sandboxState{}, fmt.Errorf("read sandbox state: %w", err)
	}
	var st sandboxState
	if err := json.Unmarshal(data, &st); err != nil {
		return sandboxState{}, fmt.Errorf("decode sandbox state for %s: %w", filepath.Base(dir), err)
	}
	return st, nil
}

// extractRootfs unpacks an image-export tar stream into dest. Entries
// that would escape dest (absolute paths, "..", escaping symlink/hardlink
// targets) are rejected: the tar comes from a local image, but a hostile
// or corrupted image must not write outside the sandbox rootfs.
//
// Every path handed to a filesystem write is first resolved with
// resolveInRootfs, which walks each component and expands symlinks —
// including symlinks planted by earlier tar entries — as rootfs-relative.
// The path actually opened therefore contains no un-walked symlink
// component for the host kernel to follow out of dest: a tar carrying
// `bin -> /some/host/dir` followed by a regular entry `bin/<file>` writes
// to dest's rootfs-relative interpretation of that target, never through
// the planted host symlink. Link entries themselves are placed via
// linkLocation, which resolves only the parent chain and appends the
// final component verbatim, so the link is created, not followed.
func extractRootfs(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read image export: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			target, err := resolveInRootfs(dest, rootfsPath(hdr.Name))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(target, fsMode(hdr.Mode, 0o755)); err != nil {
				return fmt.Errorf("create rootfs dir %s: %w", hdr.Name, err)
			}
		case tar.TypeReg:
			target, err := resolveInRootfs(dest, rootfsPath(hdr.Name))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fsMode(hdr.Mode, 0o644))
			if err != nil {
				return fmt.Errorf("create rootfs file %s: %w", hdr.Name, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write rootfs file %s: %w", hdr.Name, err)
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			target, err := linkLocation(dest, hdr.Name)
			if err != nil {
				return err
			}
			if err := checkLinkTarget(dest, target, hdr.Linkname); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("create rootfs symlink %s: %w", hdr.Name, err)
			}
		case tar.TypeLink:
			src, err := resolveInRootfs(dest, rootfsPath(hdr.Linkname))
			if err != nil {
				return err
			}
			target, err := linkLocation(dest, hdr.Name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Link(src, target); err != nil {
				return fmt.Errorf("create rootfs hardlink %s: %w", hdr.Name, err)
			}
		default:
			// Device nodes, fifos, etc. cannot be created unprivileged and
			// are not needed by the template images; skip them.
			continue
		}
	}
}

// rootfsPath renders a tar entry name as the absolute in-rootfs path
// resolveInRootfs expects.
func rootfsPath(name string) string {
	return "/" + strings.TrimPrefix(name, "/")
}

// linkLocation returns the host path at which a symlink or hardlink
// entry itself must be created: the parent directory is resolved with
// full symlink expansion (resolveInRootfs) and the final component is
// appended verbatim, so the link is placed at a walked location rather
// than followed through a previously planted symlink.
func linkLocation(root, name string) (string, error) {
	clean := strings.TrimPrefix(filepath.Clean(rootfsPath(name)), "/")
	dir, base := filepath.Split(clean)
	if base == "" || base == "." {
		return "", fmt.Errorf("%w: image entry %q has no final component", ErrInvalidSpec, name)
	}
	parent := root
	if dir != "" {
		resolved, err := resolveInRootfs(root, "/"+strings.TrimSuffix(dir, "/"))
		if err != nil {
			return "", err
		}
		parent = resolved
	}
	target := filepath.Join(parent, base)
	if !isUnder(root, target) {
		return "", fmt.Errorf("%w: image entry %q escapes the sandbox rootfs", ErrInvalidSpec, name)
	}
	return target, nil
}

// joinUnder joins name onto root and rejects anything escaping root.
// Absolute names are reinterpreted as root-relative (image tars use
// root-relative paths; a leading "/" must not escape).
func joinUnder(root, name string) (string, error) {
	clean := filepath.Clean("/" + strings.TrimPrefix(name, "/"))
	target := filepath.Join(root, clean)
	if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: image entry %q escapes the sandbox rootfs", ErrInvalidSpec, name)
	}
	return target, nil
}

func checkLinkTarget(root, linkPath, target string) error {
	if filepath.IsAbs(target) {
		// Absolute symlink targets are normal inside a rootfs (usrmerge:
		// /bin -> /usr/bin). They resolve within the rootfs when podman
		// runs with --rootfs, so they are safe to record as-is.
		return nil
	}
	resolved := filepath.Join(filepath.Dir(linkPath), target)
	if resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
		return fmt.Errorf("%w: symlink %q -> %q escapes the sandbox rootfs", ErrInvalidSpec, linkPath, target)
	}
	return nil
}

func fsMode(m int64, fallback os.FileMode) os.FileMode {
	if m == 0 {
		return fallback
	}
	return os.FileMode(m).Perm()
}
