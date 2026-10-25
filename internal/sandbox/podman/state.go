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
//
// Once every entry is in place, finishRootfs applies the permissions
// the entry loop cannot land: the declared modes themselves (creation
// is umask-filtered), the root directory's own declared mode, and a
// /run writable by the executing user.
func extractRootfs(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	var rootMode os.FileMode
	// declared records the image-declared mode of every directory and
	// regular file placed, and targets every placed path (links
	// included, for their parent chains). Creation modes alone cannot
	// land them — MkdirAll/OpenFile AND with the process umask — so
	// finishRootfs applies them by chmod once extraction completes.
	declared := map[string]os.FileMode{}
	var targets []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return finishRootfs(dest, rootMode, declared, targets)
		}
		if err != nil {
			return fmt.Errorf("read image export: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if isRootEntryName(hdr.Name) {
				// The image's declaration for the rootfs root
				// itself. The MkdirAll below cannot apply it —
				// dest already exists (Create pre-created it) and
				// MkdirAll never changes an existing directory's
				// mode — so capture it here; finishRootfs chmods
				// dest once extraction completes.
				rootMode = fsMode(hdr.Mode, 0o755)
			}
			target, err := resolveInRootfs(dest, rootfsPath(hdr.Name))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(target, fsMode(hdr.Mode, 0o755)); err != nil {
				return fmt.Errorf("create rootfs dir %s: %w", hdr.Name, err)
			}
			targets = append(targets, target)
			if target != dest {
				declared[target] = fsMode(hdr.Mode, 0o755)
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
			targets = append(targets, target)
			declared[target] = fsMode(hdr.Mode, 0o644)
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
			targets = append(targets, target)
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
			targets = append(targets, target)
		default:
			// Device nodes, fifos, etc. cannot be created unprivileged and
			// are not needed by the template images; skip them.
			continue
		}
	}
}

// isRootEntryName reports whether a tar entry name denotes the rootfs
// root itself. Image exports spell it ".", "./", or "/" — and most
// omit the entry entirely (verified against a debian:trixie-slim
// export, whose first entries are top-level names like "bin").
func isRootEntryName(name string) bool {
	switch filepath.Clean(name) {
	case ".", "/":
		return true
	}
	return false
}

// runDirMode is /run's mode in an extracted rootfs: world-writable
// with the sticky bit (1777 in chmod notation; os.ModeSticky, since
// os.FileMode does not carry the bit in the octal position).
const runDirMode = 0o777 | os.ModeSticky

// finishRootfs applies the permissions the extraction loop cannot,
// after every entry is in place:
//
//   - Every declared directory/file mode is chmod'ed to land exactly.
//     Creation (MkdirAll/OpenFile) ANDs the requested mode with the
//     process umask, so under a restrictive umask the image's modes
//     silently degrade — on a umask-0007 host, declared-0755
//     directories and executables land at 0750, traversable and
//     executable by their owner (the container's root) alone. Root
//     never notices; a non-root container user ([podman] user) cannot
//     even exec /bin/bash. Parent directories a tar omits entries for
//     (created implicitly on the way to a file) get 0755, the mode
//     extraction attempted for them.
//   - The rootfs root takes the image's declared root mode (rootMode,
//     zero when the image declares none), defaulting to 0755. This is
//     the same defect in concentrated form: Create pre-creates the
//     directory at 0700 and MkdirAll never widens an existing
//     directory. The enclosing sandbox state dir stays 0700 — it
//     holds spec.json — but the rootfs is the container's /, and a
//     0700 root owned by the host user is untraversable by a non-root
//     container user.
//   - /run is the provider's runtime scratch: the output wrapper
//     writes /run/esf-exit there as the executing user (decision D5),
//     which need not be root. Stock images ship it root-owned 0755, so
//     extraction leaves it sticky world-writable (1777, the /tmp
//     convention), creating it when the image omits it — the
//     wrapper's own mkdir -p /run would otherwise need a writable /.
//     A /run the image plants as a symlink or file is left untouched.
func finishRootfs(dest string, rootMode os.FileMode, declared map[string]os.FileMode, targets []string) error {
	modes := make(map[string]os.FileMode, len(declared))
	for path, mode := range declared {
		modes[path] = mode
	}
	// Implicit parents: directories extraction created on the way to
	// an entry without a declared mode of their own.
	for _, target := range targets {
		for dir := filepath.Dir(target); dir != dest && strings.HasPrefix(dir, dest+string(os.PathSeparator)); dir = filepath.Dir(dir) {
			if _, ok := modes[dir]; !ok {
				modes[dir] = 0o755
			}
		}
	}
	for path, mode := range modes {
		// Never chmod through a symlink: a later entry may have
		// replaced the path with one, and following it could land
		// the chmod outside the rootfs.
		if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("set rootfs permissions on %s: %w", path, err)
		}
	}
	if rootMode == 0 {
		rootMode = 0o755
	}
	if err := os.Chmod(dest, rootMode); err != nil {
		return fmt.Errorf("set rootfs root permissions: %w", err)
	}
	runDir := filepath.Join(dest, "run")
	fi, err := os.Lstat(runDir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(runDir, runDirMode); err != nil {
			return fmt.Errorf("create rootfs /run: %w", err)
		}
	case err != nil:
		return fmt.Errorf("stat rootfs /run: %w", err)
	case !fi.IsDir():
		// Planted by the image as a symlink or file: not ours to widen.
		return nil
	}
	if err := os.Chmod(runDir, runDirMode); err != nil {
		return fmt.Errorf("set rootfs /run permissions: %w", err)
	}
	return nil
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
