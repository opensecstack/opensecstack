// Virtual filesystem sandbox enforcement.
//
// The allowlist is populated from CapabilityBag::fs_allowlist at session
// start.  Any path access that falls outside the allowlist is denied with
// WASI errno::acces (permission denied) before the request reaches the
// host OS filesystem.
//
// TODO(v1.0.0): Wire the allowlist check into the wasmtime-wasi
// DirPerms / FilePerms layer so that every open() / openat() call
// from guest code goes through allow_path() below.

use std::path::{Component, Path, PathBuf};

/// Returns true if `requested_path` resolves (after lexical normalisation)
/// to a location inside an allowed prefix.
///
/// Lexical normalisation strips `.` and collapses `..` components so that
/// traversal sequences like `/lab/../etc/passwd` are resolved to `/etc/passwd`
/// before the prefix check — the naive `starts_with` approach would allow
/// the traversal because `/lab/../etc/passwd` textually starts with `/lab`.
pub fn allow_path(allowlist: &[PathBuf], requested_path: &Path) -> bool {
    let normalised = normalise(requested_path);
    allowlist
        .iter()
        .any(|allowed| normalised.starts_with(normalise(allowed)))
}

/// Lexically normalise `path` by collapsing `.` and `..` components without
/// touching the filesystem (no `canonicalize` syscall).
fn normalise(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab_allowlist() -> Vec<PathBuf> {
        vec![PathBuf::from("/lab"), PathBuf::from("/scratch")]
    }

    // ── Positive cases (access must be permitted) ─────────────────────

    #[test]
    fn allowed_path_within_lab_dir() {
        assert!(allow_path(
            &lab_allowlist(),
            Path::new("/lab/fixtures/sample.txt")
        ));
    }

    #[test]
    fn allowed_lab_root_itself() {
        assert!(allow_path(&lab_allowlist(), Path::new("/lab")));
    }

    #[test]
    fn allowed_scratch_dir() {
        assert!(allow_path(
            &lab_allowlist(),
            Path::new("/scratch/output.bin")
        ));
    }

    #[test]
    fn allowed_deeply_nested_path() {
        assert!(allow_path(
            &lab_allowlist(),
            Path::new("/lab/a/b/c/d/e/file.txt")
        ));
    }

    // ── Negative cases (access must be denied) ────────────────────────

    #[test]
    fn denied_path_outside_allowlist() {
        assert!(!allow_path(&lab_allowlist(), Path::new("/etc/passwd")));
    }

    #[test]
    fn denied_host_filesystem_root() {
        assert!(!allow_path(&lab_allowlist(), Path::new("/")));
    }

    #[test]
    fn denied_proc_filesystem() {
        assert!(!allow_path(&lab_allowlist(), Path::new("/proc/1/maps")));
    }

    #[test]
    fn denied_host_key_material() {
        assert!(!allow_path(
            &lab_allowlist(),
            Path::new("/root/.ssh/id_ed25519")
        ));
    }

    #[test]
    fn denied_dev_filesystem() {
        assert!(!allow_path(&lab_allowlist(), Path::new("/dev/sda")));
    }

    // ── Path traversal (the critical security cases) ──────────────────

    #[test]
    fn denied_single_dotdot_traversal() {
        // /lab/../etc/passwd normalises to /etc/passwd → denied.
        assert!(!allow_path(
            &lab_allowlist(),
            Path::new("/lab/../etc/passwd")
        ));
    }

    #[test]
    fn denied_deep_traversal_escape() {
        // /lab/a/../../etc/shadow normalises to /etc/shadow → denied.
        assert!(!allow_path(
            &lab_allowlist(),
            Path::new("/lab/a/../../etc/shadow")
        ));
    }

    #[test]
    fn denied_traversal_from_scratch() {
        // /scratch/../etc/passwd normalises to /etc/passwd → denied.
        assert!(!allow_path(
            &lab_allowlist(),
            Path::new("/scratch/../etc/passwd")
        ));
    }

    #[test]
    fn denied_traversal_back_to_root() {
        // Multiple .. components must not escape to /.
        assert!(!allow_path(
            &lab_allowlist(),
            Path::new("/lab/../../../")
        ));
    }

    #[test]
    fn denied_empty_allowlist() {
        assert!(!allow_path(&[], Path::new("/lab/file.txt")));
    }

    #[test]
    fn allowed_path_with_curent_dir_component() {
        // /lab/./subdir/file.txt normalises to /lab/subdir/file.txt → allowed.
        assert!(allow_path(
            &lab_allowlist(),
            Path::new("/lab/./subdir/file.txt")
        ));
    }
}
