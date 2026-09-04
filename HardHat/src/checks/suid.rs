use crate::finding::Finding;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const SCAN_DIRS: &[&str] = &["/usr/bin", "/usr/sbin"];

/// Common, expected setuid binaries. Anything else found isn't necessarily
/// a problem, but an atypical setuid binary is a classic
/// privilege-escalation hunting signal worth a human look.
const ALLOWLIST: &[&str] =
    &["passwd", "sudo", "su", "mount", "umount", "ping", "chsh", "chfn", "gpasswd", "chage", "unix_chkpwd", "newgrp"];

pub fn audit() -> Vec<Finding> {
    // Canonicalize first and dedupe — on Arch (and other merged-/usr
    // distros), /usr/sbin is just a symlink to /usr/bin, so scanning both
    // by name would otherwise double-report every match.
    let mut canonical_dirs: Vec<PathBuf> =
        SCAN_DIRS.iter().filter_map(|dir| fs::canonicalize(dir).ok()).collect();
    canonical_dirs.sort();
    canonical_dirs.dedup();

    let mut unexpected = BTreeSet::new();
    for dir in &canonical_dirs {
        for name in setuid_files_in(dir) {
            if !ALLOWLIST.contains(&name.as_str()) {
                unexpected.insert(name);
            }
        }
    }

    if unexpected.is_empty() {
        vec![Finding::pass("SUID binaries", "no unexpected setuid binaries found")]
    } else {
        unexpected
            .into_iter()
            .map(|name| Finding::warn("SUID binaries", format!("unexpected setuid binary: {}", name)))
            .collect()
    }
}

/// Lists the (non-recursive) filenames in `dir` that have the setuid bit
/// set. Doesn't follow symlinks — `DirEntry::metadata` reports the
/// symlink's own type, so a symlinked binary is simply skipped rather than
/// resolved.
fn setuid_files_in(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if metadata.is_file() && metadata.permissions().mode() & 0o4000 != 0 {
                entry.file_name().to_str().map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "hardhat-test-{}-{}-{}",
                label,
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn finds_setuid_file() {
        let dir = TempDir::new("suid-found");
        let path = dir.0.join("mystery-binary");
        fs::write(&path, b"not a real binary").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();

        let found = setuid_files_in(&dir.0);
        assert_eq!(found, vec!["mystery-binary".to_string()]);
    }

    #[test]
    fn ignores_non_setuid_file() {
        let dir = TempDir::new("suid-ignored");
        let path = dir.0.join("plain-file");
        fs::write(&path, b"nothing special").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(setuid_files_in(&dir.0).is_empty());
    }
}
