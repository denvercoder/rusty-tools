use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileRecord {
    pub hash: String,
    pub size: u64,
}

/// Relative path (forward-slash separated, relative to the scanned root) ->
/// content record. `BTreeMap` for deterministic ordering, both in the
/// baseline JSON and in diff output.
pub type Snapshot = BTreeMap<String, FileRecord>;

/// Walks `root` and hashes every regular file under it. Symlinks are
/// skipped (avoids following cycles or links outside the tree), and any
/// directory literally named `.git` is skipped (its object store churns
/// constantly and isn't meaningful integrity signal for this tool).
///
/// A restricted subdirectory or file (e.g. `/etc/sudoers.d/`, unreadable to
/// a non-root user) is skipped with a printed warning rather than aborting
/// the whole scan — one inaccessible corner of the tree shouldn't stop
/// everything else in it from being baselined/checked.
pub fn scan(root: &Path) -> Snapshot {
    let mut snapshot = Snapshot::new();
    walk(root, root, &mut snapshot);
    snapshot
}

fn walk(root: &Path, dir: &Path, out: &mut Snapshot) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("Skipping {}: {}", dir.display(), err);
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("Skipping an entry in {}: {}", dir.display(), err);
                continue;
            }
        };
        let path = entry.path();

        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                eprintln!("Skipping {}: {}", path.display(), err);
                continue;
            }
        };

        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            if entry.file_name() == ".git" {
                continue;
            }
            walk(root, &path, out);
        } else if file_type.is_file() {
            match hash_file(&path) {
                Ok(hash) => {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.insert(rel, FileRecord { hash, size });
                }
                Err(err) => eprintln!("Skipping {}: {}", path.display(), err),
            }
        }
    }
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// Creates a unique scratch directory under the system temp dir, scoped
    /// to this test process, and removes it on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "feefifofim-test-{}-{}-{}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
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
    fn hash_matches_known_sha256_vector() {
        let dir = TempDir::new("hash-vector");
        let file_path = dir.0.join("greeting.txt");
        fs::write(&file_path, b"hello").unwrap();

        assert_eq!(
            hash_file(&file_path).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn scan_excludes_git_dirs_and_symlinks() {
        let dir = TempDir::new("scan-exclusions");
        fs::write(dir.0.join("real.txt"), b"kept").unwrap();

        let git_dir = dir.0.join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join("object"), b"should be skipped").unwrap();

        symlink(dir.0.join("real.txt"), dir.0.join("link.txt")).unwrap();

        let snapshot = scan(&dir.0);
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key("real.txt"));
    }

    #[test]
    fn scan_walks_nested_directories() {
        let dir = TempDir::new("scan-nested");
        let nested = dir.0.join("a/b");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("deep.txt"), b"nested content").unwrap();

        let snapshot = scan(&dir.0);
        assert!(snapshot.contains_key("a/b/deep.txt"));
    }

    #[test]
    fn unreadable_subdirectory_is_skipped_not_fatal() {
        let dir = TempDir::new("scan-unreadable");
        fs::write(dir.0.join("visible.txt"), b"kept").unwrap();

        let locked = dir.0.join("locked");
        fs::create_dir_all(&locked).unwrap();
        fs::write(locked.join("secret.txt"), b"hidden").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let snapshot = scan(&dir.0);

        // Restore permissions so TempDir's Drop can actually remove it.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(snapshot.contains_key("visible.txt"));
        assert!(!snapshot.keys().any(|k| k.starts_with("locked/")));
    }
}
