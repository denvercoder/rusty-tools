use crate::scan::Snapshot;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum Change {
    Added { path: String, size: u64 },
    Removed { path: String },
    Modified { path: String, old_size: u64, new_size: u64 },
}

impl Change {
    pub fn path(&self) -> &str {
        match self {
            Change::Added { path, .. } => path,
            Change::Removed { path } => path,
            Change::Modified { path, .. } => path,
        }
    }

    /// A stable identity for this change (kind + path), used by `--watch`
    /// mode to tell "already reported" changes from new ones across ticks.
    pub fn key(&self) -> String {
        let kind = match self {
            Change::Added { .. } => "added",
            Change::Removed { .. } => "removed",
            Change::Modified { .. } => "modified",
        };
        format!("{}:{}", kind, self.path())
    }
}

pub fn load(path: &Path) -> io::Result<Snapshot> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub fn save(path: &Path, snapshot: &Snapshot) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let text = serde_json::to_string_pretty(snapshot)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    fs::write(path, text)
}

/// Compares `baseline` against `current`, reporting every file that's new,
/// gone, or whose content hash no longer matches. Unchanged files produce
/// nothing.
pub fn diff(baseline: &Snapshot, current: &Snapshot) -> Vec<Change> {
    let mut changes = Vec::new();

    for (path, record) in current {
        match baseline.get(path) {
            None => changes.push(Change::Added { path: path.clone(), size: record.size }),
            Some(old) if old.hash != record.hash => changes.push(Change::Modified {
                path: path.clone(),
                old_size: old.size,
                new_size: record.size,
            }),
            _ => {}
        }
    }

    for path in baseline.keys() {
        if !current.contains_key(path) {
            changes.push(Change::Removed { path: path.clone() });
        }
    }

    changes.sort_by(|a, b| a.path().cmp(b.path()));
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FileRecord;

    fn record(hash: &str, size: u64) -> FileRecord {
        FileRecord { hash: hash.to_string(), size }
    }

    #[test]
    fn detects_added_removed_modified_and_ignores_unchanged() {
        let mut baseline = Snapshot::new();
        baseline.insert("unchanged.txt".to_string(), record("aaa", 10));
        baseline.insert("modified.txt".to_string(), record("bbb", 20));
        baseline.insert("removed.txt".to_string(), record("ccc", 30));

        let mut current = Snapshot::new();
        current.insert("unchanged.txt".to_string(), record("aaa", 10));
        current.insert("modified.txt".to_string(), record("bbb-changed", 25));
        current.insert("added.txt".to_string(), record("ddd", 5));

        let changes = diff(&baseline, &current);

        assert_eq!(
            changes,
            vec![
                Change::Added { path: "added.txt".to_string(), size: 5 },
                Change::Modified {
                    path: "modified.txt".to_string(),
                    old_size: 20,
                    new_size: 25,
                },
                Change::Removed { path: "removed.txt".to_string() },
            ]
        );
    }

    #[test]
    fn identical_snapshots_produce_no_changes() {
        let mut snapshot = Snapshot::new();
        snapshot.insert("a.txt".to_string(), record("aaa", 1));
        assert_eq!(diff(&snapshot, &snapshot), Vec::new());
    }

    #[test]
    fn change_key_distinguishes_kind_and_path() {
        let added = Change::Added { path: "x.txt".to_string(), size: 1 };
        let removed = Change::Removed { path: "x.txt".to_string() };
        assert_ne!(added.key(), removed.key());
    }
}
