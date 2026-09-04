use crate::finding::Finding;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const WATCHLIST: &[&str] =
    &["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab", "/etc/hosts"];

/// Checks a fixed watchlist of sensitive files for the world-writable bit.
/// Getting a file's mode via `stat` only needs traversal (execute)
/// permission on its parent directories, not read permission on the file
/// itself — so this works even for root-only files like `/etc/shadow`
/// without needing privilege.
pub fn audit() -> Vec<Finding> {
    WATCHLIST.iter().filter_map(|path| check_file(Path::new(path))).collect()
}

fn check_file(path: &Path) -> Option<Finding> {
    let metadata = fs::metadata(path).ok()?;
    let mode = metadata.permissions().mode();
    Some(if mode & 0o002 != 0 {
        Finding::fail("File permissions", format!("{} is world-writable", path.display()))
    } else {
        Finding::pass("File permissions", format!("{} is not world-writable", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(label: &str, mode: u32) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "hardhat-test-{}-{}-{}",
            label,
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::write(&path, b"content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn flags_world_writable_file() {
        let path = temp_file("world-writable", 0o666);
        let finding = check_file(&path).unwrap();
        assert_eq!(finding.severity, Severity::Fail);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn passes_non_world_writable_file() {
        let path = temp_file("locked-down", 0o644);
        let finding = check_file(&path).unwrap();
        assert_eq!(finding.severity, Severity::Pass);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_file_produces_no_finding() {
        assert!(check_file(Path::new("/nonexistent/path/for/hardhat/tests")).is_none());
    }
}
