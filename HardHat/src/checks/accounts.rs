use crate::finding::Finding;

/// Flags any `/etc/passwd` entry with UID 0 other than `root` itself — a
/// classic backdoor-account signal.
pub fn audit_passwd(contents: &str) -> Vec<Finding> {
    let mut extra_root_accounts = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        let (Some(&name), Some(&uid)) = (fields.first(), fields.get(2)) else {
            continue;
        };
        if uid == "0" && name != "root" {
            extra_root_accounts.push(name.to_string());
        }
    }

    if extra_root_accounts.is_empty() {
        vec![Finding::pass("UID 0 accounts", "only 'root' has UID 0")]
    } else {
        extra_root_accounts
            .into_iter()
            .map(|name| Finding::fail("UID 0 accounts", format!("'{}' has UID 0 but isn't 'root'", name)))
            .collect()
    }
}

/// Flags any `/etc/shadow` entry with an empty password field — meaning no
/// password is required to log in as that account at all. A field of `!`,
/// `*`, or `!*` means password login is *disabled*, which is safe; only a
/// truly empty field is the risk.
pub fn audit_shadow(contents: &str) -> Vec<Finding> {
    let mut empty_password_accounts = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(name), Some(password)) = (fields.next(), fields.next()) else {
            continue;
        };
        if password.is_empty() {
            empty_password_accounts.push(name.to_string());
        }
    }

    if empty_password_accounts.is_empty() {
        vec![Finding::pass("Empty passwords", "no accounts with an empty password field")]
    } else {
        empty_password_accounts
            .into_iter()
            .map(|name| {
                Finding::fail(
                    "Empty passwords",
                    format!("'{}' has an empty password field — no password required to log in", name),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn passes_when_only_root_has_uid_zero() {
        let findings = audit_passwd("root:x:0:0:root:/root:/bin/bash\nsig:x:1000:1000::/home/sig:/bin/bash\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
    }

    #[test]
    fn flags_non_root_uid_zero_account() {
        let findings = audit_passwd("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Fail);
        assert!(findings[0].detail.contains("backdoor"));
    }

    #[test]
    fn passes_when_no_empty_shadow_passwords() {
        let findings = audit_shadow("root:$6$hash:19000:0:99999:7:::\nsig:!:19000:0:99999:7:::\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
    }

    #[test]
    fn flags_empty_shadow_password() {
        let findings = audit_shadow("guest::19000:0:99999:7:::\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Fail);
        assert!(findings[0].detail.contains("guest"));
    }
}
