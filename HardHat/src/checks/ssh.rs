use crate::finding::Finding;
use std::collections::HashMap;

/// Parses `Key Value` lines from sshd_config-style text (case-insensitive
/// keys, `#`-comments and blank lines ignored), keeping only the *first*
/// occurrence of each key — matching OpenSSH's own "first match wins"
/// parsing. That's also why an `Include`-d override file is expected to
/// come *before* the rest of the main config in the combined text this
/// module is given (see `main.rs::read_sshd_config`): OpenSSH's default
/// layout puts the `Include` line near the top specifically so per-package
/// overrides win.
fn parse_directives(contents: &str) -> HashMap<String, String> {
    let mut directives = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        directives.entry(key.to_ascii_lowercase()).or_insert_with(|| value.trim().to_string());
    }
    directives
}

pub fn audit(contents: &str) -> Vec<Finding> {
    let directives = parse_directives(contents);
    let get = |key: &str| directives.get(key).map(String::as_str);
    let mut findings = Vec::new();

    match get("permitrootlogin") {
        Some(v) if v.eq_ignore_ascii_case("yes") => findings.push(Finding::fail(
            "PermitRootLogin",
            "set to 'yes' — root can log in over SSH",
        )),
        Some(v) => findings.push(Finding::pass("PermitRootLogin", format!("set to '{}'", v))),
        None => findings.push(Finding::pass(
            "PermitRootLogin",
            "unset (OpenSSH default: prohibit-password)",
        )),
    }

    match get("passwordauthentication") {
        Some(v) if v.eq_ignore_ascii_case("no") => findings.push(Finding::pass(
            "PasswordAuthentication",
            "set to 'no' — key-based auth only",
        )),
        Some(v) => findings.push(Finding::warn(
            "PasswordAuthentication",
            format!("set to '{}' — consider key-based auth only", v),
        )),
        None => findings.push(Finding::warn(
            "PasswordAuthentication",
            "unset (OpenSSH default: yes) — consider key-based auth only",
        )),
    }

    match get("permitemptypasswords") {
        Some(v) if v.eq_ignore_ascii_case("yes") => findings.push(Finding::fail(
            "PermitEmptyPasswords",
            "set to 'yes' — accounts with no password can log in",
        )),
        Some(v) => findings.push(Finding::pass("PermitEmptyPasswords", format!("set to '{}'", v))),
        None => findings.push(Finding::pass("PermitEmptyPasswords", "unset (OpenSSH default: no)")),
    }

    match get("x11forwarding") {
        Some(v) if v.eq_ignore_ascii_case("yes") => findings.push(Finding::warn(
            "X11Forwarding",
            "set to 'yes' — larger attack surface if not needed",
        )),
        Some(v) => findings.push(Finding::pass("X11Forwarding", format!("set to '{}'", v))),
        None => findings.push(Finding::pass("X11Forwarding", "unset (OpenSSH default: no)")),
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn severity_for(findings: &[Finding], check: &str) -> Severity {
        findings.iter().find(|f| f.check == check).unwrap().severity
    }

    #[test]
    fn flags_permit_root_login_yes() {
        let findings = audit("PermitRootLogin yes\n");
        assert_eq!(severity_for(&findings, "PermitRootLogin"), Severity::Fail);
    }

    #[test]
    fn passes_permit_root_login_prohibit_password() {
        let findings = audit("PermitRootLogin prohibit-password\n");
        assert_eq!(severity_for(&findings, "PermitRootLogin"), Severity::Pass);
    }

    #[test]
    fn warns_password_authentication_yes_or_unset() {
        assert_eq!(
            severity_for(&audit("PasswordAuthentication yes\n"), "PasswordAuthentication"),
            Severity::Warn
        );
        assert_eq!(severity_for(&audit(""), "PasswordAuthentication"), Severity::Warn);
    }

    #[test]
    fn passes_password_authentication_no() {
        let findings = audit("PasswordAuthentication no\n");
        assert_eq!(severity_for(&findings, "PasswordAuthentication"), Severity::Pass);
    }

    #[test]
    fn flags_permit_empty_passwords_yes() {
        let findings = audit("PermitEmptyPasswords yes\n");
        assert_eq!(severity_for(&findings, "PermitEmptyPasswords"), Severity::Fail);
    }

    #[test]
    fn flags_x11_forwarding_yes() {
        let findings = audit("X11Forwarding yes\n");
        assert_eq!(severity_for(&findings, "X11Forwarding"), Severity::Warn);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let findings = audit("# PermitRootLogin yes\n\nX11Forwarding no\n");
        assert_eq!(severity_for(&findings, "PermitRootLogin"), Severity::Pass);
        assert_eq!(severity_for(&findings, "X11Forwarding"), Severity::Pass);
    }

    #[test]
    fn first_occurrence_wins() {
        let findings = audit("PermitRootLogin no\nPermitRootLogin yes\n");
        assert_eq!(severity_for(&findings, "PermitRootLogin"), Severity::Pass);
    }
}
