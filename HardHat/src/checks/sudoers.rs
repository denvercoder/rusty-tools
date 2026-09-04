use crate::finding::Finding;

/// Flags any line granting passwordless full access. Doesn't attempt to
/// fully parse sudoers grammar (aliases, `Cmnd_Alias`, `%group` rules,
/// etc.) — just looks for the classic, unambiguous `NOPASSWD: ALL` shape,
/// which is the pattern that actually matters for a quick audit like this.
pub fn audit(contents: &str) -> Vec<Finding> {
    let mut matches = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pos) = line.find("NOPASSWD:") {
            let rest = line[pos + "NOPASSWD:".len()..].trim();
            if rest.starts_with("ALL") {
                matches.push(line.to_string());
            }
        }
    }

    if matches.is_empty() {
        vec![Finding::pass("sudoers NOPASSWD", "no 'NOPASSWD: ALL' rules found")]
    } else {
        matches
            .into_iter()
            .map(|line| Finding::warn("sudoers NOPASSWD", format!("passwordless full access: {}", line)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn passes_without_nopasswd_all() {
        let findings = audit("sig ALL=(ALL:ALL) ALL\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
    }

    #[test]
    fn flags_nopasswd_all() {
        let findings = audit("deploy ALL=(ALL) NOPASSWD: ALL\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].detail.contains("deploy"));
    }

    #[test]
    fn ignores_nopasswd_for_a_specific_command() {
        let findings = audit("deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
    }
}
