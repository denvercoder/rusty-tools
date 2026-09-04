mod checks;
mod finding;

use finding::{Finding, Severity};
use std::fs;
use std::io;

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSHD_CONFIG_D: &str = "/etc/ssh/sshd_config.d";
const PASSWD_FILE: &str = "/etc/passwd";
const SHADOW_FILE: &str = "/etc/shadow";
const SUDOERS_FILE: &str = "/etc/sudoers";
const SUDOERS_D: &str = "/etc/sudoers.d";

/// Reads `path`, returning `Ok(None)` specifically for a permission-denied
/// read (expected for root-only files when not running as root) rather
/// than an error — so callers can tell "needs root" (a SKIP finding) apart
/// from any other, unexpected read failure.
fn read_optional(path: &str) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Ok(None),
        Err(err) => Err(err),
    }
}

/// Reads the main sshd_config plus any `sshd_config.d/*.conf` override
/// files, combined so overrides come first — see the precedence note on
/// `checks::ssh::parse_directives`.
fn read_sshd_config() -> String {
    let mut combined = String::new();

    if let Ok(entries) = fs::read_dir(SSHD_CONFIG_D) {
        let mut conf_files: Vec<_> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
            .collect();
        conf_files.sort();
        for path in conf_files {
            if let Ok(text) = fs::read_to_string(&path) {
                combined.push_str(&text);
                combined.push('\n');
            }
        }
    }

    if let Ok(text) = fs::read_to_string(SSHD_CONFIG) {
        combined.push_str(&text);
    }

    combined
}

fn audit_file(path: &str, check_name: &str, audit_fn: impl FnOnce(&str) -> Vec<Finding>) -> Vec<Finding> {
    match read_optional(path) {
        Ok(Some(contents)) => audit_fn(&contents),
        Ok(None) => vec![Finding::skip(check_name, format!("needs root to read {}", path))],
        Err(err) => vec![Finding::skip(check_name, format!("couldn't read {}: {}", path, err))],
    }
}

fn read_sudoers() -> Vec<Finding> {
    let mut combined = String::new();
    let mut readable = false;

    if let Ok(Some(text)) = read_optional(SUDOERS_FILE) {
        readable = true;
        combined.push_str(&text);
        combined.push('\n');
    }

    if let Ok(entries) = fs::read_dir(SUDOERS_D) {
        for entry in entries.flatten() {
            if let Ok(text) = fs::read_to_string(entry.path()) {
                readable = true;
                combined.push_str(&text);
                combined.push('\n');
            }
        }
    }

    if !readable {
        return vec![Finding::skip("sudoers NOPASSWD", format!("needs root to read {}", SUDOERS_FILE))];
    }

    checks::sudoers::audit(&combined)
}

fn main() {
    let mut findings: Vec<Finding> = Vec::new();

    findings.extend(checks::ssh::audit(&read_sshd_config()));
    findings.extend(audit_file(PASSWD_FILE, "UID 0 accounts", checks::accounts::audit_passwd));
    findings.extend(audit_file(SHADOW_FILE, "Empty passwords", checks::accounts::audit_shadow));
    findings.extend(read_sudoers());
    findings.extend(checks::firewall::audit());
    findings.extend(checks::suid::audit());
    findings.extend(checks::permissions::audit());

    let (mut pass, mut warn, mut fail, mut skip) = (0u32, 0u32, 0u32, 0u32);
    for finding in &findings {
        println!("{}", finding);
        match finding.severity {
            Severity::Pass => pass += 1,
            Severity::Warn => warn += 1,
            Severity::Fail => fail += 1,
            Severity::Skip => skip += 1,
        }
    }

    println!("{} passed, {} warnings, {} failed, {} skipped", pass, warn, fail, skip);
}
