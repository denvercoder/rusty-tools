/// A parsed sshd auth-facility log line. Only the two shapes Bunyan cares
/// about are represented — banner exchanges, session teardown, preauth
/// disconnects, etc. all fall through `parse_sshd` as `None` and are
/// silently skipped by the caller.
pub enum SshEvent {
    Failed { user: String, invalid_user: bool, source_ip: String },
    Accepted { method: String, user: String, source_ip: String },
}

/// Parses an sshd `MESSAGE`. Recognizes:
///   "Failed password for [invalid user ]USER from IP port N ssh2"
///   "Accepted METHOD for USER from IP port N ssh2"
pub fn parse_sshd(message: &str) -> Option<SshEvent> {
    if let Some(rest) = message.strip_prefix("Failed password for ") {
        let (invalid_user, rest) = match rest.strip_prefix("invalid user ") {
            Some(rest) => (true, rest),
            None => (false, rest),
        };
        let (user, rest) = rest.split_once(" from ")?;
        let source_ip = rest.split(' ').next()?;
        return Some(SshEvent::Failed {
            user: user.to_string(),
            invalid_user,
            source_ip: source_ip.to_string(),
        });
    }

    if let Some(rest) = message.strip_prefix("Accepted ") {
        let (method, rest) = rest.split_once(" for ")?;
        let (user, rest) = rest.split_once(" from ")?;
        let source_ip = rest.split(' ').next()?;
        return Some(SshEvent::Accepted {
            method: method.to_string(),
            user: user.to_string(),
            source_ip: source_ip.to_string(),
        });
    }

    None
}

/// A parsed sudo auth-facility log line.
pub enum SudoEvent {
    Command { invoking_user: String, target_user: String, command: String },
    AuthFailure { user: String },
}

/// Parses a sudo `MESSAGE`. Recognizes:
///   "  alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/whoami"
///   (sudo left-pads the invoking user with spaces)
///   "pam_unix(sudo:auth): authentication failure; ... ruser=alice  user=alice"
pub fn parse_sudo(message: &str) -> Option<SudoEvent> {
    if message.trim_start().starts_with("pam_unix(sudo:auth): authentication failure") {
        // Split on " user=" (leading space) specifically — "ruser=" also
        // contains the substring "user=", and would otherwise be matched
        // first.
        let user = message.split(" user=").nth(1)?.split_whitespace().next()?;
        return Some(SudoEvent::AuthFailure { user: user.to_string() });
    }

    let (invoking_user, rest) = message.trim_start().split_once(" : ")?;
    let command = rest.split("COMMAND=").nth(1)?;
    let target_user = rest
        .split("USER=")
        .nth(1)?
        .split(|c: char| c == ' ' || c == ';')
        .next()?;

    Some(SudoEvent::Command {
        invoking_user: invoking_user.trim().to_string(),
        target_user: target_user.to_string(),
        command: command.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_password_for_known_user() {
        let msg = "Failed password for root from 203.0.113.5 port 51234 ssh2";
        match parse_sshd(msg) {
            Some(SshEvent::Failed { user, invalid_user, source_ip }) => {
                assert_eq!(user, "root");
                assert!(!invalid_user);
                assert_eq!(source_ip, "203.0.113.5");
            }
            _ => panic!("expected a Failed event"),
        }
    }

    #[test]
    fn parses_failed_password_for_invalid_user() {
        let msg = "Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2";
        match parse_sshd(msg) {
            Some(SshEvent::Failed { user, invalid_user, .. }) => {
                assert_eq!(user, "admin");
                assert!(invalid_user);
            }
            _ => panic!("expected a Failed event"),
        }
    }

    #[test]
    fn parses_accepted_login() {
        let msg = "Accepted publickey for sig from 192.168.1.20 port 51234 ssh2: RSA SHA256:abcd";
        match parse_sshd(msg) {
            Some(SshEvent::Accepted { method, user, source_ip }) => {
                assert_eq!(method, "publickey");
                assert_eq!(user, "sig");
                assert_eq!(source_ip, "192.168.1.20");
            }
            _ => panic!("expected an Accepted event"),
        }
    }

    #[test]
    fn ignores_unrelated_sshd_lines() {
        assert!(parse_sshd("Connection closed by 192.168.1.20 port 51234 [preauth]").is_none());
    }

    // Real line captured from this machine's own journal during development.
    #[test]
    fn parses_real_sudo_command_line() {
        let msg = "     sig : TTY=pts/1 ; PWD=/home/sig/RustroverProjects/Rusty Tools ; USER=root ; COMMAND=/usr/bin/setcap cap_net_raw+ep target/release/PickAPeckOfPacketParsers";
        match parse_sudo(msg) {
            Some(SudoEvent::Command { invoking_user, target_user, command }) => {
                assert_eq!(invoking_user, "sig");
                assert_eq!(target_user, "root");
                assert_eq!(command, "/usr/bin/setcap cap_net_raw+ep target/release/PickAPeckOfPacketParsers");
            }
            _ => panic!("expected a Command event"),
        }
    }

    #[test]
    fn parses_sudo_auth_failure_and_ignores_embedded_ruser() {
        let msg = "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/1 ruser=mallory rhost=  user=alice";
        match parse_sudo(msg) {
            Some(SudoEvent::AuthFailure { user }) => assert_eq!(user, "alice"),
            _ => panic!("expected an AuthFailure event"),
        }
    }

    #[test]
    fn ignores_sudo_session_lines() {
        assert!(parse_sudo("pam_unix(sudo:session): session opened for user root(uid=0) by sig(uid=1000)").is_none());
    }
}
