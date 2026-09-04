use crate::finding::Finding;
use std::process::Command;

const FIREWALL_SERVICES: &[&str] = &["ufw", "firewalld", "nftables", "iptables"];

/// Checking whether a firewall service is *active* only needs
/// `systemctl is-active`, which works for any user — unlike inspecting the
/// actual ruleset (`nft list ruleset`, `iptables -L`), which needs root.
/// This check is therefore presence-only: it can tell you a firewall is
/// running, not whether its rules are any good.
pub fn audit() -> Vec<Finding> {
    let active: Vec<&str> =
        FIREWALL_SERVICES.iter().copied().filter(|service| is_active(service)).collect();

    if active.is_empty() {
        vec![Finding::warn(
            "Firewall",
            "no active firewall service found (checked ufw, firewalld, nftables, iptables)",
        )]
    } else {
        vec![Finding::pass("Firewall", format!("active: {}", active.join(", ")))]
    }
}

fn is_active(service: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
