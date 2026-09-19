// HumptyDumpty — static malware triage
//
// Cracks a sample open into the first-pass facts an analyst reaches for, without
// ever running it: file hashes (md5/sha256), imphash, PE/ELF identification,
// per-section entropy (flags packing), suspicious API imports, and carved IOCs
// (URLs, IPs, domains, emails, registry keys) from ASCII + wide strings.
//
// Static only, by design — dynamic behaviour is a job for a human watching a
// detonation, not an automated pass. Pairs with FluShot: decrypt a sample in
// your VM, then point HumptyDumpty at it.
//
// Output follows the rusty-tools convention: prefixed lines so it reads well on
// a raw terminal and through the dashboard's stdout stream.

mod triage;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use triage::{ascii_strings, carve_iocs, entropy, file_hashes, identify, suspicious_imports, wide_strings};

const HIGH_ENTROPY: f64 = 7.2;
const MIN_STR: usize = 5;
const MAX_IOC_PER_KIND: usize = 40;
const MAX_STRINGS: usize = 25;

#[derive(Parser)]
#[command(
    name = "HumptyDumpty",
    about = "Static malware triage — cracks a sample open into hashes, PE facts, entropy, IOCs and suspicious imports. Never runs it."
)]
struct Cli {
    /// File(s) to triage.
    #[arg(required = true, value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Also print notable (keyword-matched) strings, not just carved IOCs.
    #[arg(long)]
    strings: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut failed = false;
    for (i, path) in cli.files.iter().enumerate() {
        if i > 0 {
            println!();
        }
        if !triage_one(path, cli.strings) {
            failed = true;
        }
    }
    if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
}

fn triage_one(path: &Path, show_strings: bool) -> bool {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            println!("FAIL   {}: {e}", path.display());
            return false;
        }
    };

    println!("FILE   {} ({} bytes)", path.display(), data.len());

    let (md5, sha256) = file_hashes(&data);
    println!("HASH   md5={md5}");
    println!("HASH   sha256={sha256}");

    let overall = entropy(&data);
    let note = if overall >= HIGH_ENTROPY { "  (high — packed/encrypted?)" } else { "" };
    println!("INFO   entropy {overall:.2}/8.00{note}");

    if let Some(info) = identify(&data) {
        let mut line = format!("FILE   {} | {}", info.format, info.arch);
        if let Some(sub) = &info.subsystem {
            line.push_str(&format!(" | {sub}"));
        }
        if let Some(ts) = info.timestamp {
            line.push_str(&format!(" | compiled {}", format_timestamp(ts)));
        }
        println!("{line}");

        if let Some(ih) = &info.imphash {
            println!("HASH   imphash={ih}");
        }

        for s in &info.sections {
            let flag = if s.entropy >= HIGH_ENTROPY { "  <-- high" } else { "" };
            println!("SECTION {:<8} size={:<8} entropy={:.2}{}", s.name, s.size, s.entropy, flag);
            if s.entropy >= HIGH_ENTROPY {
                println!("ALERT  section {} entropy {:.2} — likely packed/encrypted", s.name, s.entropy);
            }
        }

        let susp = suspicious_imports(&info.imports);
        if info.imports.is_empty() {
            println!("INFO   no imports (statically linked or packed?)");
        } else {
            println!("INFO   {} imports, {} flagged suspicious", info.imports.len(), susp.len());
        }
        for (name, category) in &susp {
            println!("IMPORT {name}  ({category})");
        }
        if susp.len() >= 4 {
            println!("ALERT  {} suspicious imports — capability-rich binary", susp.len());
        }
    } else {
        println!("INFO   not a recognized executable (PE/ELF/Mach-O) — hashing + strings only");
    }

    let mut strings = ascii_strings(&data, MIN_STR);
    strings.extend(wide_strings(&data, MIN_STR));
    let iocs = carve_iocs(&strings);
    print_iocs("url", &iocs.urls);
    print_iocs("ip", &iocs.ips);
    print_iocs("domain", &iocs.domains);
    print_iocs("email", &iocs.emails);
    print_iocs("regkey", &iocs.regkeys);
    let total = iocs.urls.len() + iocs.ips.len() + iocs.domains.len() + iocs.emails.len() + iocs.regkeys.len();
    println!("INFO   {} strings, {total} IOCs carved", strings.len());

    if show_strings {
        for s in notable_strings(&strings) {
            println!("STRING {s}");
        }
    }

    true
}

fn print_iocs(kind: &str, items: &[String]) {
    for item in items.iter().take(MAX_IOC_PER_KIND) {
        println!("IOC    {kind}={item}");
    }
    if items.len() > MAX_IOC_PER_KIND {
        println!("INFO   ...{} more {kind} IOCs omitted", items.len() - MAX_IOC_PER_KIND);
    }
}

const KEYWORDS: &[&str] = &[
    "http", "ftp", "cmd.exe", "powershell", "rundll32", "regsvr32", "schtasks", "hkey", "hklm",
    "hkcu", "createobject", "wscript", "cscript", "base64", "virtualalloc", "bitsadmin",
    "certutil", "mozilla/", "user-agent", "-enc", "-nop", ".onion", "appdata", "temp\\",
];

fn notable_strings(strings: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for s in strings {
        let lower = s.to_ascii_lowercase();
        if KEYWORDS.iter().any(|k| lower.contains(k)) && seen.insert(lower.clone()) {
            out.push(s.trim().to_string());
            if out.len() >= MAX_STRINGS {
                break;
            }
        }
    }
    out
}

/// Format a PE COFF timestamp (unix seconds) as UTC. 0 / 0xffffffff are
/// meaningless placeholders. Civil-from-days keeps this dependency-free.
fn format_timestamp(ts: u32) -> String {
    if ts == 0 || ts == 0xffff_ffff {
        return format!("{ts} (placeholder)");
    }
    let secs = ts as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    let stamp = format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC");
    if (1990..=2100).contains(&y) {
        stamp
    } else {
        format!("{stamp} (implausible — likely a reproducible-build hash, not a real timestamp)")
    }
}

/// Howard Hinnant's civil_from_days: days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z_in: i64) -> (i64, u32, u32) {
    let z = z_in + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
