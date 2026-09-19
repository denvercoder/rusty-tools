//! Static triage primitives: hashing, entropy, executable identification,
//! string extraction, IOC carving, and suspicious-import matching. Nothing here
//! runs the sample — it only reads bytes.

use sha2::{Digest, Sha256};
use md5::Md5;

/// Lowercase hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// (md5, sha256) of the whole file.
pub fn file_hashes(data: &[u8]) -> (String, String) {
    (hex(Md5::digest(data).as_slice()), hex(Sha256::digest(data).as_slice()))
}

/// Shannon entropy in bits/byte (0.0 – 8.0). High values (~7.2+) suggest
/// compression, encryption, or packing.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut e = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            e -= p * p.log2();
        }
    }
    e
}

pub struct Section {
    pub name: String,
    pub size: usize,
    pub entropy: f64,
}

#[derive(Default)]
pub struct ExeInfo {
    pub format: String,
    pub arch: String,
    pub subsystem: Option<String>,
    pub timestamp: Option<u32>,
    pub imphash: Option<String>,
    pub sections: Vec<Section>,
    pub imports: Vec<String>,
}

/// Identify the executable format and pull out sections + imports. Returns
/// `None` for anything that isn't a recognized executable (still hashable /
/// stringable by the caller).
pub fn identify(data: &[u8]) -> Option<ExeInfo> {
    match goblin::Object::parse(data).ok()? {
        goblin::Object::PE(pe) => Some(identify_pe(data, &pe)),
        goblin::Object::Elf(elf) => Some(ExeInfo {
            format: if elf.is_lib { "ELF shared object".into() } else { "ELF executable".into() },
            arch: elf_machine(elf.header.e_machine),
            ..Default::default()
        }),
        goblin::Object::Mach(_) => Some(ExeInfo { format: "Mach-O".into(), ..Default::default() }),
        _ => None,
    }
}

fn identify_pe(data: &[u8], pe: &goblin::pe::PE) -> ExeInfo {
    let mut sections = Vec::new();
    for section in &pe.sections {
        let name = section.name().unwrap_or("?").to_string();
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let slice = data.get(start..start.saturating_add(size)).unwrap_or(&[]);
        sections.push(Section { name, size, entropy: entropy(slice) });
    }

    let imports: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();

    let subsystem = pe.header.optional_header.map(|opt| match opt.windows_fields.subsystem {
        1 => "native".to_string(),
        2 => "GUI".to_string(),
        3 => "console".to_string(),
        9 => "Windows CE GUI".to_string(),
        other => format!("subsystem {other}"),
    });

    ExeInfo {
        format: if pe.is_lib { "PE (DLL)".into() } else { "PE (EXE)".into() },
        arch: pe_machine(pe.header.coff_header.machine),
        subsystem,
        timestamp: Some(pe.header.coff_header.time_date_stamp),
        imphash: imphash(pe),
        sections,
        imports,
    }
}

/// Standard imphash: for each import in order, `libname.funcname` (lowercased,
/// DLL extension stripped; ordinal imports as `ordN`), joined with `,`, md5'd.
fn imphash(pe: &goblin::pe::PE) -> Option<String> {
    if pe.imports.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for imp in &pe.imports {
        let mut lib = imp.dll.to_ascii_lowercase();
        for ext in [".dll", ".ocx", ".sys"] {
            if let Some(stripped) = lib.strip_suffix(ext) {
                lib = stripped.to_string();
                break;
            }
        }
        let func = if imp.name.is_empty() {
            format!("ord{}", imp.ordinal)
        } else {
            imp.name.to_ascii_lowercase()
        };
        parts.push(format!("{lib}.{func}"));
    }
    Some(hex(Md5::digest(parts.join(",").as_bytes()).as_slice()))
}

fn pe_machine(m: u16) -> String {
    match m {
        0x014c => "x86 (i386)".into(),
        0x8664 => "x86-64".into(),
        0x01c0 | 0x01c4 => "ARM".into(),
        0xaa64 => "ARM64".into(),
        0x0200 => "IA-64".into(),
        other => format!("machine 0x{other:04x}"),
    }
}

fn elf_machine(m: u16) -> String {
    match m {
        3 => "x86 (i386)".into(),
        62 => "x86-64".into(),
        40 => "ARM".into(),
        183 => "ARM64".into(),
        other => format!("e_machine {other}"),
    }
}

/// Printable-ASCII strings of at least `min` chars.
pub fn ascii_strings(data: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min {
                out.push(String::from_utf8_lossy(&cur).into_owned());
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        out.push(String::from_utf8_lossy(&cur).into_owned());
    }
    out
}

/// UTF-16LE ("wide") strings of at least `min` chars — a common malware tell.
pub fn wide_strings(data: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let (lo, hi) = (data[i], data[i + 1]);
        if hi == 0 && (0x20..0x7f).contains(&lo) {
            cur.push(lo as char);
            i += 2;
        } else {
            if cur.len() >= min {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
            i += 1;
        }
    }
    if cur.len() >= min {
        out.push(cur);
    }
    out
}

#[derive(Default)]
pub struct Iocs {
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub emails: Vec<String>,
    pub regkeys: Vec<String>,
}

/// Carve indicators of compromise out of a set of already-extracted strings.
pub fn carve_iocs(strings: &[String]) -> Iocs {
    use regex::Regex;
    let url = Regex::new(r#"(?i)\bhttps?://[^\s"'<>\\)\]}]+"#).unwrap();
    let ipv4 = Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap();
    let email = Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap();
    let regkey = Regex::new(r#"(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s"'<>]+"#).unwrap();
    let domain = Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap();

    // TLDs we accept for bare domains, to keep file-name noise (kernel32.dll,
    // foo.exe, bar.dat, ...) out of the domain bucket.
    const TLDS: &[&str] = &[
        "com", "net", "org", "io", "co", "ru", "cn", "info", "biz", "xyz", "top", "online",
        "site", "club", "shop", "app", "dev", "gov", "edu", "uk", "de", "fr", "nl", "br",
        "in", "ir", "kr", "jp", "pl", "ua", "tk", "ml", "ga", "cf", "su", "me", "cc", "pw",
        "onion", "live", "space", "fun", "icu", "vip", "work", "world",
    ];

    let mut iocs = Iocs::default();
    for s in strings {
        for m in url.find_iter(s) {
            iocs.urls.push(m.as_str().to_string());
        }
        for m in ipv4.find_iter(s) {
            iocs.ips.push(m.as_str().to_string());
        }
        for m in email.find_iter(s) {
            iocs.emails.push(m.as_str().to_string());
        }
        for m in regkey.find_iter(s) {
            iocs.regkeys.push(m.as_str().to_string());
        }
        for m in domain.find_iter(s) {
            let d = m.as_str();
            if let Some(tld) = d.rsplit('.').next() {
                if TLDS.contains(&tld.to_ascii_lowercase().as_str()) {
                    iocs.domains.push(d.to_string());
                }
            }
        }
    }

    dedup(&mut iocs.urls);
    dedup(&mut iocs.ips);
    dedup(&mut iocs.emails);
    dedup(&mut iocs.regkeys);
    dedup(&mut iocs.domains);
    // Drop version-string false positives like "5.1.0.0" / "6.0.0.0" that the
    // IPv4 pattern also matches (file-version fields in PE manifests, etc.).
    iocs.ips.retain(|ip| {
        let o: Vec<&str> = ip.split('.').collect();
        !(o.len() == 4 && o[2] == "0" && o[3] == "0")
    });
    iocs
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|s| seen.insert(s.to_ascii_lowercase()));
}

/// Suspicious Windows API imports, grouped by intent. Matched by lowercased
/// prefix, so `VirtualAlloc` catches `VirtualAllocEx`, `CreateProcessA/W`, etc.
const SUSPICIOUS_APIS: &[(&str, &str)] = &[
    ("virtualalloc", "memory/injection"),
    ("virtualprotect", "memory/injection"),
    ("writeprocessmemory", "process injection"),
    ("readprocessmemory", "process access"),
    ("createremotethread", "process injection"),
    ("ntunmapviewofsection", "process hollowing"),
    ("queueuserapc", "APC injection"),
    ("setwindowshookex", "hooking/keylog"),
    ("getasynckeystate", "keylogging"),
    ("getkeystate", "keylogging"),
    ("winexec", "execution"),
    ("shellexecute", "execution"),
    ("createprocess", "execution"),
    ("urldownloadtofile", "download"),
    ("internetopen", "network"),
    ("internetreadfile", "network"),
    ("winhttp", "network"),
    ("httpsendrequest", "network"),
    ("wsastartup", "network"),
    ("connect", "network"),
    ("regsetvalue", "persistence/registry"),
    ("regcreatekey", "persistence/registry"),
    ("createservice", "persistence/service"),
    ("isdebuggerpresent", "anti-analysis"),
    ("checkremotedebuggerpresent", "anti-analysis"),
    ("ntqueryinformationprocess", "anti-analysis"),
    ("gettickcount", "anti-analysis/timing"),
    ("cryptencrypt", "crypto"),
    ("cryptacquirecontext", "crypto"),
    ("cryptstringtobinary", "crypto/encoding"),
    ("adjusttokenprivileges", "privilege"),
    ("openprocesstoken", "privilege"),
    ("loadlibrary", "dynamic loading"),
    ("getprocaddress", "dynamic loading"),
];

/// Return `(import_name, category)` for imports that match the suspicious list.
pub fn suspicious_imports(imports: &[String]) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for imp in imports {
        let lower = imp.to_ascii_lowercase();
        for (needle, category) in SUSPICIOUS_APIS {
            if lower.starts_with(needle) && seen.insert(imp.to_ascii_lowercase()) {
                out.push((imp.clone(), *category));
                break;
            }
        }
    }
    out
}
