// FluShot — encrypted sample vault
//
// Malware analysts can't keep live samples lying around as plaintext: Defender
// (and every other AV) scans files on write and quarantines anything it
// recognizes — often mid-download, before you can do anything with it. FluShot
// sidesteps that by never letting a recognizable byte sit on disk:
//
//   * `fetch <url>`  downloads the sample ITSELF (no browser, so no SmartScreen),
//                    encrypts it in memory, and writes only ciphertext. Plaintext
//                    never touches the disk, and the resulting blob has a novel
//                    hash + noise contents, so neither content nor hash/reputation
//                    scanning has anything to bite.
//   * `stash <file>` encrypts a file you already have.
//   * `open <blob>`  decrypts a blob — run this INSIDE your analysis VM, where AV
//                    is off; that's the only place plaintext should reappear.
//   * `list`         shows what's in the vault.
//
// Encryption is a keyfile-based ChaCha20-Poly1305 (see crypto.rs). The key file
// lives in the vault; copy it into your VM's vault once so `open` can work there.
//
// Output follows the rusty-tools convention: prefixed lines (FETCH/SAVED/OPENED/
// BLOB/KEY/SKIP/FAIL) so it reads well raw and through the dashboard stream.

mod crypto;

use crypto::Vault;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

const USER_AGENT: &str = concat!("FluShot/", env!("CARGO_PKG_VERSION"));

#[derive(Parser)]
#[command(
    name = "FluShot",
    about = "Encrypted sample vault — fetch/stash malware as noise so AV leaves it alone; decrypt inside your VM."
)]
struct Cli {
    /// Vault directory — holds the .enc blobs and the key file.
    #[arg(long, global = true, default_value = "vault")]
    vault: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Download URL(s) straight into the vault as encrypted blobs (plaintext never hits disk).
    Fetch {
        #[arg(required = true, value_name = "URL")]
        urls: Vec<String>,
    },
    /// Encrypt existing file(s) into the vault.
    Stash {
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,
    },
    /// Decrypt blob(s) out of the vault — run this inside your analysis VM.
    Open {
        #[arg(required = true, value_name = "BLOB")]
        blobs: Vec<PathBuf>,
        /// Directory to write the decrypted files into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// List the blobs currently in the vault.
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.cmd {
        Cmd::Fetch { urls } => cmd_fetch(&cli.vault, urls),
        Cmd::Stash { files } => cmd_stash(&cli.vault, files),
        Cmd::Open { blobs, out } => cmd_open(&cli.vault, blobs, out),
        Cmd::List => cmd_list(&cli.vault),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("FAIL   {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_fetch(vault_dir: &Path, urls: &[String]) -> io::Result<ExitCode> {
    let (vault, created) = Vault::open_or_create(vault_dir)?;
    announce_new_key(vault_dir, created);

    let mut had_failure = false;
    for url in urls {
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        println!("FETCH  {url}");
        match download(url) {
            Ok((name, data)) => match stash_bytes(&vault, vault_dir, &name, &data) {
                Ok(path) => println!("SAVED  {} ({} bytes)", path.display(), data.len()),
                Err(e) => {
                    println!("FAIL   {url}: {e}");
                    had_failure = true;
                }
            },
            Err(e) => {
                println!("FAIL   {url}: {e}");
                had_failure = true;
            }
        }
    }
    Ok(exit(had_failure))
}

fn cmd_stash(vault_dir: &Path, files: &[PathBuf]) -> io::Result<ExitCode> {
    let (vault, created) = Vault::open_or_create(vault_dir)?;
    announce_new_key(vault_dir, created);

    let mut had_failure = false;
    for file in files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());
        match fs::read(file).and_then(|data| stash_bytes(&vault, vault_dir, &name, &data).map(|p| (p, data.len()))) {
            Ok((path, len)) => println!("SAVED  {} ({} bytes)", path.display(), len),
            Err(e) => {
                println!("FAIL   {}: {e}", file.display());
                had_failure = true;
            }
        }
    }
    Ok(exit(had_failure))
}

fn cmd_open(vault_dir: &Path, blobs: &[PathBuf], out: &Path) -> io::Result<ExitCode> {
    let vault = Vault::open_existing(vault_dir)?;
    fs::create_dir_all(out)?;

    let mut had_failure = false;
    for blob in blobs {
        match fs::read(blob).and_then(|bytes| vault.unseal(&bytes)) {
            Ok((name, data)) => {
                let path = unique_path(out, &sanitize(&name));
                match fs::write(&path, &data) {
                    Ok(()) => println!("OPENED {} ({} bytes)", path.display(), data.len()),
                    Err(e) => {
                        println!("FAIL   {}: {e}", blob.display());
                        had_failure = true;
                    }
                }
            }
            Err(e) => {
                println!("FAIL   {}: {e}", blob.display());
                had_failure = true;
            }
        }
    }
    Ok(exit(had_failure))
}

fn cmd_list(vault_dir: &Path) -> io::Result<ExitCode> {
    let entries = match fs::read_dir(vault_dir) {
        Ok(entries) => entries,
        Err(_) => {
            println!("(vault is empty)");
            return Ok(ExitCode::SUCCESS);
        }
    };

    let mut count = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "enc") {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            println!("BLOB   {name} ({size} bytes)");
            count += 1;
        }
    }
    if count == 0 {
        println!("(vault is empty)");
    }
    Ok(ExitCode::SUCCESS)
}

/// Download a URL fully into memory and return `(filename, bytes)`. The tool
/// does this itself precisely so the browser (and SmartScreen) never sees it.
fn download(url: &str) -> Result<(String, Vec<u8>), String> {
    let response = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| e.to_string())?;

    let name = filename_from_disposition(response.header("content-disposition"))
        .unwrap_or_else(|| filename_from_url(url));

    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok((name, bytes))
}

/// Seal `data` and write it into the vault at `<name>.enc`, avoiding overwrites.
fn stash_bytes(vault: &Vault, vault_dir: &Path, name: &str, data: &[u8]) -> io::Result<PathBuf> {
    let blob = vault.seal(name, data)?;
    let path = unique_path(vault_dir, &format!("{}.enc", sanitize(name)));
    fs::write(&path, &blob)?;
    Ok(path)
}

fn announce_new_key(vault_dir: &Path, created: bool) {
    if created {
        println!(
            "KEY    generated a new vault key at {} — copy it into your VM's vault to decrypt",
            Vault::key_path(vault_dir).display()
        );
    }
}

fn exit(had_failure: bool) -> ExitCode {
    if had_failure {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Return a path in `dir` named `name`, appending `.N` before nothing/extension
/// as needed so an existing file is never clobbered.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let mut path = dir.join(name);
    let mut n = 1;
    while path.exists() {
        path = dir.join(format!("{name}.{n}"));
        n += 1;
    }
    path
}

/// Keep a filename to a safe, boring set of characters so nothing downstream
/// has to worry about path traversal or odd bytes.
fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches('.').trim_matches('_');
    if trimmed.is_empty() {
        "download.bin".to_string()
    } else {
        trimmed.to_string()
    }
}

fn filename_from_url(url: &str) -> String {
    let no_query = url.split(['?', '#']).next().unwrap_or(url);
    let segment = no_query.rsplit('/').find(|s| !s.is_empty()).unwrap_or("download");
    sanitize(segment)
}

/// Parse `filename="..."` (or bare `filename=...`) out of a Content-Disposition
/// header, if present.
fn filename_from_disposition(header: Option<&str>) -> Option<String> {
    let header = header?;
    let idx = header.to_ascii_lowercase().find("filename=")?;
    let raw = header[idx + "filename=".len()..].trim();
    let raw = raw.trim_start_matches('"');
    let end = raw.find(['"', ';']).unwrap_or(raw.len());
    let name = sanitize(&raw[..end]);
    if name.is_empty() { None } else { Some(name) }
}
