//! The vault: key management and the encrypted blob format.
//!
//! Each sample becomes a self-contained blob:
//!
//! ```text
//!   "FLSH"  |  version  |  nonce (12 bytes)  |  ChaCha20-Poly1305(name_len | name | data)
//!    0..4      4            5..17               17..
//! ```
//!
//! The original filename is stored *inside* the encrypted, authenticated
//! payload — never in the clear — so `open` can restore it exactly while a
//! blob on disk reveals nothing about what it holds.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"FLSH";
const VERSION: u8 = 1;
const KEY_FILE: &str = ".flushot.key";
const HEADER_LEN: usize = 4 + 1 + 12; // magic + version + nonce
const TAG_LEN: usize = 16; // Poly1305 tag

pub struct Vault {
    key: [u8; 32],
}

impl Vault {
    /// The key file's path for a given vault directory.
    pub fn key_path(dir: &Path) -> PathBuf {
        dir.join(KEY_FILE)
    }

    /// Open a vault that must already have a key — used by `open` (decryption).
    /// Fails with a clear message if the key isn't there, since that's the
    /// expected "you forgot to copy the key into the VM" case.
    pub fn open_existing(dir: &Path) -> io::Result<Self> {
        let path = Self::key_path(dir);
        let bytes = fs::read(&path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "no vault key at {} ({e}) — copy {KEY_FILE} from your host vault into this one",
                    path.display()
                ),
            )
        })?;
        Ok(Self { key: key_from(&bytes)? })
    }

    /// Open a vault, generating a fresh random key if none exists yet. Returns
    /// `(vault, created)` so the caller can tell the user to copy a new key.
    pub fn open_or_create(dir: &Path) -> io::Result<(Self, bool)> {
        fs::create_dir_all(dir)?;
        let path = Self::key_path(dir);
        if path.exists() {
            let bytes = fs::read(&path)?;
            return Ok((Self { key: key_from(&bytes)? }, false));
        }

        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| io::Error::other(e.to_string()))?;
        fs::write(&path, key)?;
        // Best-effort tighten permissions on Unix; harmless if it fails.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok((Self { key }, true))
    }

    /// Encrypt `data` (labelled with `name`) into a blob.
    pub fn seal(&self, name: &str, data: &[u8]) -> io::Result<Vec<u8>> {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
        }

        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;

        // plaintext = name_len (u16 LE) | name | data
        let mut plaintext = Vec::with_capacity(2 + name_bytes.len() + data.len());
        plaintext.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        plaintext.extend_from_slice(name_bytes);
        plaintext.extend_from_slice(data);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| io::Error::other("encryption failed"))?;

        let mut blob = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        blob.extend_from_slice(MAGIC);
        blob.push(VERSION);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Decrypt a blob back into its `(name, data)`.
    pub fn unseal(&self, blob: &[u8]) -> io::Result<(String, Vec<u8>)> {
        if blob.len() < HEADER_LEN + TAG_LEN || &blob[0..4] != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a FluShot blob"));
        }
        if blob[4] != VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported blob version"));
        }

        let nonce = &blob[5..HEADER_LEN];
        let ciphertext = &blob[HEADER_LEN..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decryption failed — wrong key or corrupt/tampered blob",
                )
            })?;

        if plaintext.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt blob"));
        }
        let name_len = u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;
        if plaintext.len() < 2 + name_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt blob"));
        }
        let name = String::from_utf8_lossy(&plaintext[2..2 + name_len]).into_owned();
        let data = plaintext[2 + name_len..].to_vec();
        Ok((name, data))
    }
}

fn key_from(bytes: &[u8]) -> io::Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key file must be exactly 32 bytes",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}
