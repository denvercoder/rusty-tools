# FluShot — encrypted sample vault

Malware samples can't sit on disk as plaintext: AV scans files on write and
quarantines anything it recognizes — often mid-download, before you can use them.
FluShot never lets a recognizable byte hit the disk. It downloads samples *itself*
(no browser, so no SmartScreen), encrypts them in memory, and writes only
ciphertext; the resulting blob has a novel hash and noise contents, so neither
content nor hash/reputation scanning has anything to bite. Decrypt them back only
inside your analysis VM.

## Cross-platform

Like FAFO, FluShot is pure Rust with no OS-specific APIs, so it runs on Windows,
Linux, or macOS — wherever you handle samples.

## How it defeats the download block

- **The tool downloads, not the browser** — no SmartScreen prompt, and the
  plaintext never lands on disk for the on-write real-time scan.
- **Output is a novel encrypted blob** — unknown hash and noise content, so both
  hash/reputation and content scanning come up empty.
- **Encrypting after a browser download is too late** — by then AV has already
  quarantined it, which is why `fetch` does the download itself.

## Encryption

Keyfile-based ChaCha20-Poly1305 (authenticated). A 32-byte key file
(`.flushot.key`) is generated in the vault on first use — no passphrase to type.
To decrypt inside your VM, copy that key file into the VM's vault once. The
original filename is stored *inside* the encrypted payload, so `open` restores it
exactly while a blob on disk reveals nothing about what it holds.

## Blob format

```
"FLSH" | version | nonce (12 bytes) | ChaCha20-Poly1305( name_len | name | data )
 0..4     4         5..17              17..
```

## Usage

```
# Download URL(s) straight into the vault as encrypted blobs
cargo run -p FluShot -- fetch https://example.com/sample1 https://example.com/sample2

# Encrypt file(s) you already have
cargo run -p FluShot -- stash ./suspicious.bin

# Decrypt blob(s) back out — run this INSIDE your analysis VM
cargo run -p FluShot -- open vault/suspicious.bin.enc --out ./work

# List the vault
cargo run -p FluShot -- list

# Point at a different vault directory (default: ./vault)
cargo run -p FluShot -- --vault /path/to/vault list
```

Through the dashboard: the **FluShot** card has an **ENCRYPT** tab (paste sample
URLs — a new box appears as you fill each in) and a **DECRYPT** tab (pick blobs
from the vault to restore, with a loud reminder to only do that inside your VM).

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `FETCH` | Started downloading a URL |
| `SAVED` | A sample was encrypted into the vault |
| `OPENED` | A blob was decrypted back to a file |
| `BLOB` | A blob listed from the vault (`list`) |
| `KEY` | A new vault key was generated — copy it into your VM to decrypt |
| `FAIL` | A download, encrypt, or decrypt step failed |

> Part of [Rusty Toolz](../README.md). Use only for samples you're authorized to analyze, and only ever `open` (decrypt) them inside a disposable analysis VM — never on your host.
