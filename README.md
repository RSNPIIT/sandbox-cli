# Sandbox CLI

**One encrypted file. Append-only contents. Deletion-resistant at rest.**

Sandbox CLI turns a set of files into a single encrypted vault file. It is not a
mounted directory and it never exposes a decrypted tree at the mount layer. You
unlock the vault with a passphrase to add files, list names, extract copies, or
verify integrity.

The vault is deliberately **append-only**:

- There is no `delete`, `remove`, `rename`, or overwrite command.
- Adding a path that already exists is rejected.
- Correctly unlocking the vault does **not** grant a way to delete the vault.
- The vault file is marked immutable while it is idle, so Finder, Explorer-style
  file managers, and ordinary `rm -f` / `rm -rf` operations are refused by the
  operating system.

Copyleft under the GNU GPL v3.0 or later. See [LICENSE](LICENSE).

---

## What it is (and is not)

| It is | It is not |
| --- | --- |
| A single-file encrypted archive with an append-only index | A FUSE or kernel-mounted directory |
| Argon2id + ChaCha20-Poly1305 + LZ4 | A password-protected zip with a weak password check |
| Protected from accidental and same-user deletion via OS file flags | Protection against root, disk imaging, or physical access |
| A CLI with no deletion operation | A tool that can defeat an administrator with `chflags` / `chattr` |

The passphrase is never stored on disk. There is **no password recovery**. If the
passphrase or the vault file is lost, the contents are lost.

Read the [threat model](#threat-model) before relying on the deletion protection.

---

## Install

Requirements:

- Python 3.9 or newer
- Rust 1.85 or newer (stable) and Cargo
- A C linker for your platform (Xcode command-line tools on macOS)

### Development / local install

```bash
git clone <repository-url> sandbox-cli
cd sandbox-cli

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "maturin>=1.7,<2.0" pytest
maturin develop --release
```

`maturin develop` compiles the Rust engine into
`sandbox_cli/sandbox_engine.abi3.so` and installs the `sandbox-cli` entry point
inside the active virtual environment.

### Build a wheel

```bash
maturin build --release
python -m pip install target/wheels/sandbox_cli-*.whl
```

The wheel is built with Python's stable ABI (`abi3-py39`) on supported platforms.

### Test

```bash
.venv/bin/python -m pytest
```

---

## Quick start

```bash
# 1. Create an encrypted vault. You will be asked for a passphrase twice.
sandbox-cli init private.sbx

# 2. Add files or a directory tree.
sandbox-cli add private.sbx ~/Documents/notes
sandbox-cli add private.sbx ~/Pictures/holiday.jpg --as photos/holiday.jpg

# 3. Look inside (filenames are stored encrypted).
sandbox-cli list private.sbx

# 4. Read one file without writing plaintext to disk.
sandbox-cli cat private.sbx notes/todo.txt

# 5. Extract one file, or the whole vault.
sandbox-cli extract private.sbx notes/todo.txt -o ./todo.txt
sandbox-cli extract-all private.sbx ./restored

# 6. Check every authenticated block.
sandbox-cli verify private.sbx

# 7. Inspect metadata without the passphrase.
sandbox-cli info private.sbx

# 8. Re-apply the immutable flag after a crash or manual change.
sandbox-cli protect private.sbx
```

When a directory is added, the top-level directory name becomes the prefix inside
the vault. For example, adding `~/Documents/notes` creates entries such as
`notes/todo.txt`. Symbolic links and special files are skipped and reported.
Empty directories are preserved.

### Safe use in scripts

`--password-stdin` reads a single line from standard input. It is designed for
scripts and tests; use it carefully, because the calling shell controls stdin.

```bash
printf '%s\n' "$VAULT_PASSPHRASE" |
  sandbox-cli --password-stdin add private.sbx ./new-data
```

Passphrases are never accepted as command-line arguments, because process lists
and shell history would expose them.

### JSON listing

```bash
sandbox-cli --password-stdin list private.sbx --json
```

---

## Commands

| Command | Passphrase? | Purpose |
| --- | --- | --- |
| `init VAULT` | yes (new + confirmation) | Create an empty encrypted vault |
| `add VAULT SOURCES... [--as NAME]` | yes | Append files/directories; never overwrite |
| `list VAULT [--json]` | yes | Decrypt and display the index |
| `cat VAULT ENTRY` | yes | Stream a decrypted file to stdout |
| `extract VAULT ENTRY [-o FILE]` | yes | Extract one file |
| `extract-all VAULT DIR` | yes | Extract every file and directory |
| `verify VAULT` | yes | Authenticate/decompress every block |
| `info VAULT` | no | Show format, KDF, size, protection state |
| `protect VAULT` | no | Re-apply the immutable file flag |

Useful options:

- `init --memory-mib N` (default 64): Argon2id memory cost. Lower values are
  faster but weaker; 64 MiB or more is recommended.
- `init --iterations N` (default 3): Argon2id time cost.
- `init --parallelism N` (default 1): Argon2id lanes.
- `init --no-protect`: create an encrypted but **not** deletion-protected vault.
  You can run `protect` later.
- `extract --force`: replace an existing destination file.
- `extract-all --force`: replace existing destination files.
- `--password-stdin`: global option, placed before the command.

`extract` will never write over the vault itself. `extract-all` checks every
destination, refuses to traverse symbolic links created by an attacker, and uses
a temporary file plus atomic rename for each extracted file. A failed extraction
does not leave a partially written single file at its final destination.

---

## How it works

### File format

```text
offset 0      ┌─────────────────────────────────────┐
              │ Header slot A (512 bytes)           │
offset 512    ├─────────────────────────────────────┤
              │ Header slot B (512 bytes)           │
offset 4096   ├─────────────────────────────────────┤
              │ Encrypted LZ4 chunks                 │
              │ ...                                  │
              │ Encrypted JSON index (latest)        │
              └─────────────────────────────────────┘
```

The two header slots are crash-recovery copies. Each header contains:

- magic and format version
- Argon2id salt, memory/time/parallelism parameters
- random vault ID
- creation/update timestamps
- index offset, length, and nonce
- a generation sequence number
- a CRC32 checksum over the header slot

On an append, the new encrypted index is written after the new data, then the
older header slot is overwritten with the next generation. The previous header
slot remains valid until the new one has been committed. If a crash occurs before
the commit, blocks at the end are unreferenced garbage and the previous index is
still intact. If a crash corrupts the header write, the other slot is used.

### Cryptography

| Purpose | Algorithm |
| --- | --- |
| Passphrase KDF | Argon2id (random 16-byte salt, 32-byte output) |
| Key separation | BLAKE2s-256 with a domain string |
| Authenticated encryption | ChaCha20-Poly1305, 96-bit random nonce per block |
| Index encryption | ChaCha20-Poly1305 with a vault-ID + generation AAD |
| Compression | LZ4, only when it makes the block smaller |
| Integrity | AEAD tags on every chunk and the index |

The 32-byte Argon2id output is never used directly as an AEAD key. A
domain-separated BLAKE2s step derives the vault key.

Each file is split into 4 MiB chunks. Every chunk has its own random nonce and
its own AEAD tag. The AAD binds a chunk to the vault ID, entry ID, chunk number,
and codec, so ciphertext cannot be silently moved between entries or vaults.
The encrypted JSON index is authenticated separately.

### Adding (append-only)

```text
source files
    │
    ▼
LZ4 compress each 4 MiB chunk (or store raw if compression is larger)
    │
    ▼
ChaCha20-Poly1305 seal with a fresh nonce
    │
    ▼
append ciphertext to the vault
    │
    ▼
encrypt a new JSON index and append it
    │
    ▼
commit the new header slot
```

There is no overwrite path in the engine. If a destination already exists in the
index, the entire add is rejected before the vault is unlocked for writing.

### Extracting (targeted)

```text
read header slot
    │
    ▼
Argon2id + BLAKE2s key derivation
    │
    ▼
decrypt only the JSON index
    │
    ▼
find the requested entry's chunk offsets
    │
    ▼
read/authenticate/decompress only those blocks
    │
    ▼
write to a temporary file, fsync, atomic rename
```

Reading a single 1 KiB file from a 100 GiB vault does not decrypt the whole vault.
Memory use is bounded by one 4 MiB chunk (plus compression buffers) for streaming
operations.

### Encryption boundary

- Filenames, directory structure, sizes, modes, and timestamps are in the
  encrypted index.
- The plaintext salt, KDF parameters, vault ID, timestamps, index position, and
  total file size are visible in the header or from the file length.
- The approximate number and compressed sizes of files are visible from the
  ciphertext layout and index size.
- Extracted copies of files are ordinary plaintext files. Delete them securely
  yourself if that matters.

---

## Deletion protection

### macOS (unprivileged)

The tool runs:

```bash
chflags uchg private.sbx
```

While the flag is set, the kernel refuses unlink/rename/write operations even for
the file's owner. Finder and `rm -rf` fail with `Operation not permitted`. The
tool temporarily clears the flag for an append, then immediately sets it again.

### Linux (requires privilege)

The equivalent is:

```bash
chattr +i private.sbx
```

`chattr` requires `CAP_LINUX_IMMUTABLE`, normally root. The CLI attempts the
command directly and reports a cleanup warning if it lacks the capability. The
vault remains fully encrypted, but it is **not** deletion-protected in that case.

If you want immutable protection on Linux, run the CLI with sufficient
privilege/capability. Note that running the entire CLI as root can make extracted
files root-owned; use a dedicated account or wrapper with the narrow capability
if that matters. The code intentionally does not silently invoke `sudo` or
prompt for an administrator password.

### Other platforms

There is no immutable-flag implementation for Windows in this version. The vault
still encrypts data, but the deletion-resistance guarantee is macOS/Linux
specific.

### What immutable does **not** mean

No userspace program can make a file permanently undeletable on a machine its
administrator controls. Specifically:

- Root/administrator can clear the flag (`chflags nouchg` or `chattr -i`) and
  delete or replace the file.
- The same macOS user can run `chflags nouchg` manually.
- Disk editors, backups, snapshots, and forensic copies operate below this tool.
- During an append the flag is temporarily off, creating a small window in which
  a same-user process could race the writer.
- A hard crash or `SIGKILL` between unlock and re-lock can leave the vault
  writable. Run `sandbox-cli protect VAULT` afterwards.
- Replacing the whole vault file with a different vault cannot be distinguished
  without external state. Immutable flags raise the bar; they are not a
  cryptographic anti-rollback guarantee.

The honest claim is: **an idle vault is protected against normal file-manager and
`rm` deletion; the app exposes no deletion operation even with the passphrase.**
It is not protection against a determined administrator with root access.

---

## Threat model

Protected:

- Someone who steals the vault file but does not know the passphrase.
- Offline guessing slowed by Argon2id (64 MiB / 3 iterations by default).
- Silent bit-flips or ciphertext modification, detected by AEAD tags.
- Accidental `rm`, `rm -rf`, or GUI deletion while the immutable flag is set.
- Filename/metadata leakage from the index (encrypted).
- A user knowing the passphrase trying to delete through this CLI (no operation
  exists).

Not protected:

- A compromised machine with a keylogger or memory scraper while the vault is
  unlocked.
- Root / administrator with the ability to clear immutable flags.
- Physical disk theft with the vault unlocked, or RAM capture.
- Deletion of extracted plaintext copies.
- Traffic analysis of approximate vault/file sizes.
- Rollback to an older copy of the vault file.
- Password recovery. There is no escrow, hint, or backdoor.
- Malware running as the same user while an add is in progress.

---

## Recovery and administration

If a crash leaves a vault unprotected:

```bash
sandbox-cli info private.sbx
sandbox-cli protect private.sbx
```

If you are the administrator and need to remove a vault permanently, you must
clear the OS flag yourself. The CLI deliberately has no command that does this:

```bash
# macOS
chflags nouchg private.sbx
rm private.sbx

# Linux (as root)
chattr -i private.sbx
rm private.sbx
```

Back up the **entire vault file** regularly. Use a filesystem that supports
atomic rename and, on macOS/Linux, immutable flags for the strongest behavior.
Ext4, APFS, and HFS+ support the relevant flags; some network and FAT filesystems
do not.

If `verify` reports a problem, restore from a known-good backup. Do not continue
appending to a vault with failing AEAD tags.

---

## Project layout

```text
Cargo.toml                 Rust engine package and PyO3 extension-module
pyproject.toml             maturin build, Python package, CLI entry point
src/
  lib.rs                   PyO3 bindings; Python never handles ciphertext
  crypto.rs                Argon2id, BLAKE2s, ChaCha20-Poly1305
  vault.rs                 Format, header slots, index, chunk I/O, extraction
  protect.rs               chflags/chattr delete protection
sandbox_cli/
  main.py                  click commands and routing
  ui.py                    prompts, Rich tables, formatting
tests/
  test_engine.py           engine, corruption, protection, append-only tests
  test_cli.py              end-to-end CLI tests
```

The Python layer is deliberately thin. It parses arguments, reads passphrases,
and presents results. All vault parsing, cryptographic operations, compression,
path validation, and file writes live in Rust.

---

## Security notes for contributors

- Do not add a `delete`, `remove`, `rename`, or overwrite API. Append-only is a
  product invariant, not just a missing feature.
- Do not put passphrases in argv, environment variables, logs, or exception text.
- Do not decrypt the whole vault for a single-file read.
- Do not use a nonce twice for the same key. Each chunk and each index generation
  uses a fresh 96-bit random nonce.
- Keep index and chunk AAD domain-separated and bound to the vault ID. If you
  change the format, bump `FORMAT_VERSION` and handle old vaults explicitly.
- Keep untrusted header fields bounded before allocating memory or running
  Argon2id (see `MAX_KDF_*` and `INDEX_MAX_BYTES`).
- Extraction must validate every stored path, refuse symlink traversal, write to
  a temporary file, and atomically rename.
- The two-slot header is the crash-consistency mechanism. Preserve it.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
