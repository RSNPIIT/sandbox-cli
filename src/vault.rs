// SPDX-License-Identifier: GPL-3.0-or-later

//! The on-disk vault format and all append-only operations.
//!
//! Layout:
//!
//! ```text
//! 0     magic + header slot A (512 bytes)
//! 512   header slot B (512 bytes, crash-recovery copy)
//! 4096  encrypted data blocks, followed by the encrypted JSON index
//! ```
//!
//! Every file is split into independent 4 MiB chunks. A chunk is compressed
//! with LZ4 when compression helps and is then sealed with ChaCha20-Poly1305.
//! The encrypted JSON index records paths, metadata, offsets, nonces, and
//! chunk sizes. Replacing the index is the commit point for an add.

use crate::crypto::{self, KdfSettings};
use crate::protect::{self, ProtectionStatus};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SBXVAULT";
const FORMAT_VERSION: u16 = 1;
const HEADER_SLOT_SIZE: usize = 512;
const HEADER_REGION: u64 = 4096;
const HEADER_CRC_OFFSET: usize = 508;
const INDEX_MAX_BYTES: u64 = 256 * 1024 * 1024;
const INDEX_FORMAT: &str = "sandbox-index";
const INDEX_VERSION: u32 = 1;
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_PROBLEMS: usize = 100;

const INDEX_AAD_PREFIX: &[u8] = b"SBX-IDX1";
const CHUNK_AAD_PREFIX: &[u8] = b"SBX-CHK1";

#[derive(Clone)]
struct Header {
    sequence: u64,
    created_at: i64,
    updated_at: i64,
    settings: KdfSettings,
    salt: [u8; crypto::SALT_LEN],
    vault_id: [u8; 16],
    index_offset: u64,
    index_len: u64,
    index_nonce: [u8; crypto::NONCE_LEN],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Index {
    format: String,
    version: u32,
    entries: Vec<Entry>,
}

impl Index {
    fn empty() -> Self {
        Self {
            format: INDEX_FORMAT.to_string(),
            version: INDEX_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    id: u64,
    path: String,
    kind: EntryKind,
    size: u64,
    mode: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
    #[serde(default)]
    chunks: Vec<Chunk>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum EntryKind {
    File,
    Dir,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Codec {
    Raw,
    Lz4,
}

impl Codec {
    fn tag(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::Lz4 => 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Chunk {
    offset: u64,
    stored_len: u64,
    plain_len: u32,
    codec: Codec,
    nonce: String,
}

#[derive(Clone, Debug)]
pub struct EntryView {
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub stored_size: u64,
    pub mode: u32,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub chunks: u64,
}

#[derive(Clone, Debug)]
pub struct VaultInfoView {
    pub format_version: u16,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub sequence: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub file_size: u64,
    pub vault_id: String,
    pub protection: ProtectionStatus,
    pub platform: String,
}

#[derive(Clone, Debug)]
pub struct CreateResult {
    pub vault_id: String,
    pub created_at: i64,
    pub protection: ProtectionStatus,
    pub warning: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AddResult {
    pub files_added: u64,
    pub dirs_added: u64,
    pub bytes_added: u64,
    pub stored_bytes_added: u64,
    pub total_entries: u64,
    pub skipped: Vec<String>,
    pub protection: ProtectionStatus,
    pub warning: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ExtractResult {
    pub entries_written: u64,
    pub bytes_written: u64,
}

#[derive(Clone, Debug)]
pub struct VerifyResult {
    pub ok: bool,
    pub entries_checked: u64,
    pub chunks_checked: u64,
    pub bytes_verified: u64,
    pub problems: Vec<String>,
    pub problems_truncated: bool,
}

struct PlannedEntry {
    path: String,
    source: Option<PathBuf>,
    kind: EntryKind,
    mode: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
}

struct OpenedVault {
    file: File,
    header: Header,
    key: Zeroizing<[u8; crypto::KEY_LEN]>,
    index: Index,
}

/// Guard that re-applies the OS immutable flag even if an update fails.
struct ProtectionGuard {
    path: PathBuf,
    restore: bool,
    disarmed: bool,
}

impl ProtectionGuard {
    fn begin(path: &Path, protect_after_write: bool) -> Result<Self> {
        let st = protect::status(path);
        if st.protected {
            protect::unprotect(path).context("could not temporarily unlock the vault file")?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            restore: protect_after_write || st.protected,
            disarmed: false,
        })
    }

    fn relock(mut self) -> (ProtectionStatus, Option<String>) {
        self.disarmed = true;
        if !self.restore {
            let st = protect::status(&self.path);
            let warning = if st.protected {
                None
            } else {
                Some("vault is not deletion-protected".to_string())
            };
            return (st, warning);
        }
        match protect::protect(&self.path) {
            Ok(st) => {
                let warning = if st.protected {
                    None
                } else {
                    Some("the vault could not be marked immutable".to_string())
                };
                (st, warning)
            }
            Err(err) => {
                let st = protect::status(&self.path);
                (
                    st,
                    Some(format!("vault was written but could not be re-protected: {err}")),
                )
            }
        }
    }
}

impl Drop for ProtectionGuard {
    fn drop(&mut self) {
        if !self.disarmed && self.restore {
            let _ = protect::protect(&self.path);
        }
    }
}

pub fn create(
    path: &Path,
    password: &str,
    memory_mib: u32,
    iterations: u32,
    parallelism: u32,
    protect_after_create: bool,
) -> Result<CreateResult> {
    if path.exists() {
        bail!("vault already exists: {}", path.display());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
    }

    let settings = KdfSettings::from_mib(memory_mib, iterations, parallelism)?;
    let salt = crypto::random_bytes::<{ crypto::SALT_LEN }>()?;
    let vault_id = crypto::random_bytes::<16>()?;
    let key = crypto::derive_key(password, &salt, settings)?;
    let now = now_unix();

    let index = Index::empty();
    let index_plain = serde_json::to_vec(&index).context("could not serialize the empty index")?;
    let sequence = 1u64;
    let index_aad = index_aad(&vault_id, sequence);
    let (index_cipher, index_nonce) = crypto::encrypt(&key[..], &index_plain, &index_aad)?;

    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    set_private_file_permissions(&file)?;

    file.set_len(HEADER_REGION)
        .context("could not initialize the vault header region")?;

    let header = Header {
        sequence,
        created_at: now,
        updated_at: now,
        settings,
        salt,
        vault_id,
        index_offset: HEADER_REGION,
        index_len: index_cipher.len() as u64,
        index_nonce,
    };

    file.seek(SeekFrom::Start(HEADER_REGION))?;
    file.write_all(&index_cipher)
        .context("could not write the initial encrypted index")?;
    write_header_slot(&mut file, 0, &header)?;
    file.sync_all().context("could not flush the new vault to disk")?;
    drop(file);
    sync_parent(path);

    let (protection, warning) = if protect_after_create {
        match protect::protect(path) {
            Ok(st) => {
                let warning = if st.protected {
                    None
                } else {
                    Some("the vault was created but could not be marked immutable".to_string())
                };
                (st, warning)
            }
            Err(err) => (
                protect::status(path),
                Some(format!(
                    "vault was created but is not protected from deletion: {err}"
                )),
            ),
        }
    } else {
        (
            protect::status(path),
            Some("vault was created without deletion protection (--no-protect)".to_string()),
        )
    };

    Ok(CreateResult {
        vault_id: hex::encode(vault_id),
        created_at: now,
        protection,
        warning,
    })
}

pub fn add(
    path: &Path,
    password: &str,
    sources: &[PathBuf],
    destination: Option<&str>,
    protect_after_write: bool,
) -> Result<AddResult> {
    if sources.is_empty() {
        bail!("no source files or directories were provided");
    }
    if destination.is_some() && sources.len() != 1 {
        bail!("--as can only be used when adding exactly one source");
    }

    let OpenedVault {
        file: read_handle,
        header,
        key,
        index,
    } = open_vault(path, password)?;
    drop(read_handle);

    ensure_index_has_room(&index)?;
    let (plan, skipped) = build_plan(path, sources, destination, &index)?;
    if plan.is_empty() {
        bail!("nothing was found to add (only unsupported file types?)");
    }
    validate_combined_hierarchy(&index, &plan)?;

    let initial_sequence = header.sequence;
    let vault_id = header.vault_id;
    let mut guard = Some(ProtectionGuard::begin(path, protect_after_write)?);

    let result = (|| -> Result<AddResult> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("could not open {} for writing", path.display()))?;
        file.lock_exclusive()
            .context("another Sandbox CLI operation is already writing this vault")?;

        let current = latest_header(&mut file)?;
        if current.sequence != initial_sequence || current.vault_id != vault_id {
            bail!("the vault changed while it was being opened; please retry the add");
        }

        let mut entries = index.entries.clone();
        let mut next_id = entries.iter().map(|entry| entry.id).max().unwrap_or(0) + 1;
        let mut files_added = 0u64;
        let mut dirs_added = 0u64;
        let mut bytes_added = 0u64;
        let mut stored_bytes_added = 0u64;

        file.seek(SeekFrom::End(0))?;

        for planned in plan.values() {
            match planned.kind {
                EntryKind::Dir => {
                    entries.push(Entry {
                        id: next_id,
                        path: planned.path.clone(),
                        kind: EntryKind::Dir,
                        size: 0,
                        mode: planned.mode,
                        mtime_secs: planned.mtime_secs,
                        mtime_nanos: planned.mtime_nanos,
                        chunks: Vec::new(),
                    });
                    next_id += 1;
                    dirs_added += 1;
                }
                EntryKind::File => {
                    let source = planned
                        .source
                        .as_ref()
                        .context("internal error: planned file has no source")?;
                    let (chunks, size, stored) =
                        append_file(&mut file, source, &vault_id, next_id, &key[..])?;
                    entries.push(Entry {
                        id: next_id,
                        path: planned.path.clone(),
                        kind: EntryKind::File,
                        size,
                        mode: planned.mode,
                        mtime_secs: planned.mtime_secs,
                        mtime_nanos: planned.mtime_nanos,
                        chunks,
                    });
                    next_id += 1;
                    files_added += 1;
                    bytes_added = bytes_added
                        .checked_add(size)
                        .context("added data size overflowed")?;
                    stored_bytes_added = stored_bytes_added
                        .checked_add(stored)
                        .context("stored data size overflowed")?;
                }
            }
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        if entries.len() > MAX_ENTRIES {
            bail!("the vault would exceed the supported {MAX_ENTRIES} entries");
        }
        let total_entries = entries.len() as u64;

        let new_index = Index {
            format: INDEX_FORMAT.to_string(),
            version: INDEX_VERSION,
            entries,
        };
        let index_plain = serde_json::to_vec(&new_index)
            .context("could not serialize the updated vault index")?;
        if index_plain.len() as u64 > INDEX_MAX_BYTES {
            bail!("the encrypted index would exceed the 256 MiB index limit");
        }

        let new_sequence = current.sequence + 1;
        let index_offset = file.stream_position()?;
        let index_aad = index_aad(&vault_id, new_sequence);
        let (index_cipher, index_nonce) = crypto::encrypt(&key[..], &index_plain, &index_aad)?;
        file.write_all(&index_cipher)
            .context("could not append the updated encrypted index")?;

        let mut new_header = current.clone();
        new_header.sequence = new_sequence;
        new_header.updated_at = now_unix();
        new_header.index_offset = index_offset;
        new_header.index_len = index_cipher.len() as u64;
        new_header.index_nonce = index_nonce;

        let write_slot = choose_write_slot(&mut file)?;
        write_header_slot(&mut file, write_slot, &new_header)?;
        file.sync_all()
            .context("could not flush the updated vault to disk")?;
        drop(file);
        sync_parent(path);

        let (protection, protection_warning) = guard
            .take()
            .context("internal error: protection guard disappeared")?
            .relock();
        let mut warning = protection_warning;
        if !skipped.is_empty() && warning.is_none() {
            warning = Some(format!(
                "{} symbolic link or special file(s) were skipped",
                skipped.len()
            ));
        }

        Ok(AddResult {
            files_added,
            dirs_added,
            bytes_added,
            stored_bytes_added,
            total_entries,
            skipped,
            protection,
            warning,
        })
    })();

    if let Some(restore) = guard {
        drop(restore);
    }
    result
}

pub fn list(path: &Path, password: &str) -> Result<Vec<EntryView>> {
    let opened = open_vault(path, password)?;
    let mut views = Vec::with_capacity(opened.index.entries.len());
    for entry in &opened.index.entries {
        views.push(EntryView {
            path: entry.path.clone(),
            kind: match entry.kind {
                EntryKind::File => "file".to_string(),
                EntryKind::Dir => "dir".to_string(),
            },
            size: entry.size,
            stored_size: entry.chunks.iter().map(|chunk| chunk.stored_len).sum(),
            mode: entry.mode,
            mtime_secs: entry.mtime_secs,
            mtime_nanos: entry.mtime_nanos,
            chunks: entry.chunks.len() as u64,
        });
    }
    Ok(views)
}

pub fn info(path: &Path) -> Result<VaultInfoView> {
    let mut file =
        File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let header = latest_header(&mut file)?;
    let file_size = file.metadata()?.len();
    Ok(VaultInfoView {
        format_version: FORMAT_VERSION,
        kdf_memory_kib: header.settings.memory_kib,
        kdf_iterations: header.settings.iterations,
        kdf_parallelism: header.settings.parallelism,
        sequence: header.sequence,
        created_at: header.created_at,
        updated_at: header.updated_at,
        file_size,
        vault_id: hex::encode(header.vault_id),
        protection: protect::status(path),
        platform: protect::platform().to_string(),
    })
}

pub fn read_entry(path: &Path, password: &str, entry_path: &str) -> Result<Vec<u8>> {
    let opened = open_vault(path, password)?;
    let entry = find_entry(&opened.index, entry_path)?;
    if entry.kind != EntryKind::File {
        bail!("'{}' is a directory, not a file", entry_path);
    }
    let mut file = opened.file;
    let mut output = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
    let mut total = 0u64;
    for (index, chunk) in entry.chunks.iter().enumerate() {
        let bytes = decrypt_chunk(&mut file, &opened.header, &opened.key[..], entry, index, chunk)?;
        output.extend_from_slice(&bytes);
        total += bytes.len() as u64;
    }
    if total != entry.size {
        bail!("entry '{}' failed its size check", entry.path);
    }
    Ok(output)
}

pub fn extract(
    path: &Path,
    password: &str,
    entry_path: &str,
    destination: &Path,
    force: bool,
) -> Result<ExtractResult> {
    let mut opened = open_vault(path, password)?;
    let entry = find_entry(&opened.index, entry_path)?.clone();
    if entry.kind != EntryKind::File {
        bail!("'{}' is a directory; use extract-all", entry_path);
    }
    ensure_destination_is_not_vault(path, destination)?;
    let bytes = write_entry_file(
        &mut opened.file,
        &opened.header,
        &opened.key[..],
        &entry,
        destination,
        force,
    )?;
    Ok(ExtractResult {
        entries_written: 1,
        bytes_written: bytes,
    })
}

pub fn extract_all(
    path: &Path,
    password: &str,
    destination_root: &Path,
    force: bool,
) -> Result<ExtractResult> {
    let mut opened = open_vault(path, password)?;
    ensure_destination_is_not_vault(path, destination_root)?;
    create_root_directory(destination_root)?;

    let vault_absolute = comparable_path(path)?;
    let mut entries_written = 0u64;
    let mut bytes_written = 0u64;
    let mut directory_metadata = Vec::new();
    for entry in &opened.index.entries {
        let destination = stored_path_to_path(destination_root, &entry.path);
        match entry.kind {
            EntryKind::Dir => {
                ensure_descendant_dir(destination_root, &entry.path)?;
                directory_metadata.push((
                    destination,
                    entry.path.matches('/').count(),
                    entry.mode,
                    entry.mtime_secs,
                    entry.mtime_nanos,
                ));
            }
            EntryKind::File => {
                if comparable_path(&destination)? == vault_absolute {
                    bail!(
                        "refusing to overwrite the vault itself with extracted entry '{}'",
                        entry.path
                    );
                }
                let bytes = write_entry_file(
                    &mut opened.file,
                    &opened.header,
                    &opened.key[..],
                    entry,
                    &destination,
                    force,
                )?;
                entries_written += 1;
                bytes_written = bytes_written
                    .checked_add(bytes)
                    .context("extracted byte count overflowed")?;
            }
        }
    }

    // Apply directory modes only after every child exists. Otherwise a
    // read-only directory mode from the vault could block extraction.
    directory_metadata.sort_by(|a, b| b.1.cmp(&a.1));
    for (directory, _, mode, mtime_secs, mtime_nanos) in directory_metadata {
        set_path_mode(&directory, mode)?;
        set_path_mtime(&directory, mtime_secs, mtime_nanos)?;
    }

    Ok(ExtractResult {
        entries_written,
        bytes_written,
    })
}

pub fn verify(path: &Path, password: &str) -> Result<VerifyResult> {
    let mut opened = open_vault(path, password)?;
    let mut entries_checked = 0u64;
    let mut chunks_checked = 0u64;
    let mut bytes_verified = 0u64;
    let mut problems = Vec::new();
    let mut problems_truncated = false;

    for entry in &opened.index.entries {
        entries_checked += 1;
        if entry.kind == EntryKind::Dir {
            if !entry.chunks.is_empty() {
                push_problem(
                    &mut problems,
                    &mut problems_truncated,
                    format!("directory '{}' unexpectedly has data chunks", entry.path),
                );
            }
            continue;
        }

        let mut entry_bytes = 0u64;
        for (index, chunk) in entry.chunks.iter().enumerate() {
            chunks_checked += 1;
            match decrypt_chunk(
                &mut opened.file,
                &opened.header,
                &opened.key[..],
                entry,
                index,
                chunk,
            ) {
                Ok(bytes) => {
                    entry_bytes += bytes.len() as u64;
                    bytes_verified += bytes.len() as u64;
                }
                Err(err) => push_problem(
                    &mut problems,
                    &mut problems_truncated,
                    format!("{} [chunk {}]: {err:#}", entry.path, index),
                ),
            }
        }
        if entry_bytes != entry.size {
            push_problem(
                &mut problems,
                &mut problems_truncated,
                format!(
                    "{}: index says {} bytes but chunks contain {}",
                    entry.path, entry.size, entry_bytes
                ),
            );
        }
    }

    Ok(VerifyResult {
        ok: problems.is_empty(),
        entries_checked,
        chunks_checked,
        bytes_verified,
        problems,
        problems_truncated,
    })
}

pub fn protection_status(path: &Path) -> ProtectionStatus {
    protect::status(path)
}

pub fn protect_vault(path: &Path) -> Result<ProtectionStatus> {
    if !path.exists() {
        bail!("vault does not exist: {}", path.display());
    }
    protect::protect(path)
}

fn open_vault(path: &Path, password: &str) -> Result<OpenedVault> {
    let mut file =
        File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let file_len = file.metadata()?.len();
    let header = latest_header(&mut file)?;
    let key = crypto::derive_key(password, &header.salt, header.settings)?;
    let index = load_index(&mut file, &header, &key[..], file_len)?;
    Ok(OpenedVault {
        file,
        header,
        key,
        index,
    })
}

fn latest_header(file: &mut File) -> Result<Header> {
    let headers = read_headers(file)?;
    headers
        .into_iter()
        .max_by_key(|(_, header)| header.sequence)
        .map(|(_, header)| header)
        .context("the vault has no valid header")
}

fn read_headers(file: &mut File) -> Result<Vec<(usize, Header)>> {
    let len = file.metadata()?.len();
    if len < HEADER_SLOT_SIZE as u64 {
        bail!("file is too small to be a Sandbox vault");
    }
    let mut region = [0u8; HEADER_SLOT_SIZE * 2];
    let to_read = usize::try_from(len.min(region.len() as u64)).unwrap_or(region.len());
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut region[..to_read])?;
    let mut valid = Vec::new();
    for slot in 0..2 {
        let start = slot * HEADER_SLOT_SIZE;
        if to_read >= start + HEADER_SLOT_SIZE {
            if let Ok(header) = parse_header(&region[start..start + HEADER_SLOT_SIZE]) {
                valid.push((slot, header));
            }
        }
    }
    if valid.is_empty() {
        bail!("not a Sandbox vault, or the vault header is corrupted");
    }
    Ok(valid)
}

fn choose_write_slot(file: &mut File) -> Result<usize> {
    let headers = read_headers(file)?;
    if headers.len() == 1 {
        return Ok(1 - headers[0].0);
    }
    headers
        .into_iter()
        .min_by_key(|(_, header)| header.sequence)
        .map(|(slot, _)| slot)
        .context("the vault has no valid header")
}

fn parse_header(bytes: &[u8]) -> Result<Header> {
    if bytes.len() != HEADER_SLOT_SIZE {
        bail!("header slot has the wrong size");
    }
    if &bytes[0..8] != MAGIC {
        bail!("header magic does not match");
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into()?);
    if version != FORMAT_VERSION {
        bail!("unsupported vault format version {version}");
    }
    let slot_size = u16::from_le_bytes(bytes[10..12].try_into()?) as usize;
    if slot_size != HEADER_SLOT_SIZE {
        bail!("unsupported header slot size");
    }
    let stored_crc = u32::from_le_bytes(
        bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4]
            .try_into()?,
    );
    let actual_crc = crc32fast::hash(&bytes[..HEADER_CRC_OFFSET]);
    if stored_crc != actual_crc {
        bail!("header checksum mismatch");
    }

    let algorithm = bytes[12];
    if algorithm != 1 {
        bail!("unsupported key derivation algorithm");
    }
    let sequence = u64::from_le_bytes(bytes[16..24].try_into()?);
    let created_at = i64::from_le_bytes(bytes[24..32].try_into()?);
    let updated_at = i64::from_le_bytes(bytes[32..40].try_into()?);
    let settings = KdfSettings {
        memory_kib: u32::from_le_bytes(bytes[40..44].try_into()?),
        iterations: u32::from_le_bytes(bytes[44..48].try_into()?),
        parallelism: u32::from_le_bytes(bytes[48..52].try_into()?),
    };
    settings.validate()?;
    let mut salt = [0u8; crypto::SALT_LEN];
    salt.copy_from_slice(&bytes[56..72]);
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&bytes[72..88]);
    let index_offset = u64::from_le_bytes(bytes[88..96].try_into()?);
    let index_len = u64::from_le_bytes(bytes[96..104].try_into()?);
    let mut index_nonce = [0u8; crypto::NONCE_LEN];
    index_nonce.copy_from_slice(&bytes[104..116]);
    if sequence == 0 {
        bail!("invalid header sequence");
    }
    if index_offset < HEADER_REGION {
        bail!("invalid index offset");
    }
    if index_len == 0 || index_len > INDEX_MAX_BYTES {
        bail!("invalid encrypted index size");
    }
    Ok(Header {
        sequence,
        created_at,
        updated_at,
        settings,
        salt,
        vault_id,
        index_offset,
        index_len,
        index_nonce,
    })
}

fn write_header_slot(file: &mut File, slot: usize, header: &Header) -> Result<()> {
    if slot > 1 {
        bail!("internal error: invalid header slot");
    }
    let mut bytes = [0u8; HEADER_SLOT_SIZE];
    bytes[0..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(HEADER_SLOT_SIZE as u16).to_le_bytes());
    bytes[12] = 1; // Argon2id
    bytes[13] = 0; // reserved flags
    bytes[16..24].copy_from_slice(&header.sequence.to_le_bytes());
    bytes[24..32].copy_from_slice(&header.created_at.to_le_bytes());
    bytes[32..40].copy_from_slice(&header.updated_at.to_le_bytes());
    bytes[40..44].copy_from_slice(&header.settings.memory_kib.to_le_bytes());
    bytes[44..48].copy_from_slice(&header.settings.iterations.to_le_bytes());
    bytes[48..52].copy_from_slice(&header.settings.parallelism.to_le_bytes());
    bytes[56..72].copy_from_slice(&header.salt);
    bytes[72..88].copy_from_slice(&header.vault_id);
    bytes[88..96].copy_from_slice(&header.index_offset.to_le_bytes());
    bytes[96..104].copy_from_slice(&header.index_len.to_le_bytes());
    bytes[104..116].copy_from_slice(&header.index_nonce);
    let crc = crc32fast::hash(&bytes[..HEADER_CRC_OFFSET]);
    bytes[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());

    file.seek(SeekFrom::Start((slot * HEADER_SLOT_SIZE) as u64))?;
    file.write_all(&bytes)
        .context("could not write the vault header")?;
    Ok(())
}

fn load_index(
    file: &mut File,
    header: &Header,
    key: &[u8],
    file_len: u64,
) -> Result<Index> {
    let end = header
        .index_offset
        .checked_add(header.index_len)
        .context("index offset overflow")?;
    if end > file_len {
        bail!("vault index points outside the file; the vault may be truncated");
    }
    if header.index_offset < HEADER_REGION {
        bail!("invalid index offset");
    }
    let mut ciphertext = vec![0u8; usize::try_from(header.index_len)?];
    file.seek(SeekFrom::Start(header.index_offset))?;
    file.read_exact(&mut ciphertext)?;
    let aad = index_aad(&header.vault_id, header.sequence);
    let plaintext = crypto::decrypt(key, &header.index_nonce, &ciphertext, &aad)
        .context("wrong password, or the vault index is corrupted")?;
    let index: Index = serde_json::from_slice(&plaintext)
        .context("the decrypted vault index is malformed or corrupted")?;
    validate_index(&index, file_len)?;
    Ok(index)
}

fn validate_index(index: &Index, file_len: u64) -> Result<()> {
    if index.format != INDEX_FORMAT {
        bail!("unrecognized vault index format");
    }
    if index.version != INDEX_VERSION {
        bail!("unsupported vault index version {}", index.version);
    }
    if index.entries.len() > MAX_ENTRIES {
        bail!("vault contains more than the supported {MAX_ENTRIES} entries");
    }

    let mut paths = HashSet::with_capacity(index.entries.len());
    let mut ids = HashSet::with_capacity(index.entries.len());
    for entry in &index.entries {
        validate_stored_path(&entry.path)?;
        if !paths.insert(entry.path.clone()) {
            bail!("vault index contains duplicate path '{}'", entry.path);
        }
        if entry.id == 0 || !ids.insert(entry.id) {
            bail!("vault index contains an invalid or duplicate entry id");
        }

        match entry.kind {
            EntryKind::Dir => {
                if entry.size != 0 || !entry.chunks.is_empty() {
                    bail!("vault index has a malformed directory entry '{}'", entry.path);
                }
            }
            EntryKind::File => {
                let mut size = 0u64;
                for chunk in &entry.chunks {
                    if chunk.plain_len as usize > CHUNK_SIZE {
                        bail!("vault index has an oversized chunk in '{}'", entry.path);
                    }
                    if chunk.stored_len < crypto::TAG_LEN as u64
                        || chunk.stored_len > (CHUNK_SIZE + crypto::TAG_LEN) as u64
                    {
                        bail!("vault index has an invalid chunk size in '{}'", entry.path);
                    }
                    let nonce = hex::decode(&chunk.nonce)
                        .with_context(|| format!("invalid chunk nonce in '{}'", entry.path))?;
                    if nonce.len() != crypto::NONCE_LEN {
                        bail!("vault index has an invalid chunk nonce in '{}'", entry.path);
                    }
                    let end = chunk
                        .offset
                        .checked_add(chunk.stored_len)
                        .context("chunk offset overflow")?;
                    if chunk.offset < HEADER_REGION || end > file_len {
                        bail!("vault index points outside the file in '{}'", entry.path);
                    }
                    size = size
                        .checked_add(chunk.plain_len as u64)
                        .context("entry size overflow")?;
                }
                if size != entry.size {
                    bail!(
                        "vault index size mismatch for '{}' ({} != {})",
                        entry.path,
                        size,
                        entry.size
                    );
                }
            }
        }
    }
    Ok(())
}

fn index_aad(vault_id: &[u8; 16], sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(INDEX_AAD_PREFIX.len() + 24);
    aad.extend_from_slice(INDEX_AAD_PREFIX);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad
}

fn chunk_aad(
    vault_id: &[u8; 16],
    entry_id: u64,
    chunk_index: usize,
    codec: Codec,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_PREFIX.len() + 16 + 8 + 4 + 1);
    aad.extend_from_slice(CHUNK_AAD_PREFIX);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&entry_id.to_le_bytes());
    aad.extend_from_slice(&(chunk_index as u32).to_le_bytes());
    aad.push(codec.tag());
    aad
}

fn append_file(
    file: &mut File,
    source: &Path,
    vault_id: &[u8; 16],
    entry_id: u64,
    key: &[u8],
) -> Result<(Vec<Chunk>, u64, u64)> {
    let mut input =
        File::open(source).with_context(|| format!("could not read {}", source.display()))?;
    let mut chunks = Vec::new();
    let mut total = 0u64;
    let mut stored_total = 0u64;
    let mut buffer = Vec::with_capacity(CHUNK_SIZE);

    loop {
        buffer.clear();
        let read = (&mut input)
            .take(CHUNK_SIZE as u64)
            .read_to_end(&mut buffer)
            .with_context(|| format!("could not read {}", source.display()))?;
        if read == 0 {
            break;
        }
        let plain_len = u32::try_from(buffer.len()).context("chunk is too large")?;
        let compressed = lz4_flex::compress(&buffer);
        let (payload, codec) = if compressed.len() < buffer.len() {
            (compressed, Codec::Lz4)
        } else {
            (buffer.clone(), Codec::Raw)
        };

        let chunk_index = chunks.len();
        let offset = file.stream_position()?;
        let aad = chunk_aad(vault_id, entry_id, chunk_index, codec);
        let (ciphertext, nonce) = crypto::encrypt(key, &payload, &aad)?;
        file.write_all(&ciphertext)
            .with_context(|| format!("could not append {} to the vault", source.display()))?;

        let stored_len = ciphertext.len() as u64;
        chunks.push(Chunk {
            offset,
            stored_len,
            plain_len,
            codec,
            nonce: hex::encode(nonce),
        });
        total = total
            .checked_add(read as u64)
            .context("source file size overflowed")?;
        stored_total = stored_total
            .checked_add(stored_len)
            .context("stored size overflowed")?;
    }

    Ok((chunks, total, stored_total))
}

fn build_plan(
    vault_path: &Path,
    sources: &[PathBuf],
    destination: Option<&str>,
    index: &Index,
) -> Result<(BTreeMap<String, PlannedEntry>, Vec<String>)> {
    let mut plan = BTreeMap::new();
    let mut skipped = Vec::new();
    let existing: HashSet<&str> = index.entries.iter().map(|entry| entry.path.as_str()).collect();
    let normalized_destination = destination
        .map(normalize_destination)
        .transpose()?;

    for source in sources {
        let metadata = fs::symlink_metadata(source)
            .with_context(|| format!("could not inspect {}", source.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "refusing to add symbolic link '{}'; add its target explicitly",
                source.display()
            );
        }
        if same_file(source, vault_path) {
            bail!("the vault cannot be added to itself");
        }

        let root_name = match &normalized_destination {
            Some(destination) => destination.clone(),
            None => source_root_name(source)?,
        };
        validate_stored_path(&root_name)?;

        if metadata.is_file() {
            if existing.contains(root_name.as_str()) {
                bail!("the vault already contains '{}'", root_name);
            }
            insert_planned(&mut plan, source, &root_name, EntryKind::File, &metadata)?;
            continue;
        }

        if metadata.is_dir() {
            if existing.contains(root_name.as_str()) {
                bail!("the vault already contains '{}'", root_name);
            }
            insert_planned(&mut plan, source, &root_name, EntryKind::Dir, &metadata)?;

            for item in WalkDir::new(source).min_depth(1).follow_links(false) {
                let item = item
                    .with_context(|| format!("could not walk {}", source.display()))?;
                let relative = item
                    .path()
                    .strip_prefix(source)
                    .context("internal error: walkdir returned a path outside the source")?;
                let relative = source_relative_to_stored(relative)?;
                let stored_path = format!("{root_name}/{relative}");
                validate_stored_path(&stored_path)?;

                if same_file(item.path(), vault_path) {
                    bail!(
                        "the vault is inside the source directory ({}); move the vault out of the directory or add individual files instead",
                        item.path().display()
                    );
                }
                let file_type = item.file_type();
                if file_type.is_symlink() {
                    skipped.push(format!(
                        "{} (symbolic link)",
                        item.path().display()
                    ));
                    continue;
                }
                if file_type.is_dir() {
                    if existing.contains(stored_path.as_str()) {
                        bail!("the vault already contains '{}'", stored_path);
                    }
                    let metadata = item.metadata().with_context(|| {
                        format!("could not inspect {}", item.path().display())
                    })?;
                    insert_planned(
                        &mut plan,
                        item.path(),
                        &stored_path,
                        EntryKind::Dir,
                        &metadata,
                    )?;
                } else if file_type.is_file() {
                    if existing.contains(stored_path.as_str()) {
                        bail!("the vault already contains '{}'", stored_path);
                    }
                    let metadata = item.metadata().with_context(|| {
                        format!("could not inspect {}", item.path().display())
                    })?;
                    insert_planned(
                        &mut plan,
                        item.path(),
                        &stored_path,
                        EntryKind::File,
                        &metadata,
                    )?;
                } else {
                    skipped.push(format!(
                        "{} (special file)",
                        item.path().display()
                    ));
                }
            }
            continue;
        }

        bail!(
            "unsupported source type: {} (only regular files and directories are supported)",
            source.display()
        );
    }

    Ok((plan, skipped))
}

fn insert_planned(
    plan: &mut BTreeMap<String, PlannedEntry>,
    source: &Path,
    stored_path: &str,
    kind: EntryKind,
    metadata: &fs::Metadata,
) -> Result<()> {
    let (mtime_secs, mtime_nanos) = metadata_mtime(metadata)?;
    let planned = PlannedEntry {
        path: stored_path.to_string(),
        source: if kind == EntryKind::File {
            Some(source.to_path_buf())
        } else {
            None
        },
        kind,
        mode: metadata_mode(metadata),
        mtime_secs,
        mtime_nanos,
    };
    if plan.insert(stored_path.to_string(), planned).is_some() {
        bail!("multiple sources would be added as '{stored_path}'");
    }
    Ok(())
}

fn validate_combined_hierarchy(index: &Index, plan: &BTreeMap<String, PlannedEntry>) -> Result<()> {
    let mut combined: BTreeMap<&str, bool> = BTreeMap::new();
    for entry in &index.entries {
        combined.insert(entry.path.as_str(), entry.kind == EntryKind::Dir);
    }
    for (path, planned) in plan {
        if combined
            .insert(path.as_str(), planned.kind == EntryKind::Dir)
            .is_some()
        {
            bail!("the vault already contains '{}'", path);
        }
    }

    let paths: Vec<&str> = combined.keys().copied().collect();
    for (index, path) in paths.iter().enumerate() {
        if !combined[*path] {
            let prefix = format!("{path}/");
            if let Some(next) = paths.get(index + 1) {
                if next.starts_with(&prefix) {
                    bail!(
                        "'{}' would be stored as a file but also needs to contain '{}'",
                        path,
                        next
                    );
                }
            }
        }
    }
    Ok(())
}

fn source_root_name(source: &Path) -> Result<String> {
    let direct = source.file_name().and_then(|name| name.to_str());
    if let Some(name) = direct {
        if !name.is_empty() && name != "." && name != ".." {
            return Ok(name.to_string());
        }
    }
    let canonical = fs::canonicalize(source)
        .with_context(|| format!("could not resolve {}", source.display()))?;
    canonical
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .with_context(|| {
            format!(
                "source path '{}' has no usable name; use --as",
                source.display()
            )
        })
}

fn normalize_destination(destination: &str) -> Result<String> {
    let trimmed = destination.trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("--as cannot be empty");
    }
    validate_stored_path(trimmed)?;
    Ok(trimmed.to_string())
}

fn validate_stored_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 4096 {
        bail!("invalid vault path length");
    }
    if path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        bail!("unsafe vault path: {path:?}");
    }
    if path.chars().any(|ch| ch.is_control()) {
        bail!("vault paths cannot contain control characters");
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            bail!("unsafe vault path: {path:?}");
        }
    }
    Ok(())
}

fn source_relative_to_stored(relative: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .with_context(|| format!("non-UTF-8 file name in {relative:?}"))?;
                if name.contains('\\') || name.chars().any(|ch| ch.is_control()) {
                    bail!("unsafe file name in source directory: {name:?}");
                }
                parts.push(name);
            }
            _ => bail!("unexpected path component in source directory: {relative:?}"),
        }
    }
    if parts.is_empty() {
        bail!("empty relative source path");
    }
    Ok(parts.join("/"))
}

fn same_file(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (fs::metadata(a), fs::metadata(b)) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ma.dev() == mb.dev() && ma.ino() == mb.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (ma, mb);
        fs::canonicalize(a).ok() == fs::canonicalize(b).ok()
    }
}

fn ensure_index_has_room(index: &Index) -> Result<()> {
    if index.entries.len() > MAX_ENTRIES {
        bail!("the vault would exceed the supported {MAX_ENTRIES} entries");
    }
    Ok(())
}

fn find_entry<'a>(index: &'a Index, path: &str) -> Result<&'a Entry> {
    validate_stored_path(path)?;
    index
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .with_context(|| format!("no entry named '{path}' exists in this vault"))
}

fn decrypt_chunk(
    file: &mut File,
    header: &Header,
    key: &[u8],
    entry: &Entry,
    chunk_index: usize,
    chunk: &Chunk,
) -> Result<Vec<u8>> {
    let nonce = hex::decode(&chunk.nonce).context("chunk nonce is malformed")?;
    if nonce.len() != crypto::NONCE_LEN {
        bail!("chunk nonce has an invalid length");
    }
    let mut ciphertext = vec![0u8; usize::try_from(chunk.stored_len)?];
    file.seek(SeekFrom::Start(chunk.offset))?;
    file.read_exact(&mut ciphertext)
        .with_context(|| format!("could not read chunk {chunk_index} of '{}'", entry.path))?;
    let aad = chunk_aad(&header.vault_id, entry.id, chunk_index, chunk.codec);
    let plaintext = crypto::decrypt(key, &nonce, &ciphertext, &aad).with_context(|| {
        format!(
            "chunk {chunk_index} of '{}' failed authentication (vault data is corrupted or tampered with)",
            entry.path
        )
    })?;

    let bytes = match chunk.codec {
        Codec::Raw => plaintext,
        Codec::Lz4 => lz4_flex::decompress(&plaintext, chunk.plain_len as usize)
            .with_context(|| format!("could not decompress '{}'", entry.path))?,
    };
    if bytes.len() != chunk.plain_len as usize {
        bail!(
            "chunk {chunk_index} of '{}' has an unexpected size",
            entry.path
        );
    }
    Ok(bytes)
}

fn write_entry_file(
    file: &mut File,
    header: &Header,
    key: &[u8],
    entry: &Entry,
    destination: &Path,
    force: bool,
) -> Result<u64> {
    if let Ok(metadata) = fs::symlink_metadata(destination) {
        if metadata.file_type().is_symlink() {
            bail!(
                "refusing to overwrite symbolic link '{}'",
                destination.display()
            );
        }
        if metadata.is_dir() {
            bail!("destination is a directory: {}", destination.display());
        }
        if !force {
            bail!(
                "destination already exists: {} (use --force to replace it)",
                destination.display()
            );
        }
    }

    let parent = destination.parent().filter(|path| !path.as_os_str().is_empty());
    if let Some(parent) = parent {
        create_parent_directory(parent)?;
    }

    let file_name = destination
        .file_name()
        .context("destination must include a file name")?
        .to_string_lossy()
        .to_string();
    let suffix = hex::encode(crypto::random_bytes::<8>()?);
    let temp_name = format!(".{file_name}.{suffix}.sandbox-part");
    let temp_path = match parent {
        Some(parent) => parent.join(temp_name),
        None => PathBuf::from(temp_name),
    };

    let mut temp_guard = TempPath::new(temp_path.clone());
    let mut output = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp_path)
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
        }
    }
    .with_context(|| format!("could not create {}", temp_path.display()))?;

    let mut total = 0u64;
    for (index, chunk) in entry.chunks.iter().enumerate() {
        let bytes = decrypt_chunk(file, header, key, entry, index, chunk)?;
        output
            .write_all(&bytes)
            .with_context(|| format!("could not write {}", temp_path.display()))?;
        total = total
            .checked_add(bytes.len() as u64)
            .context("extracted byte count overflowed")?;
    }
    if total != entry.size {
        bail!("entry '{}' failed its size check", entry.path);
    }
    output
        .sync_all()
        .with_context(|| format!("could not flush {}", temp_path.display()))?;
    drop(output);

    set_path_mode(&temp_path, entry.mode)?;
    fs::rename(&temp_path, destination).with_context(|| {
        format!(
            "could not move the extracted file into place at {}",
            destination.display()
        )
    })?;
    temp_guard.disarm();
    set_path_mtime(destination, entry.mtime_secs, entry.mtime_nanos)?;
    Ok(total)
}

struct TempPath {
    path: PathBuf,
    armed: bool,
}

impl TempPath {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn ensure_destination_is_not_vault(vault: &Path, destination: &Path) -> Result<()> {
    let vault_abs = comparable_path(vault)?;
    let destination_abs = comparable_path(destination)?;
    if vault_abs == destination_abs {
        bail!("refusing to extract over the vault file itself");
    }
    Ok(())
}

fn comparable_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("could not determine the current directory")?
            .join(path)
    };
    if absolute.exists() {
        return fs::canonicalize(&absolute)
            .with_context(|| format!("could not resolve {}", absolute.display()));
    }
    let file_name = absolute.file_name().context("path has no file name")?;
    let parent = absolute.parent().unwrap_or_else(|| Path::new("/"));
    let parent = if parent.exists() {
        fs::canonicalize(parent)
            .with_context(|| format!("could not resolve {}", parent.display()))?
    } else {
        lexical_normalize(parent)
    };
    Ok(parent.join(file_name))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn create_root_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            bail!("destination directory is a symbolic link: {}", path.display());
        }
        if !metadata.is_dir() {
            bail!("destination is not a directory: {}", path.display());
        }
        return Ok(());
    }
    fs::create_dir_all(path)
        .with_context(|| format!("could not create destination directory {}", path.display()))?;
    Ok(())
}

fn create_parent_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            bail!("destination parent is a symbolic link: {}", path.display());
        }
        if !metadata.is_dir() {
            bail!("destination parent is not a directory: {}", path.display());
        }
        return Ok(());
    }
    fs::create_dir_all(path)
        .with_context(|| format!("could not create destination directory {}", path.display()))?;
    Ok(())
}

fn ensure_descendant_dir(root: &Path, stored_dir: &str) -> Result<()> {
    let mut current = root.to_path_buf();
    for component in stored_dir.split('/') {
        current.push(component);
        if current.exists() {
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "refusing to extract through symbolic link '{}'",
                    current.display()
                );
            }
            if !metadata.is_dir() {
                bail!("'{}' exists and is not a directory", current.display());
            }
        } else {
            fs::create_dir(&current)
                .with_context(|| format!("could not create {}", current.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&current, fs::Permissions::from_mode(0o700));
            }
        }
    }
    Ok(())
}

fn stored_path_to_path(root: &Path, stored: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in stored.split('/') {
        path.push(component);
    }
    path
}

fn metadata_mtime(metadata: &fs::Metadata) -> Result<(i64, u32)> {
    match metadata.modified() {
        Ok(modified) => match modified.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok((
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
                duration.subsec_nanos(),
            )),
            Err(_) => Ok((0, 0)),
        },
        Err(_) => Ok((0, 0)),
    }
}

fn metadata_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0o644
    }
}

fn set_path_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if mode == 0 { 0o600 } else { mode & 0o777 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("could not set permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn set_path_mtime(path: &Path, secs: i64, nanos: u32) -> Result<()> {
    let timestamp = filetime::FileTime::from_unix_time(secs, nanos);
    filetime::set_file_mtime(path, timestamp)
        .with_context(|| format!("could not restore the timestamp on {}", path.display()))?;
    Ok(())
}

fn set_private_file_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("could not set vault permissions to 0600")?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn push_problem(problems: &mut Vec<String>, truncated: &mut bool, message: String) {
    if problems.len() < MAX_PROBLEMS {
        problems.push(message);
    } else {
        *truncated = true;
    }
}
