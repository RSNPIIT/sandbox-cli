// SPDX-License-Identifier: GPL-3.0-or-later

//! PyO3 bindings. The Python layer never touches vault ciphertext directly;
//! it only handles argument parsing, prompts, and presentation.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use std::path::PathBuf;

mod crypto;
mod protect;
mod vault;

create_exception!(
    sandbox_engine,
    VaultError,
    PyException,
    "An error raised by the Sandbox vault engine."
);

fn to_py_err(error: anyhow::Error) -> PyErr {
    VaultError::new_err(format!("{error:#}"))
}

fn status_info(status: protect::ProtectionStatus) -> ProtectionInfo {
    ProtectionInfo {
        supported: status.supported,
        protected: status.protected,
        method: status.method.to_string(),
        detail: status.detail,
    }
}

#[pyclass(module = "sandbox_cli.sandbox_engine")]
#[derive(Clone)]
struct ProtectionInfo {
    #[pyo3(get)]
    supported: bool,
    #[pyo3(get)]
    protected: bool,
    #[pyo3(get)]
    method: String,
    #[pyo3(get)]
    detail: Option<String>,
}

#[pyclass(module = "sandbox_cli.sandbox_engine")]
struct CreateInfo {
    #[pyo3(get)]
    vault_id: String,
    #[pyo3(get)]
    created_at: i64,
    #[pyo3(get)]
    protection: ProtectionInfo,
    #[pyo3(get)]
    warning: Option<String>,
}

#[pyclass(module = "sandbox_cli.sandbox_engine")]
struct AddSummary {
    #[pyo3(get)]
    files_added: u64,
    #[pyo3(get)]
    dirs_added: u64,
    #[pyo3(get)]
    bytes_added: u64,
    #[pyo3(get)]
    stored_bytes_added: u64,
    #[pyo3(get)]
    total_entries: u64,
    #[pyo3(get)]
    skipped: Vec<String>,
    #[pyo3(get)]
    protection: ProtectionInfo,
    #[pyo3(get)]
    warning: Option<String>,
}

#[pyclass(module = "sandbox_cli.sandbox_engine")]
struct EntryInfo {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    stored_size: u64,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    mtime_secs: i64,
    #[pyo3(get)]
    mtime_nanos: u32,
    #[pyo3(get)]
    chunks: u64,
}

#[pyclass(module = "sandbox_cli.sandbox_engine")]
struct VaultInfo {
    #[pyo3(get)]
    format_version: u16,
    #[pyo3(get)]
    kdf_memory_kib: u32,
    #[pyo3(get)]
    kdf_iterations: u32,
    #[pyo3(get)]
    kdf_parallelism: u32,
    #[pyo3(get)]
    sequence: u64,
    #[pyo3(get)]
    created_at: i64,
    #[pyo3(get)]
    updated_at: i64,
    #[pyo3(get)]
    file_size: u64,
    #[pyo3(get)]
    vault_id: String,
    #[pyo3(get)]
    protection: ProtectionInfo,
    #[pyo3(get)]
    platform: String,
}

#[pyclass(module = "sandbox_cli.sandbox_engine")]
struct ExtractInfo {
    #[pyo3(get)]
    entries_written: u64,
    #[pyo3(get)]
    bytes_written: u64,
}

#[pyclass(module = "sandbox_cli.sandbox_engine")]
struct VerifyReport {
    #[pyo3(get)]
    ok: bool,
    #[pyo3(get)]
    entries_checked: u64,
    #[pyo3(get)]
    chunks_checked: u64,
    #[pyo3(get)]
    bytes_verified: u64,
    #[pyo3(get)]
    problems: Vec<String>,
    #[pyo3(get)]
    problems_truncated: bool,
}

#[pyfunction]
fn version() -> String {
    format!("sandbox_engine v{} (Rust)", env!("CARGO_PKG_VERSION"))
}

#[pyfunction]
#[pyo3(signature = (vault, password, memory_mib=64, iterations=3, parallelism=1, protect_after=true))]
fn create_vault(
    vault: PathBuf,
    password: &str,
    memory_mib: u32,
    iterations: u32,
    parallelism: u32,
    protect_after: bool,
) -> PyResult<CreateInfo> {
    let result = vault::create(
        &vault,
        password,
        memory_mib,
        iterations,
        parallelism,
        protect_after,
    )
    .map_err(to_py_err)?;
    Ok(CreateInfo {
        vault_id: result.vault_id,
        created_at: result.created_at,
        protection: status_info(result.protection),
        warning: result.warning,
    })
}

#[pyfunction]
#[pyo3(signature = (vault, password, sources, destination=None, protect_after=true))]
fn add_paths(
    vault: PathBuf,
    password: &str,
    sources: Vec<PathBuf>,
    destination: Option<&str>,
    protect_after: bool,
) -> PyResult<AddSummary> {
    let result = vault::add(
        &vault,
        password,
        &sources,
        destination,
        protect_after,
    )
    .map_err(to_py_err)?;
    Ok(AddSummary {
        files_added: result.files_added,
        dirs_added: result.dirs_added,
        bytes_added: result.bytes_added,
        stored_bytes_added: result.stored_bytes_added,
        total_entries: result.total_entries,
        skipped: result.skipped,
        protection: status_info(result.protection),
        warning: result.warning,
    })
}

#[pyfunction]
fn list_entries(vault: PathBuf, password: &str) -> PyResult<Vec<EntryInfo>> {
    let entries = vault::list(&vault, password).map_err(to_py_err)?;
    Ok(entries
        .into_iter()
        .map(|entry| EntryInfo {
            path: entry.path,
            kind: entry.kind,
            size: entry.size,
            stored_size: entry.stored_size,
            mode: entry.mode,
            mtime_secs: entry.mtime_secs,
            mtime_nanos: entry.mtime_nanos,
            chunks: entry.chunks,
        })
        .collect())
}

#[pyfunction]
fn vault_info(vault: PathBuf) -> PyResult<VaultInfo> {
    let info = vault::info(&vault).map_err(to_py_err)?;
    Ok(VaultInfo {
        format_version: info.format_version,
        kdf_memory_kib: info.kdf_memory_kib,
        kdf_iterations: info.kdf_iterations,
        kdf_parallelism: info.kdf_parallelism,
        sequence: info.sequence,
        created_at: info.created_at,
        updated_at: info.updated_at,
        file_size: info.file_size,
        vault_id: info.vault_id,
        protection: status_info(info.protection),
        platform: info.platform,
    })
}

#[pyfunction]
#[pyo3(signature = (vault, password, entry, destination, force=false))]
fn extract_entry(
    vault: PathBuf,
    password: &str,
    entry: &str,
    destination: PathBuf,
    force: bool,
) -> PyResult<ExtractInfo> {
    let result =
        vault::extract(&vault, password, entry, &destination, force).map_err(to_py_err)?;
    Ok(ExtractInfo {
        entries_written: result.entries_written,
        bytes_written: result.bytes_written,
    })
}

#[pyfunction]
#[pyo3(signature = (vault, password, destination, force=false))]
fn extract_all(
    vault: PathBuf,
    password: &str,
    destination: PathBuf,
    force: bool,
) -> PyResult<ExtractInfo> {
    let result = vault::extract_all(&vault, password, &destination, force).map_err(to_py_err)?;
    Ok(ExtractInfo {
        entries_written: result.entries_written,
        bytes_written: result.bytes_written,
    })
}

#[pyfunction]
fn read_entry(vault: PathBuf, password: &str, entry: &str) -> PyResult<Vec<u8>> {
    vault::read_entry(&vault, password, entry).map_err(to_py_err)
}

#[pyfunction]
fn verify_vault(vault: PathBuf, password: &str) -> PyResult<VerifyReport> {
    let result = vault::verify(&vault, password).map_err(to_py_err)?;
    Ok(VerifyReport {
        ok: result.ok,
        entries_checked: result.entries_checked,
        chunks_checked: result.chunks_checked,
        bytes_verified: result.bytes_verified,
        problems: result.problems,
        problems_truncated: result.problems_truncated,
    })
}

#[pyfunction]
fn protection_status(vault: PathBuf) -> ProtectionInfo {
    status_info(vault::protection_status(&vault))
}

#[pyfunction]
fn protect_vault(vault: PathBuf) -> PyResult<ProtectionInfo> {
    let status = vault::protect_vault(&vault).map_err(to_py_err)?;
    Ok(status_info(status))
}

#[pymodule]
fn sandbox_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("DEFAULT_KDF_MEMORY_MIB", crypto::DEFAULT_MEMORY_MIB)?;
    m.add("DEFAULT_KDF_ITERATIONS", crypto::DEFAULT_ITERATIONS)?;
    m.add("DEFAULT_KDF_PARALLELISM", crypto::DEFAULT_PARALLELISM)?;
    m.add("VaultError", m.py().get_type::<VaultError>())?;
    m.add_class::<ProtectionInfo>()?;
    m.add_class::<CreateInfo>()?;
    m.add_class::<AddSummary>()?;
    m.add_class::<EntryInfo>()?;
    m.add_class::<VaultInfo>()?;
    m.add_class::<ExtractInfo>()?;
    m.add_class::<VerifyReport>()?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;
    m.add_function(wrap_pyfunction!(add_paths, m)?)?;
    m.add_function(wrap_pyfunction!(list_entries, m)?)?;
    m.add_function(wrap_pyfunction!(vault_info, m)?)?;
    m.add_function(wrap_pyfunction!(extract_entry, m)?)?;
    m.add_function(wrap_pyfunction!(extract_all, m)?)?;
    m.add_function(wrap_pyfunction!(read_entry, m)?)?;
    m.add_function(wrap_pyfunction!(verify_vault, m)?)?;
    m.add_function(wrap_pyfunction!(protection_status, m)?)?;
    m.add_function(wrap_pyfunction!(protect_vault, m)?)?;
    Ok(())
}
