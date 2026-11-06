// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort operating-system protection for the vault file.
//!
//! On macOS a user-owned file can be marked `uchg` (immutable) without root.
//! On Linux the equivalent `chattr +i` flag requires CAP_LINUX_IMMUTABLE, so a
//! normal user will get an actionable warning instead of a misleading success.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::{Command, Output};

#[derive(Clone, Debug)]
pub struct ProtectionStatus {
    pub supported: bool,
    pub protected: bool,
    pub method: &'static str,
    pub detail: Option<String>,
}

pub fn platform() -> &'static str {
    std::env::consts::OS
}

pub fn status(path: &Path) -> ProtectionStatus {
    let path = canonical_or_original(path);
    let path = path.as_path();
    #[cfg(target_os = "macos")]
    {
        return macos_status(path);
    }
    #[cfg(target_os = "linux")]
    {
        return linux_status(path);
    }
    #[allow(unreachable_code)]
    ProtectionStatus {
        supported: false,
        protected: false,
        method: "unsupported",
        detail: Some(format!(
            "immutable file flags are not implemented on {}",
            std::env::consts::OS
        )),
    }
}

#[allow(unreachable_code)]
pub fn protect(path: &Path) -> Result<ProtectionStatus> {
    let path = canonical_or_original(path);
    let path = path.as_path();
    #[cfg(target_os = "macos")]
    {
        run_checked("chflags", &["uchg"], path)?;
        return Ok(macos_status(path));
    }
    #[cfg(target_os = "linux")]
    {
        run_checked("chattr", &["+i"], path).with_context(|| {
            "could not set the Linux immutable flag. This normally requires root \
             (for example: sudo chattr +i PATH). The vault is still encrypted, but it is not \
             protected from deletion."
        })?;
        return Ok(linux_status(path));
    }
    bail!(
        "immutable file flags are not supported on {}",
        std::env::consts::OS
    )
}

#[allow(unreachable_code)]
pub fn unprotect(path: &Path) -> Result<()> {
    let path = canonical_or_original(path);
    let path = path.as_path();
    #[cfg(target_os = "macos")]
    {
        run_checked("chflags", &["nouchg"], path)?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        run_checked("chattr", &["-i"], path).with_context(|| {
            "could not clear the Linux immutable flag. This normally requires root \
             (for example: sudo chattr -i PATH)."
        })?;
        return Ok(());
    }
    bail!(
        "immutable file flags are not supported on {}",
        std::env::consts::OS
    )
}

#[cfg(target_os = "macos")]
fn macos_status(path: &Path) -> ProtectionStatus {
    match Command::new("stat").arg("-f").arg("%Sf").arg(path).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let protected = text
                .trim()
                .split(',')
                .any(|flag| flag.trim() == "uchg");
            ProtectionStatus {
                supported: true,
                protected,
                method: "macOS chflags uchg",
                detail: if protected {
                    None
                } else {
                    Some("vault is writable and can be deleted by its owner".to_string())
                },
            }
        }
        Ok(output) => ProtectionStatus {
            supported: true,
            protected: false,
            method: "macOS chflags uchg",
            detail: Some(command_error(&output)),
        },
        Err(err) => ProtectionStatus {
            supported: true,
            protected: false,
            method: "macOS chflags uchg",
            detail: Some(format!("could not inspect file flags: {err}")),
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_status(path: &Path) -> ProtectionStatus {
    match Command::new("lsattr").arg("-d").arg(path).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let attrs = text.split_whitespace().next().unwrap_or_default();
            let supported = !attrs.is_empty();
            let protected = supported && attrs.contains('i');
            ProtectionStatus {
                supported,
                protected,
                method: "Linux chattr +i",
                detail: if supported {
                    if protected {
                        None
                    } else {
                        Some(
                            "vault is writable and can be deleted; chattr +i requires root"
                                .to_string(),
                        )
                    }
                } else {
                    Some("this filesystem does not report extended attributes".to_string())
                },
            }
        }
        Ok(output) => ProtectionStatus {
            supported: false,
            protected: false,
            method: "Linux chattr +i",
            detail: Some(command_error(&output)),
        },
        Err(err) => ProtectionStatus {
            supported: false,
            protected: false,
            method: "Linux chattr +i",
            detail: Some(format!("could not run lsattr: {err}")),
        },
    }
}

fn run_checked(program: &str, flag: &[&str], path: &Path) -> Result<()> {
    let output = Command::new(program)
        .args(flag)
        .arg(path)
        .output()
        .with_context(|| format!("could not run {program}; is it installed?"))?;
    if !output.status.success() {
        bail!("{}", command_error(&output));
    }
    Ok(())
}

fn canonical_or_original(path: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn command_error(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        format!("command failed with status {}", output.status)
    } else {
        stderr
    }
}
