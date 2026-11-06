// SPDX-License-Identifier: GPL-3.0-or-later

//! Cryptographic primitives used by the vault format.
//!
//! Argon2id turns the user's passphrase into a root key. A domain-separated
//! BLAKE2s step derives the 256-bit vault key. Every index and data block is
//! sealed with ChaCha20-Poly1305 and a fresh 96-bit random nonce.

use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

pub const DEFAULT_MEMORY_MIB: u32 = 64;
pub const DEFAULT_ITERATIONS: u32 = 3;
pub const DEFAULT_PARALLELISM: u32 = 1;

// The header is unauthenticated input. Keep hostile KDF parameters from
// turning an unlock attempt into an out-of-memory event.
pub const MAX_KDF_MEMORY_KIB: u32 = 1_048_576; // 1 GiB
pub const MAX_KDF_ITERATIONS: u32 = 64;
pub const MAX_KDF_PARALLELISM: u32 = 8;

const KEY_DOMAIN: &[u8] = b"sandbox-cli/vault-key/v1";

#[derive(Clone, Copy, Debug)]
pub struct KdfSettings {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfSettings {
    pub fn from_mib(memory_mib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        if memory_mib == 0 {
            bail!("KDF memory must be greater than zero");
        }
        let memory_kib = memory_mib
            .checked_mul(1024)
            .context("KDF memory value is too large")?;
        let settings = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < 8 * self.parallelism {
            bail!(
                "Argon2 memory is too small: at least {} KiB is required for {} lane(s)",
                8 * self.parallelism,
                self.parallelism
            );
        }
        if self.memory_kib > MAX_KDF_MEMORY_KIB {
            bail!(
                "Argon2 memory of {} KiB exceeds the safety limit of {} KiB",
                self.memory_kib,
                MAX_KDF_MEMORY_KIB
            );
        }
        if self.iterations == 0 || self.iterations > MAX_KDF_ITERATIONS {
            bail!("Argon2 iterations must be between 1 and {MAX_KDF_ITERATIONS}");
        }
        if self.parallelism == 0 || self.parallelism > MAX_KDF_PARALLELISM {
            bail!("Argon2 parallelism must be between 1 and {MAX_KDF_PARALLELISM}");
        }
        Ok(())
    }
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("the operating system random number generator failed: {err}"))?;
    Ok(bytes)
}

pub fn derive_key(password: &str, salt: &[u8], settings: KdfSettings) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    settings.validate()?;
    if salt.len() < 8 {
        bail!("the vault salt is invalid");
    }
    if password.len() < 8 {
        bail!("passphrase must be at least 8 bytes long");
    }
    if password.len() > 1024 {
        bail!("passphrase is longer than the supported 1024-byte limit");
    }

    let params = Params::new(
        settings.memory_kib,
        settings.iterations,
        settings.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|err| anyhow::anyhow!("invalid Argon2 parameters: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut root = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, root.as_mut())
        .map_err(|err| anyhow::anyhow!("Argon2 key derivation failed: {err}"))?;

    let mut hasher = Blake2s256::new();
    hasher.update(root.as_ref());
    hasher.update(KEY_DOMAIN);
    let digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&digest[..KEY_LEN]);
    Ok(key)
}

pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    if key.len() != KEY_LEN {
        bail!("internal error: invalid encryption key length");
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("internal error: could not initialize the cipher"))?;
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok((ciphertext, nonce))
}

pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_LEN {
        bail!("internal error: invalid encryption key length");
    }
    if nonce.len() != NONCE_LEN {
        bail!("block nonce has an invalid length");
    }
    if ciphertext.len() < TAG_LEN {
        bail!("encrypted block is truncated");
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("internal error: could not initialize the cipher"))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("authentication failed"))
}
