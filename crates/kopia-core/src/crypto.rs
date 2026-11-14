//! Cryptographic and compression primitives compatible with Kopia v2/v3 repositories.
//!
//! Currently supports:
//! - Envelope decryption of `kopia.repository` (`scrypt` + `HKDF-SHA256` + `AES256_GCM`)
//! - Content encryption (`AES256-GCM-HMAC-SHA256`)
//! - Content compression (`none`, `zstd` via `ruzstd`, and `gzip` for manifests via `flate2`)

use std::io::Read;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use flate2::read::GzDecoder;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ruzstd::StreamingDecoder;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{KopiaError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Raw JSON structure of `kopia.repository` (or `kopia.repository.f`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KopiaRepositoryBlob {
    #[serde(rename = "uniqueID")]
    pub unique_id: String,
    pub key_algo: String,
    pub encryption: String,
    pub encrypted_block_format: String,
}

/// Decrypted repository format envelope (`{"format": ...}`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecryptedFormatEnvelope {
    pub format: RepoFormat,
}

/// Inner repository format configuration containing master keys and algorithm identifiers.
///
/// In Cloudflare Workers, this struct (serialized as JSON) can be injected directly as a
/// Worker Secret so cold starts skip `scrypt` key derivation completely.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoFormat {
    pub hash: String,
    pub encryption: String,
    pub secret: String,
    pub master_key: String,
    pub version: u32,
    pub index_version: u32,
}

impl KopiaRepositoryBlob {
    /// Parses `kopia.repository` JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| KopiaError::InvalidFormat(format!("invalid kopia.repository JSON: {e}")))
    }

    /// Decrypts `encryptedBlockFormat` using the repository password.
    pub fn decrypt(&self, password: &str) -> Result<RepoFormat> {
        if self.encryption != "AES256_GCM" {
            return Err(KopiaError::Unsupported(format!(
                "unsupported format encryption: {}",
                self.encryption
            )));
        }

        let salt = BASE64
            .decode(&self.unique_id)
            .map_err(|e| KopiaError::InvalidFormat(format!("invalid uniqueID base64: {e}")))?;

        let master_key = derive_scrypt_key(password.as_bytes(), &salt, &self.key_algo)?;

        let hk = Hkdf::<Sha256>::new(Some(&salt), &master_key);
        let mut aes_key = [0u8; 32];
        let mut auth_data = [0u8; 32];
        hk.expand(b"AES", &mut aes_key)
            .map_err(|e| KopiaError::Crypto(format!("HKDF AES key failed: {e}")))?;
        hk.expand(b"CHECKSUM", &mut auth_data)
            .map_err(|e| KopiaError::Crypto(format!("HKDF CHECKSUM failed: {e}")))?;

        let raw = BASE64
            .decode(&self.encrypted_block_format)
            .map_err(|e| KopiaError::InvalidFormat(format!("invalid encryptedBlockFormat: {e}")))?;

        if raw.len() < 12 + 16 {
            return Err(KopiaError::InvalidFormat(
                "encryptedBlockFormat too short".into(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| KopiaError::Crypto(format!("AES-GCM init failed: {e}")))?;
        let nonce = Nonce::from_slice(&raw[..12]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &raw[12..],
                    aad: &auth_data,
                },
            )
            .map_err(|_| {
                KopiaError::Crypto("failed to decrypt kopia.repository (wrong password?)".into())
            })?;

        let env: DecryptedFormatEnvelope = serde_json::from_slice(&pt).map_err(|e| {
            KopiaError::InvalidFormat(format!("invalid decrypted format JSON: {e}"))
        })?;
        Ok(env.format)
    }
}

fn derive_scrypt_key(password: &[u8], salt: &[u8], algo: &str) -> Result<[u8; 32]> {
    // Expected format: "scrypt-65536-8-1"
    let parts: Vec<&str> = algo.split('-').collect();
    if parts.len() != 4 || parts[0] != "scrypt" {
        return Err(KopiaError::Unsupported(format!(
            "unsupported keyAlgo: {algo}"
        )));
    }
    let n: u64 = parts[1]
        .parse()
        .map_err(|_| KopiaError::InvalidFormat(format!("invalid scrypt N: {}", parts[1])))?;
    let r: u32 = parts[2]
        .parse()
        .map_err(|_| KopiaError::InvalidFormat(format!("invalid scrypt r: {}", parts[2])))?;
    let p: u32 = parts[3]
        .parse()
        .map_err(|_| KopiaError::InvalidFormat(format!("invalid scrypt p: {}", parts[3])))?;

    if !n.is_power_of_two() || n == 0 {
        return Err(KopiaError::InvalidFormat(format!("scrypt N must be power of 2: {n}")));
    }
    let log_n = n.trailing_zeros() as u8;
    let params = scrypt::Params::new(log_n, r, p, 32)
        .map_err(|e| KopiaError::Crypto(format!("invalid scrypt params: {e}")))?;

    let mut out = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut out)
        .map_err(|e| KopiaError::Crypto(format!("scrypt failed: {e}")))?;
    Ok(out)
}

/// Content-level crypter initialized from `RepoFormat`.
#[derive(Clone)]
pub struct ContentCrypter {
    key_derivation_secret: [u8; 32],
}

impl ContentCrypter {
    /// Initializes the crypter from a decrypted `RepoFormat`.
    pub fn from_format(fmt: &RepoFormat) -> Result<Self> {
        if fmt.encryption != "AES256-GCM-HMAC-SHA256" {
            return Err(KopiaError::Unsupported(format!(
                "unsupported content encryption: {}",
                fmt.encryption
            )));
        }

        let master_key = BASE64
            .decode(&fmt.master_key)
            .map_err(|e| KopiaError::InvalidFormat(format!("invalid masterKey base64: {e}")))?;

        // Kopia derives encryption secret using HKDF(ikm=masterKey, salt="encryption", info="")
        let hk = Hkdf::<Sha256>::new(Some(b"encryption"), &master_key);
        let mut key_derivation_secret = [0u8; 32];
        hk.expand(b"", &mut key_derivation_secret)
            .map_err(|e| KopiaError::Crypto(format!("HKDF encryption key failed: {e}")))?;

        Ok(Self {
            key_derivation_secret,
        })
    }

    /// Decrypts a packed content or index blob using the 16-byte IV/AAD.
    pub fn decrypt_with_iv(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            return Err(KopiaError::InvalidFormat(format!(
                "ciphertext too short: {} bytes",
                ciphertext.len()
            )));
        }

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key_derivation_secret)
            .map_err(|e| KopiaError::Crypto(format!("HMAC init failed: {e}")))?;
        mac.update(iv);
        let key_bytes = mac.finalize().into_bytes();

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| KopiaError::Crypto(format!("AES-GCM init failed: {e}")))?;
        let nonce = Nonce::from_slice(&ciphertext[..12]);

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext[12..],
                    aad: iv,
                },
            )
            .map_err(|_| KopiaError::Crypto("AEAD decryption failed".into()))
    }

    /// Decrypts an index blob (`xn0_...`) by deriving the 16-byte IV from its blob ID.
    pub fn decrypt_index_blob(&self, blob_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let iv = get_index_blob_iv(blob_id)?;
        self.decrypt_with_iv(ciphertext, &iv)
    }
}

/// Extracts the 16-byte IV from an index blob ID:
/// takes the 32 hex chars immediately preceding the first `'-'`.
pub fn get_index_blob_iv(blob_id: &str) -> Result<[u8; 16]> {
    let prefix_part = blob_id.split('-').next().unwrap_or(blob_id);
    if prefix_part.len() < 32 {
        return Err(KopiaError::InvalidFormat(format!(
            "blob ID too short for IV: {blob_id}"
        )));
    }
    let hex_iv = &prefix_part[prefix_part.len() - 32..];
    let bytes = hex::decode(hex_iv)
        .map_err(|e| KopiaError::InvalidFormat(format!("invalid hex in blob ID {blob_id}: {e}")))?;
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&bytes);
    Ok(iv)
}

/// Decompresses content payload according to Kopia's `CompressionHeaderID`.
///
/// When `compression_header_id != 0`, Kopia prepends a 4-byte compression header
/// before the compressed stream.
pub fn decompress_content(compression_header_id: u32, data: &[u8]) -> Result<Vec<u8>> {
    if compression_header_id == 0 {
        return Ok(data.to_vec());
    }

    if data.len() < 4 {
        return Err(KopiaError::Decompression(
            "compressed payload shorter than 4-byte header".into(),
        ));
    }

    // Strip the 4-byte Kopia compression header.
    let stream = &data[4..];

    match compression_header_id {
        // zstd variants in Kopia: 0x1100 (zstd), 0x1101 (zstd-fastest), 0x1102 (zstd-better), 0x1103 (zstd-best)
        0x1100..=0x1103 => {
            let mut decoder = StreamingDecoder::new(stream)
                .map_err(|e| KopiaError::Decompression(format!("zstd init failed: {e}")))?;
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| KopiaError::Decompression(format!("zstd decode failed: {e}")))?;
            Ok(out)
        }
        other => Err(KopiaError::Unsupported(format!(
            "unsupported compressionHeaderID: 0x{other:x}"
        ))),
    }
}

/// Decompresses gzip-wrapped payloads (used by Kopia manifest blobs `m*`).
pub fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| KopiaError::Decompression(format!("gzip decode failed: {e}")))?;
    Ok(out)
}
