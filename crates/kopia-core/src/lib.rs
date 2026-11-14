//! Pure-Rust, read-only Kopia repository parser.
//!
//! Designed to run both in native CLI tools and inside `wasm32-unknown-unknown`
//! (Cloudflare Workers) without any C FFI dependencies.

pub mod crypto;
pub mod index;
pub mod repo;
pub mod webdav;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

/// Errors returned by Kopia repository parsing and storage operations.
#[derive(Debug, Error)]
pub enum KopiaError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("blob not found: {0}")]
    NotFound(String),

    #[error("invalid repository format: {0}")]
    InvalidFormat(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("decompression error: {0}")]
    Decompression(String),

    #[error("unsupported algorithm: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, KopiaError>;

/// Metadata for a raw blob stored in the underlying backend (e.g. WebDAV or local FS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeta {
    pub id: String,
    pub length: u64,
}

/// Inclusive byte range `[start, end]` for HTTP Range requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    /// Returns the number of bytes covered by this inclusive range.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start) + 1
    }

    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }
}

/// Minimal async storage abstraction implemented by both native FS/HTTP backends
/// and Cloudflare Workers (`Fetch` + `Cache API`).
#[async_trait(?Send)]
pub trait StorageReader {
    /// Lists blobs matching the given filename prefix (e.g. `"xn"`, `"m"`, `"p"`).
    async fn list_blobs(&self, prefix: &str) -> Result<Vec<BlobMeta>>;

    /// Reads the entire contents of a blob.
    async fn read_blob(&self, blob_id: &str) -> Result<Bytes>;

    /// Reads an inclusive byte range `[offset, offset + length - 1]` from a blob.
    async fn read_blob_range(&self, blob_id: &str, offset: u64, length: u64) -> Result<Bytes>;
}
