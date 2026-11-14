//! High-level read-only Kopia repository reader: snapshots, directories, and Range object reads.

use std::collections::HashMap;
use std::pin::Pin;
use std::rc::Rc;

use bytes::Bytes;
use futures_util::stream::{self, Stream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::crypto::{decompress_content, decompress_gzip, ContentCrypter};
use crate::index::{ContentId, IndexV2, MergedIndex};
use crate::{ByteRange, KopiaError, Result, StorageReader};

/// A Kopia manifest entry stored inside an `m*` blob.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestBlob {
    pub entries: Vec<ManifestItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestItem {
    pub id: String,
    #[serde(default)]
    pub labels: Option<HashMap<String, String>>,
    pub modified: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// Summary metadata for a Kopia snapshot, returned by `list_snapshots`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotInfo {
    pub id: String,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub host: Option<String>,
    pub user_name: Option<String>,
    pub path: Option<String>,
    pub root_entry: DirEntry,
}

/// Directory or file entry in Kopia's snapshot tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub mtime: Option<String>,
    #[serde(default)]
    pub obj: Option<String>,
}

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.entry_type == "d"
    }

    pub fn is_file(&self) -> bool {
        self.entry_type == "f"
    }
}

#[derive(Debug, Deserialize)]
struct DirectoryStream {
    #[allow(dead_code)]
    stream: Option<String>,
    #[serde(default)]
    entries: Vec<DirEntry>,
}

#[derive(Debug, Deserialize)]
struct IndirectStream {
    #[allow(dead_code)]
    stream: Option<String>,
    #[serde(default)]
    entries: Vec<IndirectEntry>,
}

#[derive(Debug, Deserialize)]
struct IndirectEntry {
    #[serde(default, rename = "s")]
    start: u64,
    #[serde(default, rename = "l")]
    length: u64,
    #[serde(rename = "o")]
    object: String,
}

/// Resolved contiguous chunk slice of a Kopia object.
#[derive(Debug, Clone)]
pub struct ObjectChunk {
    pub start: u64,
    pub length: u64,
    pub content_id: ContentId,
}

/// Read-only Kopia repository client backed by any `StorageReader`.
pub struct KopiaRepo<S: StorageReader> {
    storage: S,
    crypter: ContentCrypter,
    index: Rc<MergedIndex>,
}

impl<S: StorageReader> KopiaRepo<S> {
    /// Constructs a `KopiaRepo` from a pre-loaded `MergedIndex` (e.g. Isolate cache).
    pub fn from_index(storage: S, crypter: ContentCrypter, index: Rc<MergedIndex>) -> Self {
        Self {
            storage,
            crypter,
            index,
        }
    }

    /// Returns a shared handle to the merged index.
    pub fn index(&self) -> Rc<MergedIndex> {
        Rc::clone(&self.index)
    }

    /// Opens a repository by concurrently loading and merging all `xn*` index shards.
    pub async fn open(storage: S, crypter: ContentCrypter) -> Result<Self> {
        let blobs = storage.list_blobs("xn").await?;
        let mut index = MergedIndex::default();

        {
            let storage_ref = &storage;
            let crypter_ref = &crypter;
            let mut shards_stream = stream::iter(blobs)
                .map(|blob| async move {
                    let encrypted = storage_ref.read_blob(&blob.id).await?;
                    let decrypted = crypter_ref.decrypt_index_blob(&blob.id, &encrypted)?;
                    IndexV2::parse(decrypted)
                })
                .buffered(6);

            while let Some(shard) = shards_stream.next().await {
                index.merge_shard(&shard?)?;
            }
        }

        Ok(Self {
            storage,
            crypter,
            index: Rc::new(index),
        })
    }

    /// Reads, decrypts, and decompresses a single content object by `ContentId`.
    pub async fn read_content(&self, content_id: &ContentId) -> Result<Vec<u8>> {
        let entry = self
            .index
            .get(content_id)
            .ok_or_else(|| KopiaError::NotFound(format!("content not in index: {content_id}")))?;

        let raw = self
            .storage
            .read_blob_range(
                &entry.pack_blob_id,
                u64::from(entry.pack_offset),
                u64::from(entry.packed_length),
            )
            .await?;

        let iv = content_id.iv()?;
        let decrypted = self.crypter.decrypt_with_iv(&raw, &iv)?;
        decompress_content(entry.compression_header_id, &decrypted)
    }

    /// Lists all snapshots in the repository concurrently, sorted newest-first by `start_time`.
    pub async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let manifest_entries: Vec<_> = self
            .index
            .list_with_prefix(b'm')
            .into_iter()
            .map(|e| e.content_id.clone())
            .collect();
        let mut snapshots = Vec::new();

        let mut manifest_stream = stream::iter(manifest_entries)
            .map(|cid| async move {
                let raw = self.read_content(&cid).await?;
                let json_bytes = decompress_gzip(&raw)?;
                serde_json::from_slice::<ManifestBlob>(&json_bytes).map_err(|e| {
                    KopiaError::InvalidFormat(format!("invalid manifest JSON: {e}"))
                })
            })
            .buffered(6);

        while let Some(res) = manifest_stream.next().await {
            let blob = res?;
            for item in blob.entries {
                let is_snapshot = item
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("type"))
                    .map(String::as_str)
                    == Some("snapshot");
                if !is_snapshot {
                    continue;
                }
                let root_val = item
                    .data
                    .get("rootEntry")
                    .ok_or_else(|| KopiaError::InvalidFormat("snapshot missing rootEntry".into()))?;
                let root_entry: DirEntry = serde_json::from_value(root_val.clone()).map_err(|e| {
                    KopiaError::InvalidFormat(format!("invalid rootEntry JSON: {e}"))
                })?;

                let source = item.data.get("source");
                snapshots.push(SnapshotInfo {
                    id: item.id,
                    start_time: item
                        .data
                        .get("startTime")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    end_time: item
                        .data
                        .get("endTime")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    host: source
                        .and_then(|s| s.get("host"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    user_name: source
                        .and_then(|s| s.get("userName"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    path: source
                        .and_then(|s| s.get("path"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    root_entry,
                });
            }
        }

        snapshots.sort_by(|a, b| b.start_time.cmp(&a.start_time));
        Ok(snapshots)
    }

    /// Reads and parses a directory object (`k...`) into its child entries.
    pub async fn read_directory(&self, object_id: &str) -> Result<Vec<DirEntry>> {
        let cid = normalize_object_content_id(object_id)?;
        let bytes = self.read_content(&cid).await?;
        let dir: DirectoryStream = serde_json::from_slice(&bytes).map_err(|e| {
            KopiaError::InvalidFormat(format!("invalid directory JSON for {object_id}: {e}"))
        })?;
        Ok(dir.entries)
    }

    /// Resolves a snapshot ID and relative path (e.g. `"sub/nested/info.json"` or `""` for root)
    /// to its `DirEntry`.
    pub async fn stat_path(&self, snapshot_id: &str, path: &str) -> Result<DirEntry> {
        let snapshots = self.list_snapshots().await?;
        let snap = snapshots
            .iter()
            .find(|s| s.id == snapshot_id)
            .ok_or_else(|| KopiaError::NotFound(format!("snapshot not found: {snapshot_id}")))?;
        self.stat_path_in_snapshot(snap, path).await
    }

    /// Resolves a relative path within an already-loaded `SnapshotInfo`.
    pub async fn stat_path_in_snapshot(&self, snap: &SnapshotInfo, path: &str) -> Result<DirEntry> {
        let mut current = snap.root_entry.clone();
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Ok(current);
        }

        for segment in trimmed.split('/') {
            if segment.is_empty() {
                continue;
            }
            if !current.is_dir() {
                return Err(KopiaError::NotFound(format!(
                    "path component is not a directory: {}",
                    current.name
                )));
            }
            let dir_obj = current.obj.as_deref().ok_or_else(|| {
                KopiaError::InvalidFormat(format!("directory {} missing obj ID", current.name))
            })?;
            let entries = self.read_directory(dir_obj).await?;
            current = entries
                .into_iter()
                .find(|e| e.name == segment)
                .ok_or_else(|| KopiaError::NotFound(format!("path not found: {path}")))?;
        }

        Ok(current)
    }

    /// Flattens a Kopia object ID (direct or `I`-prefixed indirect stream) into ordered chunks.
    pub async fn resolve_object_chunks(&self, object_id: &str, total_size: u64) -> Result<Vec<ObjectChunk>> {
        if let Some(rest) = object_id.strip_prefix('I') {
            let cid = ContentId::parse(rest)?;
            let raw = self.read_content(&cid).await?;
            let indirect: IndirectStream = serde_json::from_slice(&raw).map_err(|e| {
                KopiaError::InvalidFormat(format!("invalid indirect object JSON: {e}"))
            })?;

            let mut chunks = Vec::new();
            for entry in indirect.entries {
                if entry.object.starts_with('I') {
                    let sub = Box::pin(self.resolve_object_chunks(&entry.object, entry.length)).await?;
                    for mut c in sub {
                        c.start += entry.start;
                        chunks.push(c);
                    }
                } else {
                    chunks.push(ObjectChunk {
                        start: entry.start,
                        length: entry.length,
                        content_id: normalize_object_content_id(&entry.object)?,
                    });
                }
            }
            Ok(chunks)
        } else {
            Ok(vec![ObjectChunk {
                start: 0,
                length: total_size,
                content_id: normalize_object_content_id(object_id)?,
            }])
        }
    }

    /// Computes the ordered list of chunk slices required to satisfy `range`.
    async fn plan_range_chunks(
        &self,
        entry: &DirEntry,
        range: Option<ByteRange>,
    ) -> Result<(u64, Vec<ChunkSliceTask>)> {
        if !entry.is_file() {
            return Err(KopiaError::InvalidFormat(format!(
                "{} is not a regular file",
                entry.name
            )));
        }
        let total_size = entry.size.unwrap_or(0);
        if total_size == 0 {
            return Ok((0, Vec::new()));
        }

        let target = match range {
            Some(r) => {
                if r.is_empty() || r.start >= total_size {
                    return Err(KopiaError::InvalidFormat("range out of bounds".into()));
                }
                ByteRange {
                    start: r.start,
                    end: r.end.min(total_size - 1),
                }
            }
            None => ByteRange {
                start: 0,
                end: total_size - 1,
            },
        };

        let object_id = entry.obj.as_deref().ok_or_else(|| {
            KopiaError::InvalidFormat(format!("file {} missing obj ID", entry.name))
        })?;

        let chunks = self.resolve_object_chunks(object_id, total_size).await?;
        let mut tasks = Vec::new();
        for chunk in chunks {
            if chunk.length == 0 {
                continue;
            }
            let chunk_end = chunk.start + chunk.length - 1;
            if chunk_end < target.start || chunk.start > target.end {
                continue;
            }
            let slice_start = target.start.saturating_sub(chunk.start) as usize;
            let slice_end = (target.end.min(chunk_end) - chunk.start) as usize + 1;
            tasks.push(ChunkSliceTask {
                content_id: chunk.content_id,
                slice_start,
                slice_end,
            });
        }

        Ok((target.len(), tasks))
    }

    async fn fetch_chunk_slice(&self, task: ChunkSliceTask) -> Result<Vec<u8>> {
        let data = self.read_content(&task.content_id).await?;
        if task.slice_end > data.len() {
            return Err(KopiaError::InvalidFormat(format!(
                "chunk {} shorter than expected: {} < {}",
                task.content_id,
                data.len(),
                task.slice_end
            )));
        }
        Ok(data[task.slice_start..task.slice_end].to_vec())
    }

    /// Streams an optional inclusive `ByteRange` of a file `DirEntry` using a bounded
    /// sliding-window concurrent fetch (`concurrency` chunks in flight, ordered output).
    pub async fn stream_file_range(
        repo: Rc<Self>,
        entry: &DirEntry,
        range: Option<ByteRange>,
        concurrency: usize,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Vec<u8>>> + 'static>>>
    where
        S: 'static,
    {
        let (_expected_len, tasks) = repo.plan_range_chunks(entry, range).await?;
        let window = concurrency.max(1);
        let s = stream::iter(tasks)
            .map(move |task| {
                let repo = Rc::clone(&repo);
                async move { repo.fetch_chunk_slice(task).await }
            })
            .buffered(window);
        Ok(Box::pin(s))
    }

    /// Reads an optional inclusive `ByteRange` of a file `DirEntry` into memory using
    /// a bounded sliding-window concurrent fetch (`concurrency = 4`).
    pub async fn read_file_range(&self, entry: &DirEntry, range: Option<ByteRange>) -> Result<Bytes> {
        let (expected_len, tasks) = self.plan_range_chunks(entry, range).await?;
        if tasks.is_empty() {
            return Ok(Bytes::new());
        }

        let mut out = Vec::with_capacity(expected_len as usize);
        let mut s = stream::iter(tasks)
            .map(|task| self.fetch_chunk_slice(task))
            .buffered(4);

        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk?);
        }

        Ok(Bytes::from(out))
    }
}

struct ChunkSliceTask {
    content_id: ContentId,
    slice_start: usize,
    slice_end: usize,
}

fn normalize_object_content_id(object_id: &str) -> Result<ContentId> {
    // Kopia prefixes direct data object IDs with 'D' inside indirect streams.
    let s = object_id.strip_prefix('D').unwrap_or(object_id);
    ContentId::parse(s)
}
