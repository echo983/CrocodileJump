//! Kopia Index v2 parser and epoch index merger.

use std::collections::BTreeMap;
use std::fmt;

use crate::{KopiaError, Result};

const V2_INDEX_HEADER_SIZE: usize = 17;
const V2_PACK_INFO_SIZE: usize = 5;
const V2_FORMAT_INFO_SIZE: usize = 6;
const V2_ENTRY_MIN_LENGTH: usize = 16;
const V2_ENTRY_MAX_LENGTH: usize = 19;

/// Binary ContentID as stored in Kopia Index v2 (`prefix_byte` + `hash_bytes`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId {
    pub raw: Vec<u8>,
}

impl ContentId {
    /// Parses a Kopia ContentID string (e.g. `"kcfb78..."` or `"ea5498..."`).
    pub fn parse(s: &str) -> Result<Self> {
        // If length is odd (e.g. 1-char ASCII prefix + 64 hex chars), first char is prefix.
        let (prefix_byte, hex_part) = if s.len() % 2 == 1 {
            let b = s.as_bytes()[0];
            (b, &s[1..])
        } else {
            (0u8, s)
        };

        let hash = hex::decode(hex_part)
            .map_err(|e| KopiaError::InvalidFormat(format!("invalid ContentID hex {s}: {e}")))?;

        let mut raw = Vec::with_capacity(1 + hash.len());
        raw.push(prefix_byte);
        raw.extend_from_slice(&hash);
        Ok(Self { raw })
    }

    /// Returns the optional single-character prefix (e.g. `Some('m')`, `Some('k')`, or `None`).
    pub fn prefix(&self) -> Option<char> {
        match self.raw.first().copied() {
            Some(0) | None => None,
            Some(b) => Some(b as char),
        }
    }

    /// Returns the raw hash bytes (excluding the 1-byte prefix).
    pub fn hash_bytes(&self) -> &[u8] {
        if self.raw.is_empty() {
            &[]
        } else {
            &self.raw[1..]
        }
    }

    /// Returns the 16-byte IV used to encrypt/decrypt this content (last 16 bytes of hash).
    pub fn iv(&self) -> Result<[u8; 16]> {
        let h = self.hash_bytes();
        if h.len() < 16 {
            return Err(KopiaError::InvalidFormat(
                "ContentID hash shorter than 16 bytes".into(),
            ));
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&h[h.len() - 16..]);
        Ok(iv)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(p) = self.prefix() {
            write!(f, "{p}")?;
        }
        write!(f, "{}", hex::encode(self.hash_bytes()))
    }
}

impl fmt::Debug for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentId({self})")
    }
}

/// A single content entry resolved from a Kopia index.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub content_id: ContentId,
    pub timestamp_seconds: i64,
    pub deleted: bool,
    pub pack_blob_id: String,
    pub pack_offset: u32,
    pub original_length: u32,
    pub packed_length: u32,
    pub compression_header_id: u32,
    pub format_version: u8,
    pub encryption_key_id: u8,
}

#[derive(Debug, Clone, Copy)]
struct FormatInfo {
    compression_header_id: u32,
    format_version: u8,
    encryption_key_id: u8,
}

/// Parsed in-memory representation of a single `xn*` Index v2 shard.
pub struct IndexV2 {
    key_size: usize,
    entry_size: usize,
    entry_count: usize,
    base_timestamp: u32,
    entries_offset: usize,
    data: Vec<u8>,
    packs: Vec<String>,
    formats: Vec<FormatInfo>,
}

impl IndexV2 {
    /// Parses a decrypted Index v2 payload.
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() < V2_INDEX_HEADER_SIZE {
            return Err(KopiaError::InvalidFormat("index v2 header too short".into()));
        }

        let version = data[0];
        if version != 2 {
            return Err(KopiaError::Unsupported(format!(
                "unsupported index version: {version}"
            )));
        }

        let key_size = data[1] as usize;
        let entry_size = u16::from_be_bytes([data[2], data[3]]) as usize;
        let entry_count = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let pack_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let format_count = data[12] as usize;
        let base_timestamp = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);

        if key_size <= 1 || !(V2_ENTRY_MIN_LENGTH..=V2_ENTRY_MAX_LENGTH).contains(&entry_size) {
            return Err(KopiaError::InvalidFormat(format!(
                "invalid index v2 sizes: key={key_size}, entry={entry_size}"
            )));
        }

        let stride = key_size + entry_size;
        let entries_offset = V2_INDEX_HEADER_SIZE;
        let packs_offset = entries_offset
            .checked_add(entry_count * stride)
            .ok_or_else(|| KopiaError::InvalidFormat("index v2 offset overflow".into()))?;
        let formats_offset = packs_offset
            .checked_add(pack_count * V2_PACK_INFO_SIZE)
            .ok_or_else(|| KopiaError::InvalidFormat("index v2 offset overflow".into()))?;
        let formats_end = formats_offset
            .checked_add(format_count * V2_FORMAT_INFO_SIZE)
            .ok_or_else(|| KopiaError::InvalidFormat("index v2 offset overflow".into()))?;

        if data.len() < formats_end {
            return Err(KopiaError::InvalidFormat("index v2 truncated".into()));
        }

        let mut packs = Vec::with_capacity(pack_count);
        for i in 0..pack_count {
            let p = &data[packs_offset + i * V2_PACK_INFO_SIZE..];
            let name_len = p[0] as usize;
            let name_off = u32::from_be_bytes([p[1], p[2], p[3], p[4]]) as usize;
            let name_end = name_off + name_len;
            if name_end > data.len() {
                return Err(KopiaError::InvalidFormat(
                    "pack blob ID out of bounds".into(),
                ));
            }
            let name = std::str::from_utf8(&data[name_off..name_end])
                .map_err(|_| KopiaError::InvalidFormat("invalid UTF-8 pack blob ID".into()))?
                .to_string();
            packs.push(name);
        }

        let mut formats = Vec::with_capacity(format_count);
        for i in 0..format_count {
            let f = &data[formats_offset + i * V2_FORMAT_INFO_SIZE..];
            formats.push(FormatInfo {
                compression_header_id: u32::from_be_bytes([f[0], f[1], f[2], f[3]]),
                format_version: f[4],
                encryption_key_id: f[5],
            });
        }

        Ok(Self {
            key_size,
            entry_size,
            entry_count,
            base_timestamp,
            entries_offset,
            data,
            packs,
            formats,
        })
    }

    fn stride(&self) -> usize {
        self.key_size + self.entry_size
    }

    fn record_at(&self, idx: usize) -> (&[u8], &[u8]) {
        let start = self.entries_offset + idx * self.stride();
        let key = &self.data[start..start + self.key_size];
        let val = &self.data[start + self.key_size..start + self.stride()];
        (key, val)
    }

    fn decode_entry(&self, key: &[u8], val: &[u8]) -> Result<IndexEntry> {
        let ts_rel = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
        let timestamp_seconds = i64::from(ts_rel) + i64::from(self.base_timestamp);

        let poff_flags = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
        let deleted = (poff_flags & 0x8000_0000) != 0;
        let pack_offset = poff_flags & 0x7fff_ffff;

        let mut original_length =
            (u32::from(val[8]) << 16) | (u32::from(val[9]) << 8) | u32::from(val[10]);
        let mut packed_length =
            (u32::from(val[11]) << 16) | (u32::from(val[12]) << 8) | u32::from(val[13]);

        if val.len() > 18 {
            original_length |= u32::from(val[18] >> 4) << 24;
            packed_length |= u32::from(val[18] & 0x0f) << 24;
        }

        let mut pack_idx = u16::from_be_bytes([val[14], val[15]]) as usize;
        if val.len() > 17 {
            pack_idx |= (val[17] as usize) << 16;
        }
        let pack_blob_id = self
            .packs
            .get(pack_idx)
            .ok_or_else(|| KopiaError::InvalidFormat(format!("pack index {pack_idx} out of bounds")))?
            .clone();

        let fmt_idx = if val.len() > 16 { val[16] as usize } else { 0 };
        let fmt = self.formats.get(fmt_idx).copied().unwrap_or(FormatInfo {
            compression_header_id: 0xffff,
            format_version: 0xff,
            encryption_key_id: 0xff,
        });

        Ok(IndexEntry {
            content_id: ContentId { raw: key.to_vec() },
            timestamp_seconds,
            deleted,
            pack_blob_id,
            pack_offset,
            original_length,
            packed_length,
            compression_header_id: fmt.compression_header_id,
            format_version: fmt.format_version,
            encryption_key_id: fmt.encryption_key_id,
        })
    }

    /// Binary-searches for an exact `ContentId` inside this sorted index shard.
    pub fn find(&self, target: &ContentId) -> Result<Option<IndexEntry>> {
        let mut lo = 0usize;
        let mut hi = self.entry_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (key, val) = self.record_at(mid);
            match key.cmp(target.raw.as_slice()) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Ok(Some(self.decode_entry(key, val)?)),
            }
        }
        Ok(None)
    }

    /// Iterates over all entries in this shard.
    pub fn entries(&self) -> Result<Vec<IndexEntry>> {
        let mut out = Vec::with_capacity(self.entry_count);
        for i in 0..self.entry_count {
            let (key, val) = self.record_at(i);
            out.push(self.decode_entry(key, val)?);
        }
        Ok(out)
    }
}

/// Merged view across multiple `xn*` index shards, resolving latest non-deleted entries.
#[derive(Default)]
pub struct MergedIndex {
    entries: BTreeMap<Vec<u8>, IndexEntry>,
}

impl MergedIndex {
    /// Merges a parsed `IndexV2` shard into the index, keeping the entry with the
    /// highest `timestamp_seconds` for each `ContentId`.
    pub fn merge_shard(&mut self, shard: &IndexV2) -> Result<()> {
        for entry in shard.entries()? {
            let key = entry.content_id.raw.clone();
            match self.entries.get(&key) {
                Some(existing) if existing.timestamp_seconds > entry.timestamp_seconds => {}
                _ => {
                    self.entries.insert(key, entry);
                }
            }
        }
        Ok(())
    }

    /// Looks up a non-deleted `ContentId`.
    pub fn get(&self, id: &ContentId) -> Option<&IndexEntry> {
        self.entries.get(&id.raw).filter(|e| !e.deleted)
    }

    /// Returns all non-deleted entries whose `ContentId` has the given prefix byte (e.g. `b'm'`).
    pub fn list_with_prefix(&self, prefix: u8) -> Vec<&IndexEntry> {
        self.entries
            .iter()
            .filter(|(k, e)| !e.deleted && k.first().copied() == Some(prefix))
            .map(|(_, e)| e)
            .collect()
    }
}
