use std::path::Path;

use async_trait::async_trait;
use bytes::Bytes;
use kopia_core::crypto::{ContentCrypter, KopiaRepositoryBlob};
use kopia_core::repo::KopiaRepo;
use kopia_core::webdav::{parse_propfind_xml, shard_blob_path, DavEntry};
use kopia_core::{BlobMeta, ByteRange, KopiaError, Result, StorageReader};
use reqwest::{Client, Method};
use sha2::{Digest, Sha256};

struct WebDavStorage {
    client: Client,
    base_url: String,
    username: String,
    password: String,
}

impl WebDavStorage {
    fn new(base_url: String, username: String, password: String) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            username,
            password,
        }
    }

    fn blob_url(&self, blob_id: &str) -> String {
        format!("{}/{}", self.base_url, shard_blob_path(blob_id))
    }

    async fn propfind_dir(&self, dir_url: &str) -> Result<Vec<DavEntry>> {
        let method = Method::from_bytes(b"PROPFIND")
            .map_err(|e| KopiaError::Storage(format!("invalid method: {e}")))?;
        let resp = self
            .client
            .request(method, dir_url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Depth", "1")
            .send()
            .await
            .map_err(|e| KopiaError::Storage(format!("PROPFIND failed: {e}")))?;

        if !resp.status().is_success() && resp.status().as_u16() != 207 {
            return Err(KopiaError::Storage(format!(
                "PROPFIND {dir_url} returned {}",
                resp.status()
            )));
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| KopiaError::Storage(format!("read PROPFIND body failed: {e}")))?;

        parse_propfind_xml(&xml, dir_url)
    }
}

#[async_trait(?Send)]
impl StorageReader for WebDavStorage {
    async fn list_blobs(&self, prefix: &str) -> Result<Vec<BlobMeta>> {
        let mut results = Vec::new();
        let first_char = prefix.chars().next().ok_or_else(|| {
            KopiaError::InvalidFormat("empty prefix for list_blobs".into())
        })?;

        let level1_url = format!("{}/{first_char}/", self.base_url);
        let level1 = self.propfind_dir(&level1_url).await?;
        let scheme_host = self
            .base_url
            .split('/')
            .take(3)
            .collect::<Vec<_>>()
            .join("/");

        for d in level1 {
            if !d.is_dir {
                continue;
            }
            let dir_name = d.href.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            let sub_prefix = format!("{first_char}{dir_name}");
            if !sub_prefix.starts_with(prefix) && !prefix.starts_with(&sub_prefix) {
                continue;
            }
            let level2_url = format!("{scheme_host}{}", d.href);
            for f in self.propfind_dir(&level2_url).await? {
                if f.is_dir {
                    continue;
                }
                let fname = f.href.rsplit('/').next().unwrap_or("");
                if let Some(stem) = fname.strip_suffix(".f") {
                    let blob_id = format!("{first_char}{dir_name}{stem}");
                    if blob_id.starts_with(prefix) {
                        results.push(BlobMeta {
                            id: blob_id,
                            length: f.content_length,
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    async fn read_blob(&self, blob_id: &str) -> Result<Bytes> {
        let url = self.blob_url(blob_id);
        let resp = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|e| KopiaError::Storage(format!("GET {url} failed: {e}")))?;

        if resp.status().as_u16() == 404 {
            return Err(KopiaError::NotFound(blob_id.to_string()));
        }
        if !resp.status().is_success() {
            return Err(KopiaError::Storage(format!(
                "GET {url} returned {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map_err(|e| KopiaError::Storage(format!("read body failed: {e}")))
    }

    async fn read_blob_range(&self, blob_id: &str, offset: u64, length: u64) -> Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }
        let url = self.blob_url(blob_id);
        let end = offset + length - 1;
        let resp = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Range", format!("bytes={offset}-{end}"))
            .send()
            .await
            .map_err(|e| KopiaError::Storage(format!("GET Range {url} failed: {e}")))?;

        if resp.status().as_u16() != 206 && !resp.status().is_success() {
            return Err(KopiaError::Storage(format!(
                "GET Range {url} returned {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map_err(|e| KopiaError::Storage(format!("read range body failed: {e}")))
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let export_format = std::env::args().any(|a| a == "--export-format");

    let token_txt = std::fs::read_to_string("secret/webdavToken.txt")?;
    let lines: Vec<&str> = token_txt
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let base_url = format!("{}/test-repo", lines[1].trim_end_matches('/'));
    let username = lines[3].to_string();
    let password = lines[5].to_string();
    let repo_pass = std::fs::read_to_string("secret/test-repo-pass.txt")?
        .trim()
        .to_string();

    let storage = WebDavStorage::new(base_url, username, password);
    let repo_blob_bytes = storage.read_blob("kopia.repository").await?;
    let repo_blob = KopiaRepositoryBlob::from_json(&repo_blob_bytes)?;
    let format = repo_blob.decrypt(&repo_pass)?;

    if export_format {
        println!("{}", serde_json::to_string(&format)?);
        return Ok(());
    }

    println!(
        "1. Format version={}, hash={}, encryption={}, indexVersion={}",
        format.version, format.hash, format.encryption, format.index_version
    );

    let crypter = ContentCrypter::from_format(&format)?;
    println!("2. Loading and merging xn* index shards...");
    let repo = KopiaRepo::open(storage, crypter).await?;

    println!("3. Listing snapshots...");
    let snapshots = repo.list_snapshots().await?;
    for s in &snapshots {
        println!(
            "   snapshot id={} start={:?} root_obj={:?}",
            s.id, s.start_time, s.root_entry.obj
        );
    }

    let latest = snapshots.first().expect("expected at least 1 snapshot");
    println!("4. Verifying files in latest snapshot {}:", latest.id);

    for rel_path in ["hello.txt", "sub/nested/info.json", "blob5m.bin"] {
        let entry = repo.stat_path(&latest.id, rel_path).await?;
        let data = repo.read_file_range(&entry, None).await?;
        let local_path = Path::new("/tmp/kopia-test-data").join(rel_path);
        let local_bytes = std::fs::read(&local_path)?;
        assert_eq!(
            data.as_ref(),
            local_bytes.as_slice(),
            "byte mismatch for {rel_path}"
        );
        println!(
            "   [OK] {rel_path} ({} bytes, sha256={})",
            data.len(),
            sha256_hex(&data)
        );
    }

    println!("5. Verifying partial Range read on blob5m.bin [1048576..=1052671]...");
    let blob_entry = repo.stat_path(&latest.id, "blob5m.bin").await?;
    let slice = repo
        .read_file_range(
            &blob_entry,
            Some(ByteRange {
                start: 1048576,
                end: 1052671,
            }),
        )
        .await?;
    let local_blob = std::fs::read("/tmp/kopia-test-data/blob5m.bin")?;
    assert_eq!(slice.as_ref(), &local_blob[1048576..=1052671]);
    println!("   [OK] Range read verified ({} bytes)", slice.len());

    Ok(())
}
