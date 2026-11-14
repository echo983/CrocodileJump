use std::rc::Rc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use futures_util::TryStreamExt;
use kopia_core::crypto::{ContentCrypter, KopiaRepositoryBlob, RepoFormat};
use kopia_core::repo::KopiaRepo;
use kopia_core::webdav::{parse_propfind_xml, shard_blob_path, DavEntry};
use kopia_core::{BlobMeta, ByteRange, KopiaError, Result as KopiaResult, StorageReader};
use percent_encoding::percent_decode_str;
use worker::*;

/// Maximum plain file size cached as a whole `200 OK` response in Cloudflare `caches.default`.
const MAX_CACHEABLE_FILE_BYTES: u64 = 20 * 1024 * 1024;

struct WorkerWebDavStorage {
    base_url: String,
    auth_header: String,
    ctx: Rc<Context>,
}

impl WorkerWebDavStorage {
    fn new(base_url: String, username: &str, password: &str, ctx: Rc<Context>) -> Self {
        let token = BASE64.encode(format!("{username}:{password}"));
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_header: format!("Basic {token}"),
            ctx,
        }
    }

    fn blob_url(&self, blob_id: &str) -> String {
        format!("{}/{}", self.base_url, shard_blob_path(blob_id))
    }

    async fn propfind_dir(&self, dir_url: &str) -> KopiaResult<Vec<DavEntry>> {
        let headers = web_sys::Headers::new()
            .map_err(|e| KopiaError::Storage(format!("headers init failed: {e:?}")))?;
        headers
            .set("Authorization", &self.auth_header)
            .map_err(|e| KopiaError::Storage(format!("set auth failed: {e:?}")))?;
        headers
            .set("Depth", "1")
            .map_err(|e| KopiaError::Storage(format!("set depth failed: {e:?}")))?;

        let init = web_sys::RequestInit::new();
        init.set_method("PROPFIND");
        init.set_headers(&headers);

        let sys_req = web_sys::Request::new_with_str_and_init(dir_url, &init)
            .map_err(|e| KopiaError::Storage(format!("Request::new failed: {e:?}")))?;
        let req: Request = sys_req.into();

        let mut resp = Fetch::Request(req)
            .send()
            .await
            .map_err(|e| KopiaError::Storage(format!("PROPFIND {dir_url} failed: {e}")))?;

        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(KopiaError::Storage(format!(
                "PROPFIND {dir_url} returned {status}"
            )));
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| KopiaError::Storage(format!("read PROPFIND body failed: {e}")))?;
        parse_propfind_xml(&xml, dir_url)
    }

    async fn fetch_bytes(&self, url: &str, range: Option<(u64, u64)>) -> KopiaResult<Bytes> {
        let mut headers = Headers::new();
        headers
            .set("Authorization", &self.auth_header)
            .map_err(|e| KopiaError::Storage(format!("set auth header: {e}")))?;
        if let Some((start, end)) = range {
            headers
                .set("Range", &format!("bytes={start}-{end}"))
                .map_err(|e| KopiaError::Storage(format!("set range header: {e}")))?;
        }

        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_headers(headers);
        let req = Request::new_with_init(url, &init)
            .map_err(|e| KopiaError::Storage(format!("Request::new_with_init: {e}")))?;

        let mut resp = Fetch::Request(req)
            .send()
            .await
            .map_err(|e| KopiaError::Storage(format!("GET {url} failed: {e}")))?;

        let status = resp.status_code();
        if status == 404 {
            return Err(KopiaError::NotFound(url.to_string()));
        }
        if !(200..300).contains(&status) {
            return Err(KopiaError::Storage(format!("GET {url} returned {status}")));
        }

        let buf = resp
            .bytes()
            .await
            .map_err(|e| KopiaError::Storage(format!("read body failed: {e}")))?;
        Ok(Bytes::from(buf))
    }
}

#[async_trait(?Send)]
impl StorageReader for WorkerWebDavStorage {
    async fn list_blobs(&self, prefix: &str) -> KopiaResult<Vec<BlobMeta>> {
        let mut results = Vec::new();
        let first_char = prefix
            .chars()
            .next()
            .ok_or_else(|| KopiaError::InvalidFormat("empty prefix for list_blobs".into()))?;

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

    async fn read_blob(&self, blob_id: &str) -> KopiaResult<Bytes> {
        let is_immutable_index = blob_id.starts_with("xn");
        let cache = Cache::default();
        let cache_key = format!("https://kopia-cache.internal/blobs/{blob_id}");

        if is_immutable_index {
            if let Ok(Some(mut cached)) = cache.get(&cache_key, false).await {
                if let Ok(bytes) = cached.bytes().await {
                    return Ok(Bytes::from(bytes));
                }
            }
        }

        let url = self.blob_url(blob_id);
        let data = self.fetch_bytes(&url, None).await?;

        if is_immutable_index {
            if let Ok(mut resp) = Response::from_bytes(data.to_vec()) {
                let _ = resp
                    .headers_mut()
                    .set("Cache-Control", "public, max-age=31536000, immutable");
                self.ctx.wait_until(async move {
                    let _ = Cache::default().put(&cache_key, resp).await;
                });
            }
        }

        Ok(data)
    }

    async fn read_blob_range(&self, blob_id: &str, offset: u64, length: u64) -> KopiaResult<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }
        let url = self.blob_url(blob_id);
        let end = offset + length - 1;
        self.fetch_bytes(&url, Some((offset, end))).await
    }
}

async fn load_format(env: &Env, storage: &WorkerWebDavStorage) -> KopiaResult<RepoFormat> {
    if let Ok(secret_var) = env.secret("KOPIA_FORMAT_JSON") {
        let json = secret_var.to_string();
        return serde_json::from_str(&json).map_err(|e| {
            KopiaError::InvalidFormat(format!("invalid KOPIA_FORMAT_JSON: {e}"))
        });
    }
    if let Ok(var) = env.var("KOPIA_FORMAT_JSON") {
        let json = var.to_string();
        return serde_json::from_str(&json).map_err(|e| {
            KopiaError::InvalidFormat(format!("invalid KOPIA_FORMAT_JSON: {e}"))
        });
    }

    let password = env
        .secret("KOPIA_PASSWORD")
        .or_else(|_| env.var("KOPIA_PASSWORD"))
        .map_err(|_| {
            KopiaError::InvalidFormat(
                "missing KOPIA_FORMAT_JSON or KOPIA_PASSWORD secret".into(),
            )
        })?
        .to_string();

    let repo_blob_bytes = storage.read_blob("kopia.repository").await?;
    let repo_blob = KopiaRepositoryBlob::from_json(&repo_blob_bytes)?;
    repo_blob.decrypt(&password)
}

fn env_str(env: &Env, key: &str) -> Result<String> {
    env.secret(key)
        .or_else(|_| env.var(key))
        .map(|v| v.to_string())
        .map_err(|_| Error::RustError(format!("missing env/secret: {key}")))
}

fn map_kopia_err(err: KopiaError) -> Response {
    match err {
        KopiaError::NotFound(msg) => Response::error(msg, 404).unwrap(),
        KopiaError::InvalidFormat(msg) | KopiaError::Unsupported(msg) => {
            Response::error(msg, 400).unwrap()
        }
        KopiaError::Crypto(msg) | KopiaError::Decompression(msg) => {
            Response::error(msg, 500).unwrap()
        }
        KopiaError::Storage(msg) => Response::error(msg, 502).unwrap(),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RangeParse {
    None,
    Valid(ByteRange),
    Unsatisfiable,
}

fn parse_range_header(header: Option<&str>, total_size: u64) -> RangeParse {
    let Some(raw) = header else {
        return RangeParse::None;
    };
    let Some(spec) = raw.trim().strip_prefix("bytes=") else {
        return RangeParse::Unsatisfiable;
    };
    // Multi-range requests are not needed for infrastructure gateway; reject cleanly.
    if spec.contains(',') {
        return RangeParse::Unsatisfiable;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeParse::Unsatisfiable;
    };

    if total_size == 0 {
        return RangeParse::Unsatisfiable;
    }

    if start_s.is_empty() {
        // Suffix range: bytes=-N
        let Ok(suffix) = end_s.trim().parse::<u64>() else {
            return RangeParse::Unsatisfiable;
        };
        if suffix == 0 {
            return RangeParse::Unsatisfiable;
        }
        let start = total_size.saturating_sub(suffix);
        return RangeParse::Valid(ByteRange {
            start,
            end: total_size - 1,
        });
    }

    let Ok(start) = start_s.trim().parse::<u64>() else {
        return RangeParse::Unsatisfiable;
    };
    if start >= total_size {
        return RangeParse::Unsatisfiable;
    }

    let end = if end_s.trim().is_empty() {
        total_size - 1
    } else {
        let Ok(e) = end_s.trim().parse::<u64>() else {
            return RangeParse::Unsatisfiable;
        };
        if e < start {
            return RangeParse::Unsatisfiable;
        }
        e.min(total_size - 1)
    };

    RangeParse::Valid(ByteRange { start, end })
}

fn decode_rel_path(raw: &str) -> std::result::Result<String, String> {
    percent_decode_str(raw)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|e| format!("invalid UTF-8 in path: {e}"))
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let method = req.method();
    if method != Method::Get && method != Method::Head {
        return Response::error("Method Not Allowed", 405);
    }

    let url = req.url()?;
    let path = url.path().to_string();

    // 1. Check Cloudflare Cache API first for immutable `/s/<id>/...` routes.
    let cache = Cache::default();
    let is_immutable_route = path.starts_with("/s/");
    if is_immutable_route {
        if let Ok(Some(hit)) = cache.get(&req, false).await {
            return Ok(hit);
        }
    }

    let webdav_url = env_str(&env, "WEBDAV_URL")?;
    let webdav_user = env_str(&env, "WEBDAV_USERNAME")?;
    let webdav_pass = env_str(&env, "WEBDAV_PASSWORD")?;

    let ctx_rc = Rc::new(ctx);
    let storage = WorkerWebDavStorage::new(webdav_url, &webdav_user, &webdav_pass, ctx_rc.clone());

    let format = match load_format(&env, &storage).await {
        Ok(f) => f,
        Err(e) => return Ok(map_kopia_err(e)),
    };
    let crypter = match ContentCrypter::from_format(&format) {
        Ok(c) => c,
        Err(e) => return Ok(map_kopia_err(e)),
    };
    let repo = match KopiaRepo::open(storage, crypter).await {
        Ok(r) => Rc::new(r),
        Err(e) => return Ok(map_kopia_err(e)),
    };

    // Route: GET /_snapshots
    if path == "/_snapshots" {
        let snapshots = match repo.list_snapshots().await {
            Ok(s) => s,
            Err(e) => return Ok(map_kopia_err(e)),
        };
        let mut resp = Response::from_json(&snapshots)?;
        resp.headers_mut()
            .set("Cache-Control", "public, max-age=30")?;
        return Ok(resp);
    }

    // Route: /s/<snapshot-id>/<rel-path> or /latest/<rel-path>
    let (snapshot_id, raw_rel_path, cache_control) = if let Some(rest) = path.strip_prefix("/s/") {
        let (sid, rel) = match rest.split_once('/') {
            Some((s, r)) => (s.to_string(), r.to_string()),
            None => (rest.to_string(), String::new()),
        };
        (
            sid,
            rel,
            "public, max-age=31536000, immutable",
        )
    } else if let Some(rest) = path.strip_prefix("/latest/") {
        let snapshots = match repo.list_snapshots().await {
            Ok(s) => s,
            Err(e) => return Ok(map_kopia_err(e)),
        };
        let Some(latest) = snapshots.first() else {
            return Response::error("no snapshots found", 404);
        };
        (
            latest.id.clone(),
            rest.to_string(),
            "public, max-age=60",
        )
    } else {
        return Response::error("Not Found", 404);
    };

    let rel_path = match decode_rel_path(&raw_rel_path) {
        Ok(p) => p,
        Err(msg) => return Response::error(msg, 400),
    };

    let is_dir_listing = rel_path.is_empty() || rel_path.ends_with('/');
    let entry = match repo.stat_path(&snapshot_id, &rel_path).await {
        Ok(e) => e,
        Err(e) => return Ok(map_kopia_err(e)),
    };

    if entry.is_dir() || is_dir_listing {
        if !entry.is_dir() {
            return Response::error("Not a directory", 404);
        }
        let Some(dir_obj) = entry.obj.as_deref() else {
            return Response::error("Directory missing object ID", 500);
        };
        let entries = match repo.read_directory(dir_obj).await {
            Ok(list) => list,
            Err(e) => return Ok(map_kopia_err(e)),
        };
        let mut resp = Response::from_json(&entries)?;
        resp.headers_mut().set("Cache-Control", cache_control)?;
        if is_immutable_route && method == Method::Get {
            if let Ok(cloned) = resp.cloned() {
                let req_url = url.to_string();
                ctx_rc.wait_until(async move {
                    let _ = Cache::default().put(&req_url, cloned).await;
                });
            }
        }
        return Ok(resp);
    }

    let total_size = entry.size.unwrap_or(0);
    let etag = format!("\"{}\"", entry.obj.as_deref().unwrap_or(""));

    // HEAD: zero Pack reads required.
    if method == Method::Head {
        let mut resp = Response::empty()?.with_status(200);
        let h = resp.headers_mut();
        h.set("Content-Length", &total_size.to_string())?;
        h.set("Accept-Ranges", "bytes")?;
        h.set("ETag", &etag)?;
        h.set("Cache-Control", cache_control)?;
        return Ok(resp);
    }

    let range_header = req.headers().get("Range")?;
    let parsed_range = parse_range_header(range_header.as_deref(), total_size);

    match parsed_range {
        RangeParse::Unsatisfiable => {
            let mut resp = Response::error("Range Not Satisfiable", 416)?;
            resp.headers_mut()
                .set("Content-Range", &format!("bytes */{total_size}"))?;
            Ok(resp)
        }
        RangeParse::Valid(byte_range) => {
            let stream = match KopiaRepo::stream_file_range(
                Rc::clone(&repo),
                &entry,
                Some(byte_range),
                4,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => return Ok(map_kopia_err(e)),
            };
            let mapped = stream.map_err(|e| Error::RustError(e.to_string()));
            let mut resp = Response::from_stream(mapped)?.with_status(206);
            let h = resp.headers_mut();
            h.set(
                "Content-Range",
                &format!("bytes {}-{}/{total_size}", byte_range.start, byte_range.end),
            )?;
            h.set("Content-Length", &byte_range.len().to_string())?;
            h.set("Accept-Ranges", "bytes")?;
            h.set("ETag", &etag)?;
            h.set("Cache-Control", cache_control)?;
            Ok(resp)
        }
        RangeParse::None => {
            if is_immutable_route && total_size <= MAX_CACHEABLE_FILE_BYTES {
                let bytes = match repo.read_file_range(&entry, None).await {
                    Ok(b) => b,
                    Err(e) => return Ok(map_kopia_err(e)),
                };
                let mut resp = Response::from_bytes(bytes.to_vec())?.with_status(200);
                let h = resp.headers_mut();
                h.set("Content-Length", &bytes.len().to_string())?;
                h.set("Accept-Ranges", "bytes")?;
                h.set("ETag", &etag)?;
                h.set("Cache-Control", cache_control)?;

                if let Ok(cloned) = resp.cloned() {
                    let req_url = url.to_string();
                    ctx_rc.wait_until(async move {
                        let _ = Cache::default().put(&req_url, cloned).await;
                    });
                }
                Ok(resp)
            } else {
                let stream =
                    match KopiaRepo::stream_file_range(Rc::clone(&repo), &entry, None, 4).await {
                        Ok(s) => s,
                        Err(e) => return Ok(map_kopia_err(e)),
                    };
                let mapped = stream.map_err(|e| Error::RustError(e.to_string()));
                let mut resp = Response::from_stream(mapped)?.with_status(200);
                let h = resp.headers_mut();
                h.set("Content-Length", &total_size.to_string())?;
                h.set("Accept-Ranges", "bytes")?;
                h.set("ETag", &etag)?;
                h.set("Cache-Control", cache_control)?;
                Ok(resp)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_rel_path() {
        assert_eq!(
            decode_rel_path("%E4%B8%AD%E6%96%87%20%E6%B5%8B%E8%AF%95.txt").unwrap(),
            "中文 测试.txt"
        );
        assert_eq!(
            decode_rel_path("sub/nested/info.json").unwrap(),
            "sub/nested/info.json"
        );
        assert!(decode_rel_path("%FF%FE").is_err());
    }

    #[test]
    fn test_parse_range_header() {
        assert_eq!(parse_range_header(None, 100), RangeParse::None);
        assert_eq!(
            parse_range_header(Some("bytes=0-9"), 100),
            RangeParse::Valid(ByteRange { start: 0, end: 9 })
        );
        assert_eq!(
            parse_range_header(Some("bytes=90-999"), 100),
            RangeParse::Valid(ByteRange { start: 90, end: 99 })
        );
        assert_eq!(
            parse_range_header(Some("bytes=50-"), 100),
            RangeParse::Valid(ByteRange { start: 50, end: 99 })
        );
        assert_eq!(
            parse_range_header(Some("bytes=-10"), 100),
            RangeParse::Valid(ByteRange { start: 90, end: 99 })
        );
        assert_eq!(
            parse_range_header(Some("bytes=100-110"), 100),
            RangeParse::Unsatisfiable
        );
        assert_eq!(
            parse_range_header(Some("bytes=20-10"), 100),
            RangeParse::Unsatisfiable
        );
    }
}
