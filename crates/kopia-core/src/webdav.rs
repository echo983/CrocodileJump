//! Shared WebDAV helpers (Kopia sharded path mapping and `PROPFIND` XML parsing).

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::{KopiaError, Result};

/// Entry parsed from a WebDAV `PROPFIND` (Depth: 1) XML response.
#[derive(Debug, Clone)]
pub struct DavEntry {
    pub href: String,
    pub is_dir: bool,
    pub content_length: u64,
}

/// Maps a Kopia blob ID to its relative WebDAV path using Kopia's default `[1, 3]` sharding.
pub fn shard_blob_path(blob_id: &str) -> String {
    if blob_id.len() > 20 {
        let p1 = &blob_id[0..1];
        let p2 = &blob_id[1..4];
        let rest = &blob_id[4..];
        format!("{p1}/{p2}/{rest}.f")
    } else {
        format!("{blob_id}.f")
    }
}

/// Parses a WebDAV `207 Multi-Status` XML body, filtering out the requested directory itself.
pub fn parse_propfind_xml(xml: &str, request_url: &str) -> Result<Vec<DavEntry>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let req_path = request_url
        .split("://")
        .nth(1)
        .and_then(|s| s.find('/').map(|i| &s[i..]))
        .unwrap_or("/")
        .trim_end_matches('/');

    let mut out = Vec::new();
    let mut in_response = false;
    let mut current_tag = String::new();
    let mut href = String::new();
    let mut is_collection = false;
    let mut length: u64 = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if name == "response" {
                    in_response = true;
                    href.clear();
                    is_collection = false;
                    length = 0;
                } else if in_response {
                    if name == "collection" {
                        is_collection = true;
                    }
                    current_tag = name;
                }
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if in_response && name == "collection" {
                    is_collection = true;
                }
            }
            Ok(Event::Text(e)) => {
                if in_response {
                    let text = e
                        .unescape()
                        .map_err(|err| KopiaError::Storage(format!("XML unescape: {err}")))?
                        .to_string();
                    match current_tag.as_str() {
                        "href" => href = text,
                        "getcontentlength" => length = text.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if name == "response" && in_response {
                    in_response = false;
                    let norm_href = href.trim_end_matches('/');
                    if norm_href != req_path && !href.is_empty() {
                        out.push(DavEntry {
                            href: href.clone(),
                            is_dir: is_collection,
                            content_length: length,
                        });
                    }
                }
                current_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(KopiaError::Storage(format!("XML parse error: {e}"))),
            _ => {}
        }
    }

    Ok(out)
}
