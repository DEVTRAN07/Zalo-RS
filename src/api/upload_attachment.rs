use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::api::client::ApiClient;
use crate::context::UploadCallback;
use crate::core::utils::get_file_extension;
use crate::errors::{Result, ZaloApiError, ZaloError};
use crate::models::r#enum::ThreadType;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttachmentSource {
    Path(String),
    Inline {
        filename: String,
        #[serde(skip)]
        data: Vec<u8>,
        #[serde(default)]
        metadata: Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UploadAttachmentImageResponse {
    pub normal_url: String,
    /// URL ảnh GỐC do server trả về (`oriUrl` trong response của
    /// `photo_original/upload`, fallback `fileUrl` khi chunk response
    /// tự mang URL trực tiếp). Rỗng khi server không trả — caller dùng
    /// [`UploadAttachmentImageResponse::original_url`] để fallback về
    /// `hd_url` rồi mới tới `normal_url`, nên hành vi cũ giữ nguyên khi
    /// không có URL gốc.
    /// Thêm field này để ảnh gửi đi giữ dạng gốc thay vì bị flatten
    /// về bản Thường (trước đây `send_uploaded_attachments` gán
    /// `oriUrl`/`rawUrl` = `normal_url`).
    #[serde(default)]
    pub ori_url: String,
    pub photo_id: String,
    pub finished: Value,
    pub hd_url: String,
    pub thumb_url: String,
    pub client_file_id: i64,
    pub chunk_id: i64,
    pub file_type: String,
    pub width: u64,
    pub height: u64,
    pub total_size: u64,
    pub hd_size: u64,
}

impl UploadAttachmentImageResponse {
    /// URL ảnh gửi đi: bản GỐC (`ori_url`) khi server trả về, nếu
    /// không thì bản HD (`hd_url` — link chất lượng cao nhất server
    /// thực tế trả về: log live `[upload-diag]` 2026-11-28 chứng minh
    /// server KHÔNG BAO GIỜ trả `oriUrl`/`fileUrl` nhưng LUÔN trả
    /// `hdUrl`), cuối cùng mới fallback bản Thường (`normal_url`).
    /// Đây là điểm duy nhất quyết định chất lượng ảnh gửi — mọi đường
    /// gửi ảnh (nhóm + riêng) đều đi qua đây, nên ảnh bot gửi luôn là
    /// bản chất lượng cao nhất có thể thay vì bị flatten về bản Thường.
    pub fn original_url(&self) -> &str {
        let ori = self.ori_url.trim();
        if !ori.is_empty() {
            return ori;
        }
        let hd = self.hd_url.trim();
        if !hd.is_empty() {
            return hd;
        }
        self.normal_url.as_str()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UploadAttachmentVideoResponse {
    pub finished: Value,
    pub client_file_id: i64,
    pub chunk_id: i64,
    pub file_type: String,
    pub file_url: String,
    pub file_id: String,
    pub checksum: String,
    pub total_size: u64,
    pub file_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UploadAttachmentFileResponse {
    pub finished: Value,
    pub client_file_id: i64,
    pub chunk_id: i64,
    pub file_type: String,
    pub file_url: String,
    pub file_id: String,
    pub checksum: String,
    pub total_size: u64,
    pub file_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UploadAttachmentType {
    Image(UploadAttachmentImageResponse),
    Video(UploadAttachmentVideoResponse),
    File(UploadAttachmentFileResponse),
}

pub type UploadAttachmentResponse = Vec<UploadAttachmentType>;

#[derive(Debug, Clone)]
struct RawUploadResponse {
    finished: Value,
    client_file_id: i64,
    chunk_id: i64,
    file_id: Option<String>,
    photo_id: Option<String>,
    normal_url: Option<String>,
    hd_url: Option<String>,
    thumb_url: Option<String>,
    /// URL ảnh gốc (`oriUrl`) nếu server trả về trong response upload.
    /// Không phải lúc nào cũng có — thiếu thì đường gửi fallback về
    /// `hd_url` rồi mới tới `normal_url` qua
    /// `UploadAttachmentImageResponse::original_url`.
    ori_url: Option<String>,
    /// Direct file URL if the chunk response itself carries one
    /// (`fileUrl`/`file_url`). Used as a fallback when the `file_done`
    /// WS event never arrives, so the upload does not end with an empty URL.
    file_url: Option<String>,
    /// Danh sách tên key của object `data` trong chunk response (chỉ tên
    /// key, không giá trị) — phục vụ log chẩn đoán vụ ảnh ra HD thay vì
    /// ORIGINAL: xem server có trả `oriUrl` không.
    data_keys: Vec<String>,
}

impl RawUploadResponse {
    fn from_value(value: Value) -> Self {
        Self {
            finished: value.get("finished").cloned().unwrap_or(Value::Null),
            client_file_id: value
                .get("clientFileId")
                .and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                })
                .unwrap_or(0),
            chunk_id: value
                .get("chunkId")
                .and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                })
                .unwrap_or(0),
            file_id: value.get("fileId").and_then(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_i64().map(|n| n.to_string()))
            }),
            photo_id: value.get("photoId").and_then(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_i64().map(|n| n.to_string()))
            }),
            normal_url: value
                .get("normalUrl")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            hd_url: value
                .get("hdUrl")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            thumb_url: value
                .get("thumbUrl")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            ori_url: value
                .get("oriUrl")
                .or_else(|| value.get("ori_url"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            file_url: value
                .get("fileUrl")
                .or_else(|| value.get("file_url"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            data_keys: value
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FileKind {
    Image,
    Video,
    Other,
}

impl FileKind {
    fn url_type(self) -> &'static str {
        match self {
            FileKind::Image => "photo_original/upload",
            FileKind::Video | FileKind::Other => "asyncfile/upload",
        }
    }
}

fn sharefile_setting_u64(settings: &Option<Value>, key: &str, default: u64) -> u64 {
    settings
        .as_ref()
        .and_then(|s| s.get("features").or_else(|| s.get("sharefile")))
        .and_then(|s| {
            if s.get(key).is_some() {
                Some(s)
            } else {
                s.get("sharefile")
            }
        })
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n.max(0) as u64)))
        .unwrap_or(default)
}

fn restricted_extensions(settings: &Option<Value>) -> Vec<String> {
    let values = settings
        .as_ref()
        .and_then(|s| s.get("features").or_else(|| s.get("sharefile")))
        .and_then(|s| s.get("sharefile").or(Some(s)))
        .and_then(|s| s.get("restricted_ext_file"))
        .and_then(|v| v.as_array());
    values
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_str()
                        .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn is_extension_valid(ext: &str, settings: &Option<Value>) -> bool {
    let restricted = restricted_extensions(settings);
    if restricted.is_empty() {
        return true;
    }
    !restricted.iter().any(|e| e.eq_ignore_ascii_case(ext))
}

fn classify_extension(ext: &str) -> FileKind {
    match ext.to_ascii_lowercase().as_str() {
        // GIF is an image (animated): sending it as a plain file would not
        // play inline. mov/webm are video containers, not generic files.
        "jpg" | "jpeg" | "png" | "webp" | "gif" => FileKind::Image,
        "mp4" | "mov" | "webm" => FileKind::Video,
        _ => FileKind::Other,
    }
}

fn image_dimensions(data: &[u8]) -> Option<(u64, u64)> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") && data.len() >= 24 && &data[12..16] == b"IHDR" {
        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]) as u64;
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]) as u64;
        return Some((width, height));
    }

    if data.starts_with(&[0xff, 0xd8]) {
        let mut i = 2usize;
        while i + 9 < data.len() {
            if data[i] != 0xff {
                i += 1;
                continue;
            }
            let marker = data[i + 1];
            i += 2;
            if marker == 0xd8 || marker == 0xd9 {
                continue;
            }
            if i + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
            if len < 2 || i + len > data.len() {
                break;
            }
            if (0xc0..=0xc3).contains(&marker)
                || (0xc5..=0xc7).contains(&marker)
                || (0xc9..=0xcb).contains(&marker)
                || (0xcd..=0xcf).contains(&marker)
            {
                if i + 7 >= data.len() {
                    break;
                }
                let height = u16::from_be_bytes([data[i + 3], data[i + 4]]) as u64;
                let width = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u64;
                if width > 0 && height > 0 {
                    return Some((width, height));
                }
            }
            i += len;
        }
    }

    // WebP: RIFF....WEBPVP8 / VP8L / VP8X
    if data.len() >= 30 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        if &data[12..16] == b"VP8 " && data.len() >= 30 {
            // lossy: starts at 0x14 in some streams; scan for sync code 0x9d012a
            if let Some(pos) = data.windows(3).position(|w| w == [0x9d, 0x01, 0x2a]) {
                let p = pos + 3;
                if p + 4 <= data.len() {
                    let width = u16::from_le_bytes([data[p], data[p + 1]]) & 0x3fff;
                    let height = u16::from_le_bytes([data[p + 2], data[p + 3]]) & 0x3fff;
                    if width > 0 && height > 0 {
                        return Some((width as u64, height as u64));
                    }
                }
            }
        }
        if &data[12..16] == b"VP8L" && data.len() >= 25 && data[20] == 0x2f {
            let bits = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
            let width = ((bits & 0x3fff) + 1) as u64;
            let height = (((bits >> 14) & 0x3fff) + 1) as u64;
            return Some((width, height));
        }
        if &data[12..16] == b"VP8X" && data.len() >= 30 {
            let width =
                1u64 + (data[24] as u64) + ((data[25] as u64) << 8) + ((data[26] as u64) << 16);
            let height =
                1u64 + (data[27] as u64) + ((data[28] as u64) << 8) + ((data[29] as u64) << 16);
            return Some((width, height));
        }
    }

    None
}

async fn file_bytes_and_name(source: AttachmentSource) -> Result<(Vec<u8>, String)> {
    match source {
        AttachmentSource::Path(path) => {
            let data = fs::read(&path).await.map_err(|e| {
                ZaloError::Api(ZaloApiError::new(format!(
                    "Failed to read file {}: {}",
                    path, e
                )))
            })?;
            let filename = Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string();
            Ok((data, filename))
        }
        // Move the buffer out instead of cloning it: the caller owns `source`
        // and no longer needs it after this point.
        AttachmentSource::Inline { filename, data, .. } => Ok((data, filename)),
    }
}

/// MD5 over the buffer already read for upload. The old code re-read the
/// whole file from disk here (`fs::read`), so a 100 MB file cost >200 MB
/// RAM (read #1 for chunking + read #2 for the checksum, plus a clone per
/// chunk). Checksumming the shared buffer removes the second full copy.
/// (Note: `core::utils::get_md5_large_file_object` streams from disk but
/// takes the *other* `AttachmentSource` type (`models::attachment`, with an
/// `InMemory` variant), so it cannot be reused for this enum directly.)
fn checksum_bytes(bytes: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Register the `file_done` WS callback for `file_id` and return the
/// receiver the upload waits on. The WS dispatcher (`ws/mod.rs`) stashes
/// a `file_done` event whose `file_id` has no registered callback yet, so
/// the callback must exist *before* the server can emit the event — i.e.
/// before the final chunk is POSTed (see the chunk loop), not after.
/// If the event already arrived and was stashed (single-chunk upload),
/// it is delivered to the callback right away.
fn register_upload_callback(client: &ApiClient, file_id: &str) -> oneshot::Receiver<Value> {
    let (tx, rx) = oneshot::channel::<Value>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    let callback: UploadCallback = Arc::new(move |data| {
        let tx = tx.clone();
        Box::pin(async move {
            if let Some(sender) = tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = sender.send(data);
            }
        }) as Pin<Box<dyn Future<Output = ()> + Send>>
    });
    if let Ok(mut map) = client.ctx().upload_callbacks.lock() {
        map.insert(file_id.to_string(), callback.clone());
    }
    // The server may already have emitted `file_done` before this
    // callback existed (single-chunk upload); if the dispatcher stashed
    // that event, deliver it to the callback right away instead of
    // waiting out the 120s timeout.
    if let Some(data) = client.ctx().file_done_stash.take(file_id) {
        let cb = callback;
        tokio::spawn(async move {
            cb(data).await;
        });
    }
    rx
}

fn unregister_upload_callback(client: &ApiClient, file_id: &str) {
    if let Ok(mut map) = client.ctx().upload_callbacks.lock() {
        map.remove(file_id);
    }
    client.ctx().file_done_stash.remove(file_id);
}

/// Pick the URL to send the message with. `file_done` data wins; the chunk
/// response's own `fileUrl` is the fallback. Never returns an empty URL:
/// a caller that sent an empty `fileUrl` would fail downstream anyway, so
/// fail loudly here instead of stalling the bot and then sending a broken
/// message.
fn resolve_file_url(ws_data: Option<&Value>, raw_file_url: Option<&str>) -> Result<String> {
    let from_ws = ws_data
        .and_then(|d| d.get("fileUrl").or_else(|| d.get("file_url")))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !from_ws.is_empty() {
        return Ok(from_ws.to_string());
    }
    if let Some(url) = raw_file_url.filter(|u| !u.is_empty()) {
        return Ok(url.to_string());
    }
    Err(ZaloError::Api(ZaloApiError::new(
        "Upload finished without a fileUrl (file_done event never arrived)",
    )))
}

/// Check an upload envelope for an error code, unwrap its `data` field,
/// and build the typed response. `data` must be an object: the old code
/// passed a string `data` straight into `RawUploadResponse::from_value`,
/// which silently produced an all-empty struct (empty URL) for an
/// encrypted response that was never decrypted.
fn raw_from_envelope(value: Value) -> Result<RawUploadResponse> {
    if let Some(error_code) = value.get("error_code").and_then(|v| v.as_i64()) {
        if error_code != 0 {
            let msg = value
                .get("error_message")
                .and_then(|v| v.as_str())
                .unwrap_or("Upload error")
                .to_string();
            return Err(ZaloError::Api(ZaloApiError::with_code(msg, error_code)));
        }
    }
    let data = value.get("data").cloned().unwrap_or(value);
    if let Some(error_code) = data.get("error_code").and_then(|v| v.as_i64()) {
        if error_code != 0 {
            let msg = data
                .get("error_message")
                .and_then(|v| v.as_str())
                .unwrap_or("Upload error")
                .to_string();
            return Err(ZaloError::Api(ZaloApiError::with_code(msg, error_code)));
        }
    }
    if !data.is_object() {
        return Err(ZaloError::Api(ZaloApiError::new(
            "Failed to parse upload response: data is not an object (encrypted response?)",
        )));
    }
    Ok(RawUploadResponse::from_value(data))
}

/// If `value` carries `data` as an encrypted string, decrypt it (same
/// AES scheme as `factory::handle_zalo_response`) and parse the result.
/// Returns `None` when `data` is not a string or decryption/parsing fails,
/// in which case the caller falls through to the plain path.
fn try_decrypt_data_field(client: &ApiClient, value: &Value) -> Option<Value> {
    let data_str = value.get("data")?.as_str()?;
    let decoded = crate::crypto::decode_aes(&client.ctx().secret_key, data_str)?;
    serde_json::from_str::<Value>(&decoded).ok()
}

/// Parse an upload response body: plain JSON first, then — as the old
/// comment promised but never implemented — fall back to the encrypted
/// resolver when `data` is an encrypted string, or when the whole body is
/// a raw encrypted string.
fn parse_upload_response(client: &ApiClient, body: &[u8]) -> Result<RawUploadResponse> {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(decrypted) = try_decrypt_data_field(client, &value) {
            return raw_from_envelope(decrypted);
        }
        return raw_from_envelope(value);
    }
    // Not JSON at all: the body itself may be a raw encrypted string.
    if let Ok(text) = std::str::from_utf8(body) {
        let text = text.trim();
        if !text.is_empty() {
            if let Some(decoded) = crate::crypto::decode_aes(&client.ctx().secret_key, text) {
                if let Ok(value) = serde_json::from_str::<Value>(&decoded) {
                    return raw_from_envelope(value);
                }
            }
        }
    }
    Err(ZaloError::Api(ZaloApiError::new(
        "Failed to parse upload response",
    )))
}

async fn post_chunk(
    client: &ApiClient,
    request_url: &str,
    chunk: Vec<u8>,
    filename: &str,
) -> Result<RawUploadResponse> {
    let base = client.ctx_to_base();
    let http = crate::http::get_http(&base).await?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ORIGIN,
        reqwest::header::HeaderValue::from_static("https://chat.zalo.me"),
    );
    headers.insert(
        reqwest::header::REFERER,
        reqwest::header::HeaderValue::from_static("https://chat.zalo.me/"),
    );
    if let Ok(ua) = reqwest::header::HeaderValue::from_str(&client.ctx().user_agent) {
        headers.insert(reqwest::header::USER_AGENT, ua);
    }

    // The old code sent the chunk with no per-request timeout (the client
    // only has a 5s *connect* timeout) and no retry, so a stalled chunk
    // hung the send task forever. Retry 429/5xx + transport errors with
    // the session's retry policy; a chunk POST is idempotent (same
    // clientId + chunkId re-uploads the same chunk), and each attempt gets
    // the policy timeout (default 60s) instead of hanging indefinitely.
    // (`http::request` cannot be used here: it only sends string bodies,
    // not multipart forms.)
    let policy = &client.ctx().options.retry;
    let attempts = policy.limit.saturating_add(1).max(1);
    let per_attempt_timeout = if policy.timeout_ms > 0 {
        Duration::from_millis(policy.timeout_ms)
    } else {
        Duration::from_secs(60)
    };
    let mut last_err: Option<ZaloError> = None;
    for attempt in 0..attempts {
        let form = reqwest::multipart::Form::new().part(
            "chunkContent",
            reqwest::multipart::Part::bytes(chunk.clone())
                .file_name(filename.to_string())
                .mime_str("application/octet-stream")
                .unwrap_or_else(|_| reqwest::multipart::Part::bytes(Vec::new())),
        );
        let send = http
            .client
            .post(request_url)
            .headers(headers.clone())
            .multipart(form)
            .timeout(per_attempt_timeout)
            .send()
            .await;
        match send {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    // Retry rate-limits / server errors; fail fast otherwise.
                    let retryable =
                        status.as_u16() == 429 || status.is_server_error();
                    if retryable && attempt + 1 < attempts {
                        let wait = policy
                            .delay_ms
                            .saturating_mul(2u64.saturating_pow(attempt))
                            .min(policy.max_delay_ms);
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                        continue;
                    }
                    return Err(ZaloError::Api(ZaloApiError::new(format!(
                        "Upload failed with status {}",
                        status
                    ))));
                }
                let body = resp.bytes().await.map_err(ZaloError::Http)?;
                return parse_upload_response(client, &body);
            }
            Err(e) => {
                if attempt + 1 < attempts {
                    last_err = Some(ZaloError::Http(e));
                    let wait = policy
                        .delay_ms
                        .saturating_mul(2u64.saturating_pow(attempt))
                        .min(policy.max_delay_ms);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    continue;
                }
                return Err(ZaloError::Http(e));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        ZaloError::Api(ZaloApiError::new("Upload failed: retry loop ended without a result"))
    }))
}

pub async fn upload_attachment(
    client: &ApiClient,
    sources: Vec<AttachmentSource>,
    thread_id: &str,
    thread_type: ThreadType,
) -> Result<UploadAttachmentResponse> {
    upload_attachment_internal(client, sources, thread_id, thread_type).await
}

pub async fn upload_attachment_sources(
    client: &ApiClient,
    sources: Vec<AttachmentSource>,
    thread_id: &str,
    thread_type: ThreadType,
) -> Result<UploadAttachmentResponse> {
    upload_attachment_internal(client, sources, thread_id, thread_type).await
}

async fn upload_attachment_internal(
    client: &ApiClient,
    sources: Vec<AttachmentSource>,
    thread_id: &str,
    thread_type: ThreadType,
) -> Result<UploadAttachmentResponse> {
    if sources.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new("Missing sources")));
    }
    if thread_id.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new("Missing threadId")));
    }

    let settings = client.ctx().settings.clone();
    let max_file = sharefile_setting_u64(&settings, "max_file", 10) as usize;
    if sources.len() > max_file {
        return Err(ZaloError::Api(ZaloApiError::new(format!(
            "Exceed maximum file of {}",
            max_file
        ))));
    }

    let chunk_size = sharefile_setting_u64(&settings, "chunk_size_file", 1_048_576) as usize;
    let max_size_mb = sharefile_setting_u64(&settings, "max_size_share_file_v3", 100);
    let max_size_bytes = max_size_mb.saturating_mul(1024 * 1024);

    let is_group = matches!(thread_type, ThreadType::Group);
    let file_base = client.service_url("file", "/api")?;
    let type_param = if is_group { "11" } else { "2" };
    let mut client_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let mut results: UploadAttachmentResponse = Vec::with_capacity(sources.len());

    for source in sources {
        // Validate existence for paths early.
        if let AttachmentSource::Path(path) = &source {
            if !Path::new(path).exists() {
                return Err(ZaloError::Api(ZaloApiError::new("File not found")));
            }
        }

        // Extension is derived before the source is moved into
        // `file_bytes_and_name` (which takes ownership so an inline buffer
        // is moved, not cloned).
        let ext = get_file_extension(match &source {
            AttachmentSource::Path(p) => p.as_str(),
            AttachmentSource::Inline { filename, .. } => filename.as_str(),
        })
        .trim_start_matches('.')
        .to_ascii_lowercase();
        if !is_extension_valid(&ext, &settings) {
            return Err(ZaloError::Api(ZaloApiError::new(format!(
                "File extension \"{}\" is not allowed",
                ext
            ))));
        }

        let (bytes, file_name) = file_bytes_and_name(source).await?;

        let total_size = bytes.len() as u64;
        // Empty file: `bytes.chunks()` would iterate zero times, leaving
        // `last_raw` as None and failing later with the cryptic
        // "Empty upload response". Fail here with a clear message instead.
        if total_size == 0 {
            return Err(ZaloError::Api(ZaloApiError::new(format!(
                "File rỗng (empty file, 0 bytes): {}",
                file_name
            ))));
        }
        if max_size_bytes > 0 && total_size > max_size_bytes {
            return Err(ZaloError::Api(ZaloApiError::new(format!(
                "File {} size exceed maximum size of {}MB",
                file_name, max_size_mb
            ))));
        }

        let kind = classify_extension(&ext);
        let (width, height) = if matches!(kind, FileKind::Image) {
            image_dimensions(&bytes).unwrap_or((0, 0))
        } else {
            (0, 0)
        };

        let total_chunk = std::cmp::max(1, ((total_size as usize) + chunk_size - 1) / chunk_size);
        let mut params = serde_json::Map::new();
        if is_group {
            params.insert("grid".to_string(), Value::String(thread_id.to_string()));
        } else {
            params.insert("toid".to_string(), Value::String(thread_id.to_string()));
        }
        params.insert("totalChunk".to_string(), Value::from(total_chunk as i64));
        params.insert("fileName".to_string(), Value::String(file_name.clone()));
        params.insert("clientId".to_string(), Value::from(client_id));
        client_id += 1;
        params.insert("totalSize".to_string(), Value::from(total_size as i64));
        params.insert("imei".to_string(), Value::String(client.ctx().imei.clone()));
        params.insert("isE2EE".to_string(), Value::from(0));
        params.insert("jxl".to_string(), Value::from(0));
        params.insert("chunkId".to_string(), Value::from(1));

        let url_path = format!(
            "{}/{}/{}",
            file_base.trim_end_matches('/'),
            if is_group { "group" } else { "message" },
            kind.url_type()
        );

        let mut last_raw: Option<RawUploadResponse> = None;
        // Receiver for the `file_done` WS event, registered as soon as the
        // server first returns a file id. Images never wait for `file_done`,
        // so only file/video uploads register.
        let needs_file_done = matches!(kind, FileKind::Video | FileKind::Other);
        let mut upload_rx: Option<oneshot::Receiver<Value>> = None;
        let mut upload_file_id: Option<String> = None;
        for (idx, chunk) in bytes.chunks(chunk_size).enumerate() {
            params.insert("chunkId".to_string(), Value::from((idx + 1) as i64));
            let params_value = Value::Object(params.clone());
            let encrypted = client
                .encode_aes(&params_value.to_string())
                .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Failed to encrypt message")))?;

            // `make_url` appends the `zpw_ver` / `zpw_type` markers the Zalo
            // web API expects on every request (and URL-encodes the values).
            let request_url = client.make_url(
                &url_path,
                &[
                    ("type", type_param.to_string()),
                    ("params", encrypted.clone()),
                ],
                true,
            )?;
            let raw = match post_chunk(client, &request_url, chunk.to_vec(), &file_name).await {
                Ok(raw) => raw,
                Err(e) => {
                    // Do not leak a callback registered for an upload that
                    // will never complete.
                    if let Some(fid) = &upload_file_id {
                        unregister_upload_callback(client, fid);
                    }
                    return Err(e);
                }
            };
            // Race fix: the server emits `file_done` as soon as the final
            // chunk lands, and the WS dispatcher drops the event if no
            // callback is registered for that file id yet. The file id is
            // normally already present in the first chunk response, so
            // register here — before the final chunk is POSTed — instead
            // of only after the whole upload (the old code registered
            // after the last chunk, then waited up to 120s for an event
            // that had already been dropped, and sent an empty URL).
            // Single-chunk uploads still register right after their only
            // chunk; if the event already arrived, the dispatcher stashed
            // it and `register_upload_callback` delivers it immediately.
            if needs_file_done && upload_rx.is_none() {
                if let Some(fid) = raw.file_id.clone().filter(|s| !s.is_empty()) {
                    upload_rx = Some(register_upload_callback(client, &fid));
                    upload_file_id = Some(fid);
                }
            }
            last_raw = Some(raw);
        }

        let raw =
            last_raw.ok_or_else(|| ZaloError::Api(ZaloApiError::new("Empty upload response")))?;

        let valid = raw.file_id.as_deref().map(|id| id != "-1").unwrap_or(true)
            && raw.photo_id.as_deref().map(|id| id != "-1").unwrap_or(true);

        if !valid {
            if let Some(fid) = &upload_file_id {
                unregister_upload_callback(client, fid);
            }
            return Err(ZaloError::Api(ZaloApiError::new(
                "Upload rejected by server",
            )));
        }

        match kind {
            FileKind::Image => {
                // LOG CHẨN ĐOÁN (tạm thời, vụ ảnh ra HD thay vì ORIGINAL):
                // ghi tên key của chunk response cuối + oriUrl có về không.
                // Chỉ log TÊN key, không log giá trị URL. Mức warn để chắc
                // chắn hiện trong log live của bot (bot mặc định chỉ hiện
                // ERROR khi không set RUST_LOG; user đang thấy cả WARN).
                // Khi chẩn đoán xong thì xoá log này (hoặc hạ xuống debug).
                let has = |v: &Option<String>| {
                    v.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
                };
                log::warn!(
                    "[upload-diag] chunk cuoi upload anh: keys={:?} oriUrl={} fileUrl={} normalUrl={} hdUrl={} thumbUrl={}",
                    raw.data_keys,
                    has(&raw.ori_url),
                    has(&raw.file_url),
                    has(&raw.normal_url),
                    has(&raw.hd_url),
                    has(&raw.thumb_url),
                );
                results.push(UploadAttachmentType::Image(UploadAttachmentImageResponse {
                    normal_url: raw.normal_url.unwrap_or_default(),
                    // Giữ URL gốc: ưu tiên oriUrl server trả về, rồi
                    // fileUrl trực tiếp từ chunk response, cuối cùng rỗng
                    // (đường gửi sẽ fallback về normal_url).
                    ori_url: raw
                        .ori_url
                        .or(raw.file_url)
                        .unwrap_or_default(),
                    photo_id: raw.photo_id.unwrap_or_default(),
                    finished: raw.finished,
                    hd_url: raw.hd_url.clone().unwrap_or_default(),
                    thumb_url: raw.thumb_url.unwrap_or_default(),
                    client_file_id: raw.client_file_id,
                    chunk_id: raw.chunk_id,
                    file_type: "image".to_string(),
                    width,
                    height,
                    total_size,
                    hd_size: total_size,
                }));
            }
            FileKind::Video | FileKind::Other => {
                let file_id = raw.file_id.clone().unwrap_or_default();
                // LOG CHẨN ĐOÁN (như nhánh Image): tên key chunk response
                // cuối + fileUrl có về không. Chỉ log TÊN key, không log
                // giá trị URL. Mức warn để chắc chắn hiện trong log live.
                log::warn!(
                    "[upload-diag] chunk cuoi upload file: kind={} keys={:?} fileUrl={} fileId_rong={}",
                    if matches!(kind, FileKind::Video) { "video" } else { "other" },
                    raw.data_keys,
                    raw.file_url.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
                    file_id.is_empty(),
                );
                // If the file id only appeared in the last chunk response
                // (e.g. a single-chunk upload), register now, immediately
                // after the upload — the early-registration path above
                // already handled the multi-chunk case.
                if upload_rx.is_none() && !file_id.is_empty() {
                    upload_rx = Some(register_upload_callback(client, &file_id));
                    upload_file_id = Some(file_id.clone());
                }

                let ws_data: Option<Value> = match upload_rx {
                    Some(rx) => {
                        let data = timeout(Duration::from_secs(120), rx)
                            .await
                            .ok()
                            .and_then(|r| r.ok());
                        if let Some(fid) = &upload_file_id {
                            unregister_upload_callback(client, fid);
                        }
                        data
                    }
                    None => None,
                };

                // Checksum over the buffer already in RAM — no second read.
                let checksum = checksum_bytes(&bytes);
                // Never send an empty URL: fall back to the chunk
                // response's own fileUrl, else fail loudly instead of
                // waiting 120s and then sending a broken message.
                let file_url = resolve_file_url(ws_data.as_ref(), raw.file_url.as_deref())?;
                let resolved_file_id = ws_data
                    .as_ref()
                    .and_then(|d| d.get("fileId").or_else(|| d.get("file_id")))
                    .and_then(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .or_else(|| v.as_i64().map(|n| n.to_string()))
                    })
                    .unwrap_or(file_id);

                if matches!(kind, FileKind::Video) {
                    results.push(UploadAttachmentType::Video(UploadAttachmentVideoResponse {
                        finished: raw.finished,
                        client_file_id: raw.client_file_id,
                        chunk_id: raw.chunk_id,
                        file_type: "video".to_string(),
                        file_url,
                        file_id: resolved_file_id,
                        checksum,
                        total_size,
                        file_name: file_name.clone(),
                    }));
                } else {
                    results.push(UploadAttachmentType::File(UploadAttachmentFileResponse {
                        finished: raw.finished,
                        client_file_id: raw.client_file_id,
                        chunk_id: raw.chunk_id,
                        file_type: "others".to_string(),
                        file_url,
                        file_id: resolved_file_id,
                        checksum,
                        total_size,
                        file_name: file_name.clone(),
                    }));
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_url_uu_tien_ori_url_roi_moi_fallback_normal_url() {
        // Có oriUrl (gốc) -> gửi bản gốc, không gửi bản Thường.
        let with_ori = UploadAttachmentImageResponse {
            normal_url: "https://cdn/n.jpg".to_string(),
            ori_url: "https://cdn/o.jpg".to_string(),
            ..Default::default()
        };
        assert_eq!(with_ori.original_url(), "https://cdn/o.jpg");
        // Không có oriUrl -> fallback bản Thường (hành vi cũ giữ nguyên).
        let without_ori = UploadAttachmentImageResponse {
            normal_url: "https://cdn/n.jpg".to_string(),
            ori_url: String::new(),
            ..Default::default()
        };
        assert_eq!(without_ori.original_url(), "https://cdn/n.jpg");
        // oriUrl toàn khoảng trắng cũng coi như không có.
        let blank_ori = UploadAttachmentImageResponse {
            normal_url: "https://cdn/n.jpg".to_string(),
            ori_url: "   ".to_string(),
            ..Default::default()
        };
        assert_eq!(blank_ori.original_url(), "https://cdn/n.jpg");
        // Không có oriUrl nhưng có hdUrl -> dùng hdUrl (server live
        // không bao giờ trả oriUrl/fileUrl nhưng luôn trả hdUrl —
        // log `[upload-diag]` 2026-11-28).
        let no_ori_with_hd = UploadAttachmentImageResponse {
            normal_url: "https://cdn/n.jpg".to_string(),
            ori_url: String::new(),
            hd_url: "https://cdn/h.jpg".to_string(),
            ..Default::default()
        };
        assert_eq!(no_ori_with_hd.original_url(), "https://cdn/h.jpg");
        // oriUrl trắng + có hdUrl -> dùng hdUrl.
        let blank_ori_with_hd = UploadAttachmentImageResponse {
            normal_url: "https://cdn/n.jpg".to_string(),
            ori_url: "   ".to_string(),
            hd_url: "https://cdn/h.jpg".to_string(),
            ..Default::default()
        };
        assert_eq!(blank_ori_with_hd.original_url(), "https://cdn/h.jpg");
        // Có cả oriUrl lẫn hdUrl -> oriUrl vẫn thắng.
        let both = UploadAttachmentImageResponse {
            normal_url: "https://cdn/n.jpg".to_string(),
            ori_url: "https://cdn/o.jpg".to_string(),
            hd_url: "https://cdn/h.jpg".to_string(),
            ..Default::default()
        };
        assert_eq!(both.original_url(), "https://cdn/o.jpg");
        // Không có oriUrl, hdUrl trắng -> fallback bản Thường.
        let blank_hd = UploadAttachmentImageResponse {
            normal_url: "https://cdn/n.jpg".to_string(),
            ori_url: String::new(),
            hd_url: "   ".to_string(),
            ..Default::default()
        };
        assert_eq!(blank_hd.original_url(), "https://cdn/n.jpg");
    }

    #[test]
    fn raw_upload_response_doc_ori_url_tu_chunk_response() {
        let raw = RawUploadResponse::from_value(serde_json::json!({
            "normalUrl": "https://cdn/n.jpg",
            "hdUrl": "https://cdn/h.jpg",
            "thumbUrl": "https://cdn/t.jpg",
            "oriUrl": "https://cdn/o.jpg",
            "fileUrl": "https://cdn/f.jpg",
            "photoId": "123"
        }));
        assert_eq!(raw.ori_url.as_deref(), Some("https://cdn/o.jpg"));
        assert_eq!(raw.normal_url.as_deref(), Some("https://cdn/n.jpg"));
        // Không có oriUrl -> None (đường gửi fallback về hd_url rồi mới
        // tới normal_url).
        let raw2 = RawUploadResponse::from_value(serde_json::json!({
            "normalUrl": "https://cdn/n.jpg",
            "photoId": "123"
        }));
        assert!(raw2.ori_url.is_none());
    }

    #[test]
    fn classify_gif_is_image_and_mov_webm_are_video() {
        assert!(matches!(classify_extension("gif"), FileKind::Image));
        assert!(matches!(classify_extension("GIF"), FileKind::Image));
        assert!(matches!(classify_extension("mov"), FileKind::Video));
        assert!(matches!(classify_extension("webm"), FileKind::Video));
        assert!(matches!(classify_extension("mp4"), FileKind::Video));
        assert!(matches!(classify_extension("jpg"), FileKind::Image));
        assert!(matches!(classify_extension("pdf"), FileKind::Other));
        assert!(matches!(classify_extension("aac"), FileKind::Other));
    }

    #[test]
    fn checksum_bytes_matches_known_md5() {
        // md5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(
            checksum_bytes(b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            checksum_bytes(b""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn raw_from_envelope_unwraps_data_and_rejects_string_data() {
        // Plain object inside `data`.
        let raw = raw_from_envelope(serde_json::json!({
            "error_code": 0,
            "data": {"fileId": "42", "fileUrl": "https://x/y", "clientFileId": 7, "chunkId": 1}
        }))
        .unwrap();
        assert_eq!(raw.file_id.as_deref(), Some("42"));
        assert_eq!(raw.file_url.as_deref(), Some("https://x/y"));

        // Encrypted-style `data` as a string must NOT silently become an
        // empty struct with an empty URL — it is an error until decrypted
        // (see `try_decrypt_data_field` / `parse_upload_response`).
        assert!(raw_from_envelope(serde_json::json!({
            "error_code": 0,
            "data": "U2FsdGVkX1+encrypted..."
        }))
        .is_err());

        // Non-zero error codes surface.
        assert!(raw_from_envelope(
            serde_json::json!({"error_code": 5, "error_message": "nope"})
        )
        .is_err());
        assert!(raw_from_envelope(serde_json::json!({
            "error_code": 0,
            "data": {"error_code": 9, "error_message": "bad"}
        }))
        .is_err());
    }

    #[test]
    fn resolve_file_url_prefers_ws_event_then_raw_fallback_then_errors() {
        // file_done data wins.
        assert_eq!(
            resolve_file_url(
                Some(&serde_json::json!({"fileUrl": "https://ws/url", "fileId": "1"})),
                Some("https://raw/url"),
            )
            .unwrap(),
            "https://ws/url"
        );
        // No WS event yet the chunk response carried a URL: use it instead
        // of an empty string.
        assert_eq!(
            resolve_file_url(None, Some("https://raw/url")).unwrap(),
            "https://raw/url"
        );
        // Nothing at all: fail loudly, never an empty URL.
        assert!(resolve_file_url(None, None).is_err());
        assert!(resolve_file_url(None, Some("")).is_err());
        assert!(resolve_file_url(
            Some(&serde_json::json!({"fileUrl": ""})),
            None,
        )
        .is_err());
    }
}
