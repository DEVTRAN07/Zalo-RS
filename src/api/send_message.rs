//! Send message endpoint: text messages with optional mentions, quotes,
//! attachments, text styles, urgency and TTL (mirrors the TypeScript source).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::api::client::ApiClient;
use crate::api::upload_attachment::{
    checksum_bytes, file_bytes_and_name, image_dimensions, sharefile_setting_u64,
    AttachmentSource, UploadAttachmentType,
};
use crate::errors::{Result, ZaloApiError, ZaloError};
use crate::models::r#enum::ThreadType;

/// Last clientId handed out (wall-clock millis). Kept so that two sends in
/// the same millisecond still get distinct ids instead of colliding on a
/// bare `Date.now()` — Zalo dedups by clientId and would drop one of them.
static LAST_CLIENT_ID: AtomicI64 = AtomicI64::new(0);

/// Unique per-process `clientId`, shared by the other `send_*` endpoints.
///
/// The value stays timestamp-like: it is the current wall-clock millis,
/// bumped just past the previously issued id only when the clock has not
/// advanced yet (bursts within one millisecond). Strictly increasing within
/// the process, so concurrent sends can never share a clientId.
pub(crate) fn next_client_id() -> i64 {
    let now = chrono::Utc::now().timestamp_millis();
    let mut last = LAST_CLIENT_ID.load(Ordering::Relaxed);
    loop {
        let next = now.max(last.saturating_add(1));
        match LAST_CLIENT_ID.compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return next,
            Err(actual) => last = actual,
        }
    }
}

/// Message urgency, mirrored into `metaData.urgency` (matches the TS `Urgency` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Urgency {
    Default = 0,
    Important = 1,
    Urgent = 2,
}

/// Typed response for send_message and send_message_options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub msg_id: i64,
    /// clientId đã gửi kèm request — cần cho `undo` (thu hồi) và
    /// `addReaction`. Trước đây upstream tự sinh nhưng không trả ra,
    /// nên bot không bao giờ hẹn thu hồi được.
    #[serde(default)]
    pub cli_msg_id: i64,
}

/// Options for [`send_message_options`], mirroring the TypeScript `MessageContent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageOptions {
    pub message: String,
    pub thread_id: String,
    pub thread_type: ThreadType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mention_info: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_msg_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_owner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_cli_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_ts: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_ttl: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<AttachmentSource>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_properties: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urgency: Option<Urgency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<i32>,
}

fn insert_opt(map: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        map.insert(key.to_string(), value);
    }
}

/// Extract msg_id from API response (handles both msgId and msg_id, and
/// both numeric and string forms: Zalo returns msgId as a string —
/// `TMessage.msg_id` is a `String` — so a numeric-only parse would report
/// "Missing msg_id" even though the message was sent).
fn extract_msg_id(response: Value) -> Result<i64> {
    response
        .get("msgId")
        .or_else(|| response.get("msg_id"))
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Missing msg_id in response")))
}

/// Send a plain text message.
///
/// `thread_type`: 0 = user, 1 = group.
///
/// This preserves the original minimal behaviour when no extra features are used.
pub async fn send_message(
    client: &ApiClient,
    message: &str,
    thread_id: &str,
    thread_type: u8,
) -> Result<SendMessageResponse> {
    if message.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new("Missing message content")));
    }
    if thread_id.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new("Missing thread_id")));
    }

    let is_group = thread_type == 1;
    let (service, path) = if is_group {
        ("group", "/api/group/sendmsg")
    } else {
        ("chat", "/api/message/sms")
    };

    let url = client.service_url(service, path)?;
    let url = client.make_url(&url, &[], true)?;

    let client_id = next_client_id();

    let params = if is_group {
        serde_json::json!({
            "grid": thread_id,
            "message": message,
            "clientId": client_id,
            "visibility": 0,
            "imei": client.ctx().imei,
        })
    } else {
        serde_json::json!({
            "toId": thread_id,
            "message": message,
            "clientId": client_id,
            "imei": client.ctx().imei,
            "mentionInfo": "",
        })
    };

    let response = client.post_encrypted(&url, &params).await?;
    let msg_id = extract_msg_id(response)?;
    Ok(SendMessageResponse { msg_id, cli_msg_id: client_id })
}

/// Send a message with optional mentions, quotes, attachments, text styles,
/// urgency and TTL.
///
/// The URL path is chosen based on the features present:
/// - quote fields  → `/api/{message,group}/quote`
/// - mention (group only) → `/api/group/mention`
/// - otherwise     → `/api/message/sms` (user) or `/api/group/sendmsg` (group)
///
/// Quote + mention together: the quote endpoint is chosen, but `mentionInfo`
/// is still sent along for group threads (the quote endpoint receives it);
/// when the text is sent first ahead of attachments it carries the mention
/// too. Mentions in 1-1 chats are rejected outright instead of being dropped
/// silently — the Zalo mention endpoints are group-only.
///
/// When only a plain text message is given the behaviour matches
/// [`send_message`].
pub async fn send_message_options(
    client: &ApiClient,
    options: SendMessageOptions,
) -> Result<SendMessageResponse> {
    let SendMessageOptions {
        message,
        thread_id,
        thread_type,
        mention_info,
        quote_msg_id,
        quote_owner_id,
        quote_cli_id,
        quote_type,
        quote_ts,
        quote_data,
        quote_ttl,
        attachments,
        text_properties,
        urgency,
        meta_data,
        ttl,
        visibility,
    } = options;

    if thread_id.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new("Missing thread_id")));
    }
    let has_attachments = attachments.as_ref().map_or(false, |src| !src.is_empty());
    if message.is_empty() && !has_attachments {
        return Err(ZaloError::Api(ZaloApiError::new("Missing message content")));
    }

    let is_group = thread_type == ThreadType::Group;
    let service = if is_group { "group" } else { "chat" };
    let root = if is_group {
        "/api/group"
    } else {
        "/api/message"
    };

    let quote_present = quote_msg_id.is_some()
        || quote_owner_id.is_some()
        || quote_cli_id.is_some()
        || quote_type.is_some()
        || quote_ts.is_some()
        || quote_data.is_some()
        || quote_ttl.is_some();
    let mention_present = mention_info.is_some();

    // Mentions are group-only: fail loudly instead of silently dropping
    // mentionInfo for a 1-1 thread.
    if mention_present && !is_group {
        return Err(ZaloError::Api(ZaloApiError::new(
            "Mentions are only supported in group threads",
        )));
    }

    let path = if quote_present {
        format!("{}/quote", root)
    } else if mention_present && is_group {
        format!("{}/mention", root)
    } else if is_group {
        "/api/group/sendmsg".to_string()
    } else {
        "/api/message/sms".to_string()
    };

    let url = client.service_url(service, &path)?;
    let url = client.make_url(&url, &[("nretry", "0".to_string())], true)?;

    let client_id = next_client_id();

    let message_empty = message.is_empty();
    let mut params = Map::new();
    params.insert("message".to_string(), Value::String(message.clone()));
    params.insert("clientId".to_string(), Value::from(client_id));
    if !is_group || !quote_present {
        params.insert("imei".to_string(), Value::String(client.ctx().imei.clone()));
    }
    if is_group {
        params.insert("grid".to_string(), Value::String(thread_id.clone()));
        params.insert(
            "visibility".to_string(),
            Value::from(visibility.unwrap_or(0)),
        );
    } else {
        params.insert("toid".to_string(), Value::String(thread_id.clone()));
    }
    if is_group {
        insert_opt(&mut params, "mentionInfo", mention_info.clone());
    }
    params.insert("ttl".to_string(), Value::from(ttl.unwrap_or(0)));
    insert_opt(&mut params, "textProperties", text_properties);
    let meta = meta_data.or_else(|| urgency.map(|u| serde_json::json!({ "urgency": u as i64 })));
    insert_opt(&mut params, "metaData", meta.clone());
    let attachment_meta = meta;

    if quote_present {
        insert_opt(&mut params, "qmsgOwner", quote_owner_id.map(Value::String));
        insert_opt(&mut params, "qmsgId", quote_msg_id.map(Value::String));
        insert_opt(&mut params, "qmsgCliId", quote_cli_id.map(Value::String));
        insert_opt(&mut params, "qmsgType", quote_type.map(Value::String));
        insert_opt(&mut params, "qmsgTs", quote_ts.map(Value::from));
        insert_opt(&mut params, "qmsg", quote_data.map(Value::String));
        insert_opt(&mut params, "qmsgTTL", quote_ttl.map(Value::from));
        if is_group {
            params.insert("visibility".to_string(), Value::from(0));
        }
    }

    let params = Value::Object(params);

    if has_attachments {
        let sources = attachments.expect("presence checked above");
        // JS gốc tách file .gif ra khỏi upload thường: gif đi endpoint
        // `gif?` riêng (kèm upthumb) — gửi qua `photo_original` sẽ bị
        // flatten thành ảnh tĩnh (xem `sendMessage.js:265,377`).
        let (gif_sources, other_sources): (Vec<AttachmentSource>, Vec<AttachmentSource>) =
            sources
                .into_iter()
                .partition(|s| attachment_extension(s) == "gif");
        let has_others = !other_sources.is_empty();
        let can_be_desc = has_others && can_carry_text_as_desc(&other_sources);
        let mut desc = message.clone();
        // Text chỉ gửi trước riêng khi có file thường (hoặc có quote —
        // gif không mang được quote); gif-only không quote thì text đi
        // kèm trong params `msg` của gif đầu tiên (đúng JS).
        let send_text_first =
            !message_empty && (!can_be_desc || quote_present) && (has_others || quote_present);
        if send_text_first {
            let response = client.post_encrypted(&url, &params).await?;
            let _ = extract_msg_id(response)?;
            desc = String::new();
        }
        // Text đi kèm gif đầu tiên chỉ khi chưa gửi trước và không có
        // file thường nào mang nó (desc trên ảnh); các gif sau msg rỗng
        // để không lặp text (JS gốc lặp msg ở mọi gif — ta chỉ gửi 1 lần).
        let gif_msg: &str = if desc.is_empty() || has_others {
            ""
        } else {
            &message
        };
        // Đo tách upload-ms vs send-ms: bot cần con số này để biết lệnh
        // chậm ở khâu upload file hay khâu gửi tin (phía bot không đo
        // được vì `send_uploaded_attachments` là private ở đây). Mức warn
        // để hiện trong log live của bot như `[upload-diag]`.
        let t_upload = std::time::Instant::now();
        let mut last_ids: Option<(i64, i64)> = None;
        if has_others {
            let uploaded = crate::api::upload_attachment::upload_attachment(
                client,
                other_sources,
                &thread_id,
                thread_type,
            )
            .await?;
            let upload_ms = t_upload.elapsed().as_millis();
            let t_send = std::time::Instant::now();
            let ids = send_uploaded_attachments(
                client,
                &uploaded,
                &thread_id,
                thread_type,
                &desc,
                mention_info.as_ref(),
                can_be_desc && !quote_present,
                ttl,
                attachment_meta.as_ref(),
            )
            .await?;
            let send_ms = t_send.elapsed().as_millis();
            log::warn!(
                "[send] upload_ms={} send_ms={} total_ms={} n={} is_group={}",
                upload_ms,
                send_ms,
                upload_ms + send_ms,
                uploaded.len() + gif_sources.len(),
                is_group
            );
            last_ids = Some(ids);
        }
        // GIF đi sau file thường (đúng thứ tự JS), mỗi gif 1 POST `gif?`.
        // Khi chỉ có gif thì log tách ở trên không chạy — log gọn ở đây.
        let t_gif = std::time::Instant::now();
        let n_gif = gif_sources.len();
        for (i, gif) in gif_sources.into_iter().enumerate() {
            let msg = if i == 0 { gif_msg } else { "" };
            let r = send_gif(client, &thread_id, thread_type, gif, msg, ttl).await?;
            last_ids = Some((r.msg_id, r.cli_msg_id));
        }
        if !has_others {
            let gif_ms = t_gif.elapsed().as_millis();
            log::warn!(
                "[send] upload_ms=0 send_ms={} total_ms={} n={} is_group={} (gif)",
                gif_ms,
                gif_ms,
                n_gif,
                is_group
            );
        }
        // Trả (msg_id, cli_msg_id) của attachment cuối — đó là id của
        // tin đã gửi (`send_uploaded_attachments` cũng trả như vậy).
        return match last_ids {
            Some((msg_id, cli_msg_id)) => Ok(SendMessageResponse { msg_id, cli_msg_id }),
            None => Err(ZaloError::Api(ZaloApiError::new(
                "No attachment was sent successfully",
            ))),
        };
    }

    let response = client.post_encrypted(&url, &params).await?;
    let msg_id = extract_msg_id(response)?;
    Ok(SendMessageResponse { msg_id, cli_msg_id: client_id })
}

/// Params cho endpoint `gif?` (JS gốc `sendMessage.js` — nhánh gif trong
/// `handleAttachment`). Thuần túy để test được: clientId là string,
/// `visibility`/`toid`/`grid` chỉ có theo đúng phía (nhóm: grid +
/// visibility 0; 1-1: toid).
fn gif_send_params(
    client_id: i64,
    file_name: &str,
    total_size: u64,
    width: u64,
    height: u64,
    msg: &str,
    ttl: i64,
    is_group: bool,
    thread_id: &str,
    thumb: &str,
    checksum: &str,
) -> Value {
    let mut p = serde_json::json!({
        "clientId": client_id.to_string(),
        "fileName": file_name,
        "totalSize": total_size,
        "width": width,
        "height": height,
        "msg": msg,
        "type": 1,
        "ttl": ttl,
        "thumb": thumb,
        "checksum": checksum,
        "totalChunk": 1,
        "chunkId": 1,
    });
    if is_group {
        p["grid"] = Value::String(thread_id.to_string());
        p["visibility"] = Value::from(0);
    } else {
        p["toid"] = Value::String(thread_id.to_string());
    }
    p
}

/// POST 1 form multipart (1 lần, timeout theo retry policy, mặc định 60s —
/// đúng JS gốc, nhánh gif không có vòng retry riêng như `post_chunk`).
/// Trả response thô để caller tự `resolve` (envelope Zalo).
async fn post_multipart(
    client: &ApiClient,
    url: &str,
    form: reqwest::multipart::Form,
) -> Result<reqwest::Response> {
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
    let policy = &client.ctx().options.retry;
    let per_attempt_timeout = if policy.timeout_ms > 0 {
        Duration::from_millis(policy.timeout_ms)
    } else {
        Duration::from_secs(60)
    };
    let resp = http
        .client
        .post(url)
        .headers(headers)
        .multipart(form)
        .timeout(per_attempt_timeout)
        .send()
        .await
        .map_err(ZaloError::Http)?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ZaloError::Api(ZaloApiError::new(format!(
            "Multipart POST failed with status {}",
            status
        ))));
    }
    Ok(resp)
}

/// Upload thumbnail cho GIF (JS gốc `upthumb` trong `sendMessage.js`):
/// POST bytes GIF làm `fileContent` (filename `blob`, content-type
/// `image/png`) tới `{file}/api/message/upthumb?params=<AES {clientId,
/// imei}>` — luôn dùng base User kể cả khi gửi vào nhóm. Trả `url` thumb.
async fn upthumb_gif(client: &ApiClient, bytes: &[u8]) -> Result<String> {
    let file_base = client.service_url("file", "/api")?;
    let url_path = format!("{}/message/upthumb", file_base.trim_end_matches('/'));
    let params = serde_json::json!({
        "clientId": next_client_id(),
        "imei": client.ctx().imei,
    });
    let encrypted = client
        .encode_aes(&params.to_string())
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Failed to encrypt message")))?;
    let url = client.make_url(&url_path, &[("params", encrypted)], true)?;
    let form = reqwest::multipart::Form::new().part(
        "fileContent",
        reqwest::multipart::Part::bytes(bytes.to_vec())
            .file_name("blob".to_string())
            .mime_str("image/png")
            .unwrap_or_else(|_| reqwest::multipart::Part::bytes(Vec::new())),
    );
    let resp = post_multipart(client, &url, form).await?;
    let data: Value = client.resolve(resp).await?;
    data.get("url")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("upthumb did not return a thumb url")))
}

/// Gửi 1 file GIF động qua endpoint `gif?` riêng (JS gốc `sendMessage.js`
/// `attachmentUrlType.gif = "gif?"`).
///
/// Trước đây Zalo-RS không có đường này: `.gif` bị xếp `FileKind::Image`
/// rồi gửi qua `photo_original/send` nên Zalo flatten thành ảnh tĩnh —
/// bot phải tự làm `send_gif` phía bot để workaround. Giờ gửi đúng JS:
/// upthumb trước, rồi POST 1 chunk `chunkContent` (toàn bộ file) tới
/// `{file}/api/{group|message}/gif?nretry=0&params=<AES>&type=1`.
/// Bot dùng hàm này thì bỏ được workaround phía bot (đổi phía bot riêng).
pub async fn send_gif(
    client: &ApiClient,
    thread_id: &str,
    thread_type: ThreadType,
    source: AttachmentSource,
    message: &str,
    ttl: Option<i64>,
) -> Result<SendMessageResponse> {
    if thread_id.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new("Missing thread_id")));
    }
    let (bytes, file_name) = file_bytes_and_name(source).await?;
    if !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return Err(ZaloError::Api(ZaloApiError::new(
            "File is not a GIF (expected GIF87a/GIF89a header)",
        )));
    }
    let max_size_mb = sharefile_setting_u64(&client.ctx().settings, "max_size_share_file_v3", 100);
    let max_size_bytes = max_size_mb.saturating_mul(1024 * 1024);
    if max_size_bytes > 0 && (bytes.len() as u64) > max_size_bytes {
        return Err(ZaloError::Api(ZaloApiError::new(format!(
            "File {} size exceed maximum size of {}MB",
            file_name, max_size_mb
        ))));
    }
    let (width, height) = image_dimensions(&bytes).unwrap_or((0, 0));
    let thumb = upthumb_gif(client, &bytes).await?;
    let checksum = checksum_bytes(&bytes);
    let is_group = thread_type == ThreadType::Group;
    let client_id = next_client_id();
    let params = gif_send_params(
        client_id,
        &file_name,
        bytes.len() as u64,
        width,
        height,
        message,
        ttl.unwrap_or(0),
        is_group,
        thread_id,
        &thumb,
        &checksum,
    );
    let encrypted = client
        .encode_aes(&params.to_string())
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Failed to encrypt message")))?;
    let file_base = client.service_url("file", "/api")?;
    let path = if is_group {
        "/api/group/gif"
    } else {
        "/api/message/gif"
    };
    let url_path = format!("{}{}", file_base.trim_end_matches('/'), path);
    let url = client.make_url(
        &url_path,
        &[
            ("nretry", "0".to_string()),
            ("params", encrypted),
            ("type", "1".to_string()),
        ],
        true,
    )?;
    let form = reqwest::multipart::Form::new().part(
        "chunkContent",
        reqwest::multipart::Part::bytes(bytes)
            .file_name(file_name)
            .mime_str("application/octet-stream")
            .unwrap_or_else(|_| reqwest::multipart::Part::bytes(Vec::new())),
    );
    let resp = post_multipart(client, &url, form).await?;
    let data: Value = client.resolve(resp).await?;
    let msg_id = extract_msg_id(data)?;
    Ok(SendMessageResponse {
        msg_id,
        cli_msg_id: client_id,
    })
}

/// File extension (lowercase, without the dot) of an attachment source.
fn attachment_extension(source: &AttachmentSource) -> String {
    let name = match source {
        AttachmentSource::Path(p) => p.as_str(),
        AttachmentSource::Inline { filename, .. } => filename.as_str(),
    };
    crate::core::utils::get_file_extension(name).to_ascii_lowercase()
}

/// Whether the text can be sent together with the attachments as the image
/// description: exactly one attachment and it is an image (jpg/jpeg/png/webp).
/// Mirrors the TypeScript `canBeDesc` check.
fn can_carry_text_as_desc(sources: &[AttachmentSource]) -> bool {
    sources.len() == 1
        && matches!(
            attachment_extension(&sources[0]).as_str(),
            "jpg" | "jpeg" | "png" | "webp"
        )
}

/// Send already-uploaded attachments through the per-type endpoints, exactly
/// like the TypeScript `handleAttachment` does:
///
/// - image  -> `{file}/api/{group|message}/photo_original/send?`
/// - video / other file -> `{file}/api/{group|message}/asyncfile/msg?`
///
/// Returns the `msg_id` of the last attachment sent (the TypeScript client
/// returns one result per attachment; this API returns a single `msg_id`).
/// Fails instead of returning `0` when nothing was sent at all.
///
/// Mentions ride on the separately-sent text message when a quote is
/// present; on the attachment itself they only ride on a single image that
/// carries the text as its description, without a quote (TypeScript).
async fn send_uploaded_attachments(
    client: &ApiClient,
    uploaded: &[UploadAttachmentType],
    thread_id: &str,
    thread_type: ThreadType,
    desc: &str,
    mention_info: Option<&Value>,
    can_be_desc: bool,
    ttl: Option<i64>,
    meta_data: Option<&Value>,
) -> Result<(i64, i64)> {
    if uploaded.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new(
            "No attachments to send",
        )));
    }
    let is_group = thread_type == ThreadType::Group;
    let is_multi = uploaded.len() > 1;
    // TypeScript `getGroupLayoutId()` returns `Date.now()`.
    let group_layout_id = chrono::Utc::now().timestamp_millis();
    // TypeScript counts down from `uploadAttachment.length - 1`.
    let mut index_in_group = uploaded.len() as i64 - 1;
    let mut last_msg_id: Option<i64> = None;
    // cli_msg_id của attachment cuối — chính là id dùng để thu hồi
    // tin đã gửi: ảnh dùng `client_id` sinh mới ở mỗi vòng lặp
    // (`"clientId": client_id.to_string()`); video/file dùng
    // `client_file_id` từ response upload (`"clientId": client_file_id`).
    let mut last_cli_msg_id: i64 = 0;

    for att in uploaded {
        // Fresh unique id per attachment (never a bare timestamp: two
        // attachments sent in the same millisecond must not share one).
        let client_id = next_client_id();
        // clientId thực tế gửi kèm attachment này.
        let sent_cli_id = match att {
            UploadAttachmentType::Image(_) => client_id,
            UploadAttachmentType::Video(v) => v.client_file_id,
            UploadAttachmentType::File(f) => f.client_file_id,
        };
        let (path, mut params) = match att {
            UploadAttachmentType::Image(img) => {
                // ORIGINAL: mọi URL ảnh gửi đi lấy bản gốc
                // (`UploadAttachmentImageResponse::original_url` = oriUrl
                // server trả về, nếu không có thì hdUrl — server không
                // bao giờ trả oriUrl/fileUrl nhưng luôn trả hdUrl theo
                // log live `[upload-diag]` — cuối cùng mới fallback
                // normalUrl). Trước đây cả 3 field đều gán normal_url
                // (bản Thường đã nén) nên ảnh gửi đi bị flatten về bản
                // Thường. hdUrl/thumbUrl giữ nguyên: chỉ là bản xem
                // trước/HD kèm theo, không phải ảnh chính người nhận mở.
                let original_url = img.original_url();
                let mut p = serde_json::json!({
                    "photoId": img.photo_id,
                    "clientId": client_id.to_string(),
                    "desc": desc,
                    "width": img.width,
                    "height": img.height,
                    "rawUrl": original_url,
                    "hdUrl": img.hd_url,
                    "thumbUrl": img.thumb_url,
                    "hdSize": img.total_size.to_string(),
                    "zsource": -1,
                    "ttl": ttl.unwrap_or(0),
                    "jcp": "{\"convertible\":\"jxl\"}",
                });
                // The upload could not measure this image: omit the
                // dimensions instead of sending a bogus 0x0 and letting
                // Zalo use the uploaded file's real size.
                if img.width == 0 || img.height == 0 {
                    p.as_object_mut()
                        .map(|o| {
                            o.remove("width");
                            o.remove("height");
                        });
                }
                if is_group {
                    p["grid"] = Value::String(thread_id.to_string());
                    p["oriUrl"] = Value::String(original_url.to_string());
                } else {
                    p["toid"] = Value::String(thread_id.to_string());
                    p["normalUrl"] = Value::String(original_url.to_string());
                }
                if is_multi {
                    p["groupLayoutId"] = Value::from(group_layout_id);
                    p["isGroupLayout"] = Value::from(1);
                    p["idInGroup"] = Value::from(index_in_group);
                    p["totalItemInGroup"] = Value::from(uploaded.len() as i64);
                }
                // Mentions only ride on a single image that carries the text
                // as its description, without a quote (TypeScript).
                if !is_multi && can_be_desc && is_group {
                    if let Some(m) = mention_info {
                        p["mentionInfo"] = m.clone();
                    }
                }
                let path = if is_group {
                    "/api/group/photo_original/send"
                } else {
                    "/api/message/photo_original/send"
                };
                (path, p)
            }
            UploadAttachmentType::Video(_) | UploadAttachmentType::File(_) => {
                // `Video` and `File` share the same send shape; extract the
                // fields through a common tuple (the two response structs
                // are different types, so one or-pattern binding cannot
                // cover both).
                let (file_id, checksum, total_size, file_name, client_file_id, file_url) = match att
                {
                    UploadAttachmentType::Video(v) => (
                        v.file_id.clone(),
                        v.checksum.clone(),
                        v.total_size,
                        v.file_name.clone(),
                        v.client_file_id,
                        v.file_url.clone(),
                    ),
                    UploadAttachmentType::File(f) => (
                        f.file_id.clone(),
                        f.checksum.clone(),
                        f.total_size,
                        f.file_name.clone(),
                        f.client_file_id,
                        f.file_url.clone(),
                    ),
                    UploadAttachmentType::Image(_) => unreachable!(),
                };
                let mut p = serde_json::json!({
                    "fileId": file_id,
                    "checksum": checksum,
                    // Note the misspelling: the Zalo API expects `extention`.
                    "extention": crate::core::utils::get_file_extension(&file_name)
                        .to_ascii_lowercase(),
                    "checksumSha": "",
                    "totalSize": total_size,
                    "fileName": file_name,
                    "clientId": client_file_id,
                    "fType": 1,
                    "fileCount": 0,
                    "fdata": "{}",
                    "fileUrl": file_url,
                    "zsource": -1,
                    "ttl": ttl.unwrap_or(0),
                });
                if is_group {
                    p["grid"] = Value::String(thread_id.to_string());
                } else {
                    p["toid"] = Value::String(thread_id.to_string());
                }
                let path = if is_group {
                    "/api/group/asyncfile/msg"
                } else {
                    "/api/message/asyncfile/msg"
                };
                (path, p)
            }
        };
        // Urgency/metaData ride on every attachment send, like the
        // TypeScript `handleUrgency(data.params, urgency)` call.
        if let Some(m) = meta_data {
            params["metaData"] = m.clone();
        }
        index_in_group -= 1;

        let base_url = client.service_url("file", path)?;
        let url = client.make_url(&base_url, &[("nretry", "0".to_string())], true)?;
        let response: Value = client.post_encrypted(&url, &params).await?;
        last_msg_id = Some(extract_msg_id(response)?);
        last_cli_msg_id = sent_cli_id;
    }

    match last_msg_id {
        Some(msg_id) => Ok((msg_id, last_cli_msg_id)),
        None => Err(ZaloError::Api(ZaloApiError::new(
            "No attachment was sent successfully",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_extension_is_lowercase_without_dot() {
        assert_eq!(
            attachment_extension(&AttachmentSource::Path("/tmp/Photo.JPG".into())),
            "jpg"
        );
        assert_eq!(
            attachment_extension(&AttachmentSource::Inline {
                filename: "clip.PNG".into(),
                data: vec![],
                metadata: Value::Null,
            }),
            "png"
        );
        assert_eq!(
            attachment_extension(&AttachmentSource::Path("/tmp/noext".into())),
            ""
        );
    }

    #[test]
    fn extract_msg_id_accepts_string_and_numeric_forms() {
        // Zalo returns msgId as a string (TMessage.msg_id is a String).
        assert_eq!(
            extract_msg_id(serde_json::json!({"msgId": "9"})).unwrap(),
            9
        );
        assert_eq!(
            extract_msg_id(serde_json::json!({"msgId": 42})).unwrap(),
            42
        );
        assert_eq!(
            extract_msg_id(serde_json::json!({"msg_id": "7"})).unwrap(),
            7
        );
        assert!(extract_msg_id(serde_json::json!({})).is_err());
        assert!(extract_msg_id(serde_json::json!({"msgId": "not-a-number"})).is_err());
    }

    #[test]
    fn next_client_id_is_unique_and_strictly_increasing() {
        let ids: Vec<i64> = (0..1000).map(|_| next_client_id()).collect();
        for w in ids.windows(2) {
            assert!(w[1] > w[0], "clientIds must be strictly increasing");
        }
        let unique: std::collections::HashSet<i64> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn can_carry_text_as_desc_only_single_image() {
        let img = AttachmentSource::Path("/tmp/a.jpg".into());
        let img2 = AttachmentSource::Path("/tmp/b.png".into());
        let vid = AttachmentSource::Path("/tmp/c.mp4".into());
        assert!(can_carry_text_as_desc(std::slice::from_ref(&img)));
        assert!(!can_carry_text_as_desc(&[img.clone(), img2]));
        assert!(!can_carry_text_as_desc(std::slice::from_ref(&vid)));
        assert!(!can_carry_text_as_desc(&[]));
    }

    #[test]
    fn gif_send_params_dung_shape_js_theo_nhom_va_ca_nhan() {
        // Nhóm: grid + visibility 0, không có toid.
        let p = gif_send_params(
            123456789,
            "fun.gif",
            1024,
            480,
            270,
            "hello",
            0,
            true,
            "555",
            "https://thumb/u",
            "abc123",
        );
        assert_eq!(p["clientId"], "123456789");
        assert_eq!(p["fileName"], "fun.gif");
        assert_eq!(p["totalSize"], 1024);
        assert_eq!(p["width"], 480);
        assert_eq!(p["height"], 270);
        assert_eq!(p["msg"], "hello");
        assert_eq!(p["type"], 1);
        assert_eq!(p["totalChunk"], 1);
        assert_eq!(p["chunkId"], 1);
        assert_eq!(p["thumb"], "https://thumb/u");
        assert_eq!(p["checksum"], "abc123");
        assert_eq!(p["grid"], "555");
        assert_eq!(p["visibility"], 0);
        assert!(p.get("toid").is_none());
        // Chat 1-1: toid, không có grid/visibility.
        let p2 = gif_send_params(
            999, "a.gif", 10, 1, 1, "", 60, false, "777", "https://t", "md5",
        );
        assert_eq!(p2["toid"], "777");
        assert_eq!(p2["ttl"], 60);
        assert!(p2.get("grid").is_none());
        assert!(p2.get("visibility").is_none());
    }

    #[test]
    fn gif_dimensions_doc_tu_header() {
        // GIF89a 480x270: byte 6..10 = width/height LE u16.
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&480u16.to_le_bytes());
        gif.extend_from_slice(&270u16.to_le_bytes());
        gif.extend_from_slice(&[0u8; 10]);
        assert_eq!(image_dimensions(&gif), Some((480, 270)));
        // GIF87a cũng đọc được.
        let mut gif87 = b"GIF87a".to_vec();
        gif87.extend_from_slice(&100u16.to_le_bytes());
        gif87.extend_from_slice(&50u16.to_le_bytes());
        assert_eq!(image_dimensions(&gif87), Some((100, 50)));
        // Không phải GIF -> None (buffer rác).
        assert_eq!(image_dimensions(b"not an image at all"), None);
    }

    #[test]
    fn send_message_response_cli_msg_id_mac_dinh_0() {
        // JSON cũ không có cli_msg_id vẫn parse được (serde default).
        let r: SendMessageResponse = serde_json::from_str(r#"{"msg_id": 123}"#).unwrap();
        assert_eq!(r.msg_id, 123);
        assert_eq!(r.cli_msg_id, 0);
    }

    #[test]
    fn send_message_response_cli_msg_id_round_trip() {
        let r = SendMessageResponse { msg_id: 123, cli_msg_id: 456 };
        let back: SendMessageResponse =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back.msg_id, 123);
        assert_eq!(back.cli_msg_id, 456);
    }
}