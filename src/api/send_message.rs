//! Send message endpoint: text messages with optional mentions, quotes,
//! attachments, text styles, urgency and TTL (mirrors the TypeScript source).

use std::sync::atomic::{AtomicI64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::api::client::ApiClient;
use crate::api::upload_attachment::{AttachmentSource, UploadAttachmentType};
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
    Ok(SendMessageResponse { msg_id })
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
        // Mirrors the TypeScript `sendMessage` attachment flow
        // (zca-js `src/apis/sendMessage.ts`, `handleAttachment`): the text
        // rides along as the image description only for a single
        // jpg/jpeg/png/webp attachment without a quote; otherwise the text
        // is sent first as its own message and the attachments follow with
        // an empty description.
        let can_be_desc = can_carry_text_as_desc(&sources);
        let mut desc = message.clone();
        if !message_empty && (!can_be_desc || quote_present) {
            let response = client.post_encrypted(&url, &params).await?;
            let _ = extract_msg_id(response)?;
            desc = String::new();
        }
        let uploaded = crate::api::upload_attachment::upload_attachment(
            client,
            sources,
            &thread_id,
            thread_type,
        )
        .await?;
        let msg_id = send_uploaded_attachments(
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
        return Ok(SendMessageResponse { msg_id });
    }

    let response = client.post_encrypted(&url, &params).await?;
    let msg_id = extract_msg_id(response)?;
    Ok(SendMessageResponse { msg_id })
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
) -> Result<i64> {
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

    for att in uploaded {
        // Fresh unique id per attachment (never a bare timestamp: two
        // attachments sent in the same millisecond must not share one).
        let client_id = next_client_id();
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
    }

    last_msg_id.ok_or_else(|| {
        ZaloError::Api(ZaloApiError::new("No attachment was sent successfully"))
    })
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
}