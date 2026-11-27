//! General purpose helpers: file metadata, formatting, event decoding.

use std::fs;
use std::io::Read;
use std::path::Path;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::aes::{Aes128, Aes192, Aes256};
use aes_gcm::{AesGcm, KeyInit};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{Datelike, Timelike};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use generic_array::typenum::U16;
use generic_array::GenericArray;
use md5::{Digest, Md5};
use serde_json::Map;
use unicode_normalization::UnicodeNormalization;

use crate::errors::ZaloApiError;
use crate::models::attachment::AttachmentSource;
use crate::models::friend_event::FriendEventType;
use crate::models::group_event::GroupEventType;

/// Always `false` on Rust (no Bun runtime).
pub const IS_BUN: bool = false;

/// Check if a JSON map owns a key.
pub fn has_own(obj: &Map<String, serde_json::Value>, key: &str) -> bool {
    obj.contains_key(key)
}

/// Remove keys with `null` values from a JSON map (Rust equivalent of removing
/// `undefined` keys).
pub fn remove_undefined_keys(obj: &mut Map<String, serde_json::Value>) {
    obj.retain(|_, v| !v.is_null());
}

/// Decode a Base64 string into a byte buffer.
pub fn decode_base64_to_buffer(data: &str) -> Vec<u8> {
    BASE64.decode(data).unwrap_or_default()
}

/// Base64 decode with the same leniency as Node's `Buffer.from(s, "base64")`
/// (what zca-js `decodeBase64ToBuffer` uses): accepts the standard and the
/// URL-safe alphabets, with or without `=` padding, and ignores whitespace.
/// The strict `STANDARD` decoder rejects all of those, so a server payload
/// in base64url / unpadded form failed to decode and every encrypted WS
/// event fell back to its raw `{encrypt, data, ...}` frame (group messages
/// were then dropped by the bot because they have no `groupMsgs`).
fn decode_base64_lenient(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let cleaned: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    BASE64
        .decode(&cleaned)
        .or_else(|_| URL_SAFE.decode(&cleaned))
        .or_else(|_| STANDARD_NO_PAD.decode(&cleaned))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&cleaned))
}

/// Decode a UTF-8 byte array into a string, or `None` on invalid UTF-8.
pub fn decode_unit8_array(data: &[u8]) -> Option<String> {
    std::str::from_utf8(data).ok().map(String::from)
}

/// A decoded websocket event payload.
#[derive(Debug, Clone)]
pub enum DecodedEventData {
    Object(Map<String, serde_json::Value>),
    Value(serde_json::Value),
}

/// Try decompressing `buf` as zlib; `None` when it is not valid zlib.
fn try_zlib(buf: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(buf);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Try decompressing `buf` as gzip; `None` when it is not valid gzip.
fn try_gzip(buf: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(buf);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Try decompressing `buf` as raw deflate (no zlib header); `None` when it
/// is not valid raw deflate.
fn try_raw_deflate(buf: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(buf);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Decompress a decrypted WS payload.
///
/// Zalo normally sends zlib, but live 521 (group message) / 621 frames
/// sometimes arrive uncompressed (plain JSON), gzip, or raw deflate. The
/// AES-GCM step already authenticated the bytes, so a zlib-only decoder
/// drops those frames entirely ("Failed to decompress data: corrupt
/// deflate stream") and the bot silently misses real group messages.
/// Try zlib first (the documented format), then plain JSON, gzip, then
/// raw deflate; only fail when none of them yields JSON.
fn decompress_event_payload(decrypted: &[u8]) -> Result<Vec<u8>, ZaloApiError> {
    if let Some(out) = try_zlib(decrypted) {
        return Ok(out);
    }
    // Plain JSON straight from the server (no compression at all).
    if serde_json::from_slice::<serde_json::Value>(decrypted).is_ok() {
        return Ok(decrypted.to_vec());
    }
    if let Some(out) = try_gzip(decrypted) {
        if serde_json::from_slice::<serde_json::Value>(&out).is_ok() {
            return Ok(out);
        }
    }
    if let Some(out) = try_raw_deflate(decrypted) {
        if serde_json::from_slice::<serde_json::Value>(&out).is_ok() {
            return Ok(out);
        }
    }
    // Log the head of the authenticated plaintext so the next run shows
    // exactly what format the server sent (never the full payload: it may
    // hold message content).
    let preview: String = decrypted
        .iter()
        .take(32)
        .map(|b| format!("{:02x}", b))
        .collect();
    crate::zlog_warn!(
        "WS decode: payload is not zlib/plain-json/gzip/raw-deflate after AES-GCM (len={}, head_hex={})",
        decrypted.len(),
        preview
    );
    Err(ZaloApiError::new(
        "Failed to decompress data: payload is not zlib, plain JSON, gzip or raw deflate",
    ))
}

/// Decodes a websocket event payload, decrypting/decompressing it when needed.
///
/// # Errors
/// Returns a [`ZaloApiError`] if the payload is invalid, the cipher key is
/// missing for encrypted types, or decryption/decompression fails.
pub async fn decode_event_data(
    parsed: &Map<String, serde_json::Value>,
    cipher_key: Option<&str>,
) -> Result<Option<DecodedEventData>, ZaloApiError> {
    let data = parsed
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ZaloApiError::new("Invalid data, expected string"))?;

    let encrypt = parsed
        .get("encrypt")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ZaloApiError::new("Invalid encrypt type, expected number"))?;

    if !(0..=3).contains(&encrypt) {
        return Err(ZaloApiError::new(format!(
            "Invalid encrypt type, expected 0-3 but got {}",
            encrypt
        )));
    }

    if encrypt == 0 {
        let value: serde_json::Value = serde_json::from_str(data)
            .map_err(|e| ZaloApiError::new(format!("Failed to parse JSON: {}", e)))?;
        return Ok(Some(DecodedEventData::Value(value)));
    }

    let raw_data: String = if encrypt == 1 {
        data.to_string()
    } else {
        urlencoding::decode(data)
            .map_err(|e| ZaloApiError::new(format!("Failed to URL-decode data: {}", e)))?
            .into_owned()
    };

    let decoded_buffer = decode_base64_lenient(&raw_data).map_err(|e| {
        ZaloApiError::new(format!("Failed to base64-decode data: {}", e))
    })?;

    let decrypted_buffer = if encrypt != 1 {
        let key_b64 = cipher_key.ok_or_else(|| {
            ZaloApiError::new("Invalid data length or missing cipher key")
        })?;
        if decoded_buffer.len() < 48 {
            return Err(ZaloApiError::new("Invalid data length or missing cipher key"));
        }

        let key_bytes = decode_base64_lenient(key_b64).map_err(|e| {
            ZaloApiError::new(format!("Failed to decode cipher key: {}", e))
        })?;
        // WebCrypto `importKey("raw", ...)` in zca-js accepts any valid
        // AES-GCM key size (128/192/256 bit); the old code required exactly
        // 16 bytes, so a 24/32-byte server cipher key made EVERY encrypted
        // event fail to decode (and the WS layer silently fell back to the
        // raw frame, which the bot then dropped).
        let nonce = GenericArray::<u8, U16>::from_slice(&decoded_buffer[0..16]);
        let aad = &decoded_buffer[16..32];
        let tag = GenericArray::<u8, U16>::from_slice(&decoded_buffer[decoded_buffer.len() - 16..]);
        let mut ciphertext = decoded_buffer[32..decoded_buffer.len() - 16].to_vec();
        match key_bytes.len() {
            16 => {
                let cipher = AesGcm::<Aes128, U16>::new_from_slice(&key_bytes)
                    .map_err(|e| ZaloApiError::new(format!("Failed to create cipher: {}", e)))?;
                cipher
                    .decrypt_in_place_detached(nonce, aad, &mut ciphertext, tag)
                    .map_err(|e| ZaloApiError::new(format!("AES-GCM decryption failed: {}", e)))?;
            }
            24 => {
                let cipher = AesGcm::<Aes192, U16>::new_from_slice(&key_bytes)
                    .map_err(|e| ZaloApiError::new(format!("Failed to create cipher: {}", e)))?;
                cipher
                    .decrypt_in_place_detached(nonce, aad, &mut ciphertext, tag)
                    .map_err(|e| ZaloApiError::new(format!("AES-GCM decryption failed: {}", e)))?;
            }
            32 => {
                let cipher = AesGcm::<Aes256, U16>::new_from_slice(&key_bytes)
                    .map_err(|e| ZaloApiError::new(format!("Failed to create cipher: {}", e)))?;
                cipher
                    .decrypt_in_place_detached(nonce, aad, &mut ciphertext, tag)
                    .map_err(|e| ZaloApiError::new(format!("AES-GCM decryption failed: {}", e)))?;
            }
            n => {
                return Err(ZaloApiError::new(format!(
                    "Cipher key must be 16, 24 or 32 bytes, got {}",
                    n
                )))
            }
        }

        ciphertext
    } else {
        decoded_buffer
    };

    let decompressed_buffer = if encrypt == 3 {
        decrypted_buffer
    } else {
        decompress_event_payload(&decrypted_buffer)?
    };

    let decoded_data = String::from_utf8(decompressed_buffer).ok();
    let decoded_data = decoded_data.filter(|s| !s.is_empty());

    match decoded_data {
        Some(s) => {
            let value: serde_json::Value = serde_json::from_str(&s).map_err(|e| {
                ZaloApiError::new(format!("Failed to parse decoded JSON: {}", e))
            })?;
            Ok(Some(DecodedEventData::Value(value)))
        }
        None => Ok(None),
    }
}

/// MD5 of a (possibly large) file, computed by streaming the source in 2MB
/// chunks so memory usage stays constant regardless of file size.
pub async fn get_md5_large_file_object(
    source: &AttachmentSource,
    _file_size: u64,
) -> Result<(u64, String), ZaloApiError> {
    const CHUNK_SIZE: usize = 2_097_152; // 2MB
    let mut hasher = Md5::new();
    let mut current_chunk: u64 = 0;

    match source {
        AttachmentSource::Path(path) => {
            let mut file = fs::File::open(path).map_err(|e| {
                ZaloApiError::new(format!("Failed to open file: {}", e))
            })?;
            let mut buffer = [0u8; CHUNK_SIZE];
            loop {
                let bytes_read = file.read(&mut buffer).map_err(|e| {
                    ZaloApiError::new(format!("Failed to read file: {}", e))
                })?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
                current_chunk += 1;
            }
        }
        AttachmentSource::InMemory { data, .. } => {
            for offset in (0..data.len()).step_by(CHUNK_SIZE) {
                let end = (offset + CHUNK_SIZE).min(data.len());
                hasher.update(&data[offset..end]);
                current_chunk += 1;
            }
        }
    }

    let digest = hex::encode(hasher.finalize());
    Ok((current_chunk, digest))
}

/// Image metadata returned by a metadata getter.
#[derive(Debug, Clone)]
pub struct ImageMetaData {
    pub file_name: String,
    pub total_size: u64,
    pub width: u64,
    pub height: u64,
}

/// Get image metadata via a context-provided getter callback.
pub async fn get_image_meta_data<F, Fut>(
    file_path: &str,
    getter: F,
) -> Result<ImageMetaData, ZaloApiError>
where
    F: FnOnce(&str) -> Fut,
    Fut: std::future::Future<Output = Option<ImageMetaData>>,
{
    let image_data = getter(file_path).await.ok_or_else(|| {
        ZaloApiError::new("Failed to get image metadata")
    })?;

    Ok(ImageMetaData {
        file_name: get_file_name(file_path).to_string(),
        total_size: image_data.total_size,
        width: image_data.width,
        height: image_data.height,
    })
}

/// Get GIF metadata via a context-provided getter callback.
pub async fn get_gif_meta_data<F, Fut>(
    file_path: &str,
    getter: F,
) -> Result<ImageMetaData, ZaloApiError>
where
    F: FnOnce(&str) -> Fut,
    Fut: std::future::Future<Output = Option<ImageMetaData>>,
{
    let gif_data = getter(file_path).await.ok_or_else(|| {
        ZaloApiError::new("Failed to get gif metadata")
    })?;

    Ok(ImageMetaData {
        file_name: Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(file_path)
            .to_string(),
        total_size: gif_data.total_size,
        width: gif_data.width,
        height: gif_data.height,
    })
}

/// Get the size of a file in bytes.
pub async fn get_file_size(file_path: &str) -> Result<u64, ZaloApiError> {
    let metadata = fs::metadata(file_path).map_err(|e| {
        ZaloApiError::new(format!("Failed to stat file: {}", e))
    })?;
    Ok(metadata.len())
}

/// Get the extension of a file path (without the leading dot).
pub fn get_file_extension(file_path: &str) -> String {
    Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string()
}

/// Get the file name from a path.
pub fn get_file_name(file_path: &str) -> &str {
    Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file_path)
}

/// Left-pad a string to a given length.
pub fn str_pad_left(value: &str, pad: &str, length: usize) -> String {
    let s = value.to_string();
    if s.len() == length {
        return s;
    }
    if s.len() > length {
        return s[s.len() - length..].to_string();
    }
    let repeat_count = length - s.len();
    pad.repeat(repeat_count) + &s
}

/// Format a timestamp according to a format string.
pub fn format_time(format: &str, timestamp: i64) -> String {
    let date = chrono::DateTime::from_timestamp_millis(timestamp)
        .unwrap_or_else(|| chrono::Utc::now());

    if format.contains("%H") || format.contains("%d") {
        let mut result = format.to_string();
        result = result.replace("%H", &format!("{:02}", date.hour()));
        result = result.replace("%M", &format!("{:02}", date.minute()));
        result = result.replace("%S", &format!("{:02}", date.second()));
        result = result.replace("%d", &format!("{:02}", date.day()));
        result = result.replace("%m", &format!("{:02}", date.month()));
        result = result.replace("%Y", &date.year().to_string());
        return result;
    }

    date.format("%d/%m/%Y %H:%M:%S").to_string()
}

/// Get a full time string from a millisecond timestamp.
pub fn get_full_time_from_millisecond(timestamp: i64) -> String {
    let date = chrono::DateTime::from_timestamp_millis(timestamp)
        .unwrap_or_else(|| chrono::Utc::now());

    format!(
        "{:02}:{:02} {:02}/{:02}/{}",
        date.hour(),
        date.minute(),
        date.day(),
        date.month(),
        date.year()
    )
}

/// Map a client message type string to a numeric code.
pub fn get_client_message_type(msg_type: &str) -> i64 {
    match msg_type {
        "webchat" => 1,
        "chat.voice" => 31,
        "chat.photo" => 32,
        "chat.sticker" => 36,
        "chat.doodle" => 37,
        "chat.recommended" => 38,
        "chat.link" => 38,
        "chat.video.msg" => 44,
        "share.file" => 46,
        "chat.gif" => 49,
        "chat.location.new" => 43,
        _ => 1,
    }
}

/// Map a group event action string to a [`GroupEventType`].
pub fn get_group_event_type(act: &str) -> GroupEventType {
    match act {
        "join_request" => GroupEventType::JoinRequest,
        "join" => GroupEventType::Join,
        "leave" => GroupEventType::Leave,
        "remove_member" => GroupEventType::RemoveMember,
        "block_member" => GroupEventType::BlockMember,
        "update_setting" => GroupEventType::UpdateSetting,
        "update" => GroupEventType::Update,
        "new_link" => GroupEventType::NewLink,
        "add_admin" => GroupEventType::AddAdmin,
        "remove_admin" => GroupEventType::RemoveAdmin,
        "new_pin_topic" => GroupEventType::NewPinTopic,
        "update_pin_topic" => GroupEventType::UpdatePinTopic,
        "update_board" => GroupEventType::UpdateBoard,
        "remove_board" => GroupEventType::RemoveBoard,
        "reorder_pin_topic" => GroupEventType::ReorderPinTopic,
        "unpin_topic" => GroupEventType::UnpinTopic,
        "remove_topic" => GroupEventType::RemoveTopic,
        "accept_remind" => GroupEventType::AcceptRemind,
        "reject_remind" => GroupEventType::RejectRemind,
        "remind_topic" => GroupEventType::RemindTopic,
        "update_avatar" => GroupEventType::UpdateAvatar,
        _ => GroupEventType::Unknown,
    }
}

/// Map a friend event action string to a [`FriendEventType`].
pub fn get_friend_event_type(act: &str) -> FriendEventType {
    match act {
        "add" => FriendEventType::Add,
        "remove" => FriendEventType::Remove,
        "block" => FriendEventType::Block,
        "unblock" => FriendEventType::Unblock,
        "block_call" => FriendEventType::BlockCall,
        "unblock_call" => FriendEventType::UnblockCall,
        "req_v2" => FriendEventType::Request,
        "reject" => FriendEventType::RejectRequest,
        "undo_req" => FriendEventType::UndoRequest,
        "seen_fr_req" => FriendEventType::SeenFriendRequest,
        "pin_unpin" => FriendEventType::PinUnpin,
        "pin_create" => FriendEventType::PinCreate,
        _ => FriendEventType::Unknown,
    }
}

/// Convert a hex color code (`#RRGGBB` / `#AARRGGBB`) into the negative color
/// number used by the Zalo API.
pub fn hex_to_negative_color(hex: &str) -> i64 {
    let hex = if hex.starts_with('#') {
        hex.to_string()
    } else {
        format!("#{}", hex)
    };
    let hex_value: String = if hex[1..].len() == 6 {
        format!("FF{}", &hex[1..])
    } else {
        hex[1..].to_string()
    };
    let decimal = i64::from_str_radix(&hex_value, 16).unwrap_or(0);
    if decimal > 0x7fffffff {
        decimal - 4294967296
    } else {
        decimal
    }
}

/// Convert a negative color number from the Zalo API back into a hex color.
pub fn negative_color_to_hex(negative_color: i64) -> String {
    let positive_color = negative_color + 4294967296;
    format!("#{:06x}", positive_color & 0xffffff)
}

/// Normalize a bank account holder name (uppercase, accent-free, A-Z0-9 only).
pub fn normalize_holder_name(input: Option<&str>) -> Option<String> {
    let input = input?;
    let normalized: String = input
        .nfd()
        .filter(|c| !(*c as u32 >= 0x0300 && *c as u32 <= 0x036f))
        .collect();
    let normalized = normalized.replace(['\u{0110}', '\u{0111}'], "d");
    let normalized = normalized.to_uppercase();
    let normalized: String = normalized
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect();
    let normalized = normalized.trim().to_string();

    if normalized.len() >= 5 {
        Some(normalized)
    } else {
        None
    }
}

#[cfg(test)]
mod decode_event_data_tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use std::io::Write;

    /// Wire-format `data` exactly like the Zalo server / zca-js
    /// `decodeEventData` expects: zlib (unless encrypt==3) -> AES-GCM
    /// (nonce[0..16] + aad[16..32] + ciphertext+tag) -> base64 ->
    /// URL-encoded (unless encrypt==1). Key may be 16/24/32 bytes.
    fn encrypt_ts_style(payload: &str, key_b64: &str, encrypt: i64) -> String {
        encrypt_ts_style_mode(payload, key_b64, encrypt, "zlib")
    }

    /// Like `encrypt_ts_style`, but the pre-encryption transform is
    /// selectable: `"zlib"` (default), `"plain"` (no compression — what
    /// the server sends on some live 521/621 frames), `"gzip"`, or
    /// `"deflate"` (raw deflate, no zlib header).
    fn encrypt_ts_style_mode(payload: &str, key_b64: &str, encrypt: i64, mode: &str) -> String {
        let key_bytes = BASE64.decode(key_b64).unwrap();
        let plain: Vec<u8> = if encrypt == 3 {
            payload.as_bytes().to_vec()
        } else {
            match mode {
                "plain" => payload.as_bytes().to_vec(),
                "gzip" => {
                    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
                    enc.write_all(payload.as_bytes()).unwrap();
                    enc.finish().unwrap()
                }
                "deflate" => {
                    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
                    enc.write_all(payload.as_bytes()).unwrap();
                    enc.finish().unwrap()
                }
                _ => {
                    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
                    enc.write_all(payload.as_bytes()).unwrap();
                    enc.finish().unwrap()
                }
            }
        };
        let mut wire: Vec<u8> = Vec::new();
        let nonce: [u8; 16] = [7u8; 16];
        let aad: [u8; 16] = [9u8; 16];
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&aad);
        let ct = match key_bytes.len() {
            16 => {
                let c = AesGcm::<Aes128, U16>::new_from_slice(&key_bytes).unwrap();
                c.encrypt(
                    GenericArray::from_slice(&nonce),
                    Payload { msg: &plain, aad: &aad },
                )
                .unwrap()
            }
            24 => {
                let c = AesGcm::<Aes192, U16>::new_from_slice(&key_bytes).unwrap();
                c.encrypt(
                    GenericArray::from_slice(&nonce),
                    Payload { msg: &plain, aad: &aad },
                )
                .unwrap()
            }
            32 => {
                let c = AesGcm::<Aes256, U16>::new_from_slice(&key_bytes).unwrap();
                c.encrypt(
                    GenericArray::from_slice(&nonce),
                    Payload { msg: &plain, aad: &aad },
                )
                .unwrap()
            }
            n => panic!("bad key len {n}"),
        };
        wire.extend_from_slice(&ct);
        let b64 = BASE64.encode(&wire);
        if encrypt == 1 {
            b64
        } else {
            urlencoding::encode(&b64).into_owned()
        }
    }

    fn frame(data: &str, encrypt: i64) -> Map<String, serde_json::Value> {
        serde_json::json!({
            "encrypt": encrypt,
            "data": data,
            "error_message": "",
            "error_code": 0,
        })
        .as_object()
        .unwrap()
        .clone()
    }

    /// The exact shape a live 521 group frame has on the wire
    /// (keys encrypt/data/error_message/error_code); after decode it must
    /// yield the groupMsgs payload the bot parses.
    const GROUP_PAYLOAD: &str =
        r#"{"groupMsgs":[{"idTo":"123456","uidFrom":"418669971689260834","content":"/bot on","cliMsgId":"7","msgId":"9"}]}"#;

    fn decoded_value(
        out: Result<Option<DecodedEventData>, ZaloApiError>,
    ) -> serde_json::Value {
        match out {
            Ok(Some(DecodedEventData::Value(v))) => v,
            other => panic!("expected decoded Value, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypt2_16_byte_key_decodes_group_frame() {
        let key_b64 = BASE64.encode([1u8; 16]);
        let data = encrypt_ts_style(GROUP_PAYLOAD, &key_b64, 2);
        let v = decoded_value(decode_event_data(&frame(&data, 2), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["idTo"], "123456");
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt2_24_byte_key_decodes_group_frame() {
        let key_b64 = BASE64.encode([2u8; 24]);
        let data = encrypt_ts_style(GROUP_PAYLOAD, &key_b64, 2);
        let v = decoded_value(decode_event_data(&frame(&data, 2), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt2_32_byte_key_decodes_group_frame() {
        let key_b64 = BASE64.encode([3u8; 32]);
        let data = encrypt_ts_style(GROUP_PAYLOAD, &key_b64, 2);
        let v = decoded_value(decode_event_data(&frame(&data, 2), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt3_32_byte_key_no_decompress() {
        let key_b64 = BASE64.encode([4u8; 32]);
        let data = encrypt_ts_style(GROUP_PAYLOAD, &key_b64, 3);
        let v = decoded_value(decode_event_data(&frame(&data, 3), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt1_base64_zlib_no_key() {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(GROUP_PAYLOAD.as_bytes()).unwrap();
        let data = BASE64.encode(enc.finish().unwrap());
        let v = decoded_value(decode_event_data(&frame(&data, 1), None).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt0_plain_json() {
        let v = decoded_value(decode_event_data(&frame(GROUP_PAYLOAD, 0), None).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt2_base64url_unpadded_payload_decodes() {
        // Node's Buffer.from(s, "base64") accepts base64url alphabet and
        // missing padding; the strict decoder rejected both.
        let key_b64 = BASE64.encode([5u8; 16]);
        let data = encrypt_ts_style(GROUP_PAYLOAD, &key_b64, 2);
        let url_decoded = urlencoding::decode(&data).unwrap().into_owned();
        let b64url_unpadded = url_decoded
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string();
        let wire = urlencoding::encode(&b64url_unpadded).into_owned();
        let v = decoded_value(decode_event_data(&frame(&wire, 2), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt2_missing_key_is_error() {
        let key_b64 = BASE64.encode([1u8; 16]);
        let data = encrypt_ts_style(GROUP_PAYLOAD, &key_b64, 2);
        let out = decode_event_data(&frame(&data, 2), None).await;
        assert!(out.is_err(), "missing cipher key must fail, got {out:?}");
    }

    #[tokio::test]
    async fn invalid_key_length_is_error() {
        let key_b64 = BASE64.encode([1u8; 20]);
        let data = encrypt_ts_style(GROUP_PAYLOAD, &BASE64.encode([1u8; 16]), 2);
        let out = decode_event_data(&frame(&data, 2), Some(&key_b64)).await;
        assert!(out.is_err(), "20-byte key must fail, got {out:?}");
    }

    #[tokio::test]
    async fn encrypt2_plain_json_fallback_decodes_group_frame() {
        // Live 521 frames sometimes arrive uncompressed: AES-GCM is fine,
        // zlib fails ("corrupt deflate stream") — the plaintext JSON must
        // still decode instead of dropping a real group message.
        let key_b64 = BASE64.encode([6u8; 16]);
        let data = encrypt_ts_style_mode(GROUP_PAYLOAD, &key_b64, 2, "plain");
        let v = decoded_value(decode_event_data(&frame(&data, 2), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt2_gzip_fallback_decodes_group_frame() {
        let key_b64 = BASE64.encode([7u8; 16]);
        let data = encrypt_ts_style_mode(GROUP_PAYLOAD, &key_b64, 2, "gzip");
        let v = decoded_value(decode_event_data(&frame(&data, 2), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt2_raw_deflate_fallback_decodes_group_frame() {
        let key_b64 = BASE64.encode([8u8; 16]);
        let data = encrypt_ts_style_mode(GROUP_PAYLOAD, &key_b64, 2, "deflate");
        let v = decoded_value(decode_event_data(&frame(&data, 2), Some(&key_b64)).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt1_plain_json_fallback_decodes_group_frame() {
        // encrypt==1 (base64, no AES) with an uncompressed payload.
        let data = BASE64.encode(GROUP_PAYLOAD);
        let v = decoded_value(decode_event_data(&frame(&data, 1), None).await);
        assert_eq!(v["groupMsgs"][0]["content"], "/bot on");
    }

    #[tokio::test]
    async fn encrypt2_garbage_payload_still_errors() {
        // Authenticated but neither zlib, JSON, gzip nor raw deflate:
        // must still fail (with the decompress error), not silently
        // return garbage.
        let key_b64 = BASE64.encode([9u8; 16]);
        let data = encrypt_ts_style_mode("not json {{{ garbage", &key_b64, 2, "plain");
        let out = decode_event_data(&frame(&data, 2), Some(&key_b64)).await;
        assert!(out.is_err(), "garbage payload must fail, got {out:?}");
        let msg = format!("{:?}", out.unwrap_err());
        assert!(msg.contains("decompress"), "error must mention decompress, got {msg}");
    }
}
