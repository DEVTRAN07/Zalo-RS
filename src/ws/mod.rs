//! WebSocket listener for real-time Zalo events.
//!
//! Binary protocol: 4-byte header `[version(1), cmd(2 LE), subCmd(1)]` + JSON payload.

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::context::ContextSession;
use crate::core::utils::{decode_event_data, DecodedEventData};
use crate::errors::{Result, ZaloApiError, ZaloError};
use crate::{zlog_error, zlog_info, zlog_verbose, zlog_warn};

/// Close reasons matching the TypeScript implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CloseReason {
    ManualClosure = 1000,
    AbnormalClosure = 1006,
    DuplicateConnection = 3000,
    KickConnection = 3003,
}

/// Decoded WebSocket payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsPayload {
    pub version: u8,
    pub cmd: u16,
    #[serde(rename = "subCmd")]
    pub sub_cmd: u8,
    pub data: Value,
}

/// Events emitted by the listener.
#[derive(Debug, Clone)]
pub enum ListenerEvent {
    Connected,
    Disconnected {
        code: u16,
        reason: String,
    },
    CipherKey(String),
    Message(Value),
    GroupMessage(Value),
    Reaction(Value),
    Control(Value),
    OldMessages(Value),
    SeenDelivered(Value),
    Error(String),
    /// Raw/other payload for unhandled cmd/subCmd combinations.
    Raw(WsPayload),
}

/// WebSocket listener for Zalo real-time events.
pub struct Listener {
    ctx: ContextSession,
    urls: Vec<String>,
    stop_tx: Option<mpsc::Sender<()>>,
    /// Reconnect after a close/error. Defaults to `true` (the historical
    /// behaviour); `listen()` sets it from `ListenOptions::retry_on_close`.
    retry_on_close: bool,
}

impl Listener {
    pub fn new(ctx: ContextSession, urls: Vec<String>) -> Self {
        Self {
            ctx,
            urls,
            stop_tx: None,
            retry_on_close: true,
        }
    }

    /// Set whether the listener reconnects after the socket closes or
    /// errors. With `false` it emits a single `Disconnected` event and
    /// stops after the first close/error instead of retrying forever.
    pub fn with_retry_on_close(mut self, retry_on_close: bool) -> Self {
        self.retry_on_close = retry_on_close;
        self
    }

    /// Start the listener and return a receiver for events.
    ///
    /// Spawns a background task that manages the WebSocket connection.
    pub fn start(&mut self) -> Result<mpsc::UnboundedReceiver<ListenerEvent>> {
        if self.stop_tx.is_some() {
            return Err(ZaloError::Api(ZaloApiError::new("Already started")));
        }
        if self.urls.is_empty() {
            return Err(ZaloError::Api(ZaloApiError::new(
                "No WebSocket URLs available",
            )));
        }

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        self.stop_tx = Some(stop_tx);

        let ctx = self.ctx.clone();
        let urls = self.urls.clone();
        let retry_on_close = self.retry_on_close;
        let mut consecutive_failures: u32 = 0;
        let last_connected_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

        tokio::spawn(async move {
            let mut url_idx = 0usize;
            loop {
                let base = &urls[url_idx % urls.len()];
                // Match the TypeScript client: append `t` plus the zpw_ver/zpw_type
                // markers the server expects on the WebSocket handshake URL.
                let base_ctx = crate::context::ContextBase {
                    api_type: ctx.api_type,
                    api_version: ctx.api_version,
                    imei: Some(ctx.imei.clone()),
                    user_agent: Some(ctx.user_agent.clone()),
                    language: Some(ctx.language.clone()),
                    secret_key: Some(ctx.secret_key.clone()),
                    uid: Some(ctx.uid.clone()),
                    options: ctx.options.clone(),
                    http: ctx.http.clone(),
                    login_info: Some(ctx.login_info.clone()),
                    settings: ctx.settings.clone(),
                    extra_ver: ctx.extra_ver.clone(),
                    upload_callbacks: ctx.upload_callbacks.clone(),
                    file_done_stash: ctx.file_done_stash.clone(),
                };
                let ws_query = vec![
                    ("t", now_ms().to_string()),
                    ("imei", base_ctx.imei.clone().unwrap_or_default()),
                    ("uid", base_ctx.uid.clone().unwrap_or_default()),
                    ("zpw_enk", base_ctx.secret_key.clone().unwrap_or_default()),
                ];
                let ws_url = crate::http::make_url(&base_ctx, base, &ws_query, true)
                    .unwrap_or_else(|_| {
                        let sep = if base.contains('?') { '&' } else { '?' };
                        format!(
                            "{}{}t={}&imei={}&uid={}&zpw_enk={}",
                            base,
                            sep,
                            now_ms(),
                            base_ctx.imei.clone().unwrap_or_default(),
                            base_ctx.uid.clone().unwrap_or_default(),
                            base_ctx.secret_key.clone().unwrap_or_default(),
                        )
                    });

                zlog_info!("Connecting to WebSocket: {}", ws_url);
                zlog_verbose!("WS URL query params: t, imei, uid, zpw_enk | base={}", base);
                let cipher_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

                // Clear the previous session's connect timestamp so a failed
                // connect can never look like a long-lived session.
                *last_connected_at.lock().await = None;
                let connect_result = connect_and_run(
                    &ctx,
                    &ws_url,
                    event_tx.clone(),
                    &mut stop_rx,
                    cipher_key,
                    ctx.options.self_listen,
                    last_connected_at.clone(),
                )
                .await;

                match connect_result {
                    Ok(should_stop) => {
                        if should_stop {
                            let _ = event_tx.send(ListenerEvent::Disconnected {
                                code: CloseReason::ManualClosure as u16,
                                reason: "stopped".into(),
                            });
                            break;
                        }
                        if !retry_on_close {
                            let _ = event_tx.send(ListenerEvent::Disconnected {
                                code: CloseReason::AbnormalClosure as u16,
                                reason: "closed".into(),
                            });
                            break;
                        }
                        // Connection closed; try next endpoint after a backoff delay.
                        // A session that lived long enough counts as healthy and
                        // resets the failure streak; a quick close counts as a
                        // failure and grows the delay (1s, 2s, 4s, ... capped 30s).
                        url_idx = (url_idx + 1) % urls.len();
                        let lived_long = last_connected_at
                            .lock()
                            .await
                            .map(|t| t.elapsed() > std::time::Duration::from_secs(60))
                            .unwrap_or(false);
                        if lived_long {
                            consecutive_failures = 0;
                        } else {
                            consecutive_failures += 1;
                        }
                        let delay_ms = backoff_delay_ms(consecutive_failures);
                        zlog_warn!(
                            "WebSocket closed, reconnecting in {}ms (consecutive failures: {})...",
                            delay_ms,
                            consecutive_failures
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }
                    Err(e) => {
                        let _ = event_tx.send(ListenerEvent::Error(e.to_string()));
                        if !retry_on_close {
                            break;
                        }
                        consecutive_failures += 1;
                        if is_auth_error(&e) {
                            // Permanent failure (expired/invalid cookie): retrying
                            // forever cannot fix it, so stop and say so.
                            let _ = event_tx.send(ListenerEvent::Disconnected {
                                code: CloseReason::AbnormalClosure as u16,
                                reason: "authentication failed (cookie expired?)".into(),
                            });
                            break;
                        }
                        if consecutive_failures >= 5 {
                            let _ = event_tx.send(ListenerEvent::Disconnected {
                                code: CloseReason::AbnormalClosure as u16,
                                reason: format!(
                                    "giving up after {} consecutive failures: {}",
                                    consecutive_failures, e
                                ),
                            });
                            break;
                        }
                        url_idx = (url_idx + 1) % urls.len();
                        let delay_ms = backoff_delay_ms(consecutive_failures);
                        zlog_warn!(
                            "WebSocket error: {}, reconnecting in {}ms (consecutive failures: {})...",
                            e,
                            delay_ms,
                            consecutive_failures
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        });

        Ok(event_rx)
    }

    /// Stop the listener.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(()).await;
        }
    }
}

/// Exponential backoff for reconnects: 1s, 2s, 4s, 8s, 16s, capped at 30s.
/// `failures == 0` (a healthy session just closed) waits the base 1s.
fn backoff_delay_ms(failures: u32) -> u64 {
    if failures == 0 {
        return 1_000;
    }
    (1_000u64 << failures.saturating_sub(1).min(5)).min(30_000)
}

/// True when the error looks like an authentication failure (expired/invalid
/// cookie). Such errors are permanent: retrying forever cannot fix them.
fn is_auth_error(e: &ZaloError) -> bool {
    let s = e.to_string().to_lowercase();
    s.contains("401") || s.contains("403") || s.contains("unauthorized") || s.contains("forbidden")
}

async fn connect_and_run(
    ctx: &ContextSession,
    ws_url: &str,
    event_tx: mpsc::UnboundedSender<ListenerEvent>,
    stop_rx: &mut mpsc::Receiver<()>,
    cipher_key: Arc<Mutex<Option<String>>>,
    self_listen: bool,
    last_connected_at: Arc<Mutex<Option<Instant>>>,
) -> Result<bool> {
    // Build request with headers matching the TypeScript client exactly.
    let mut request = ws_url
        .into_client_request()
        .map_err(|e| ZaloError::WebSocket(e.to_string()))?;
    let headers = request.headers_mut();
    headers.insert("Origin", HeaderValue::from_static("https://chat.zalo.me"));
    if let Ok(ua) = HeaderValue::from_str(&ctx.user_agent) {
        headers.insert("User-Agent", ua);
    }
    headers.insert(
        "Accept-Encoding",
        HeaderValue::from_static("gzip, deflate, br, zstd"),
    );
    headers.insert(
        "Accept-Language",
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    headers.insert("Cache-Control", HeaderValue::from_static("no-cache"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    headers.insert(
        "Sec-WebSocket-Extensions",
        HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
    );
    // Cookie header: extract from cookie store
    if let Some(cookie_str) = get_cookie_header(ctx).await {
        if let Ok(v) = HeaderValue::from_str(&cookie_str) {
            headers.insert("Cookie", v);
        }
    }
    // Explicit Host header (some proxies/servers reject requests without it)
    // Note: tokio-tungstenite already sets Host from the URL; re-setting it here
    // can produce a duplicate header on some servers, so we leave it alone.

    let (ws_stream, _) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| {
            zlog_error!("WebSocket connect_async failed: {}", e);
            ZaloError::WebSocket(e.to_string())
        })?;

    let _ = event_tx.send(ListenerEvent::Connected);
    *last_connected_at.lock().await = Some(Instant::now());
    zlog_info!("WebSocket connected");

    let (mut write, mut read) = ws_stream.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let ping_interval_ms = get_ping_interval_ms(ctx);
    // Pong watchdog: if the server goes silent (no frames at all, not even a
    // pong) for twice the ping interval (min 120s), the socket is dead even
    // though no close frame arrived — drop it so the listener reconnects.
    // The 120s floor avoids killing a healthy connection while the server
    // is merely idle.
    let mut last_rx_at = Instant::now();
    let watchdog_limit =
        std::time::Duration::from_millis(ping_interval_ms.saturating_mul(2).max(120_000));
    let mut ping_interval =
        tokio::time::interval(std::time::Duration::from_millis(ping_interval_ms));
    ping_interval.tick().await; // first tick is immediate

    // Writer task
    let writer = tokio::spawn(async move {
        while let Some(data) = out_rx.recv().await {
            if write.send(WsMessage::Binary(data.into())).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            Some(()) = stop_rx.recv() => {
                // Chỉ dừng khi nhận tín hiệu stop thật (Listener::stop()).
                // Kênh đóng (None — Listener bị drop) KHÔNG được coi là
                // stop: trước đây `_ = stop_rx.recv()` bắt cả None nên
                // drop Listener (vd: ZaloApi::listen() tạo Listener cục
                // bộ, trả rx rồi drop ngay) giết kết nối ngay sau khi
                // nối, phát Disconnected 1000 "stopped" dù không ai gọi
                // stop(). Với pattern Some(()), kênh đóng chỉ vô hiệu
                // nhánh này; vòng lặp tiếp tục qua ping/read, socket
                // đóng thật thì trả Ok(false) để retry_on_close nối lại.
                let _ = out_tx.send(encode_payload(1, 3, 1, &serde_json::json!({"reason": "manual"})));
                writer.abort();
                return Ok(true);
            }
            _ = ping_interval.tick() => {
                if last_rx_at.elapsed() > watchdog_limit {
                    zlog_warn!(
                        "WS watchdog: no frames received for {:?} (limit {:?}), reconnecting...",
                        last_rx_at.elapsed(),
                        watchdog_limit
                    );
                    writer.abort();
                    return Ok(false);
                }
                let payload = encode_payload(1, 2, 1, &serde_json::json!({"eventId": now_ms()}));
                if out_tx.send(payload).is_err() {
                    writer.abort();
                    return Ok(false);
                }
            }
            msg = read.next() => {
                let Some(msg) = msg else {
                    writer.abort();
                    return Ok(false);
                };
                // Any frame at all proves the socket is alive.
                if msg.is_ok() {
                    last_rx_at = Instant::now();
                }
                match msg {
                    Ok(WsMessage::Binary(data)) => {
                        if handle_binary_message(&ctx, &data, &cipher_key, &event_tx, &out_tx, self_listen).await {
                            writer.abort();
                            return Ok(false);
                        }
                    }
                    Ok(WsMessage::Close(frame)) => {
                        zlog_verbose!("WS close frame: {:?}", frame);
                        writer.abort();
                        return Ok(false);
                    }
                    Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) => {
                        zlog_verbose!("WS ping/pong frame");
                    }
                    Ok(other) => {
                        zlog_verbose!("WS frame: {:?}", std::mem::discriminant(&other));
                    }
                    Err(e) => {
                        zlog_error!("WS read error: {}", e);
                        writer.abort();
                        return Err(ZaloError::WebSocket(e.to_string()));
                    }
                }
            }
        }
    }
}

/// Check if an event payload indicates it was sent by the current account.
/// Returns true only when a clear boolean `isSelf` (or `data.isSelf`) is present and true.
fn is_self_event(data: &Value) -> bool {
    fn check(v: &Value) -> Option<bool> {
        v.as_bool()
    }
    if let Some(b) = data.get("isSelf").and_then(check) {
        return b;
    }
    if let Some(b) = data
        .get("data")
        .and_then(|d| d.get("isSelf"))
        .and_then(check)
    {
        return b;
    }
    false
}

/// True when a uid value (string or number) matches our own uid.
fn uid_matches(v: &Value, self_uid: &str) -> bool {
    match v {
        Value::String(s) => s == self_uid,
        Value::Number(n) => n.to_string() == self_uid,
        _ => false,
    }
}

/// Check whether an event was sent by the current account, including group
/// events whose `groupMsgs` items carry the sender per message.
///
/// Returns true when the top-level `isSelf` says so, or when EVERY item in
/// `groupMsgs` (at `data.groupMsgs` or `data.data.groupMsgs`) is from us
/// (`isSelf == true` or `uidFrom == self_uid`). A mixed batch — some items
/// from us, some from others — must still be dispatched, so it returns false.
fn is_self_group_event(data: &Value, self_uid: &str) -> bool {
    if is_self_event(data) {
        return true;
    }
    let msgs = data
        .get("groupMsgs")
        .or_else(|| data.get("data").and_then(|d| d.get("groupMsgs")));
    let Some(msgs) = msgs.and_then(|m| m.as_array()) else {
        return false;
    };
    if msgs.is_empty() {
        return false;
    }
    msgs.iter().all(|item| {
        item.get("isSelf").and_then(|v| v.as_bool()).unwrap_or(false)
            || item
                .get("uidFrom")
                .map(|v| uid_matches(v, self_uid))
                .unwrap_or(false)
    })
}

/// Handle one binary frame. Returns `true` when the caller must close the
/// socket (e.g. the server reports a duplicate connection).
async fn handle_binary_message(
    ctx: &ContextSession,
    data: &[u8],
    cipher_key: &Arc<Mutex<Option<String>>>,
    event_tx: &mpsc::UnboundedSender<ListenerEvent>,
    out_tx: &mpsc::UnboundedSender<Vec<u8>>,
    self_listen: bool,
) -> bool {
    if data.len() < 4 {
        zlog_warn!("WS frame too short: {} bytes, expected at least 4", data.len());
        return false;
    }
    let version = data[0];
    let cmd = u16::from_le_bytes([data[1], data[2]]);
    let sub_cmd = data[3];
    let payload_bytes = &data[4..];

    let parsed_data: Value = if payload_bytes.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(payload_bytes) {
            Ok(v) => v,
            Err(e) => {
                zlog_warn!(
                    "Failed to parse WS payload JSON (cmd={}, sub={}): {}",
                    cmd,
                    sub_cmd,
                    e
                );
                Value::Null
            }
        }
    };

    // Cipher key handshake
    if version == 1 && cmd == 1 && sub_cmd == 1 {
        if let Some(key) = parsed_data.get("key").and_then(|v| v.as_str()) {
            let mut guard = cipher_key.lock().await;
            *guard = Some(key.to_string());
            zlog_info!("WS cipher key received ({} chars)", key.len());
            let _ = event_tx.send(ListenerEvent::CipherKey(key.to_string()));
            // Send initial ping
            let _ = out_tx.send(encode_payload(
                1,
                2,
                1,
                &serde_json::json!({"eventId": now_ms()}),
            ));
            return false;
        }
    }

    // Duplicate connection: another client logged in with the same account.
    // The server will not deliver events to this socket any more, so ask the
    // caller to close it and reconnect instead of idling forever.
    if version == 1 && cmd == 3000 && sub_cmd == 0 {
        zlog_error!("Another connection is opened (duplicate connection)");
        let _ = event_tx.send(ListenerEvent::Error("Duplicate connection".into()));
        return true;
    }

    // Decode encrypted event payloads. Mirrors the TypeScript client, which
    // calls decodeEventData on every event cmd before processing.
    // NOTE: a failed decode used to fall back to the raw frame SILENTLY, so
    // every encrypted group message arrived at the bot as
    // {encrypt, data, error_message, error_code} with no groupMsgs and was
    // dropped without a trace. Log the reason (no message content) so the
    // next run shows exactly why a frame could not be decoded.
    let key_guard = cipher_key.lock().await;
    let event_data = if let Value::Object(map) = &parsed_data {
        let encrypt = map.get("encrypt").and_then(|v| v.as_i64()).unwrap_or(0);
        if encrypt > 0 {
            match decode_event_data(map, key_guard.as_deref()).await {
                Ok(Some(DecodedEventData::Object(m))) => Value::Object(m),
                Ok(Some(DecodedEventData::Value(v))) => v,
                Ok(None) => {
                    zlog_warn!(
                        "WS decode: cmd={} sub={} encrypt={} decoded empty (data_len={}, key_present={})",
                        cmd,
                        sub_cmd,
                        encrypt,
                        map.get("data").and_then(|v| v.as_str()).map(|s| s.len()).unwrap_or(0),
                        key_guard.is_some()
                    );
                    parsed_data.clone()
                }
                Err(e) => {
                    zlog_warn!(
                        "WS decode failed: cmd={} sub={} encrypt={} data_len={} key_present={} err={}",
                        cmd,
                        sub_cmd,
                        encrypt,
                        map.get("data").and_then(|v| v.as_str()).map(|s| s.len()).unwrap_or(0),
                        key_guard.is_some(),
                        e
                    );
                    parsed_data.clone()
                }
            }
        } else {
            parsed_data.clone()
        }
    } else {
        parsed_data.clone()
    };
    drop(key_guard);

    let payload = WsPayload {
        version,
        cmd,
        sub_cmd,
        data: event_data.clone(),
    };

    match (cmd, sub_cmd) {
        (501, 0) | (551, 0) => {
            if !self_listen && is_self_group_event(&event_data, &ctx.uid) {
                return false;
            }
            let _ = event_tx.send(ListenerEvent::Message(event_data));
        }
        (521, 0) => {
            if !self_listen && is_self_group_event(&event_data, &ctx.uid) {
                return false;
            }
            let _ = event_tx.send(ListenerEvent::GroupMessage(event_data));
        }
        (612, _) | (610, _) | (611, _) => {
            if !self_listen && is_self_group_event(&event_data, &ctx.uid) {
                return false;
            }
            let _ = event_tx.send(ListenerEvent::Reaction(event_data));
        }
        (601, 0) => {
            // Dispatch the upload completion callback FIRST: a self-sent
            // file/voice upload must resolve its waiter even when
            // self_listen is off, otherwise the upload stalls until its
            // 120s timeout. Only afterwards filter self events.
            dispatch_file_done_callback(ctx, &event_data).await;
            if !self_listen && is_self_event(&event_data) {
                return false;
            }
            let _ = event_tx.send(ListenerEvent::Control(event_data.clone()));
        }
        (510, 1) | (511, 1) => {
            let _ = event_tx.send(ListenerEvent::OldMessages(event_data));
        }
        (502, 0) | (522, 0) | (602, 0) => {
            // TS filters GroupDeliveredMessage (cmd 522) by isSelf only.
            if cmd == 522 && !self_listen && is_self_event(&event_data) {
                return false;
            }
            let _ = event_tx.send(ListenerEvent::SeenDelivered(event_data));
        }
        (621, _) => {
            // cmd 621 is a newer Zalo event type not present in the original
            // TypeScript source. Its payload is encrypted (base64) and must be
            // decoded with the cipher key. Unlike other events, the `encrypt`
            // field may be 0 or missing, so we attempt decode unconditionally
            // here and emit the decrypted content as a Raw event.
            let decoded = if let Value::Object(map) = &parsed_data {
                let key_guard = cipher_key.lock().await;
                match decode_event_data(map, key_guard.as_deref()).await {
                    Ok(Some(DecodedEventData::Object(m))) => Value::Object(m),
                    Ok(Some(DecodedEventData::Value(v))) => v,
                    Ok(None) | Err(_) => parsed_data.clone(),
                }
            } else {
                parsed_data.clone()
            };
            let _ = event_tx.send(ListenerEvent::Raw(WsPayload {
                version,
                cmd,
                sub_cmd,
                data: decoded,
            }));
        }
        _ => {
            let _ = event_tx.send(ListenerEvent::Raw(payload));
        }
    }

    false
}

/// Async upload completion callback (TS: listen.ts uploadCallbacks for
/// file_done/send_file_done). Resolves the waiter registered by an upload so
/// a sent file/voice does not stall until its timeout.
///
/// If no callback is registered for the file id yet, the event is stashed
/// (see `FileDoneStash`) instead of dropped: single-chunk uploads register
/// their callback only after their only chunk is POSTed, so the event can
/// legitimately arrive first. The callback registered right after picks
/// the stashed event up immediately.
async fn dispatch_file_done_callback(ctx: &ContextSession, event_data: &Value) {
    if let Some(obj) = event_data.as_object() {
        if let Some(content) = obj.get("content").and_then(|v| v.as_object()) {
            let act = content.get("act").and_then(|v| v.as_str()).unwrap_or("");
            let act_type = content
                .get("act_type")
                .or_else(|| content.get("actType"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if act_type == "file_done" && (act == "send_file_done" || act == "file_done") {
                if let Some(file_id) = content
                    .get("fileId")
                    .or_else(|| content.get("file_id"))
                    .and_then(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .or_else(|| v.as_i64().map(|n| n.to_string()))
                    })
                {
                    let file_url = content
                        .get("data")
                        .and_then(|d| d.get("url").or_else(|| d.get("fileUrl")))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let data = serde_json::json!({
                        "fileUrl": file_url,
                        "fileId": file_id.clone(),
                    });
                    let callback = ctx
                        .upload_callbacks
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&file_id);
                    if let Some(cb) = callback {
                        cb(data).await;
                    } else {
                        // No callback registered yet (single-chunk upload:
                        // the event can arrive before the only chunk's
                        // response is processed). Stash it so the callback
                        // registered right after picks it up instead of
                        // waiting out the full 120s timeout.
                        zlog_info!(
                            "file_done for {} arrived before its callback was registered; stashing",
                            file_id
                        );
                        ctx.file_done_stash.store(file_id, data);
                    }
                }
            }
        }
    }
}

/// Encode a WS payload into the binary format: [ver, cmd_lo, cmd_hi, subCmd] + JSON bytes.
pub fn encode_payload(version: u8, cmd: u16, sub_cmd: u8, data: &Value) -> Vec<u8> {
    let json = serde_json::to_vec(data).unwrap_or_default();
    let cmd_bytes = cmd.to_le_bytes();
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.push(version);
    buf.push(cmd_bytes[0]);
    buf.push(cmd_bytes[1]);
    buf.push(sub_cmd);
    buf.extend_from_slice(&json);
    buf
}

/// Decode the 4-byte header.
pub fn decode_header(buf: &[u8]) -> Option<(u8, u16, u8)> {
    if buf.len() < 4 {
        return None;
    }
    let version = buf[0];
    let cmd = u16::from_le_bytes([buf[1], buf[2]]);
    let sub_cmd = buf[3];
    Some((version, cmd, sub_cmd))
}

async fn get_cookie_header(ctx: &ContextSession) -> Option<String> {
    let guard = ctx.http.lock().await;
    let http = guard.as_ref()?;
    let store = http.cookie_store.lock().ok()?;
    let url = url::Url::parse("https://chat.zalo.me/").ok()?;
    let cookies: Vec<String> = store
        .get_request_values(&url)
        .map(|(name, value)| format!("{}={}", name, value))
        .collect();
    if cookies.is_empty() {
        None
    } else {
        Some(cookies.join("; "))
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Read the ping interval (ms) from `ctx.settings.features.socket.ping_interval`,
/// falling back to the TypeScript default of 30s when unavailable.
fn get_ping_interval_ms(ctx: &ContextSession) -> u64 {
    let default = 30_000u64;
    let Some(settings) = ctx.settings.as_ref() else {
        return default;
    };
    let interval = settings
        .get("features")
        .and_then(|f| f.get("socket"))
        .and_then(|s| s.get("ping_interval"))
        .and_then(|v| v.as_u64())
        .unwrap_or(default);
    if interval == 0 {
        default
    } else {
        interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{FileDoneStash, Options, UploadCallback};
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;

    fn dummy_ctx() -> ContextSession {
        ContextSession {
            api_type: 30,
            api_version: 685,
            imei: "test-imei".into(),
            user_agent: "test-ua".into(),
            language: "vi".into(),
            secret_key: "test-key".into(),
            uid: "1".into(),
            options: Options::default(),
            http: Arc::new(Mutex::new(None)),
            login_info: Default::default(),
            settings: None,
            extra_ver: None,
            upload_callbacks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            file_done_stash: FileDoneStash::new(),
        }
    }

    fn file_done_event(file_id: &str, file_url: &str) -> Value {
        serde_json::json!({
            "content": {
                "act": "send_file_done",
                "act_type": "file_done",
                "fileId": file_id,
                "data": {"url": file_url, "fileUrl": file_url},
            }
        })
    }

    #[tokio::test]
    async fn file_done_without_callback_is_stashed_not_dropped() {
        let ctx = dummy_ctx();
        // Event arrives before any callback exists (single-chunk upload).
        dispatch_file_done_callback(&ctx, &file_done_event("fid-1", "https://cdn/x")).await;
        // Stashed, not dropped.
        let stashed = ctx.file_done_stash.take("fid-1");
        assert!(stashed.is_some());
        assert_eq!(stashed.unwrap()["fileUrl"], "https://cdn/x");
        // Delivered at most once.
        assert_eq!(ctx.file_done_stash.take("fid-1"), None);
    }

    #[tokio::test]
    async fn file_done_with_callback_is_delivered_not_stashed() {
        let ctx = dummy_ctx();
        let (tx, rx) = tokio::sync::oneshot::channel::<Value>();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let callback: UploadCallback = Arc::new(move |data| {
            let tx = tx.clone();
            Box::pin(async move {
                if let Some(sender) = tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    let _ = sender.send(data);
                }
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        });
        ctx.upload_callbacks
            .lock()
            .unwrap()
            .insert("fid-2".to_string(), callback);
        dispatch_file_done_callback(&ctx, &file_done_event("fid-2", "https://cdn/y")).await;
        let got = rx.await.expect("callback should receive the event");
        assert_eq!(got["fileUrl"], "https://cdn/y");
        assert_eq!(ctx.file_done_stash.take("fid-2"), None);
    }
}
