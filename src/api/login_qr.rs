//! QR-code login flow (pre-authentication, uses `ContextBase`).
//!
//! Full interactive port of the TypeScript `loginQR` flow:
//! 1. `load_login_page` — GET `id.zalo.me/account?continue=...`
//! 2. `get_login_info` — POST `/account/logininfo`
//! 3. `verify_client` — POST `/account/verify-client`
//! 4. `generate_qr` — POST `/account/authen/qr/generate`
//! 5. `waiting_scan` — poll `/account/authen/qr/waiting-scan`
//! 6. `waiting_confirm` — poll `/account/authen/qr/waiting-confirm`
//! 7. `check_session` — GET `/account/checksession`
//! 8. `get_user_info_qr` — GET `jr.chat.zalo.me/jr/userinfo`
//!
//! The flow respects a 100s QR expiry timeout and reports progress through
//! a `LoginQrCallback`. Cookies set during the flow are persisted in the
//! shared reqwest cookie store and returned in [`LoginQrResult`].

use base64::engine::{general_purpose::STANDARD, Engine as _};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, REFERER};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::{Duration, timeout};

use crate::context::{ContextBase, ZaloCookie};
use crate::errors::{Result, ZaloApiError, ZaloError};
use crate::http;
use crate::{zlog_error, zlog_info, zlog_warn};

const QR_TIMEOUT_SECS: u64 = 100;
const POLL_INTERVAL_SECS: u64 = 2;

// --- Data structures (ported from the TypeScript flow) ---

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrGenerateData {
    pub code: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub options: Value,
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrGenerateResponse {
    #[serde(default)]
    pub data: Option<QrGenerateData>,
    #[serde(default)]
    pub error_code: i64,
    #[serde(default)]
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrScanData {
    #[serde(default)]
    pub avatar: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrScanResponse {
    #[serde(default)]
    pub data: Option<QrScanData>,
    #[serde(default)]
    pub error_code: i64,
    #[serde(default)]
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrConfirmResponse {
    #[serde(default)]
    pub error_code: i64,
    #[serde(default)]
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrUserInfoData {
    #[serde(default)]
    pub logged: bool,
    #[serde(default)]
    pub session_chat_valid: bool,
    #[serde(default)]
    pub info: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrUserInfoResponse {
    #[serde(default)]
    pub data: Option<QrUserInfoData>,
    #[serde(default)]
    pub error_code: i64,
    #[serde(default)]
    pub error_message: String,
}

/// Result of a completed QR login: cookies persisted during the flow plus
/// the user info payload returned by `jr.chat.zalo.me/jr/userinfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginQrResult {
    pub cookies: Vec<ZaloCookie>,
    pub user_info: Value,
}

/// Events reported to the UI callback during the QR login flow.
#[derive(Debug, Clone)]
pub enum LoginQrEvent {
    QrGenerated {
        code: String,
        image: String,
        options: Value,
        token: String,
    },
    QrScanned {
        avatar: String,
        display_name: String,
    },
    QrDeclined {
        code: String,
    },
    GotLoginInfo,
    QrExpired,
    Error(String),
}

/// UI callback invoked with [`LoginQrEvent`]s during the flow.
pub type LoginQrCallback = Box<dyn Fn(LoginQrEvent) + Send + Sync>;

/// Options for [`login_qr`].
pub struct LoginQrOptions {
    pub user_agent: String,
    pub qr_path: Option<String>,
}

// --- Low-level HTTP steps ---

/// Extract the login JS bundle version from the login page HTML.
///
/// The login page references both a CSS bundle (`main-<version>.css`) and
/// the JS bundle (`main-<version>.js`) under `https://stc-zlogin.zdn.vn/`.
/// Only the `.js` bundle's version is valid: every occurrence of the marker
/// is scanned and the first one whose URL (up to the closing quote, query
/// string stripped) ends with `.js` wins. Returns `None` when no JS bundle
/// is found, so the caller reports a clear error instead of sending a
/// garbage version to Zalo (which rejects it with "Truy cập không hợp lệ").
fn extract_login_version(html: &str) -> Option<String> {
    let marker = "https://stc-zlogin.zdn.vn/main-";
    let mut search_from = 0;
    while let Some(rel) = html[search_from..].find(marker) {
        let start = search_from + rel + marker.len();
        let rest = &html[start..];
        let end = rest.find(|c| c == '"' || c == '\'').unwrap_or(rest.len());
        let mut url_tail = &rest[..end];
        if let Some(q) = url_tail.find(|c| c == '?' || c == '#') {
            url_tail = &url_tail[..q];
        }
        if let Some(version) = url_tail.strip_suffix(".js") {
            if !version.is_empty()
                && version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Some(version.to_string());
            }
        }
        search_from = start;
    }
    None
}

/// Discover the login page JS version.
pub async fn load_login_page(ctx: &ContextBase) -> Result<String> {
    let url = "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F";
    let res = http::request(ctx, Method::GET, url, None, Some(qr_page_headers()), false).await?;
    let html = res.text().await?;
    extract_login_version(&html).ok_or_else(|| {
        ZaloError::Api(ZaloApiError::new("Cannot get API login version"))
    })
}

// --- Browser fingerprint headers (ported 1:1 from zca-js loginQR.js) ---
//
// The working JS bot (zalo-client / zca-js) sends full Chrome browser
// headers on every QR-login request. The previous Rust code only sent the
// generic API defaults (Accept: application/json, Accept-Language: en-US,
// Referer: chat.zalo.me, no sec-ch-ua / sec-fetch-* at all), so Zalo's
// server rejected QR generation with error_code=-4 "Truy cập không hợp lệ"
// even though the version and the User-Agent were correct.
// These builders reproduce zca-js's per-request headers exactly, so the
// Rust requests are indistinguishable from the working JS ones.

const SEC_CH_UA: &str = "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"";
const ACCEPT_LANG: &str = "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5";
const REFERRER_POLICY: &str = "strict-origin-when-cross-origin";
const LOGININFO_REFERER: &str =
    "https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc";
const WAITING_REFERER: &str =
    "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F";
const NAV_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";

fn hv(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("static header value")
}

fn sec_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("sec-ch-ua"),
        hv(SEC_CH_UA),
    );
    headers.insert(
        HeaderName::from_static("sec-ch-ua-mobile"),
        hv("?0"),
    );
    headers.insert(
        HeaderName::from_static("sec-ch-ua-platform"),
        hv("\"Windows\""),
    );
}

fn base_browser_headers(headers: &mut HeaderMap) {
    headers.insert(ACCEPT_LANGUAGE, hv(ACCEPT_LANG));
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        hv(REFERRER_POLICY),
    );
    sec_headers(headers);
}

/// Navigation (document) headers for `load_login_page` and `check_session`.
/// Mirrors zca-js: `accept` is the full browser document list, `sec-fetch-*`
/// describes a top-level navigation, `priority: u=0, i`.
fn qr_page_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, hv(NAV_ACCEPT));
    headers.insert(REFERER, hv("https://chat.zalo.me/"));
    headers.insert(
        HeaderName::from_static("cache-control"),
        hv("max-age=0"),
    );
    headers.insert(HeaderName::from_static("priority"), hv("u=0, i"));
    headers.insert(
        HeaderName::from_static("sec-fetch-dest"),
        hv("document"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-mode"),
        hv("navigate"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        hv("same-site"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-user"),
        hv("?1"),
    );
    headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        hv("1"),
    );
    base_browser_headers(&mut headers);
    headers
}

/// POST headers for the id.zalo.me account endpoints, mirroring zca-js:
/// `accept: */*`, `sec-fetch-*` for a CORS fetch, `priority: u=1, i`,
/// and the endpoint-specific `Referer` the JS flow sends.
fn qr_post_headers(referer: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, hv("*/*"));
    headers.insert(REFERER, hv(referer));
    headers.insert(HeaderName::from_static("priority"), hv("u=1, i"));
    headers.insert(
        HeaderName::from_static("sec-fetch-dest"),
        hv("empty"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-mode"),
        hv("cors"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        hv("same-origin"),
    );
    base_browser_headers(&mut headers);
    headers
}

/// GET headers for `check_session` (document navigation from the login page).
fn qr_session_headers() -> HeaderMap {
    let mut headers = qr_page_headers();
    headers.insert(REFERER, hv(WAITING_REFERER));
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        hv("same-origin"),
    );
    headers.remove(HeaderName::from_static("sec-fetch-user"));
    headers
}

/// GET headers for `get_user_info_qr` (jr.chat.zalo.me), mirroring zca-js.
fn qr_userinfo_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, hv("*/*"));
    headers.insert(REFERER, hv("https://chat.zalo.me/"));
    headers.insert(HeaderName::from_static("priority"), hv("u=1, i"));
    headers.insert(
        HeaderName::from_static("sec-fetch-dest"),
        hv("empty"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-mode"),
        hv("cors"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        hv("same-site"),
    );
    base_browser_headers(&mut headers);
    headers
}

async fn post_id_form(
    ctx: &ContextBase,
    url: &str,
    params: &[(&str, &str)],
    headers: HeaderMap,
) -> Result<Value> {
    let form: Vec<(&str, String)> = params.iter().map(|(k, v)| (*k, v.to_string())).collect();
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let res = http::request(ctx, Method::POST, url, Some(body), Some(headers), false).await?;
    let data: Value = res.json().await?;
    Ok(data)
}

pub async fn get_login_info(ctx: &ContextBase, version: &str) -> Result<Value> {
    post_id_form(
        ctx,
        "https://id.zalo.me/account/logininfo",
        &[("continue", "https://zalo.me/pc"), ("v", version)],
        qr_post_headers(LOGININFO_REFERER),
    )
    .await
}

pub async fn verify_client(ctx: &ContextBase, version: &str) -> Result<Value> {
    post_id_form(
        ctx,
        "https://id.zalo.me/account/verify-client",
        &[
            ("type", "device"),
            ("continue", "https://zalo.me/pc"),
            ("v", version),
        ],
        qr_post_headers(LOGININFO_REFERER),
    )
    .await
}

pub async fn generate_qr(ctx: &ContextBase, version: &str) -> Result<QrGenerateResponse> {
    let data = post_id_form(
        ctx,
        "https://id.zalo.me/account/authen/qr/generate",
        &[("continue", "https://zalo.me/pc"), ("v", version)],
        qr_post_headers(LOGININFO_REFERER),
    )
    .await?;
    let resp: QrGenerateResponse = serde_json::from_value(data.clone()).unwrap_or_default();
    if resp.data.is_none() {
        let raw: String = serde_json::to_string(&data).unwrap_or_default();
        let raw: String = raw.chars().take(500).collect();
        zlog_error!(
            "generate_qr failed: error_code={} error_message={} raw={}",
            resp.error_code,
            resp.error_message,
            raw
        );
    }
    Ok(resp)
}

pub async fn waiting_scan(ctx: &ContextBase, version: &str, code: &str) -> Result<QrScanResponse> {
    loop {
        let data = post_id_form(
            ctx,
            "https://id.zalo.me/account/authen/qr/waiting-scan",
            &[
                ("code", code),
                ("continue", "https://chat.zalo.me/"),
                ("v", version),
            ],
            qr_post_headers(WAITING_REFERER),
        )
        .await?;
        let resp: QrScanResponse = serde_json::from_value(data).unwrap_or_default();
        if resp.error_code == 8 {
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
            continue;
        }
        return Ok(resp);
    }
}

pub async fn waiting_confirm(
    ctx: &mut ContextBase,
    version: &str,
    code: &str,
) -> Result<QrConfirmResponse> {
    loop {
        let data = post_id_form(
            ctx,
            "https://id.zalo.me/account/authen/qr/waiting-confirm",
            &[
                ("code", code),
                ("gToken", ""),
                ("gAction", "CONFIRM_QR"),
                ("continue", "https://chat.zalo.me/"),
                ("v", version),
            ],
            qr_post_headers(WAITING_REFERER),
        )
        .await?;
        let resp: QrConfirmResponse = serde_json::from_value(data).unwrap_or_default();
        if resp.error_code == 8 {
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
            continue;
        }
        return Ok(resp);
    }
}

pub async fn check_session(ctx: &ContextBase) -> Result<reqwest::Response> {
    http::request(
        ctx,
        Method::GET,
        "https://id.zalo.me/account/checksession?continue=https%3A%2F%2Fchat.zalo.me%2Findex.html",
        None,
        Some(qr_session_headers()),
        false,
    )
    .await
}

pub async fn get_user_info_qr(ctx: &ContextBase) -> Result<QrUserInfoResponse> {
    let res = http::request(
        ctx,
        Method::GET,
        "https://jr.chat.zalo.me/jr/userinfo",
        None,
        Some(qr_userinfo_headers()),
        false,
    )
    .await?;
    let data: Value = res.json().await?;
    Ok(serde_json::from_value(data).unwrap_or_default())
}

/// Save a base64-encoded QR image (data URI prefix stripped) to a file.
async fn save_qr_to_file(path: &str, image_base64: &str) -> Result<()> {
    let bytes = STANDARD.decode(image_base64)
        .map_err(|e| ZaloError::Api(ZaloApiError::new(format!("Invalid base64 QR image: {e}"))))?;
    tokio::fs::write(path, bytes)
        .await
        .map_err(|e| ZaloError::Io(e))?;
    Ok(())
}

/// Extract cookies persisted in the shared reqwest cookie store as [`ZaloCookie`]s.
async fn extract_cookies(ctx: &ContextBase) -> Result<Vec<ZaloCookie>> {
    let http = http::get_http(ctx).await?;
    let store = http
        .cookie_store
        .lock()
        .map_err(|_| ZaloError::Api(ZaloApiError::new("Cookie store lock poisoned")))?;

    // Iterate the stored cookies directly instead of `get_request_values`
    // (which only yields name/value pairs), so domain/path/expiry survive
    // into account.json/cookie.json. `iter_unexpired` already drops cookies
    // past their expiry, so an expired cookie is never persisted and then
    // sent again on the next login.
    let mut cookies = Vec::new();
    for c in store.iter_unexpired() {
        let domain = c.domain.as_cow().map(|d| d.into_owned());
        let host_only = matches!(c.domain, cookie_store::CookieDomain::HostOnly(_));
        let expiration_date = match c.expires {
            cookie_store::CookieExpiration::AtUtc(dt) => Some(dt.unix_timestamp() as f64),
            cookie_store::CookieExpiration::SessionEnd => None,
        };
        cookies.push(ZaloCookie {
            name: c.name().to_string(),
            value: c.value().to_string(),
            domain,
            path: Some(c.path.as_ref().to_string()),
            expiration_date,
            host_only: Some(host_only),
            http_only: c.http_only(),
            secure: c.secure(),
            same_site: c.same_site().map(|s| format!("{s:?}").to_lowercase()),
            session: Some(!c.is_persistent()),
            store_id: None,
            key: None,
        });
    }
    Ok(cookies)
}

/// Run the full interactive QR login flow.
///
/// Steps: load login page → get login info → verify client → generate QR →
/// wait for scan → wait for confirm → check session → get user info.
///
/// The scan/confirm polling is bounded by a 100s timeout matching the TS
/// QR expiry. On timeout a [`LoginQrEvent::QrExpired`] is emitted and an
/// error is returned; the caller may retry.
pub async fn login_qr(
    ctx: &mut ContextBase,
    options: LoginQrOptions,
    callback: Option<LoginQrCallback>,
) -> Result<LoginQrResult> {
    ctx.user_agent = Some(options.user_agent.clone());

    let emit = |event: LoginQrEvent| {
        if let Some(cb) = &callback {
            cb(event);
        }
    };

    // 1. Load login page to discover the login JS version.
    let version = load_login_page(ctx).await?;
    zlog_info!("Got login version: {}", version);

    // 2. Get login info (errors are logged but non-fatal, mirroring TS).
    if let Err(e) = get_login_info(ctx, &version).await {
        zlog_warn!("get_login_info failed (non-fatal): {}", e);
    }
    emit(LoginQrEvent::GotLoginInfo);

    // 3. Verify client.
    if let Err(e) = verify_client(ctx, &version).await {
        zlog_warn!("verify_client failed (non-fatal): {}", e);
    }

    // 4. Generate QR.
    let qr = generate_qr(ctx, &version).await?;
    let qr_data = qr.data.ok_or_else(|| {
        ZaloError::Api(ZaloApiError::new(format!(
            "Unable to generate QRCode (error_code={}): {}",
            qr.error_code, qr.error_message
        )))
    })?;

    let image = qr_data
        .image
        .strip_prefix("data:image/png;base64,")
        .unwrap_or(&qr_data.image)
        .to_string();

    emit(LoginQrEvent::QrGenerated {
        code: qr_data.code.clone(),
        image: image.clone(),
        options: qr_data.options.clone(),
        token: qr_data.token.clone(),
    });

    // Save QR to file when a path is provided.
    if let Some(path) = &options.qr_path {
        save_qr_to_file(path, &image).await?;
        zlog_info!("Scan the QR code at '{}'", path);
    }

    // 5-6. Wait for scan, then wait for confirm, bounded by the 100s expiry.
    let flow = async {
        let scan_result = waiting_scan(ctx, &version, &qr_data.code).await?;
        let scan_data = scan_result
            .data
            .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Cannot get scan result")))?;

        emit(LoginQrEvent::QrScanned {
            avatar: scan_data.avatar.clone(),
            display_name: scan_data.display_name.clone(),
        });

        let confirm_result = waiting_confirm(ctx, &version, &qr_data.code).await?;
        if confirm_result.error_code == -13 {
            emit(LoginQrEvent::QrDeclined {
                code: qr_data.code.clone(),
            });
            return Err::<(), ZaloError>(ZaloError::Api(ZaloApiError::new(
                "QRCode login declined",
            )));
        } else if confirm_result.error_code != 0 {
            return Err::<(), ZaloError>(ZaloError::Api(ZaloApiError::new(format!(
                "An error has occurred.\nResponse: {}",
                serde_json::to_string(&confirm_result).unwrap_or_default()
            ))));
        }

        Ok::<(), ZaloError>(())
    };

    match timeout(Duration::from_secs(QR_TIMEOUT_SECS), flow).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            emit(LoginQrEvent::QrExpired);
            return Err(ZaloError::Api(ZaloApiError::new(format!(
                "QR code expired after {QR_TIMEOUT_SECS}s"
            ))));
        }
    }

    // 7. Check session (non-fatal: a transient network blip here must not
    // fail the whole QR flow once the user has already confirmed, mirroring
    // get_login_info/verify_client above).
    if let Err(e) = check_session(ctx).await {
        zlog_warn!("check_session failed (non-fatal): {}", e);
    }
    zlog_info!("Successfully logged into the account");

    // 8. Get user info.
    let user_info = get_user_info_qr(ctx).await?;
    let user_info_data = user_info
        .data
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Can't get account info")))?;
    if !user_info_data.logged {
        return Err(ZaloError::Api(ZaloApiError::new("Can't login")));
    }

    let cookies = extract_cookies(ctx).await?;

    Ok(LoginQrResult {
        cookies,
        user_info: user_info_data.info,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        extract_login_version, qr_page_headers, qr_post_headers, qr_userinfo_headers,
        LOGININFO_REFERER,
    };

    #[test]
    fn post_headers_match_working_js_flow() {
        let h = qr_post_headers(LOGININFO_REFERER);
        assert_eq!(h.get("accept").unwrap(), "*/*");
        assert_eq!(
            h.get("accept-language").unwrap(),
            "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"
        );
        assert_eq!(
            h.get("sec-ch-ua").unwrap(),
            "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\""
        );
        assert_eq!(h.get("sec-ch-ua-mobile").unwrap(), "?0");
        assert_eq!(h.get("sec-ch-ua-platform").unwrap(), "\"Windows\"");
        assert_eq!(h.get("sec-fetch-dest").unwrap(), "empty");
        assert_eq!(h.get("sec-fetch-mode").unwrap(), "cors");
        assert_eq!(h.get("sec-fetch-site").unwrap(), "same-origin");
        assert_eq!(h.get("priority").unwrap(), "u=1, i");
        assert_eq!(h.get("referer").unwrap(), LOGININFO_REFERER);
        assert_eq!(
            h.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    #[test]
    fn page_headers_look_like_browser_navigation() {
        let h = qr_page_headers();
        assert_eq!(h.get("sec-fetch-dest").unwrap(), "document");
        assert_eq!(h.get("sec-fetch-mode").unwrap(), "navigate");
        assert_eq!(h.get("sec-fetch-site").unwrap(), "same-site");
        assert_eq!(h.get("sec-fetch-user").unwrap(), "?1");
        assert_eq!(h.get("upgrade-insecure-requests").unwrap(), "1");
        assert_eq!(h.get("cache-control").unwrap(), "max-age=0");
        assert_eq!(h.get("referer").unwrap(), "https://chat.zalo.me/");
    }

    #[test]
    fn userinfo_headers_match_working_js_flow() {
        let h = qr_userinfo_headers();
        assert_eq!(h.get("accept").unwrap(), "*/*");
        assert_eq!(h.get("sec-fetch-site").unwrap(), "same-site");
        assert_eq!(h.get("referer").unwrap(), "https://chat.zalo.me/");
    }

    #[test]
    fn ignores_css_bundle_and_picks_js_version() {
        let html = r#"<link href="https://stc-zlogin.zdn.vn/main-2606161423.css" rel="stylesheet"><script src="https://stc-zlogin.zdn.vn/main-2606161423.js"></script>"#;
        assert_eq!(
            extract_login_version(html).as_deref(),
            Some("2606161423")
        );
    }

    #[test]
    fn returns_none_when_only_css_present() {
        let html =
            r#"<link href="https://stc-zlogin.zdn.vn/main-2606161423.css" rel="stylesheet">"#;
        assert_eq!(extract_login_version(html), None);
    }

    #[test]
    fn reproduces_reported_garbage_version_case() {
        // Shape of the real login page from the user's Mac log: the old
        // code returned `2606161423.css" rel="stylesheet">...` as the
        // "version" because it scanned to the next ".js" far away in the HTML.
        let html = concat!(
            "<link href=\"https://stc-zlogin.zdn.vn/main-2606161423.css\" rel=\"stylesheet\">\n",
            "<title>Đăng nhập tài khoản Zalo</title>\n",
            "<script src=\"https://stc-zlogin.zdn.vn/main-2606161423.js\"></script>",
        );
        assert_eq!(
            extract_login_version(html).as_deref(),
            Some("2606161423")
        );
    }
}
