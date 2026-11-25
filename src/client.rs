//! High-level client: authenticates and returns a ready-to-use API instance.

use reqwest_cookie_store::CookieStoreMutex;
use std::sync::Arc;

use crate::api::login as login_api;
use crate::api::ZaloApi;
use crate::context::{create_context, ContextSession, Credentials, Options, ZaloCookie};
use crate::errors::{Result, ZaloApiError, ZaloError};
use crate::http;
use crate::{zlog_info, zlog_warn};

/// Entry point of the library: authenticates and returns a ready-to-use API instance.
///
/// # Example
/// ```no_run
/// # use zalo_rs::{ZaloClient, Credentials, ZaloCookie};
/// # async fn demo() -> zalo_rs::errors::Result<()> {
/// let client = ZaloClient::new(Default::default());
/// let creds = Credentials {
///     imei: "...".into(),
///     cookie: vec![/* ... */],
///     user_agent: "Mozilla/5.0 ...".into(),
///     language: Some("vi".into()),
/// };
/// let api = client.login(creds).await?;
/// # Ok(())
/// # }
/// ```
pub struct ZaloClient {
    options: Options,
}

impl ZaloClient {
    pub fn new(options: Options) -> Self {
        Self { options }
    }

    /// Logs in with an existing cookie + imei + userAgent triple.
    pub async fn login(&self, credentials: Credentials) -> Result<ZaloApi> {
        let mut ctx = create_context(self.options.api_type, self.options.api_version);
        ctx.options = self.options.clone();
        self.login_with_context(&mut ctx, credentials).await
    }

    /// Alias for [`login`](Self::login).
    pub async fn login_from_browser(&self, credentials: Credentials) -> Result<ZaloApi> {
        self.login(credentials).await
    }

    fn parse_cookies(&self, cookies: &[ZaloCookie]) -> Arc<CookieStoreMutex> {
        let mut store = cookie_store::CookieStore::new(None);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        for c in cookies {
            let name = c.key.as_deref().unwrap_or(&c.name);
            // Skip cookies that are already expired instead of sending them
            // and letting the server reject the login with a generic error.
            if let Some(exp) = c.expiration_date {
                if exp <= now {
                    zlog_warn!(
                        "Skipping expired cookie '{}' (expired at {})",
                        name,
                        exp as i64
                    );
                    continue;
                }
            }
            let domain = c.domain.as_deref().unwrap_or("chat.zalo.me");
            let domain_clean = domain.strip_prefix('.').unwrap_or(domain);
            let url_str = format!("https://{}", domain_clean);
            let path = c.path.as_deref().unwrap_or("/");
            let secure = c.secure.unwrap_or(false);
            let http_only = c.http_only.unwrap_or(false);
            // Build a Set-Cookie string that the cookie_store can parse
            let mut cookie_str = format!("{}={}; Domain={}; Path={}", name, c.value, domain_clean, path);
            if secure {
                cookie_str.push_str("; Secure");
            }
            if http_only {
                cookie_str.push_str("; HttpOnly");
            }
            // Keep the expiry so the store itself drops the cookie once it
            // lapses instead of sending a stale cookie on later requests.
            if let Some(exp) = c.expiration_date {
                if let Some(dt) =
                    chrono::DateTime::<chrono::Utc>::from_timestamp(exp as i64, 0)
                {
                    cookie_str.push_str(&format!(
                        "; Expires={}",
                        dt.format("%a, %d %b %Y %H:%M:%S GMT")
                    ));
                }
            }
            if let Ok(url) = url::Url::parse(&url_str) {
                if let Err(e) = store.parse(&cookie_str, &url) {
                    zlog_warn!("Failed to parse cookie '{}': {:?}", name, e);
                }
            }
        }
        Arc::new(CookieStoreMutex::new(store))
    }

    async fn login_with_context(
        &self,
        ctx: &mut crate::context::ContextBase,
        credentials: Credentials,
    ) -> Result<ZaloApi> {
        if credentials.imei.is_empty()
            || credentials.cookie.is_empty()
            || credentials.user_agent.is_empty()
        {
            return Err(ZaloError::Api(ZaloApiError::new("Missing required params")));
        }

        ctx.imei = Some(credentials.imei.clone());
        ctx.user_agent = Some(credentials.user_agent.clone());
        ctx.language = Some(credentials.language.clone().unwrap_or_else(|| "vi".into()));

        let cookie_store = self.parse_cookies(&credentials.cookie);
        http::init_http(ctx, cookie_store).await?;

        let login_data = login_api::login(ctx, true).await?;
        // Check the login result BEFORE get_server_info: a login failure
        // (expired cookie, wrong imei, ...) must surface as itself, not be
        // masked by a server-info error.
        let login_data = login_data.ok_or_else(|| {
            ZaloError::Api(ZaloApiError::new("Đăng nhập thất bại: empty login response"))
        })?;

        let server_info = login_api::get_server_info(ctx, true).await?;

        // login_data may be wrapped in { data: ... } or be the data directly
        let login_info_val = login_data.get("data").cloned().unwrap_or(login_data);

        // Parse leniently: a single field with an unexpected shape must not
        // wipe the whole struct (see parse_login_info_lenient).
        let login_info: crate::context::LoginInfo =
            serde_json::from_value(login_info_val.clone())
                .unwrap_or_else(|_| parse_login_info_lenient(&login_info_val));

        let secret_key = login_info
            .zpw_enk
            .clone()
            .or_else(|| login_info_val.get("zpw_enk").and_then(|v| v.as_str()).map(String::from))
            .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Missing zpw_enk in login response")))?;

        let uid = login_info
            .uid
            .clone()
            .or_else(|| login_info_val.get("uid").and_then(|v| v.as_str()).map(String::from))
            .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Missing uid in login response")))?;

        ctx.secret_key = Some(secret_key);
        ctx.uid = Some(uid.clone());
        ctx.login_info = Some(login_info.clone());

        // Settings: Zalo sometimes returns `setttings` (typo) instead of `settings`
        let settings = server_info
            .settings
            .clone()
            .or(server_info.setttings.clone());
        ctx.settings = settings;
        ctx.extra_ver = server_info.extra_ver.clone();

        if crate::context::ContextSession::from_base(ctx).is_none() {
            return Err(ZaloError::Api(ZaloApiError::new("Khởi tạo ngữ cảnh thất bại")));
        }

        zlog_info!("Logged in as {}", uid);

        let session = ContextSession::from_base(ctx)
            .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Failed to create session context")))?;

        let ws_urls = login_info.zpw_ws.clone().unwrap_or_default();
        let zpw_service_map = login_info.zpw_service_map_v3.clone().unwrap_or(serde_json::Value::Null);

        Ok(ZaloApi::new(session, zpw_service_map, ws_urls))
    }
}

/// Parse `LoginInfo` field-by-field instead of all-or-nothing.
///
/// The server sometimes returns a single field with an unexpected shape
/// (e.g. `zpw_ws` as one string instead of an array, `uid` as a JSON
/// number, an odd `zpw_service_map_v3`). A strict whole-struct
/// `serde_json::from_value` then fails and `unwrap_or_default()` silently
/// drops every other (valid) field, losing `uid`/`zpw_enk`/`zpw_ws` and
/// failing login with "Missing zpw_enk" / "No WebSocket URLs available"
/// even though the server returned all the data. Parsing leniently keeps
/// every usable field when one of them is malformed.
fn parse_login_info_lenient(v: &serde_json::Value) -> crate::context::LoginInfo {
    let mut info = crate::context::LoginInfo::default();
    info.uid = v.get("uid").and_then(|x| match x {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    });
    info.zpw_enk = v
        .get("zpw_enk")
        .and_then(|x| x.as_str())
        .map(String::from);
    info.zpw_ws = v.get("zpw_ws").and_then(|x| match x {
        serde_json::Value::Array(items) => Some(
            items
                .iter()
                .filter_map(|i| i.as_str().map(String::from))
                .collect(),
        ),
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        _ => None,
    });
    info.zpw_service_map_v3 = v
        .get("zpw_service_map_v3")
        .cloned()
        .filter(|x| !x.is_null());
    if let serde_json::Value::Object(map) = v {
        for (k, val) in map {
            match k.as_str() {
                "uid" | "zpw_enk" | "zpw_ws" | "zpw_service_map_v3" => {}
                _ => {
                    info.extra.insert(k.clone(), val.clone());
                }
            }
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::parse_login_info_lenient;

    #[test]
    fn lenient_parse_recovers_fields_when_one_field_has_wrong_shape() {
        // uid as a number + zpw_ws as a single string: strict whole-struct
        // parse fails, so without the lenient fallback every field would
        // be lost (uid/zpw_enk/ws -> default).
        let v = serde_json::json!({
            "uid": 418669971689260834u64,
            "zpw_enk": "secret-enk",
            "zpw_ws": "wss://ws2-msg.chat.zalo.me",
            "zpw_service_map_v3": {"chat": "https://wpa.chat.zalo.me"},
        });
        assert!(serde_json::from_value::<crate::context::LoginInfo>(v.clone()).is_err());
        let info = parse_login_info_lenient(&v);
        assert_eq!(info.uid.as_deref(), Some("418669971689260834"));
        assert_eq!(info.zpw_enk.as_deref(), Some("secret-enk"));
        assert_eq!(
            info.zpw_ws.as_deref(),
            Some(vec!["wss://ws2-msg.chat.zalo.me".to_string()].as_slice())
        );
        assert!(info.zpw_service_map_v3.is_some());
    }

    #[test]
    fn lenient_parse_filters_non_string_ws_entries() {
        let v = serde_json::json!({
            "uid": "123",
            "zpw_enk": "enk",
            "zpw_ws": ["wss://a", 42, "wss://b"],
        });
        let info = parse_login_info_lenient(&v);
        assert_eq!(
            info.zpw_ws.as_deref(),
            Some(
                vec!["wss://a".to_string(), "wss://b".to_string()].as_slice()
            )
        );
    }
}
