//! Session context: configuration, credentials, and runtime state.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Retry / timeout policy for outgoing HTTP requests.
#[derive(Debug, Clone)]
pub struct RetryOptions {
    /// Maximum retry attempts after the initial request. Default `3`.
    pub limit: u32,
    /// Base delay (ms) of the exponential backoff. Default `250`.
    pub delay_ms: u64,
    /// Upper bound (ms) for a single backoff delay. Default `5000`.
    pub max_delay_ms: u64,
    /// HTTP methods eligible for retry. Default `["GET", "HEAD"]`.
    pub methods: Vec<String>,
    /// Overall request timeout (ms). Default `60000`. Use `0` to disable.
    pub timeout_ms: u64,
}

impl Default for RetryOptions {
    fn default() -> Self {
        Self {
            limit: 3,
            delay_ms: 250,
            max_delay_ms: 5000,
            methods: vec!["GET".into(), "HEAD".into()],
            timeout_ms: 60_000,
        }
    }
}

/// Log level setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logging {
    Silent,
    Error,
    Warn,
    Info,
    Verbose,
}

/// Client options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Receive events triggered by the current account (self listen).
    pub self_listen: bool,
    /// Logging level.
    pub logging: Logging,
    pub api_type: u32,
    pub api_version: u32,
    pub retry: RetryOptions,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            self_listen: false,
            logging: Logging::Info,
            api_type: 30,
            api_version: 685,
            retry: RetryOptions::default(),
        }
    }
}

/// A browser cookie in the JSON-array format used by Zalo credential import.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaloCookie {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub expiration_date: Option<f64>,
    #[serde(default)]
    pub host_only: Option<bool>,
    #[serde(default)]
    pub http_only: Option<bool>,
    #[serde(default)]
    pub secure: Option<bool>,
    #[serde(default)]
    pub same_site: Option<String>,
    #[serde(default)]
    pub session: Option<bool>,
    #[serde(default)]
    pub store_id: Option<String>,
    /// Support `key` field from tough-cookie serialized format
    #[serde(default)]
    pub key: Option<String>,
}

/// Minimal credential shape used by Zalo login flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZaloCredentials {
    pub imei: String,
    pub cookie: Vec<ZaloCookie>,
    pub user_agent: String,
    #[serde(default)]
    pub language: Option<String>,
}

/// Alias used by examples / public API.
pub type Credentials = ZaloCredentials;

/// Login info returned by the getLoginInfo API.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoginInfo {
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub zpw_enk: Option<String>,
    #[serde(default)]
    pub zpw_ws: Option<Vec<String>>,
    #[serde(default)]
    pub zpw_service_map_v3: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Service map (zpw_service_map_v3).
pub type ZpwServiceMap = serde_json::Value;

/// Server info settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerInfo {
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(default)]
    pub setttings: Option<serde_json::Value>, // Zalo typo fallback
    #[serde(default)]
    pub extra_ver: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Shared HTTP client state (cookie jar + reqwest client).
#[derive(Clone)]
pub struct HttpState {
    pub client: reqwest::Client,
    pub cookie_store: Arc<reqwest_cookie_store::CookieStoreMutex>,
}

impl std::fmt::Debug for HttpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpState").finish_non_exhaustive()
    }
}

pub type UploadCallback = Arc<dyn Fn(Value) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;
pub type UploadCallbacks = Arc<std::sync::Mutex<HashMap<String, UploadCallback>>>;

fn new_upload_callbacks() -> UploadCallbacks {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

/// How long a stashed early `file_done` event is kept. Uploads wait at
/// most 120s for the event, so 5 minutes leaves ample margin.
const FILE_DONE_STASH_TTL: std::time::Duration = std::time::Duration::from_secs(300);
/// Maximum stashed events. An upload only ever waits for one event per
/// file id, so this bounds memory even if the server emits events for
/// uploads this context never started.
const FILE_DONE_STASH_CAP: usize = 64;

/// Stash for `file_done` WS events that arrive before the upload has
/// registered its callback.
///
/// Single-chunk uploads (video <= 1 MB) register their callback only
/// after their only chunk is POSTed, so the server can emit `file_done`
/// before any callback exists. The WS dispatcher used to drop such an
/// event silently and the upload then stalled for the full 120s timeout.
/// Stashing the event lets the late-registered callback pick it up
/// immediately instead (see `register_upload_callback` in
/// `api::upload_attachment`).
#[derive(Clone, Debug)]
pub struct FileDoneStash {
    inner: Arc<std::sync::Mutex<HashMap<String, (Value, std::time::Instant)>>>,
}

impl FileDoneStash {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Store `data` for `file_id`, evicting expired entries and, if the
    /// stash is full, the oldest entry.
    pub fn store(&self, file_id: String, data: Value) {
        let now = std::time::Instant::now();
        if let Ok(mut map) = self.inner.lock() {
            map.retain(|_, (_, at)| now.duration_since(*at) < FILE_DONE_STASH_TTL);
            if map.len() >= FILE_DONE_STASH_CAP && !map.contains_key(&file_id) {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
            map.insert(file_id, (data, now));
        }
    }

    /// Take the stashed event for `file_id`, if any and not expired.
    pub fn take(&self, file_id: &str) -> Option<Value> {
        let now = std::time::Instant::now();
        if let Ok(mut map) = self.inner.lock() {
            match map.remove(file_id) {
                Some((data, at)) if now.duration_since(at) < FILE_DONE_STASH_TTL => {
                    Some(data)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Drop any stashed event for `file_id` (upload finished / cancelled).
    pub fn remove(&self, file_id: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(file_id);
        }
    }
}

impl Default for FileDoneStash {
    fn default() -> Self {
        Self::new()
    }
}

fn new_file_done_stash() -> FileDoneStash {
    FileDoneStash::new()
}

/// Base context for pre-login operations.
#[derive(Clone)]
pub struct ContextBase {
    pub api_type: u32,
    pub api_version: u32,
    pub imei: Option<String>,
    pub user_agent: Option<String>,
    pub language: Option<String>,
    pub secret_key: Option<String>,
    pub uid: Option<String>,
    pub options: Options,
    pub http: Arc<Mutex<Option<HttpState>>>,
    pub login_info: Option<LoginInfo>,
    pub settings: Option<serde_json::Value>,
    pub extra_ver: Option<serde_json::Value>,
    pub upload_callbacks: UploadCallbacks,
    pub file_done_stash: FileDoneStash,
}

impl std::fmt::Debug for ContextBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextBase")
            .field("api_type", &self.api_type)
            .field("api_version", &self.api_version)
            .field("imei", &self.imei)
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

/// Authenticated session context.
#[derive(Clone)]
pub struct ContextSession {
    pub api_type: u32,
    pub api_version: u32,
    pub imei: String,
    pub user_agent: String,
    pub language: String,
    pub secret_key: String,
    pub uid: String,
    pub options: Options,
    pub http: Arc<Mutex<Option<HttpState>>>,
    pub login_info: LoginInfo,
    pub settings: Option<serde_json::Value>,
    pub extra_ver: Option<serde_json::Value>,
    pub upload_callbacks: UploadCallbacks,
    pub file_done_stash: FileDoneStash,
}

impl std::fmt::Debug for ContextSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextSession")
            .field("api_type", &self.api_type)
            .field("api_version", &self.api_version)
            .field("imei", &self.imei)
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

impl ContextSession {
    pub fn from_base(base: &ContextBase) -> Option<Self> {
        Some(Self {
            api_type: base.api_type,
            api_version: base.api_version,
            imei: base.imei.clone()?,
            user_agent: base.user_agent.clone()?,
            language: base.language.clone().unwrap_or_else(|| "vi".into()),
            secret_key: base.secret_key.clone()?,
            uid: base.uid.clone()?,
            options: base.options.clone(),
            http: base.http.clone(),
            login_info: base.login_info.clone().unwrap_or_default(),
            settings: base.settings.clone(),
            extra_ver: base.extra_ver.clone(),
            upload_callbacks: base.upload_callbacks.clone(),
            file_done_stash: base.file_done_stash.clone(),
        })
    }
}

/// Create a default pre-login context.
pub fn create_context(api_type: u32, api_version: u32) -> ContextBase {
    ContextBase {
        api_type,
        api_version,
        imei: None,
        user_agent: None,
        language: None,
        secret_key: None,
        uid: None,
        options: Options {
            api_type,
            api_version,
            ..Options::default()
        },
        http: Arc::new(Mutex::new(None)),
        login_info: None,
        settings: None,
        extra_ver: None,
        upload_callbacks: new_upload_callbacks(),
        file_done_stash: new_file_done_stash(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_done_stash_store_take_once() {
        let stash = FileDoneStash::new();
        let data = serde_json::json!({"fileUrl": "https://x/y", "fileId": "42"});
        stash.store("42".to_string(), data.clone());
        assert_eq!(stash.take("42"), Some(data));
        // A stashed event is delivered at most once.
        assert_eq!(stash.take("42"), None);
    }

    #[test]
    fn file_done_stash_remove_drops_entry() {
        let stash = FileDoneStash::new();
        stash.store(
            "7".to_string(),
            serde_json::json!({"fileUrl": "https://x/z", "fileId": "7"}),
        );
        stash.remove("7");
        assert_eq!(stash.take("7"), None);
    }

    #[test]
    fn file_done_stash_take_expired_returns_none() {
        let stash = FileDoneStash::new();
        let old = std::time::Instant::now() - FILE_DONE_STASH_TTL
            - std::time::Duration::from_secs(1);
        stash
            .inner
            .lock()
            .unwrap()
            .insert("old".to_string(), (serde_json::json!({"fileId": "old"}), old));
        assert_eq!(stash.take("old"), None);
    }

    #[test]
    fn file_done_stash_store_prunes_expired_entries() {
        let stash = FileDoneStash::new();
        let old = std::time::Instant::now() - FILE_DONE_STASH_TTL
            - std::time::Duration::from_secs(1);
        stash
            .inner
            .lock()
            .unwrap()
            .insert("old".to_string(), (serde_json::json!({"fileId": "old"}), old));
        stash.store(
            "new".to_string(),
            serde_json::json!({"fileId": "new"}),
        );
        assert_eq!(stash.take("old"), None);
        assert_eq!(
            stash.take("new").unwrap()["fileId"],
            serde_json::json!("new")
        );
    }

    #[test]
    fn file_done_stash_evicts_oldest_at_cap() {
        let stash = FileDoneStash::new();
        // Fill the stash with entries of increasing age so f0 is oldest.
        let base = std::time::Instant::now() - std::time::Duration::from_secs(60);
        for i in 0..FILE_DONE_STASH_CAP {
            stash.inner.lock().unwrap().insert(
                format!("f{i}"),
                (
                    serde_json::json!({"fileId": format!("f{i}")}),
                    base + std::time::Duration::from_secs(i as u64),
                ),
            );
        }
        stash.store(
            "new".to_string(),
            serde_json::json!({"fileId": "new"}),
        );
        // Oldest entry evicted to make room.
        assert_eq!(stash.take("f0"), None);
        assert!(stash.take("f1").is_some());
        assert!(stash.take("new").is_some());
    }
}
