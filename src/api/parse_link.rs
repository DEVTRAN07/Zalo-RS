use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::api::client::ApiClient;
use crate::errors::{Result, ZaloApiError, ZaloError};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParseLinkResponse {
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub error_maps: HashMap<String, i64>,
}

/// Parse link.
pub async fn parse_link(client: &ApiClient, link: &str) -> Result<ParseLinkResponse> {
    let base_url = client.service_url("file", "/api/message/parselink")?;
    let params = serde_json::json!({
        "link": link,
        "version": 1,
        "imei": client.ctx().imei,
    });
    let encrypted = client
        .encode_aes(&params.to_string())
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Failed to encrypt params")))?;
    // `make_url` appends the `zpw_ver` / `zpw_type` markers the Zalo web API
    // expects on every request (and URL-encodes the values).
    let url = client.make_url(&base_url, &[("params", encrypted)], true)?;
    let res = client.request_get(&url).await?;
    client.resolve(res).await
}
