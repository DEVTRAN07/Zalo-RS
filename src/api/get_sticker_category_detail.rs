use serde_json::Value;

use crate::api::client::ApiClient;
use crate::errors::{Result, ZaloApiError, ZaloError};

pub type GetStickerCategoryDetailResponse = Value;

/// Get sticker category detail.
pub async fn get_sticker_category_detail(
    client: &ApiClient,
    cid: i64,
) -> Result<GetStickerCategoryDetailResponse> {
    let base_url = client.service_url("sticker", "/api/message/sticker/cate-detail")?;
    let params = serde_json::json!({ "cid": cid, "imei": client.ctx().imei });
    let encrypted = client
        .encode_aes(&params.to_string())
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Failed to encrypt params")))?;
    // `make_url` appends the `zpw_ver` / `zpw_type` markers the Zalo web API
    // expects on every request (and URL-encodes the values).
    let url = client.make_url(&base_url, &[("params", encrypted)], true)?;
    let res = client.request_get(&url).await?;
    client.resolve(res).await
}
