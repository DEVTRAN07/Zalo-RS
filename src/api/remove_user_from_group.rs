use serde::{Deserialize, Serialize};

use crate::api::client::ApiClient;
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemoveUserFromGroupResponse {
    #[serde(rename = "errorMembers", default)]
    pub error_members: Vec<String>,
}

/// Remove user(s) from an existing group.
pub async fn remove_user_from_group(
    client: &ApiClient,
    member_ids: &[String],
    group_id: &str,
) -> Result<RemoveUserFromGroupResponse> {
    let base_url = client.service_url("group", "/api/group/kickout")?;
    // `make_url` appends the `zpw_ver` / `zpw_type` markers the Zalo web API
    // expects on every request (same as `add_user_to_group`).
    let url = client.make_url(&base_url, &[("nretry", "0".to_string())], true)?;
    let params = serde_json::json!({
        "grid": group_id,
        "members": member_ids,
        "imei": client.ctx().imei,
    });
    client.post_encrypted(&url, &params).await
}
