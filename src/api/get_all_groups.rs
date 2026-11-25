//! Get all groups.

use crate::api::client::ApiClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetAllGroupsResponse {
    #[serde(default)]
    pub version: String,
    #[serde(rename = "gridVerMap")]
    #[serde(default)]
    pub grid_ver_map: HashMap<String, String>,
}

/// Get all groups.
pub async fn get_all_groups(client: &ApiClient) -> Result<GetAllGroupsResponse> {
    let base_url = client.service_url("group_poll", "/api/group/getlg/v4")?;
    // `make_url` appends the `zpw_ver` / `zpw_type` markers the Zalo web API
    // expects on every request.
    let url = client.make_url(&base_url, &[], true)?;
    let res = client.request_get(&url).await?;
    client.resolve(res).await
}
