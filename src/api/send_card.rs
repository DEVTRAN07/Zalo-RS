use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::client::ApiClient;
use crate::api::get_qr;
use crate::api::send_message::next_client_id;
use crate::errors::{Result, ZaloApiError, ZaloError};
use crate::models::r#enum::ThreadType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendCardOptions {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "phoneNumber")]
    pub phone_number: Option<String>,
    pub ttl: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SendCardResponse {
    #[serde(rename = "msgId", default)]
    pub msg_id: Value,
}

/// Send a card to a User/Group.
pub async fn send_card(
    client: &ApiClient,
    options: SendCardOptions,
    thread_id: &str,
    thread_type: ThreadType,
) -> Result<SendCardResponse> {
    let qr = get_qr::get_qr(client, &[options.user_id.clone()]).await?;
    let qr_code_url = qr.get(&options.user_id).cloned().unwrap_or_default();
    // A card without its QR code URL is useless: fail loudly instead of
    // sending it with an empty qrCodeUrl.
    if qr_code_url.is_empty() {
        return Err(ZaloError::Api(ZaloApiError::new(
            "Missing QR code URL for user",
        )));
    }
    let client_id = next_client_id().to_string();

    let mut msg_info = serde_json::json!({
        "contactUid": options.user_id,
        "qrCodeUrl": qr_code_url,
    });
    if let Some(phone) = &options.phone_number {
        msg_info["phone"] = Value::String(phone.clone());
    }

    let mut params = serde_json::json!({
        "ttl": options.ttl.unwrap_or(0),
        "msgType": 6,
        "clientId": client_id,
        "msgInfo": msg_info.to_string(),
    });

    let path = match thread_type {
        ThreadType::Group => "/api/group/forward",
        ThreadType::User => "/api/message/forward",
    };
    let base_url = client.service_url("file", path)?;
    let url = client.make_url(&base_url, &[], true)?;

    match thread_type {
        ThreadType::Group => {
            params["visibility"] = serde_json::json!(0);
            params["grid"] = Value::String(thread_id.to_string());
        }
        ThreadType::User => {
            params["toId"] = Value::String(thread_id.to_string());
            params["imei"] = Value::String(client.ctx().imei.clone());
        }
    }

    client.post_encrypted(&url, &params).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_card_response_accepts_string_msg_id() {
        // Same as the other send_* responses: msgId may arrive as a string.
        let resp: SendCardResponse =
            serde_json::from_value(serde_json::json!({"msgId": "123"})).unwrap();
        assert_eq!(resp.msg_id, Value::String("123".to_string()));
        let resp: SendCardResponse =
            serde_json::from_value(serde_json::json!({"msgId": 456})).unwrap();
        assert_eq!(resp.msg_id, Value::from(456));
    }
}
