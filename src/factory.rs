//! API factory helpers: response parsing and encryption utilities.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::context::ContextSession;
use crate::crypto::decode_aes;
use crate::errors::{Result, ZaloApiError, ZaloError};

/// Standard Zalo API response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZaloEnvelope<T = serde_json::Value> {
    #[serde(default, deserialize_with = "deserialize_error_code")]
    pub error_code: i64,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub data: Option<T>,
}

/// Parse an `error_code` leniently: Zalo sometimes returns it as a JSON
/// string (`"0"`, `"-4"`) instead of a number. Reading it with
/// `as_i64()` alone would treat those as 0, silently swallowing the real
/// error and letting the code continue into decrypt/deserialize, where it
/// then fails with an unrelated-looking error.
pub(crate) fn parse_error_code(v: Option<&serde_json::Value>) -> i64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.trim().parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

fn deserialize_error_code<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(deserializer)?;
    Ok(parse_error_code(Some(&v)))
}

/// Parsed result from a Zalo API response.
#[derive(Debug, Clone)]
pub struct ZaloResponse<T> {
    pub data: Option<T>,
    pub error: Option<ZaloResponseError>,
}

#[derive(Debug, Clone)]
pub struct ZaloResponseError {
    pub message: String,
    pub code: Option<i64>,
}

/// Reads a Zalo API response, optionally decrypting its AES payload.
pub async fn handle_zalo_response<T: DeserializeOwned>(
    ctx: &ContextSession,
    response: reqwest::Response,
    is_encrypted: bool,
) -> ZaloResponse<T> {
    if !response.status().is_success() {
        return ZaloResponse {
            data: None,
            error: Some(ZaloResponseError {
                message: format!("Request failed with status code {}", response.status()),
                code: None,
            }),
        };
    }

    let json: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(e) => {
            return ZaloResponse {
                data: None,
                error: Some(ZaloResponseError {
                    message: format!("Failed to parse response JSON: {}", e),
                    code: None,
                }),
            }
        }
    };

    let error_code = parse_error_code(json.get("error_code"));
    if error_code != 0 {
        let msg = json
            .get("error_message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error")
            .to_string();
        return ZaloResponse {
            data: None,
            error: Some(ZaloResponseError {
                message: msg,
                code: Some(error_code),
            }),
        };
    }

    let payload = if is_encrypted {
        // Encrypted responses carry `data` as an AES-encrypted string, but
        // some endpoints return `data` as a plain JSON object instead. The
        // TypeScript client handles both (`resolveResponse` only decrypts
        // when `data` is a string); do the same instead of failing with
        // "Encrypted response missing data field".
        match json.get("data") {
            Some(v) if !v.is_string() => json.clone(),
            Some(v) => {
                let data_str = v.as_str().unwrap_or_default();
                match decode_aes(&ctx.secret_key, data_str) {
                    Some(decoded) => match serde_json::from_str::<serde_json::Value>(&decoded) {
                        Ok(v) => v,
                        Err(e) => {
                            return ZaloResponse {
                                data: None,
                                error: Some(ZaloResponseError {
                                    message: format!("Failed to parse decrypted payload: {}", e),
                                    code: None,
                                }),
                            }
                        }
                    },
                    None => {
                        return ZaloResponse {
                            data: None,
                            error: Some(ZaloResponseError {
                                message: "Failed to decrypt response data".into(),
                                code: None,
                            }),
                        }
                    }
                }
            }
            None => {
                return ZaloResponse {
                    data: None,
                    error: Some(ZaloResponseError {
                        message: "Encrypted response missing data field".into(),
                        code: None,
                    }),
                }
            }
        }
    } else {
        json
    };

    // The decrypted payload may itself have error_code/data
    let inner_code = parse_error_code(payload.get("error_code"));
    if inner_code != 0 {
        let msg = payload
            .get("error_message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error")
            .to_string();
        return ZaloResponse {
            data: None,
            error: Some(ZaloResponseError {
                message: msg,
                code: Some(inner_code),
            }),
        };
    }

    let data_val = payload.get("data").cloned().unwrap_or(payload);
    match serde_json::from_value::<T>(data_val) {
        Ok(data) => ZaloResponse {
            data: Some(data),
            error: None,
        },
        Err(e) => ZaloResponse {
            data: None,
            error: Some(ZaloResponseError {
                message: format!("Failed to deserialize response data: {}", e),
                code: None,
            }),
        },
    }
}

/// Resolve a response into plain data, returning `ZaloApiError` on failure.
pub async fn resolve_response<T: DeserializeOwned>(
    ctx: &ContextSession,
    res: reqwest::Response,
    is_encrypted: bool,
) -> Result<T> {
    let result = handle_zalo_response::<T>(ctx, res, is_encrypted).await;
    if let Some(err) = result.error {
        return Err(ZaloError::Api(match err.code {
            Some(code) => ZaloApiError::with_code(err.message, code),
            None => ZaloApiError::new(err.message),
        }));
    }
    result
        .data
        .ok_or_else(|| ZaloError::Api(ZaloApiError::new("Empty response data")))
}

#[cfg(test)]
mod tests {
    use super::{parse_error_code, ZaloEnvelope};

    #[test]
    fn error_code_accepts_numbers_and_numeric_strings() {
        assert_eq!(parse_error_code(Some(&serde_json::json!(0))), 0);
        assert_eq!(parse_error_code(Some(&serde_json::json!(-4))), -4);
        assert_eq!(parse_error_code(Some(&serde_json::json!("0"))), 0);
        assert_eq!(parse_error_code(Some(&serde_json::json!("-4"))), -4);
        assert_eq!(parse_error_code(Some(&serde_json::json!("  8 "))), 8);
        assert_eq!(parse_error_code(Some(&serde_json::json!("bogus"))), 0);
        assert_eq!(parse_error_code(None), 0);
        assert_eq!(parse_error_code(Some(&serde_json::Value::Null)), 0);
    }

    #[test]
    fn envelope_deserializes_string_error_code() {
        let env: ZaloEnvelope = serde_json::from_value(serde_json::json!({
            "error_code": "-4",
            "error_message": "expired",
            "data": null,
        }))
        .unwrap();
        assert_eq!(env.error_code, -4);
        assert_eq!(env.error_message.as_deref(), Some("expired"));
    }
}
