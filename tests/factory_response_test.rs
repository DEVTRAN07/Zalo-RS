//! Response-resolution tests for `factory::resolve_response`.
//!
//! The tests serve canned HTTP bodies from a one-shot local TCP server so
//! `resolve_response` can be exercised with a real `reqwest::Response`
//! without talking to Zalo.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use zalo_rs::context::{create_context, ContextSession};
use zalo_rs::crypto::encode_aes;
use zalo_rs::factory::resolve_response;

/// Spin up a one-shot HTTP server on 127.0.0.1:0 that answers a single
/// request with `body` as JSON, and return the URL to fetch.
fn serve_once(body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
    let port = listener.local_addr().expect("local addr").port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}/api/test")
}

fn test_key() -> String {
    BASE64.encode([0x11u8; 16])
}

fn test_ctx() -> ContextSession {
    let mut base = create_context(30, 685);
    base.imei = Some("test-imei".into());
    base.user_agent = Some("test-agent".into());
    base.secret_key = Some(test_key());
    base.uid = Some("123".into());
    ContextSession::from_base(&base).expect("session")
}

async fn fetch(url: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(url)
        .send()
        .await
        .expect("fetch from local server")
}

/// Regression test: some endpoints return `data` as a plain JSON object
/// instead of an AES-encrypted string. The TypeScript client accepts both;
/// `resolve_response(..., is_encrypted = true)` used to fail these with
/// "Encrypted response missing data field".
#[tokio::test]
async fn encrypted_response_with_plain_object_data_resolves() {
    let ctx = test_ctx();
    let body = json!({
        "error_code": 0,
        "data": {"version": "v1", "gridVerMap": {"111": "2"}},
    })
    .to_string();
    let res = fetch(&serve_once(body)).await;
    let value: serde_json::Value = resolve_response(&ctx, res, true)
        .await
        .expect("object data should resolve");
    assert_eq!(value["version"], "v1");
    assert_eq!(value["gridVerMap"]["111"], "2");
}

/// The normal encrypted path still works: `data` as an AES string is
/// decrypted and parsed.
#[tokio::test]
async fn encrypted_response_with_encrypted_string_data_still_decrypts() {
    let ctx = test_ctx();
    let inner = json!({"msgId": 987}).to_string();
    let enc = encode_aes(&test_key(), &inner).expect("encrypt");
    let body = json!({"error_code": 0, "data": enc}).to_string();
    let res = fetch(&serve_once(body)).await;
    let value: serde_json::Value = resolve_response(&ctx, res, true)
        .await
        .expect("encrypted data should decrypt");
    assert_eq!(value["msgId"], 987);
}

/// A response with no `data` field at all still errors (the fallback only
/// applies when `data` is present but not a string).
#[tokio::test]
async fn encrypted_response_missing_data_still_errors() {
    let ctx = test_ctx();
    let body = json!({"error_code": 0}).to_string();
    let res = fetch(&serve_once(body)).await;
    let err = resolve_response::<serde_json::Value>(&ctx, res, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("missing data"),
        "unexpected error: {err}"
    );
}
