use hbb_common::log;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::time::Duration;

const VERIFY_TIMEOUT_MS: u64 = 800;

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(VERIFY_TIMEOUT_MS))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MustLoginMode {
    Off,
    Api,
    Local,
}

impl MustLoginMode {
    pub fn from_arg(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "" | "n" | "no" | "off" | "false" | "0" => Self::Off,
            "local" | "jwt" => Self::Local,
            "y" | "yes" | "on" | "true" | "1" | "api" => Self::Api,
            other => {
                log::warn!("Unknown must-login mode {:?}, MUST_LOGIN stays off", other);
                Self::Off
            }
        }
    }

    pub fn enabled(self) -> bool {
        self != Self::Off
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Api => "api",
            Self::Local => "local",
        }
    }
}

#[derive(Deserialize)]
struct VerifyResponse {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    message: String,
    data: Option<VerifyData>,
}

#[derive(Deserialize)]
struct VerifyData {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    #[allow(dead_code)]
    user_id: u32,
    exp: usize,
}

/// Ask the API whether `token` still belongs to an enabled user.
/// Any transport error, non-2xx status or malformed body is a rejection:
/// MUST_LOGIN fails closed.
pub async fn verify_by_api(
    api_server: &str,
    secret: &str,
    token: &str,
    peer_id: &str,
    ip: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/api/server/verify-token",
        api_server.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "token": token,
        "guid": peer_id,
        "uuid": "",
        "ip": ip,
    });
    let resp = HTTP_CLIENT
        .post(&url)
        .header("X-Rdtest-Secret", secret)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("api request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("api returned {status}"));
    }
    let body: VerifyResponse = resp
        .json()
        .await
        .map_err(|e| format!("invalid api response: {e}"))?;
    match body.data {
        Some(data) if body.code == 0 && data.ok => Ok(()),
        Some(data) => Err(non_empty(&data.reason, "rejected by api")),
        None => Err(non_empty(&body.message, "rejected by api")),
    }
}

/// Local HS256 check used when the API is unreachable by design.
/// It only proves the token was signed by us and has not expired; revocation
/// requires mode `api`.
pub fn verify_by_jwt(jwt_key: &str, token: &str) -> Result<(), String> {
    if jwt_key.is_empty() {
        return Err("api-jwt-key is not configured".to_owned());
    }
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 30;
    match decode::<Claims>(token, &DecodingKey::from_secret(jwt_key.as_bytes()), &validation) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("invalid token: {err}")),
    }
}

fn non_empty(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}
