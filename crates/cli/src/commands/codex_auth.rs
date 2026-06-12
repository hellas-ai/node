use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(feature = "hellas-executor")]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::Url;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::commands::http_client;

const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const ISSUER: &str = "https://auth.openai.com";
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const AUTH_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "hellas-executor")]
const REFRESH_SKEW_SECONDS: u64 = 120;

pub(crate) async fn login(auth_path: Option<&Path>) -> anyhow::Result<()> {
    let store = CodexAuthStore::new(auth_path)?;
    let client = CodexAuthClient::new(
        Url::parse(ISSUER).expect("Codex auth issuer URL is valid"),
        Url::parse(TOKEN_URL).expect("Codex auth token URL is valid"),
    );
    let tokens = client.device_login().await?;
    store.save(&CodexAuthState::new(tokens, None))?;
    eprintln!("Codex auth saved: {}", store.path().display());
    Ok(())
}

pub(crate) fn status(auth_path: Option<&Path>) -> anyhow::Result<()> {
    let store = CodexAuthStore::new(auth_path)?;
    match store.load() {
        Ok(state) => {
            let expires_at = access_token_expires_at(&state.tokens.access_token);
            println!("logged_in: true");
            println!("auth_path: {}", store.path().display());
            println!(
                "last_refresh: {}",
                state.last_refresh.as_deref().unwrap_or("unknown")
            );
            println!(
                "refresh_token_blocked: {}",
                state.refresh_token_blocked.is_some()
            );
            if let Some(expires_at) = expires_at {
                println!("access_token_expires_at: {expires_at}");
            }
        }
        Err(CodexAuthError::Missing) => {
            println!("logged_in: false");
            println!("auth_path: {}", store.path().display());
        }
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

pub(crate) fn import_codex_cli(
    auth_path: Option<&Path>,
    source_path: Option<&Path>,
) -> anyhow::Result<()> {
    let source_path = match source_path {
        Some(path) => path.to_path_buf(),
        None => default_codex_cli_auth_path()?,
    };
    let bytes = fs::read(&source_path)
        .map_err(|err| CodexAuthError::CodexCliAuthRead(source_path.clone(), err))?;
    let value: JsonValue =
        serde_json::from_slice(&bytes).map_err(CodexAuthError::CodexCliAuthInvalidJson)?;
    let tokens = tokens_from_codex_cli_json(&value)?;
    let last_refresh = required_string(&value, "last_refresh");

    let store = CodexAuthStore::new(auth_path)?;
    store.save(&CodexAuthState::new(tokens, last_refresh))?;
    eprintln!("Codex auth imported: {}", store.path().display());
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct CodexAuthStore {
    path: PathBuf,
    #[cfg(feature = "hellas-executor")]
    token_url: Url,
}

impl CodexAuthStore {
    pub(crate) fn new(path: Option<&Path>) -> Result<Self, CodexAuthError> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => default_auth_path()?,
        };
        Ok(Self {
            path,
            #[cfg(feature = "hellas-executor")]
            token_url: Url::parse(TOKEN_URL).expect("Codex auth token URL is valid"),
        })
    }

    #[cfg(all(test, feature = "hellas-executor"))]
    pub(crate) fn with_token_url(path: PathBuf, token_url: Url) -> Self {
        Self { path, token_url }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn load(&self) -> Result<CodexAuthState, CodexAuthError> {
        self.load_unlocked()
    }

    fn load_unlocked(&self) -> Result<CodexAuthState, CodexAuthError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(CodexAuthError::InvalidJson),
            Err(err) if err.kind() == ErrorKind::NotFound => Err(CodexAuthError::Missing),
            Err(err) => Err(CodexAuthError::Io(err)),
        }
    }

    #[cfg(feature = "hellas-executor")]
    pub(crate) async fn access_token(&self) -> Result<String, CodexAuthError> {
        if !self.path.exists() {
            return Err(CodexAuthError::Missing);
        }
        let _guard = FileLock::lock(&self.path)?;
        let mut state = self.load_unlocked()?;
        if let Some(blocked) = &state.refresh_token_blocked {
            return Err(CodexAuthError::RefreshBlocked(blocked.message.clone()));
        }
        if access_token_expiring(&state.tokens.access_token, REFRESH_SKEW_SECONDS) {
            let client = http_client(AUTH_HTTP_TIMEOUT);
            let refreshed = refresh_tokens(&client, self.token_url.clone(), &state.tokens).await;
            match refreshed {
                Ok(tokens) => {
                    state.tokens = tokens;
                    state.last_refresh = Some(now_timestamp());
                    state.refresh_token_blocked = None;
                    self.save_unlocked(&state)?;
                }
                Err(err) if err.is_terminal() => {
                    state.refresh_token_blocked = Some(BlockedRefreshToken {
                        message: err.to_string(),
                        blocked_at: now_timestamp(),
                    });
                    self.save_unlocked(&state)?;
                    return Err(err);
                }
                Err(err) => return Err(err),
            }
        }
        Ok(state.tokens.access_token)
    }

    pub(crate) fn save(&self, state: &CodexAuthState) -> Result<(), CodexAuthError> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| CodexAuthError::InvalidPath(self.path.clone()))?;
        create_dir_restricted(dir).map_err(CodexAuthError::Io)?;
        let _guard = FileLock::lock(&self.path)?;
        self.save_unlocked(state)
    }

    fn save_unlocked(&self, state: &CodexAuthState) -> Result<(), CodexAuthError> {
        let bytes = serde_json::to_vec_pretty(state).map_err(CodexAuthError::Encode)?;
        atomic_write_restricted(&self.path, &bytes).map_err(CodexAuthError::Io)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CodexAuthState {
    version: u8,
    tokens: CodexTokens,
    last_refresh: Option<String>,
    refresh_token_blocked: Option<BlockedRefreshToken>,
}

impl CodexAuthState {
    pub(crate) fn new(tokens: CodexTokens, last_refresh: Option<String>) -> Self {
        Self {
            version: 1,
            tokens,
            last_refresh,
            refresh_token_blocked: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CodexTokens {
    access_token: String,
    refresh_token: String,
}

#[cfg(all(test, feature = "hellas-executor"))]
pub(crate) fn test_tokens(access_token: &str, refresh_token: &str) -> CodexTokens {
    CodexTokens {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockedRefreshToken {
    message: String,
    blocked_at: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CodexAuthError {
    #[error("no Codex credentials found; run `hellas codex-auth login`")]
    Missing,
    #[cfg(feature = "hellas-executor")]
    #[error("Codex auth refresh token is blocked: {0}")]
    RefreshBlocked(String),
    #[error("Codex auth path has no parent directory: {0}")]
    InvalidPath(PathBuf),
    #[error("Codex auth file is invalid JSON: {0}")]
    InvalidJson(serde_json::Error),
    #[error("failed to encode Codex auth file: {0}")]
    Encode(serde_json::Error),
    #[error("Codex auth IO error: {0}")]
    Io(std::io::Error),
    #[error("HOME environment variable is not set; pass --auth-path")]
    MissingHome,
    #[error("failed to read Codex CLI auth file {0}: {1}")]
    CodexCliAuthRead(PathBuf, std::io::Error),
    #[error("Codex CLI auth file is invalid JSON: {0}")]
    CodexCliAuthInvalidJson(serde_json::Error),
    #[error("Codex CLI auth file is missing tokens.access_token or tokens.refresh_token")]
    CodexCliAuthShape,
    #[error("failed to request Codex device code: {0}")]
    DeviceCodeRequest(reqwest::Error),
    #[error("Codex device auth response is invalid JSON: {0}")]
    DeviceCodeJson(serde_json::Error),
    #[error("Codex device code request returned HTTP {0}")]
    DeviceCodeStatus(reqwest::StatusCode),
    #[error("Codex device code response is missing required fields")]
    DeviceCodeShape,
    #[error("Codex login timed out")]
    DeviceCodeTimeout,
    #[error("Codex device auth polling returned HTTP {0}")]
    DevicePollStatus(reqwest::StatusCode),
    #[error("Codex device auth response is missing authorization_code or code_verifier")]
    DevicePollShape,
    #[error("Codex token exchange failed: {0}")]
    TokenExchange(reqwest::Error),
    #[error("Codex token exchange response is invalid JSON: {0}")]
    TokenExchangeJson(serde_json::Error),
    #[error("Codex token exchange returned HTTP {0}")]
    TokenExchangeStatus(reqwest::StatusCode),
    #[error("Codex token response is missing access_token")]
    TokenMissingAccessToken,
    #[error("Codex token response is missing refresh_token")]
    TokenMissingRefreshToken,
    #[cfg(feature = "hellas-executor")]
    #[error("Codex token refresh failed: {message}")]
    RefreshFailed { message: String, terminal: bool },
}

impl CodexAuthError {
    #[cfg(feature = "hellas-executor")]
    fn is_terminal(&self) -> bool {
        matches!(self, Self::RefreshFailed { terminal: true, .. })
    }
}

struct CodexAuthClient {
    http: reqwest::Client,
    issuer: Url,
    token_url: Url,
}

impl CodexAuthClient {
    fn new(issuer: Url, token_url: Url) -> Self {
        Self {
            http: http_client(AUTH_HTTP_TIMEOUT),
            issuer,
            token_url,
        }
    }

    async fn device_login(&self) -> Result<CodexTokens, CodexAuthError> {
        let device = self.request_device_code().await?;
        eprintln!("To continue, open this URL:");
        eprintln!("  {}codex/device", self.issuer);
        eprintln!("Enter this code:");
        eprintln!("  {}", device.user_code);
        eprintln!("Waiting for sign-in...");

        let exchange = self.poll_device_code(&device).await?;
        self.exchange_device_code(exchange).await
    }

    async fn request_device_code(&self) -> Result<DeviceCode, CodexAuthError> {
        let response = self
            .http
            .post(
                self.issuer
                    .join("api/accounts/deviceauth/usercode")
                    .expect("valid path"),
            )
            .header(CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({ "client_id": CLIENT_ID }))
                    .expect("valid JSON"),
            )
            .send()
            .await
            .map_err(CodexAuthError::DeviceCodeRequest)?;
        let status = response.status();
        if !status.is_success() {
            return Err(CodexAuthError::DeviceCodeStatus(status));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(CodexAuthError::DeviceCodeRequest)?;
        let value: JsonValue =
            serde_json::from_slice(&bytes).map_err(CodexAuthError::DeviceCodeJson)?;
        let user_code =
            required_string(&value, "user_code").ok_or(CodexAuthError::DeviceCodeShape)?;
        let device_auth_id =
            required_string(&value, "device_auth_id").ok_or(CodexAuthError::DeviceCodeShape)?;
        let interval = value
            .get("interval")
            .and_then(JsonValue::as_u64)
            .unwrap_or(5)
            .max(3);
        Ok(DeviceCode {
            user_code,
            device_auth_id,
            interval,
        })
    }

    async fn poll_device_code(
        &self,
        device: &DeviceCode,
    ) -> Result<DeviceExchange, CodexAuthError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(device.interval)).await;
            let response = self
                .http
                .post(
                    self.issuer
                        .join("api/accounts/deviceauth/token")
                        .expect("valid path"),
                )
                .header(CONTENT_TYPE, "application/json")
                .body(
                    serde_json::to_vec(&serde_json::json!({
                        "device_auth_id": device.device_auth_id,
                        "user_code": device.user_code,
                    }))
                    .expect("valid JSON"),
                )
                .send()
                .await
                .map_err(CodexAuthError::DeviceCodeRequest)?;
            match response.status().as_u16() {
                200 => {
                    let bytes = response
                        .bytes()
                        .await
                        .map_err(CodexAuthError::DeviceCodeRequest)?;
                    let value: JsonValue =
                        serde_json::from_slice(&bytes).map_err(CodexAuthError::DeviceCodeJson)?;
                    let authorization_code = required_string(&value, "authorization_code")
                        .ok_or(CodexAuthError::DevicePollShape)?;
                    let code_verifier = required_string(&value, "code_verifier")
                        .ok_or(CodexAuthError::DevicePollShape)?;
                    return Ok(DeviceExchange {
                        authorization_code,
                        code_verifier,
                    });
                }
                403 | 404 => {}
                _ => return Err(CodexAuthError::DevicePollStatus(response.status())),
            }
        }
        Err(CodexAuthError::DeviceCodeTimeout)
    }

    async fn exchange_device_code(
        &self,
        exchange: DeviceExchange,
    ) -> Result<CodexTokens, CodexAuthError> {
        let response = self
            .http
            .post(self.token_url.clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form_body(&[
                ("grant_type", "authorization_code"),
                ("code", exchange.authorization_code.as_str()),
                (
                    "redirect_uri",
                    "https://auth.openai.com/deviceauth/callback",
                ),
                ("client_id", CLIENT_ID),
                ("code_verifier", exchange.code_verifier.as_str()),
            ]))
            .send()
            .await
            .map_err(CodexAuthError::TokenExchange)?;
        let status = response.status();
        if !status.is_success() {
            return Err(CodexAuthError::TokenExchangeStatus(status));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(CodexAuthError::TokenExchange)?;
        let value: JsonValue =
            serde_json::from_slice(&bytes).map_err(CodexAuthError::TokenExchangeJson)?;
        tokens_from_json(value)
    }
}

struct DeviceCode {
    user_code: String,
    device_auth_id: String,
    interval: u64,
}

struct DeviceExchange {
    authorization_code: String,
    code_verifier: String,
}

#[cfg(feature = "hellas-executor")]
async fn refresh_tokens(
    client: &reqwest::Client,
    token_url: Url,
    tokens: &CodexTokens,
) -> Result<CodexTokens, CodexAuthError> {
    if tokens.refresh_token.trim().is_empty() {
        return Err(CodexAuthError::RefreshFailed {
            message: "missing refresh_token".to_string(),
            terminal: true,
        });
    }
    let response = client
        .post(token_url)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form_body(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens.refresh_token.as_str()),
            ("client_id", CLIENT_ID),
        ]))
        .send()
        .await
        .map_err(|err| CodexAuthError::RefreshFailed {
            message: err.to_string(),
            terminal: false,
        })?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let (message, terminal) = refresh_error(status, &body);
        return Err(CodexAuthError::RefreshFailed { message, terminal });
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|err| CodexAuthError::RefreshFailed {
            message: format!("body read failed: {err}"),
            terminal: false,
        })?;
    let value: JsonValue =
        serde_json::from_slice(&bytes).map_err(|err| CodexAuthError::RefreshFailed {
            message: format!("invalid JSON: {err}"),
            terminal: false,
        })?;
    let access_token =
        required_string(&value, "access_token").ok_or_else(|| CodexAuthError::RefreshFailed {
            message: "missing access_token".to_string(),
            terminal: false,
        })?;
    let refresh_token =
        required_string(&value, "refresh_token").unwrap_or_else(|| tokens.refresh_token.clone());
    Ok(CodexTokens {
        access_token,
        refresh_token,
    })
}

fn tokens_from_json(value: JsonValue) -> Result<CodexTokens, CodexAuthError> {
    let access_token =
        required_string(&value, "access_token").ok_or(CodexAuthError::TokenMissingAccessToken)?;
    let refresh_token =
        required_string(&value, "refresh_token").ok_or(CodexAuthError::TokenMissingRefreshToken)?;
    Ok(CodexTokens {
        access_token,
        refresh_token,
    })
}

fn tokens_from_codex_cli_json(value: &JsonValue) -> Result<CodexTokens, CodexAuthError> {
    let Some(tokens) = value.get("tokens") else {
        return Err(CodexAuthError::CodexCliAuthShape);
    };
    let access_token =
        required_string(tokens, "access_token").ok_or(CodexAuthError::CodexCliAuthShape)?;
    let refresh_token =
        required_string(tokens, "refresh_token").ok_or(CodexAuthError::CodexCliAuthShape)?;
    Ok(CodexTokens {
        access_token,
        refresh_token,
    })
}

#[cfg(feature = "hellas-executor")]
fn refresh_error(status: reqwest::StatusCode, body: &str) -> (String, bool) {
    let mut code = None;
    let mut message = None;
    if let Ok(JsonValue::Object(object)) = serde_json::from_str::<JsonValue>(body)
        && let Some(error) = object.get("error")
    {
        match error {
            JsonValue::String(value) => code = Some(value.clone()),
            JsonValue::Object(error) => {
                code = error
                    .get("code")
                    .or_else(|| error.get("type"))
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string);
                message = error
                    .get("message")
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string);
            }
            _ => {}
        }
        message = message.or_else(|| {
            object
                .get("error_description")
                .or_else(|| object.get("message"))
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
        });
    }

    let terminal = matches!(
        code.as_deref(),
        Some("invalid_grant" | "invalid_token" | "invalid_request" | "refresh_token_reused")
    ) || matches!(status.as_u16(), 401 | 403);
    let message = message.unwrap_or_else(|| format!("HTTP {status}"));
    (message, terminal)
}

fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", form_escape(key), form_escape(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn required_string(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[cfg(feature = "hellas-executor")]
fn access_token_expiring(token: &str, skew_seconds: u64) -> bool {
    let Some(expires_at) = access_token_expiry_seconds(token) else {
        return true;
    };
    let now = unix_seconds();
    expires_at <= now.saturating_add(skew_seconds)
}

fn access_token_expires_at(token: &str) -> Option<u64> {
    access_token_expiry_seconds(token)
}

fn access_token_expiry_seconds(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .ok()?;
    let value: JsonValue = serde_json::from_slice(&decoded).ok()?;
    value.get("exp").and_then(JsonValue::as_u64)
}

#[cfg(feature = "hellas-executor")]
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(feature = "hellas-executor")]
fn now_timestamp() -> String {
    unix_seconds().to_string()
}

fn default_auth_path() -> Result<PathBuf, CodexAuthError> {
    let home = std::env::var("HOME").map_err(|_| CodexAuthError::MissingHome)?;
    Ok(PathBuf::from(home).join(".hellas").join("codex-auth.json"))
}

fn default_codex_cli_auth_path() -> Result<PathBuf, CodexAuthError> {
    let home = std::env::var("HOME").map_err(|_| CodexAuthError::MissingHome)?;
    Ok(PathBuf::from(home).join(".codex").join("auth.json"))
}

fn create_dir_restricted(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

fn atomic_write_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "auth path has no parent directory")
    })?;
    let tmp = dir.join(format!(
        ".codex-auth.json.tmp.{}.{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    write_file_restricted(&tmp, data)?;
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            Err(err)
        }
    }
}

fn write_file_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)
    }
}

struct FileLock {
    #[cfg(unix)]
    file: fs::File,
}

impl FileLock {
    fn lock(path: &Path) -> Result<Self, CodexAuthError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            let lock_path = path.with_extension("lock");
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .open(lock_path)
                .map_err(CodexAuthError::Io)?;
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if result != 0 {
                return Err(CodexAuthError::Io(std::io::Error::last_os_error()));
            }
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(Self {})
        }
    }
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "hellas-executor")]
    use axum::Router;
    #[cfg(feature = "hellas-executor")]
    use axum::extract::State;
    #[cfg(feature = "hellas-executor")]
    use axum::routing::post;
    #[cfg(feature = "hellas-executor")]
    use serde_json::json;
    #[cfg(feature = "hellas-executor")]
    use std::sync::Arc;

    #[test]
    fn parses_jwt_expiry() {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        let token = format!("x.{payload}.y");
        assert_eq!(access_token_expires_at(&token), Some(4102444800));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = CodexAuthStore::new(Some(&dir.path().join("codex-auth.json"))).unwrap();
        let state = CodexAuthState::new(
            CodexTokens {
                access_token: "access".to_string(),
                refresh_token: "refresh".to_string(),
            },
            Some("1".to_string()),
        );

        store.save(&state).unwrap();
        let loaded = store.load().unwrap();

        assert_eq!(loaded.tokens.access_token, "access");
        assert_eq!(loaded.tokens.refresh_token, "refresh");
        assert_eq!(loaded.last_refresh.as_deref(), Some("1"));
    }

    #[test]
    fn import_codex_cli_auth_extracts_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("codex-cli-auth.json");
        fs::write(
            &source_path,
            serde_json::to_vec(&serde_json::json!({
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": null,
                "tokens": {
                    "id_token": "ignored",
                    "access_token": "access",
                    "refresh_token": "refresh",
                    "account_id": "ignored"
                },
                "last_refresh": "123"
            }))
            .unwrap(),
        )
        .unwrap();

        let target_path = dir.path().join("hellas-codex-auth.json");
        import_codex_cli(Some(&target_path), Some(&source_path)).unwrap();
        let loaded = CodexAuthStore::new(Some(&target_path))
            .unwrap()
            .load()
            .unwrap();

        assert_eq!(loaded.tokens.access_token, "access");
        assert_eq!(loaded.tokens.refresh_token, "refresh");
        assert_eq!(loaded.last_refresh.as_deref(), Some("123"));
    }

    #[cfg(feature = "hellas-executor")]
    #[tokio::test]
    async fn refresh_rotates_tokens() {
        #[derive(Clone)]
        struct Capture(Arc<tokio::sync::Mutex<Option<String>>>);

        async fn token(State(capture): State<Capture>, body: String) -> axum::Json<JsonValue> {
            *capture.0.lock().await = Some(body);
            axum::Json(json!({
                "access_token": "new.access.token",
                "refresh_token": "new-refresh"
            }))
        }

        let capture = Capture(Arc::new(tokio::sync::Mutex::new(None)));
        let app = Router::new()
            .route("/token", post(token))
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let store = CodexAuthStore::with_token_url(
            dir.path().join("codex-auth.json"),
            Url::parse(&format!("http://{addr}/token")).unwrap(),
        );
        store
            .save(&CodexAuthState::new(
                CodexTokens {
                    access_token: "expired".to_string(),
                    refresh_token: "old-refresh".to_string(),
                },
                None,
            ))
            .unwrap();

        let access = store.access_token().await.unwrap();
        assert_eq!(access, "new.access.token");
        let body = capture.0.lock().await.clone().unwrap();
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=old-refresh"));
        assert!(body.contains("client_id=app_EMoamEEZ73f0CkXaXp7hrann"));
    }

    #[cfg(feature = "hellas-executor")]
    #[tokio::test]
    async fn terminal_refresh_error_blocks_token() {
        async fn token() -> (axum::http::StatusCode, axum::Json<JsonValue>) {
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(json!({"error":"invalid_grant"})),
            )
        }

        let app = Router::new().route("/token", post(token));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let store = CodexAuthStore::with_token_url(
            dir.path().join("codex-auth.json"),
            Url::parse(&format!("http://{addr}/token")).unwrap(),
        );
        store
            .save(&CodexAuthState::new(
                CodexTokens {
                    access_token: "expired".to_string(),
                    refresh_token: "old-refresh".to_string(),
                },
                None,
            ))
            .unwrap();

        assert!(store.access_token().await.is_err());
        assert!(store.load().unwrap().refresh_token_blocked.is_some());
    }

    #[cfg(feature = "hellas-executor")]
    #[tokio::test]
    async fn malformed_refresh_success_is_retryable() {
        async fn token() -> axum::Json<JsonValue> {
            axum::Json(json!({"refresh_token":"new-refresh"}))
        }

        let app = Router::new().route("/token", post(token));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let store = CodexAuthStore::with_token_url(
            dir.path().join("codex-auth.json"),
            Url::parse(&format!("http://{addr}/token")).unwrap(),
        );
        store
            .save(&CodexAuthState::new(
                CodexTokens {
                    access_token: "expired".to_string(),
                    refresh_token: "old-refresh".to_string(),
                },
                None,
            ))
            .unwrap();

        assert!(store.access_token().await.is_err());
        assert!(store.load().unwrap().refresh_token_blocked.is_none());
    }
}
