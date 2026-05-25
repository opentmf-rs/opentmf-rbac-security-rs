use crate::config::SecurityConfig;
use crate::error::JwtError;
use http::HeaderMap;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, Header, TokenData, Validation};
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderValue as ReqwestHeaderValue};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct JwtValidator {
    inner: Arc<JwtValidatorInner>,
}

#[derive(Debug)]
struct JwtValidatorInner {
    issuer: Option<String>,
    state: RwLock<JwksState>,
    remote: Option<RemoteJwks>,
    refresh_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
struct RemoteJwks {
    jwks_uri: String,
    client: reqwest::Client,
    refresh_interval: Duration,
    max_stale: Duration,
}

#[derive(Debug, Clone)]
struct JwksState {
    keys: Vec<JwtKey>,
    last_success_at: Instant,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct JwtKey {
    key_id: Option<String>,
    decoding_key: DecodingKey,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    jwks_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwksHealth {
    pub status: &'static str,
    pub detail: String,
    pub key_count: usize,
    pub seconds_since_success: u64,
    pub last_error: Option<String>,
}

impl JwksHealth {
    pub fn is_up(&self) -> bool {
        self.status == "UP"
    }
}

impl JwtValidator {
    pub async fn from_config(config: &SecurityConfig) -> Result<Self, JwtError> {
        let jwks_uri = match &config.jwk_set_uri {
            Some(uri) => uri.clone(),
            None => discover_jwks_uri(config).await?,
        };

        Self::from_jwks_uri_with_options(
            &jwks_uri,
            config.issuer_uri.clone(),
            config.jwks_refresh_interval,
            config.jwks_max_stale,
            config.jwks_request_timeout,
            config.jwks_accept_invalid_certs,
        )
        .await
    }

    pub async fn from_jwks_uri(jwks_uri: &str, issuer: Option<String>) -> Result<Self, JwtError> {
        Self::from_jwks_uri_with_options(
            jwks_uri,
            issuer,
            Duration::from_secs(300),
            Duration::from_secs(3600),
            Duration::from_secs(5),
            false,
        )
        .await
    }

    pub async fn from_jwks_uri_with_options(
        jwks_uri: &str,
        issuer: Option<String>,
        refresh_interval: Duration,
        max_stale: Duration,
        request_timeout: Duration,
        accept_invalid_certs: bool,
    ) -> Result<Self, JwtError> {
        if accept_invalid_certs {
            warn!(
                jwks_uri = %sanitize_uri(jwks_uri),
                "JWKS TLS certificate verification is disabled; use only as a temporary non-production workaround"
            );
        }
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()
            .map_err(JwtError::JwksFetch)?;
        let remote = RemoteJwks {
            jwks_uri: jwks_uri.to_string(),
            client,
            refresh_interval,
            max_stale,
        };
        info!(
            jwks_uri = %sanitize_uri(jwks_uri),
            "Fetching JWKS during RBAC startup"
        );
        let keys = fetch_keys(&remote).await?;
        let now = Instant::now();
        info!(
            jwks_uri = %sanitize_uri(jwks_uri),
            key_count = keys.len(),
            refresh_after_seconds = refresh_interval.as_secs(),
            "JWKS startup fetch completed"
        );
        let validator = Self {
            inner: Arc::new(JwtValidatorInner {
                issuer,
                state: RwLock::new(JwksState {
                    keys,
                    last_success_at: now,
                    last_error: None,
                }),
                remote: Some(remote),
                refresh_lock: Mutex::new(()),
            }),
        };
        validator.spawn_refresh_task();
        Ok(validator)
    }

    pub fn from_jwk_set_str(jwk_set_json: &str, issuer: Option<String>) -> Result<Self, JwtError> {
        let jwk_set: JwkSet = serde_json::from_str(jwk_set_json).map_err(JwtError::JwksParse)?;
        Self::from_jwk_set(jwk_set, issuer)
    }

    pub fn from_jwk_set(jwk_set: JwkSet, issuer: Option<String>) -> Result<Self, JwtError> {
        let keys = jwk_set_to_keys(jwk_set)?;
        Ok(Self::from_keys(keys, issuer, None))
    }

    fn from_keys(keys: Vec<JwtKey>, issuer: Option<String>, remote: Option<RemoteJwks>) -> Self {
        let now = Instant::now();
        Self {
            inner: Arc::new(JwtValidatorInner {
                issuer,
                state: RwLock::new(JwksState {
                    keys,
                    last_success_at: now,
                    last_error: None,
                }),
                remote,
                refresh_lock: Mutex::new(()),
            }),
        }
    }

    pub fn from_decoding_key(
        key_id: Option<String>,
        decoding_key: DecodingKey,
        issuer: Option<String>,
    ) -> Self {
        Self::from_keys(
            vec![JwtKey {
                key_id,
                decoding_key,
            }],
            issuer,
            None,
        )
    }

    pub fn validate(&self, token: &str) -> Result<Value, JwtError> {
        let header = decode_header(token).map_err(JwtError::Header)?;
        let state = self.inner.state.read().expect("JWKS state lock poisoned");
        self.ensure_not_stale(&state)?;
        debug!(
            key_count = state.keys.len(),
            "Validating JWT with cached JWKS"
        );
        validate_with_keys(&state.keys, &self.inner.issuer, token, &header)
    }

    pub async fn validate_async(&self, token: &str) -> Result<Value, JwtError> {
        let header = decode_header(token).map_err(JwtError::Header)?;
        {
            let state = self.inner.state.read().expect("JWKS state lock poisoned");
            self.ensure_not_stale(&state)?;
            debug!(
                key_count = state.keys.len(),
                "Validating JWT with cached JWKS"
            );
            match validate_with_keys(&state.keys, &self.inner.issuer, token, &header) {
                Ok(claims) => return Ok(claims),
                Err(JwtError::NoMatchingKey)
                    if header.kid.is_some() && self.inner.remote.is_some() => {}
                Err(error) => return Err(error),
            }
        }

        warn!(
            kid = header.kid.as_deref().unwrap_or("<none>"),
            "JWT kid was not found in cache; refreshing JWKS and retrying once"
        );
        self.refresh_now("unknown-kid").await?;
        let state = self.inner.state.read().expect("JWKS state lock poisoned");
        self.ensure_not_stale(&state)?;
        validate_with_keys(&state.keys, &self.inner.issuer, token, &header)
    }

    pub async fn refresh_now(&self, reason: &'static str) -> Result<(), JwtError> {
        let Some(remote) = self.inner.remote.clone() else {
            return Ok(());
        };
        let _guard = self.inner.refresh_lock.lock().await;
        info!(
            jwks_uri = %sanitize_uri(&remote.jwks_uri),
            reason,
            "Refreshing JWKS"
        );
        match fetch_keys(&remote).await {
            Ok(keys) => {
                let key_count = keys.len();
                let now = Instant::now();
                let mut state = self.inner.state.write().expect("JWKS state lock poisoned");
                state.keys = keys;
                state.last_success_at = now;
                state.last_error = None;
                info!(
                    jwks_uri = %sanitize_uri(&remote.jwks_uri),
                    key_count,
                    next_refresh_seconds = remote.refresh_interval.as_secs(),
                    "JWKS refresh completed"
                );
                Ok(())
            }
            Err(error) => {
                let mut state = self.inner.state.write().expect("JWKS state lock poisoned");
                state.last_error = Some(error.to_string());
                let age = state.last_success_at.elapsed();
                warn!(
                    jwks_uri = %sanitize_uri(&remote.jwks_uri),
                    error = %error,
                    seconds_since_success = age.as_secs(),
                    usable = age <= remote.max_stale,
                    "JWKS refresh failed"
                );
                Err(error)
            }
        }
    }

    pub fn health(&self) -> JwksHealth {
        let state = self.inner.state.read().expect("JWKS state lock poisoned");
        let seconds_since_success = state.last_success_at.elapsed().as_secs();
        match &self.inner.remote {
            Some(remote) if state.keys.is_empty() => JwksHealth {
                status: "DOWN",
                detail: format!("JWKS cache is empty for {}", sanitize_uri(&remote.jwks_uri)),
                key_count: 0,
                seconds_since_success,
                last_error: state.last_error.clone(),
            },
            Some(remote) if state.last_success_at.elapsed() > remote.max_stale => JwksHealth {
                status: "DOWN",
                detail: format!(
                    "JWKS cache is stale for {}; last success {} seconds ago",
                    sanitize_uri(&remote.jwks_uri),
                    seconds_since_success
                ),
                key_count: state.keys.len(),
                seconds_since_success,
                last_error: state.last_error.clone(),
            },
            Some(remote) => JwksHealth {
                status: "UP",
                detail: format!(
                    "JWKS cache has {} keys from {}; last success {} seconds ago",
                    state.keys.len(),
                    sanitize_uri(&remote.jwks_uri),
                    seconds_since_success
                ),
                key_count: state.keys.len(),
                seconds_since_success,
                last_error: state.last_error.clone(),
            },
            None => JwksHealth {
                status: "UP",
                detail: format!("static JWT key set has {} keys", state.keys.len()),
                key_count: state.keys.len(),
                seconds_since_success,
                last_error: None,
            },
        }
    }

    fn spawn_refresh_task(&self) {
        let Some(remote) = self.inner.remote.clone() else {
            return;
        };
        let validator = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(remote.refresh_interval).await;
                let _ = validator.refresh_now("scheduled").await;
            }
        });
    }

    fn ensure_not_stale(&self, state: &JwksState) -> Result<(), JwtError> {
        let Some(remote) = &self.inner.remote else {
            return Ok(());
        };
        let age = state.last_success_at.elapsed();
        if age > remote.max_stale {
            return Err(JwtError::JwksStale(format!(
                "last successful refresh for {} was {} seconds ago",
                sanitize_uri(&remote.jwks_uri),
                age.as_secs()
            )));
        }
        Ok(())
    }
}

fn validate_with_keys(
    keys: &[JwtKey],
    issuer: &Option<String>,
    token: &str,
    header: &Header,
) -> Result<Value, JwtError> {
    let mut saw_matching_key = false;
    let mut last_validation_error = None;
    let matching_keys = keys.iter().filter(|key| match (&header.kid, &key.key_id) {
        (Some(token_kid), Some(key_kid)) => token_kid == key_kid,
        (Some(_), None) => false,
        (None, _) => true,
    });

    for key in matching_keys {
        let mut validation = Validation::new(header.alg);
        validation.validate_aud = false;
        if let Some(issuer) = issuer {
            validation.set_issuer(&[issuer]);
        }

        let decoded: Result<TokenData<Value>, _> = decode(token, &key.decoding_key, &validation);
        saw_matching_key = true;
        if let Ok(decoded) = decoded {
            return Ok(decoded.claims);
        } else if let Err(error) = decoded {
            last_validation_error = Some(error);
        }
    }

    match (saw_matching_key, last_validation_error) {
        (true, Some(error)) => Err(JwtError::Validation(error)),
        _ => Err(JwtError::NoMatchingKey),
    }
}

pub fn bearer_token(headers: &HeaderMap) -> Result<&str, JwtError> {
    let value = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(JwtError::MissingBearerToken)?;

    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .filter(|token| !token.is_empty())
        .ok_or(JwtError::MissingBearerToken)
}

async fn discover_jwks_uri(config: &SecurityConfig) -> Result<String, JwtError> {
    let issuer = config.issuer_uri.as_ref().ok_or(JwtError::MissingJwksUri)?;
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let document = reqwest::get(discovery_url)
        .await
        .map_err(JwtError::DiscoveryFetch)?
        .json::<DiscoveryDocument>()
        .await
        .map_err(JwtError::DiscoveryFetch)?;
    document.jwks_uri.ok_or(JwtError::MissingJwksUri)
}

async fn fetch_keys(remote: &RemoteJwks) -> Result<Vec<JwtKey>, JwtError> {
    let request = remote
        .client
        .get(&remote.jwks_uri)
        .build()
        .map_err(JwtError::JwksFetch)?;
    debug!(
        method = %request.method(),
        jwks_uri = %sanitize_uri(request.url().as_str()),
        request_headers = %sanitized_headers(request.headers()),
        request_body = "<empty>",
        "JWKS HTTP request prepared"
    );

    let response = remote
        .client
        .execute(request)
        .await
        .map_err(JwtError::JwksFetch)?;
    let status = response.status();
    let response_headers = sanitized_headers(response.headers());

    let status_error = response.error_for_status_ref().err();
    let body = response.text().await.map_err(JwtError::JwksFetch)?;
    let preview = body_preview(&body, 4096);
    debug!(
        status = status.as_u16(),
        response_headers = %response_headers,
        response_body_preview = %preview.preview,
        response_body_truncated = preview.truncated,
        "JWKS HTTP response received"
    );

    if let Some(error) = status_error {
        return Err(JwtError::JwksFetch(error));
    }

    let jwk_set: JwkSet = serde_json::from_str(&body).map_err(JwtError::JwksParse)?;
    jwk_set_to_keys(jwk_set)
}

fn jwk_set_to_keys(jwk_set: JwkSet) -> Result<Vec<JwtKey>, JwtError> {
    let keys = jwk_set
        .keys
        .into_iter()
        .filter_map(|jwk| jwk_to_key(jwk).ok())
        .collect::<Vec<_>>();

    if keys.is_empty() {
        return Err(JwtError::NoMatchingKey);
    }

    Ok(keys)
}

fn jwk_to_key(jwk: Jwk) -> Result<JwtKey, jsonwebtoken::errors::Error> {
    let key_id = jwk.common.key_id.clone();
    let decoding_key = DecodingKey::from_jwk(&jwk)?;
    Ok(JwtKey {
        key_id,
        decoding_key,
    })
}

fn sanitize_uri(uri: &str) -> String {
    reqwest::Url::parse(uri)
        .map(|url| {
            let mut sanitized = String::new();
            sanitized.push_str(url.scheme());
            sanitized.push_str("://");
            if let Some(host) = url.host_str() {
                sanitized.push_str(host);
            }
            sanitized.push_str(url.path());
            sanitized
        })
        .unwrap_or_else(|_| "<invalid-jwks-uri>".to_string())
}

fn sanitized_headers(headers: &ReqwestHeaderMap) -> Value {
    let mut values = Map::new();

    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let value = sanitized_header_value(&name, value);

        match values.get_mut(&name) {
            Some(Value::Array(existing)) => existing.push(value),
            Some(existing) => {
                let first = std::mem::replace(existing, Value::Null);
                *existing = Value::Array(vec![first, value]);
            }
            None => {
                values.insert(name, value);
            }
        }
    }

    Value::Object(values)
}

fn sanitized_header_value(name: &str, value: &ReqwestHeaderValue) -> Value {
    if is_sensitive_header_name(name) {
        return Value::String("<redacted>".to_string());
    }

    match value.to_str() {
        Ok(value) => Value::String(value.to_string()),
        Err(_) => Value::String("<non-utf8>".to_string()),
    }
}

fn is_sensitive_header_name(name: &str) -> bool {
    const SENSITIVE_PATTERNS: &[&str] = &[
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
        "cookie",
        "api-key",
        "apikey",
        "session",
        "jwt",
        "bearer",
        "csrf",
        "xsrf",
    ];

    let name = name.to_ascii_lowercase();
    SENSITIVE_PATTERNS
        .iter()
        .any(|pattern| name.contains(pattern))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BodyPreview {
    preview: String,
    truncated: bool,
}

fn body_preview(body: &str, max_bytes: usize) -> BodyPreview {
    if body.len() <= max_bytes {
        return BodyPreview {
            preview: body.to_string(),
            truncated: false,
        };
    }

    let mut end = max_bytes;
    while !body.is_char_boundary(end) {
        end -= 1;
    }

    BodyPreview {
        preview: body[..end].to_string(),
        truncated: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::axum::routing::get;
    use ::axum::Router;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::sync::{Arc, RwLock as StdRwLock};
    use std::time::Duration;

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer abc.def.ghi".parse().unwrap(),
        );

        assert_eq!(bearer_token(&headers).unwrap(), "abc.def.ghi");
    }

    #[test]
    fn extracts_lowercase_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "bearer abc.def.ghi".parse().unwrap(),
        );

        assert_eq!(bearer_token(&headers).unwrap(), "abc.def.ghi");
    }

    #[test]
    fn rejects_missing_malformed_and_empty_bearer_tokens() {
        let headers = HeaderMap::new();
        assert!(matches!(
            bearer_token(&headers),
            Err(JwtError::MissingBearerToken)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(matches!(
            bearer_token(&headers),
            Err(JwtError::MissingBearerToken)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert!(matches!(
            bearer_token(&headers),
            Err(JwtError::MissingBearerToken)
        ));
    }

    #[test]
    fn validates_token_with_static_decoding_key() {
        let secret = b"test-secret";
        let validator =
            JwtValidator::from_decoding_key(None, DecodingKey::from_secret(secret), None);
        let mut header = Header::new(Algorithm::HS256);
        header.kid = None;
        let token = encode(
            &header,
            &json!({"sub": "user-1", "roles": ["admin"], "exp": 4_102_444_800i64}),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let claims = validator.validate(&token).unwrap();

        assert_eq!(claims["sub"], "user-1");
    }

    #[test]
    fn reports_static_jwks_health() {
        let validator =
            JwtValidator::from_decoding_key(None, DecodingKey::from_secret(b"secret"), None);

        let health = validator.health();

        assert!(health.is_up());
        assert_eq!(health.key_count, 1);
    }

    #[test]
    fn reports_validation_errors_for_matching_keys() {
        let validator =
            JwtValidator::from_decoding_key(None, DecodingKey::from_secret(b"right-secret"), None);
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({"sub": "user-1", "exp": 4_102_444_800i64}),
            &EncodingKey::from_secret(b"wrong-secret"),
        )
        .unwrap();

        assert!(matches!(
            validator.validate(&token),
            Err(JwtError::Validation(_))
        ));
    }

    #[test]
    fn invalid_jwt_header_is_reported() {
        let validator =
            JwtValidator::from_decoding_key(None, DecodingKey::from_secret(b"secret"), None);

        assert!(matches!(
            validator.validate("not-a-token"),
            Err(JwtError::Header(_))
        ));
    }

    #[test]
    fn token_kid_mismatch_returns_no_matching_key() {
        let validator = JwtValidator::from_decoding_key(
            Some("expected-key".into()),
            DecodingKey::from_secret(b"secret"),
            None,
        );
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("other-key".into());
        let token = encode(
            &header,
            &json!({"sub": "user-1", "exp": 4_102_444_800i64}),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        assert!(matches!(
            validator.validate(&token),
            Err(JwtError::NoMatchingKey)
        ));
    }

    #[test]
    fn token_without_kid_can_use_available_key() {
        let validator = JwtValidator::from_decoding_key(
            Some("expected-key".into()),
            DecodingKey::from_secret(b"secret"),
            None,
        );
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({"sub": "user-1", "exp": 4_102_444_800i64}),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let claims = validator.validate(&token).unwrap();

        assert_eq!(claims["sub"], "user-1");
    }

    #[test]
    fn issuer_validation_accepts_matching_issuer() {
        let validator = JwtValidator::from_decoding_key(
            None,
            DecodingKey::from_secret(b"secret"),
            Some("https://issuer.example.com".into()),
        );
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "exp": 4_102_444_800i64
            }),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let claims = validator.validate(&token).unwrap();

        assert_eq!(claims["iss"], "https://issuer.example.com");
    }

    #[test]
    fn issuer_validation_rejects_wrong_issuer() {
        let validator = JwtValidator::from_decoding_key(
            None,
            DecodingKey::from_secret(b"secret"),
            Some("https://issuer.example.com".into()),
        );
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({
                "iss": "https://other-issuer.example.com",
                "sub": "user-1",
                "exp": 4_102_444_800i64
            }),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        assert!(matches!(
            validator.validate(&token),
            Err(JwtError::Validation(_))
        ));
    }

    #[test]
    fn jwk_set_string_reports_parse_and_empty_key_errors() {
        assert!(matches!(
            JwtValidator::from_jwk_set_str("not-json", None),
            Err(JwtError::JwksParse(_))
        ));

        assert!(matches!(
            JwtValidator::from_jwk_set_str(r#"{"keys":[]}"#, None),
            Err(JwtError::NoMatchingKey)
        ));
    }

    #[tokio::test]
    async fn unknown_kid_refreshes_jwks_and_retries_validation() {
        let jwks = Arc::new(StdRwLock::new(oct_jwks("kid-1", "c2VjcmV0LW9uZQ")));
        let jwks_url = spawn_jwks_server(Arc::clone(&jwks)).await;
        let validator = JwtValidator::from_jwks_uri_with_options(
            &jwks_url,
            None,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::from_secs(5),
            false,
        )
        .await
        .unwrap();

        *jwks.write().unwrap() = oct_jwks("kid-2", "c2VjcmV0LXR3bw");
        let token = token_with_kid("kid-2", b"secret-two");

        let claims = validator.validate_async(&token).await.unwrap();

        assert_eq!(claims["sub"], "user-1");
        assert_eq!(validator.health().key_count, 1);
        assert!(validator.health().is_up());
    }

    #[tokio::test]
    async fn failed_refresh_keeps_last_known_good_keys_healthy_until_stale() {
        let jwks = Arc::new(StdRwLock::new(oct_jwks("kid-1", "c2VjcmV0LW9uZQ")));
        let jwks_url = spawn_jwks_server(Arc::clone(&jwks)).await;
        let validator = JwtValidator::from_jwks_uri_with_options(
            &jwks_url,
            None,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::from_secs(5),
            false,
        )
        .await
        .unwrap();

        *jwks.write().unwrap() = "not-json".to_string();
        let error = validator.refresh_now("test").await.unwrap_err();

        assert!(matches!(error, JwtError::JwksParse(_)));
        let health = validator.health();
        assert!(health.is_up());
        assert_eq!(health.key_count, 1);
        assert!(health.last_error.is_some());
    }

    #[tokio::test]
    async fn stale_cache_reports_down_and_rejects_validation() {
        let jwks = Arc::new(StdRwLock::new(oct_jwks("kid-1", "c2VjcmV0LW9uZQ")));
        let jwks_url = spawn_jwks_server(Arc::clone(&jwks)).await;
        let validator = JwtValidator::from_jwks_uri_with_options(
            &jwks_url,
            None,
            Duration::from_secs(3600),
            Duration::from_secs(1),
            Duration::from_secs(5),
            false,
        )
        .await
        .unwrap();
        {
            let mut state = validator
                .inner
                .state
                .write()
                .expect("JWKS state lock poisoned");
            state.last_success_at = Instant::now() - Duration::from_secs(2);
        }
        let token = token_with_kid("kid-1", b"secret-one");

        let health = validator.health();
        let error = validator.validate_async(&token).await.unwrap_err();

        assert!(!health.is_up());
        assert!(matches!(error, JwtError::JwksStale(_)));
    }

    #[tokio::test]
    async fn from_config_requires_jwks_or_issuer() {
        let error = JwtValidator::from_config(&SecurityConfig::default())
            .await
            .unwrap_err();

        assert!(matches!(error, JwtError::MissingJwksUri));
    }

    fn token_with_kid(kid: &str, secret: &[u8]) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &json!({"sub": "user-1", "roles": ["admin"], "exp": 4_102_444_800i64}),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn oct_jwks(kid: &str, secret_base64_url: &str) -> String {
        json!({
            "keys": [{
                "kty": "oct",
                "kid": kid,
                "alg": "HS256",
                "k": secret_base64_url
            }]
        })
        .to_string()
    }

    #[test]
    fn redacts_sensitive_jwks_http_headers_by_pattern() {
        let mut headers = ReqwestHeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            "Bearer secret-token".parse().unwrap(),
        );
        headers.insert("x-api-key", "secret".parse().unwrap());
        headers.insert("x-session-id", "session".parse().unwrap());
        headers.insert(reqwest::header::ACCEPT, "application/json".parse().unwrap());

        let sanitized = sanitized_headers(&headers);

        assert_eq!(sanitized["authorization"], "<redacted>");
        assert_eq!(sanitized["x-api-key"], "<redacted>");
        assert_eq!(sanitized["x-session-id"], "<redacted>");
        assert_eq!(sanitized["accept"], "application/json");
    }

    #[test]
    fn body_preview_is_bounded_and_utf8_safe() {
        let body = "abc-şğü";
        let preview = body_preview(body, 6);

        assert_eq!(preview.preview, "abc-ş");
        assert!(preview.truncated);

        let full = body_preview(body, 1024);
        assert_eq!(full.preview, body);
        assert!(!full.truncated);
    }

    async fn spawn_jwks_server(jwks: Arc<StdRwLock<String>>) -> String {
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let jwks = Arc::clone(&jwks);
                async move { jwks.read().unwrap().clone() }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = ::axum::serve(listener, app).await;
        });
        format!("http://{addr}/jwks")
    }
}
