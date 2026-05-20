use crate::config::SecurityConfig;
use crate::error::JwtError;
use http::HeaderMap;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, TokenData, Validation};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct JwtValidator {
    keys: Vec<JwtKey>,
    issuer: Option<String>,
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

impl JwtValidator {
    pub async fn from_config(config: &SecurityConfig) -> Result<Self, JwtError> {
        let jwks_uri = match &config.jwk_set_uri {
            Some(uri) => uri.clone(),
            None => discover_jwks_uri(config).await?,
        };

        Self::from_jwks_uri(&jwks_uri, config.issuer_uri.clone()).await
    }

    pub async fn from_jwks_uri(jwks_uri: &str, issuer: Option<String>) -> Result<Self, JwtError> {
        let body = reqwest::get(jwks_uri)
            .await
            .map_err(JwtError::JwksFetch)?
            .text()
            .await
            .map_err(JwtError::JwksFetch)?;
        Self::from_jwk_set_str(&body, issuer)
    }

    pub fn from_jwk_set_str(jwk_set_json: &str, issuer: Option<String>) -> Result<Self, JwtError> {
        let jwk_set: JwkSet = serde_json::from_str(jwk_set_json).map_err(JwtError::JwksParse)?;
        Self::from_jwk_set(jwk_set, issuer)
    }

    pub fn from_jwk_set(jwk_set: JwkSet, issuer: Option<String>) -> Result<Self, JwtError> {
        let keys = jwk_set
            .keys
            .into_iter()
            .filter_map(|jwk| jwk_to_key(jwk).ok())
            .collect::<Vec<_>>();

        if keys.is_empty() {
            return Err(JwtError::NoMatchingKey);
        }

        Ok(Self { keys, issuer })
    }

    pub fn from_decoding_key(
        key_id: Option<String>,
        decoding_key: DecodingKey,
        issuer: Option<String>,
    ) -> Self {
        Self {
            keys: vec![JwtKey {
                key_id,
                decoding_key,
            }],
            issuer,
        }
    }

    pub fn validate(&self, token: &str) -> Result<Value, JwtError> {
        let header = decode_header(token).map_err(JwtError::Header)?;
        let mut saw_matching_key = false;
        let mut last_validation_error = None;
        let matching_keys = self
            .keys
            .iter()
            .filter(|key| match (&header.kid, &key.key_id) {
                (Some(token_kid), Some(key_kid)) => token_kid == key_kid,
                (Some(_), None) => false,
                (None, _) => true,
            });

        for key in matching_keys {
            let mut validation = Validation::new(header.alg);
            validation.validate_aud = false;
            if let Some(issuer) = &self.issuer {
                validation.set_issuer(&[issuer]);
            }

            let decoded: Result<TokenData<Value>, _> =
                decode(token, &key.decoding_key, &validation);
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

fn jwk_to_key(jwk: Jwk) -> Result<JwtKey, jsonwebtoken::errors::Error> {
    let key_id = jwk.common.key_id.clone();
    let decoding_key = DecodingKey::from_jwk(&jwk)?;
    Ok(JwtKey {
        key_id,
        decoding_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

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
    async fn from_config_requires_jwks_or_issuer() {
        let error = JwtValidator::from_config(&SecurityConfig::default())
            .await
            .unwrap_err();

        assert!(matches!(error, JwtError::MissingJwksUri));
    }
}
