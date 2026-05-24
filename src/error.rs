use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing both jwk-set-uri and issuer-uri")]
    MissingJwksConfiguration,
    #[error("endpoint path must start with '/': {0}")]
    InvalidPath(String),
    #[error("failed to parse YAML config: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("authorization header is missing or is not a bearer token")]
    MissingBearerToken,
    #[error("failed to fetch OIDC discovery document: {0}")]
    DiscoveryFetch(reqwest::Error),
    #[error("OIDC discovery document does not contain jwks_uri")]
    MissingJwksUri,
    #[error("failed to fetch JWK set: {0}")]
    JwksFetch(reqwest::Error),
    #[error("failed to parse JWK set: {0}")]
    JwksParse(serde_json::Error),
    #[error("token header could not be decoded: {0}")]
    Header(jsonwebtoken::errors::Error),
    #[error("no usable JWK matched the token header")]
    NoMatchingKey,
    #[error("JWK set is stale: {0}")]
    JwksStale(String),
    #[error("token validation failed: {0}")]
    Validation(jsonwebtoken::errors::Error),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("request requires authentication")]
    Unauthorized,
    #[error("request is forbidden")]
    Forbidden,
    #[error("principal could not be built from JWT claims")]
    MissingPrincipal,
    #[error(transparent)]
    Jwt(#[from] JwtError),
}
