use crate::config::SecurityConfig;
use crate::error::AuthError;
use crate::jwt::{bearer_token, JwtValidator};
use crate::policy::{PolicyDecision, PolicyRequirement, SecurityPolicy};
use crate::principal::Principal;
use ::axum::body::Body;
use ::axum::http::{Request, StatusCode};
use ::axum::response::{IntoResponse, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct OpenTmfSecurityLayer {
    policy: Arc<SecurityPolicy>,
    validator: Arc<JwtValidator>,
}

impl OpenTmfSecurityLayer {
    pub fn new(config: SecurityConfig, validator: JwtValidator) -> Self {
        Self {
            policy: Arc::new(SecurityPolicy::new(config)),
            validator: Arc::new(validator),
        }
    }

    pub async fn from_config(config: SecurityConfig) -> Result<Self, crate::JwtError> {
        let validator = JwtValidator::from_config(&config).await?;
        Ok(Self::new(config, validator))
    }

    pub fn jwks_health(&self) -> crate::jwt::JwksHealth {
        self.validator.health()
    }
}

impl<S> Layer<S> for OpenTmfSecurityLayer {
    type Service = OpenTmfSecurityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OpenTmfSecurityService {
            inner,
            policy: Arc::clone(&self.policy),
            validator: Arc::clone(&self.validator),
        }
    }
}

#[derive(Clone)]
pub struct OpenTmfSecurityService<S> {
    inner: S,
    policy: Arc<SecurityPolicy>,
    validator: Arc<JwtValidator>,
}

impl<S> Service<Request<Body>> for OpenTmfSecurityService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let policy = Arc::clone(&self.policy);
        let validator = Arc::clone(&self.validator);

        let method = req.method().clone();
        let path = req.uri().path().to_string();

        Box::pin(async move {
            let requirement = policy.requirement(&method, &path);
            debug!(
                method = %method,
                path = %path,
                requirement = ?requirement,
                "Security policy requirement determined"
            );

            if requirement == PolicyRequirement::PermitAll {
                debug!("Permitting request without authentication");
                return inner.call(req).await;
            }
            if requirement == PolicyRequirement::DenyAll {
                warn!(method = %method, path = %path, "Request denied by policy");
                return Ok(error_response(AuthError::Forbidden));
            }

            let token = match bearer_token(req.headers()) {
                Ok(token) => token,
                Err(e) => {
                    warn!(
                        method = %method,
                        path = %path,
                        error = ?e,
                        "Missing or invalid bearer token"
                    );
                    return Ok(error_response(AuthError::Unauthorized));
                }
            };

            let claims = match validator.validate_async(token).await {
                Ok(claims) => {
                    debug!("JWT token validated successfully");
                    claims
                }
                Err(error) => {
                    warn!(
                        method = %method,
                        path = %path,
                        error = ?error,
                        "JWT validation failed"
                    );
                    return Ok(error_response(AuthError::Jwt(error)));
                }
            };

            let principal = match Principal::from_claims(claims, policy.config()) {
                Some(principal) => {
                    debug!("Principal extracted from JWT");
                    principal
                }
                None => {
                    warn!(
                        method = %method,
                        path = %path,
                        "Could not build principal from JWT claims"
                    );
                    return Ok(error_response(AuthError::MissingPrincipal));
                }
            };

            match policy.authorize(&method, &path, Some(&principal)) {
                PolicyDecision::Allow => {
                    debug!("Request authorized");
                    req.extensions_mut().insert(principal);
                    inner.call(req).await
                }
                PolicyDecision::Unauthorized => {
                    warn!("Request unauthorized (missing authentication)");
                    Ok(error_response(AuthError::Unauthorized))
                }
                PolicyDecision::Forbidden => {
                    warn!("Request forbidden (insufficient permissions)");
                    Ok(error_response(AuthError::Forbidden))
                }
            }
        })
    }
}

fn error_response(error: AuthError) -> Response {
    let status = match error {
        AuthError::Unauthorized | AuthError::MissingPrincipal | AuthError::Jwt(_) => {
            StatusCode::UNAUTHORIZED
        }
        AuthError::Forbidden => StatusCode::FORBIDDEN,
    };
    status.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OtherEndpoints, SecureEndpoint};
    use ::axum::extract::Extension;
    use ::axum::routing::{get, post};
    use ::axum::Router;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use tower::ServiceExt;

    async fn public_handler() -> &'static str {
        "public"
    }

    async fn protected_handler(Extension(principal): Extension<Principal>) -> String {
        principal.name
    }

    fn token(secret: &[u8], claims: serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn protects_axum_routes() {
        let secret = b"test-secret";
        let config = SecurityConfig {
            whitelist: vec!["/public".into()],
            secure_endpoints: vec![SecureEndpoint {
                method: http::Method::POST,
                path: "/orders".into(),
                roles: vec!["order:write".into()],
            }],
            other_endpoints: OtherEndpoints::Deny,
            ..SecurityConfig::default()
        };
        let validator = JwtValidator::from_decoding_key(
            None,
            jsonwebtoken::DecodingKey::from_secret(secret),
            None,
        );
        let layer = OpenTmfSecurityLayer::new(config, validator);
        let app = Router::new()
            .route("/public", get(public_handler))
            .route("/orders", post(protected_handler))
            .layer(layer);

        let public_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/public")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_response.status(), StatusCode::OK);

        let denied_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied_response.status(), StatusCode::UNAUTHORIZED);

        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({"sub": "user-1", "roles": ["order:write"], "exp": 4_102_444_800i64}),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let allowed_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_role_returns_forbidden() {
        let secret = b"test-secret";
        let config = SecurityConfig {
            secure_endpoints: vec![SecureEndpoint {
                method: http::Method::POST,
                path: "/orders".into(),
                roles: vec!["order:write".into()],
            }],
            other_endpoints: OtherEndpoints::Deny,
            ..SecurityConfig::default()
        };
        let layer = OpenTmfSecurityLayer::new(
            config,
            JwtValidator::from_decoding_key(
                None,
                jsonwebtoken::DecodingKey::from_secret(secret),
                None,
            ),
        );
        let app = Router::new()
            .route("/orders", post(protected_handler))
            .layer(layer);
        let token = token(
            secret,
            json!({"sub": "user-1", "roles": ["order:read"], "exp": 4_102_444_800i64}),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invalid_token_returns_unauthorized() {
        let secret = b"test-secret";
        let config = SecurityConfig {
            secure_endpoints: vec![SecureEndpoint {
                method: http::Method::POST,
                path: "/orders".into(),
                roles: vec!["order:write".into()],
            }],
            ..SecurityConfig::default()
        };
        let layer = OpenTmfSecurityLayer::new(
            config,
            JwtValidator::from_decoding_key(
                None,
                jsonwebtoken::DecodingKey::from_secret(secret),
                None,
            ),
        );
        let app = Router::new()
            .route("/orders", post(protected_handler))
            .layer(layer);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header(http::header::AUTHORIZATION, "Bearer not-a-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticated_fallback_allows_any_valid_principal() {
        let secret = b"test-secret";
        let config = SecurityConfig {
            other_endpoints: OtherEndpoints::Authenticated,
            ..SecurityConfig::default()
        };
        let layer = OpenTmfSecurityLayer::new(
            config,
            JwtValidator::from_decoding_key(
                None,
                jsonwebtoken::DecodingKey::from_secret(secret),
                None,
            ),
        );
        let app = Router::new()
            .route("/profile", get(protected_handler))
            .layer(layer);
        let token = token(
            secret,
            json!({"sub": "user-1", "roles": [], "exp": 4_102_444_800i64}),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/profile")
                    .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_principal_claim_returns_unauthorized() {
        let secret = b"test-secret";
        let config = SecurityConfig {
            other_endpoints: OtherEndpoints::Authenticated,
            ..SecurityConfig::default()
        };
        let layer = OpenTmfSecurityLayer::new(
            config,
            JwtValidator::from_decoding_key(
                None,
                jsonwebtoken::DecodingKey::from_secret(secret),
                None,
            ),
        );
        let app = Router::new()
            .route("/profile", get(protected_handler))
            .layer(layer);
        let token = token(secret, json!({"roles": ["user"], "exp": 4_102_444_800i64}));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/profile")
                    .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
