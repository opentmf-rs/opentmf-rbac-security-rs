use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use opentmf_rbac_security_rs::{JwtValidator, OpenTmfSecurityLayer, Principal, SecurityConfig};
use serde_json::json;
use tower::ServiceExt;

const SECRET: &[u8] = b"integration-test-secret";

async fn health() -> &'static str {
    "healthy"
}

async fn create_order(Extension(principal): Extension<Principal>) -> String {
    format!("created by {}", principal.name)
}

fn app_from_yaml_config() -> Router {
    let config = SecurityConfig::from_yaml_str(
        r#"
opentmf:
  security:
    user-claim: email
    fallback-user-claims: [client_id, sub]
    authorities-claim: permissions
    whitelist:
      - /health
    secure-endpoints:
      - method: POST
        path: /orders
        roles: [order:write, admin]
    other-endpoints: deny
"#,
    )
    .expect("YAML configuration should parse");
    let validator =
        JwtValidator::from_decoding_key(None, jsonwebtoken::DecodingKey::from_secret(SECRET), None);
    let layer = OpenTmfSecurityLayer::new(config, validator);

    Router::new()
        .route("/health", get(health))
        .route("/orders", post(create_order))
        .layer(layer)
}

fn token(claims: serde_json::Value) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .expect("test token should encode")
}

#[tokio::test]
async fn configured_axum_app_allows_public_and_authorized_requests() {
    let app = app_from_yaml_config();

    let health_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_response.status(), StatusCode::OK);

    let authorized_token = token(json!({
        "email": "writer@example.com",
        "permissions": ["order:write"],
        "exp": 4_102_444_800i64
    }));
    let authorized_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {authorized_token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn configured_axum_app_rejects_missing_or_insufficient_authorization() {
    let app = app_from_yaml_config();

    let missing_token_response = app
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
    assert_eq!(missing_token_response.status(), StatusCode::UNAUTHORIZED);

    let read_only_token = token(json!({
        "email": "reader@example.com",
        "permissions": ["order:read"],
        "exp": 4_102_444_800i64
    }));
    let forbidden_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {read_only_token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
}
