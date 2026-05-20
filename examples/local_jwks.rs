use http::Method;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use opentmf_rbac_security_rs::{
    JwtValidator, OpenTmfSecurityLayer, OtherEndpoints, SecureEndpoint, SecurityConfig,
};
use serde_json::json;

fn local_config() -> SecurityConfig {
    SecurityConfig {
        user_claim: "sub".into(),
        authorities_claim: "roles".into(),
        secure_endpoints: vec![SecureEndpoint {
            method: Method::GET,
            path: "/admin".into(),
            roles: vec!["admin".into()],
        }],
        other_endpoints: OtherEndpoints::Deny,
        ..SecurityConfig::default()
    }
}

fn demo_token(secret: &[u8]) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        &json!({
            "sub": "local-user",
            "roles": ["admin"],
            "exp": 4_102_444_800i64
        }),
        &EncodingKey::from_secret(secret),
    )
    .expect("demo token should encode")
}

fn main() {
    let secret = b"local-development-secret";
    let config = local_config();
    let validator = JwtValidator::from_decoding_key(None, DecodingKey::from_secret(secret), None);
    let token = demo_token(secret);
    let claims = validator
        .validate(&token)
        .expect("demo token should validate");
    let _layer = OpenTmfSecurityLayer::new(config, validator);

    println!("Local development token validated with claims: {claims}");
    println!("Use `Authorization: Bearer {token}` against routes protected by the demo layer.");
}
