use http::Method;
use opentmf_rbac_security_rs::{
    OpenTmfSecurityLayer, OtherEndpoints, SecureEndpoint, SecurityConfig,
};

fn keycloak_config() -> SecurityConfig {
    SecurityConfig {
        issuer_uri: Some("https://keycloak.example.com/realms/opentmf".into()),
        jwk_set_uri: Some(
            "https://keycloak.example.com/realms/opentmf/protocol/openid-connect/certs".into(),
        ),
        user_claim: "preferred_username".into(),
        fallback_user_claims: vec!["client_id".into(), "azp".into(), "sub".into()],
        authorities_claim: "realm_access.roles".into(),
        whitelist: vec!["/health".into(), "/info".into()],
        secure_endpoints: vec![SecureEndpoint {
            method: Method::POST,
            path: "/products".into(),
            roles: vec!["product-writer".into(), "admin".into()],
        }],
        other_endpoints: OtherEndpoints::Deny,
        ..SecurityConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = keycloak_config();

    println!("Keycloak is just one provider; realm roles can be read from `realm_access.roles`.");
    println!("Config: {config:#?}");

    if std::env::var("RUN_PROVIDER_DEMO").as_deref() == Ok("1") {
        let _layer = OpenTmfSecurityLayer::from_config(config).await?;
        println!("Layer created from live Keycloak JWKS metadata.");
    }

    Ok(())
}
