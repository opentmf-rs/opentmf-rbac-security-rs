use http::Method;
use opentmf_rbac_security_rs::{
    OpenTmfSecurityLayer, OtherEndpoints, SecureEndpoint, SecurityConfig,
};

fn azure_entra_config() -> SecurityConfig {
    SecurityConfig {
        issuer_uri: Some("https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0".into()),
        jwk_set_uri: Some(
            "https://login.microsoftonline.com/YOUR_TENANT_ID/discovery/v2.0/keys".into(),
        ),
        user_claim: "preferred_username".into(),
        fallback_user_claims: vec!["azp".into(), "appid".into(), "sub".into()],
        // Use `roles` for app roles. For delegated scopes, use `scp` and model scopes as roles.
        authorities_claim: "roles".into(),
        whitelist: vec!["/health".into()],
        secure_endpoints: vec![SecureEndpoint {
            method: Method::DELETE,
            path: "/orders/*".into(),
            roles: vec!["Orders.Delete".into(), "Admin".into()],
        }],
        other_endpoints: OtherEndpoints::Deny,
        ..SecurityConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = azure_entra_config();

    println!("Azure Entra ID can use `roles` for app roles or `scp` for delegated scopes.");
    println!("Config: {config:#?}");

    if std::env::var("RUN_PROVIDER_DEMO").as_deref() == Ok("1") {
        let _layer = OpenTmfSecurityLayer::from_config(config).await?;
        println!("Layer created from live Azure Entra JWKS metadata.");
    }

    Ok(())
}
