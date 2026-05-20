use http::Method;
use opentmf_rbac_security_rs::{
    OpenTmfSecurityLayer, OtherEndpoints, SecureEndpoint, SecurityConfig,
};

fn okta_config() -> SecurityConfig {
    SecurityConfig {
        issuer_uri: Some("https://YOUR_OKTA_DOMAIN/oauth2/default".into()),
        jwk_set_uri: Some("https://YOUR_OKTA_DOMAIN/oauth2/default/v1/keys".into()),
        user_claim: "email".into(),
        fallback_user_claims: vec!["uid".into(), "sub".into()],
        authorities_claim: "groups".into(),
        whitelist: vec!["/health".into()],
        secure_endpoints: vec![SecureEndpoint {
            method: Method::GET,
            path: "/admin/**".into(),
            roles: vec!["Admin".into(), "Support".into()],
        }],
        other_endpoints: OtherEndpoints::Authenticated,
        ..SecurityConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = okta_config();

    println!("Okta commonly emits group membership in a `groups` claim.");
    println!("Config: {config:#?}");

    if std::env::var("RUN_PROVIDER_DEMO").as_deref() == Ok("1") {
        let _layer = OpenTmfSecurityLayer::from_config(config).await?;
        println!("Layer created from live Okta JWKS metadata.");
    }

    Ok(())
}
