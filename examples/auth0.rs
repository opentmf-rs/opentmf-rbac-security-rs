use http::Method;
use opentmf_rbac_security_rs::{
    Endpoint, OpenTmfSecurityLayer, OtherEndpoints, SecureEndpoint, SecurityConfig,
};

fn auth0_config() -> SecurityConfig {
    SecurityConfig {
        issuer_uri: Some("https://YOUR_DOMAIN.auth0.com/".into()),
        jwk_set_uri: Some("https://YOUR_DOMAIN.auth0.com/.well-known/jwks.json".into()),
        user_claim: "email".into(),
        fallback_user_claims: vec!["client_id".into(), "sub".into()],
        authorities_claim: "permissions".into(),
        whitelist: vec!["/health".into(), "/info".into()],
        allowed_endpoints: vec![Endpoint {
            method: Method::GET,
            path: "/catalog/**".into(),
        }],
        secure_endpoints: vec![SecureEndpoint {
            method: Method::POST,
            path: "/orders".into(),
            roles: vec!["order:write".into(), "admin".into()],
        }],
        other_endpoints: OtherEndpoints::Deny,
        ..SecurityConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = auth0_config();

    println!("Auth0 usually maps API permissions into the `permissions` claim.");
    println!("Config: {config:#?}");

    if std::env::var("RUN_PROVIDER_DEMO").as_deref() == Ok("1") {
        let _layer = OpenTmfSecurityLayer::from_config(config).await?;
        println!("Layer created from live Auth0 JWKS metadata.");
    }

    Ok(())
}
