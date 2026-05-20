use http::Method;
use opentmf_rbac_security_rs::{
    OpenTmfSecurityLayer, OtherEndpoints, SecureEndpoint, SecurityConfig,
};

fn cognito_config() -> SecurityConfig {
    SecurityConfig {
        issuer_uri: Some("https://cognito-idp.YOUR_REGION.amazonaws.com/YOUR_USER_POOL_ID".into()),
        jwk_set_uri: Some(
            "https://cognito-idp.YOUR_REGION.amazonaws.com/YOUR_USER_POOL_ID/.well-known/jwks.json"
                .into(),
        ),
        user_claim: "username".into(),
        fallback_user_claims: vec!["client_id".into(), "sub".into()],
        authorities_claim: "cognito:groups".into(),
        whitelist: vec!["/health".into()],
        secure_endpoints: vec![SecureEndpoint {
            method: Method::PATCH,
            path: "/customers/*".into(),
            roles: vec!["operators".into(), "admins".into()],
        }],
        other_endpoints: OtherEndpoints::Authenticated,
        ..SecurityConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = cognito_config();

    println!("Amazon Cognito group membership is usually in `cognito:groups`.");
    println!("Config: {config:#?}");

    if std::env::var("RUN_PROVIDER_DEMO").as_deref() == Ok("1") {
        let _layer = OpenTmfSecurityLayer::from_config(config).await?;
        println!("Layer created from live Cognito JWKS metadata.");
    }

    Ok(())
}
