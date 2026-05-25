# opentmf-rbac-security-rs

Provider-neutral OpenID/JWT RBAC middleware for Axum.

This crate is a Rust counterpart to OpenTMF's Spring Boot `openid-rbac-security`
library. It keeps the same deployment idea: configure endpoint security
declaratively, validate bearer JWTs with a JWK Set, extract a principal and
authorities from configurable claims, and enforce the policy before handlers run.

The first version supports Axum through a Tower layer.

## Features

- Bearer JWT validation from a configured `jwk-set-uri`.
- Optional OIDC discovery through `issuer-uri`.
- Configurable principal claim and ordered fallback user claims.
- Configurable authorities claim with dot notation for nested claims.
- Provider-neutral RBAC: Auth0, Okta, Azure Entra ID, Cognito, Keycloak, and custom OIDC providers.
- Endpoint policy model: blacklist, whitelist, allowed endpoints, secure endpoints, and catch-all `other-endpoints`.
- Axum request extension with the authenticated `Principal`.

## Configuration Shape

```yaml
opentmf:
  security:
    issuer-uri: https://issuer.example.com
    jwk-set-uri: https://issuer.example.com/.well-known/jwks.json
    user-claim: email
    fallback-user-claims: [client_id, azp, sub]
    authorities-claim: permissions
    jwks-refresh-interval: 300
    jwks-max-stale: 3600
    jwks-request-timeout: 5
    jwks-accept-invalid-certs: false

    whitelist:
      - /health
      - /info

    allowed-endpoints:
      - method: GET
        path: /catalog/**

    secure-endpoints:
      - method: POST
        path: /orders
        roles: [order:write, admin]

    other-endpoints: deny
```

## Axum Usage

```rust
use axum::{extract::Extension, routing::{get, post}, Router};
use opentmf_rbac_security_rs::{OpenTmfSecurityLayer, Principal, SecurityConfig};

async fn public() -> &'static str {
    "ok"
}

async fn create_order(Extension(principal): Extension<Principal>) -> String {
    format!("created by {}", principal.name)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::from_yaml_str(include_str!("security.yml"))?;
    let layer = OpenTmfSecurityLayer::from_config(config).await?;

    let app = Router::new()
        .route("/health", get(public))
        .route("/orders", post(create_order))
        .layer(layer);

    // Serve `app` with your preferred Axum server setup.
    Ok(())
}
```

## Policy Order

Policy evaluation intentionally follows the Java library:

1. `blacklist`: deny matching paths.
2. `whitelist`: allow matching paths without authentication.
3. `allowed-endpoints`: allow matching method + path without authentication.
4. `secure-endpoints`: require any configured role/authority.
5. `other-endpoints`: apply `allow`, `deny`, or `authenticated`.

## JWKS Cache and Refresh

When `jwk-set-uri` or `issuer-uri` is configured, the middleware fetches and
parses the JWKS during startup. If this initial fetch fails, security layer
construction fails and the application should not become ready.

After startup, keys are kept in memory and refreshed in the background. The
defaults are:

- `jwks-refresh-interval: 300` seconds
- `jwks-max-stale: 3600` seconds
- `jwks-request-timeout: 5` seconds
- `jwks-accept-invalid-certs: false`

If a scheduled refresh fails, the last-known-good keys remain usable until the
max stale window is exceeded. If a token arrives with an unknown `kid`, the
validator refreshes JWKS immediately and retries validation once, which helps
with identity-provider key rotation.

The middleware emits structured `tracing` logs for startup fetch, scheduled
refresh, refresh failures, and unknown-`kid` refresh attempts. At `debug` level,
JWKS HTTP fetches also log the outbound request method, sanitized request
headers, empty request body marker, response status, sanitized response headers,
and a bounded response body preview. Header values are redacted by sensitive
name patterns such as `token`, `secret`, `password`, `credential`,
`authorization`, `cookie`, `api-key`, `session`, `jwt`, `bearer`, `csrf`, and
`xsrf`. Redacted headers remain visible as `"<redacted>"` so operators can tell
that they were sent.

The crate does not log raw JWTs, decoded claims, private keys, credentials, or
secrets. JWKS response bodies contain public key material and are only logged at
`debug` level with a bounded preview.

For temporary non-production troubleshooting, `jwks-accept-invalid-certs: true`
can be used to disable TLS certificate verification for JWKS HTTP calls. This is
dangerous and should not be used in production; the preferred fix is to install
the correct CA certificate or fix the issuer's certificate chain.

## Provider Claim Mapping

| Provider | Common principal claim | Common authorities claim |
| --- | --- | --- |
| Auth0 | `email`, `sub`, `client_id` | `permissions` or a custom namespaced claim |
| Okta | `email`, `uid`, `sub` | `groups` |
| Azure Entra ID | `preferred_username`, `azp`, `appid`, `sub` | `roles` for app roles, `scp` for delegated scopes |
| Amazon Cognito | `username`, `client_id`, `sub` | `cognito:groups` |
| Keycloak | `preferred_username`, `client_id`, `azp`, `sub` | `realm_access.roles` or `resource_access.<client>.roles` |

The crate does not depend on Keycloak. Keycloak is only one supported provider shape.

## Examples

Provider examples live in `examples/`:

- `auth0.rs`
- `okta.rs`
- `azure_entra.rs`
- `cognito.rs`
- `keycloak.rs`
- `local_jwks.rs`

Most provider examples print a ready-to-adapt configuration. Set
`RUN_PROVIDER_DEMO=1` to make them fetch live JWKS metadata from the configured
placeholder URLs after you replace those URLs with real provider values.

```powershell
cargo run --example auth0
cargo run --example local_jwks
```

## Coverage

Rust does not use JaCoCo. This crate uses `cargo-llvm-cov`, which is the closest
modern Rust equivalent and can export LCOV for SonarQube, Codecov, Coveralls, and
similar tools.

Install the tool once:

```powershell
cargo install cargo-llvm-cov
```

Run coverage locally:

```powershell
cargo coverage
```

Enforce the coverage gate:

```powershell
cargo coverage-check
```

The gate mirrors the Java JaCoCo threshold intent:

| Java JaCoCo threshold | Rust coverage gate |
| --- | --- |
| Line coverage >= 80% | `--fail-under-lines 80` |
| Instruction coverage >= 80% | `--fail-under-regions 80` |
| Branch coverage >= 80% | Not currently exposed by `rustc`/`cargo-llvm-cov` |
| Class missed count = 0 | Approximated with `--fail-under-functions 80` |

Generate LCOV output for CI/reporting:

```powershell
cargo coverage-lcov
```

## Notes

- Dot notation is supported for nested claims, such as `realm_access.roles`.
- Claim names containing `:` are supported directly, such as `cognito:groups`.
- If `user-claim` is missing, fallback claims are tried in order, then `sub`.
- The first version focuses on Axum. A future Actix adapter can reuse the same
  `config`, `claims`, `principal`, `jwt`, and `policy` modules.
