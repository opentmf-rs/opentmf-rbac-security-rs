# Architecture Overview - opentmf-rbac-security-rs

**Purpose**: Provider-neutral OpenID/JWT RBAC middleware for Axum  
**Version**: 0.1.0  
**Language**: Rust 2021 Edition

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Axum Application                           │
│                    (HTTP Router & Handlers)                     │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              OpenTmfSecurityLayer (Tower Layer)                 │
│         ┌──────────────────────────────────────────┐            │
│         │     OpenTmfSecurityService (Middleware)  │            │
│         │                                          │            │
│         │  1. Extract PolicyRequirement            │            │
│         │     └─> SecurityPolicy::requirement()    │            │
│         │                                          │            │
│         │  2. Check Policy Decision                │            │
│         │     ├─> PermitAll → pass through         │            │
│         │     ├─> DenyAll → return 403             │            │
│         │     └─> Authenticated/AnyAuthority       │            │
│         │         ├─> Extract bearer token         │            │
│         │         ├─> Validate JWT                 │            │
│         │         ├─> Extract Principal            │            │
│         │         └─> Authorize & inject           │            │
│         │                                          │            │
│         └──────────────────────────────────────────┘            │
│                         │                                       │
│      ┌──────────────────┼──────────────────┐                   │
│      ▼                  ▼                  ▼                   │
│  [config]         [jwt]              [policy]                 │
│  SecurityConfig   JwtValidator       SecurityPolicy           │
│  ├─ user_claim    ├─ keys            ├─ config              │
│  ├─ auth_claim    ├─ issuer          ├─ requirement()       │
│  ├─ endpoints     ├─ validate()      └─ authorize()         │
│  └─ policies      └─ from_config()                          │
│                                                              │
│  [claims]                [principal]                         │
│  claim_value()          Principal                           │
│  claim_as_string()      ├─ name                             │
│  claim_as_string_list() ├─ authorities (HashSet)            │
│                         ├─ claims (serde_json::Value)       │
│                         └─ has_any_authority()              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Breakdown

### 1. **config.rs** - Configuration Management
**Responsibility**: Parse and validate security configuration

**Key Types**:
- `ConfigFile`: YAML root wrapper
- `OpenTmfConfig`: Top-level opentmf section
- `SecurityConfig`: Security policy configuration
  - `issuer_uri`: Optional OIDC issuer for discovery
  - `jwk_set_uri`: Optional direct JWKS endpoint
  - `user_claim`: Principal name extraction claim
  - `fallback_user_claims`: Fallback chain for principal
  - `authorities_claim`: Authorization roles/permissions claim
  - `secure_endpoints`: Protected routes requiring roles
  - `allowed_endpoints`: Public routes with method matching
  - `blacklist`: Paths explicitly denied
  - `whitelist`: Paths explicitly allowed
  - `other_endpoints`: Policy for unspecified routes

**Key Methods**:
- `from_yaml_str()`: Parse YAML configuration
- `validate()`: Validate all path patterns start with `/`

**Example Configuration**:
```yaml
opentmf:
  security:
    issuer-uri: https://auth.example.com
    jwk-set-uri: https://auth.example.com/.well-known/jwks.json
    user-claim: email
    fallback-user-claims: [client_id, sub]
    authorities-claim: permissions
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

---

### 2. **jwt.rs** - JWT Validation
**Responsibility**: Fetch, parse, and validate JWTs

**Key Types**:
- `JwtValidator`: Main validator (cloneable, thread-safe)
  - Contains Vec<JwtKey> internally
  - Optional issuer for validation
- `JwtKey`: Internal wrapper for (kid, decoding_key)
- `DiscoveryDocument`: OIDC discovery response

**Key Methods**:
- `from_config()`: Initialize from SecurityConfig
- `from_jwks_uri()`: Load from JWKS endpoint
- `from_jwk_set_str()`: Parse JWK set JSON
- `from_jwk_set()`: Build from parsed JwkSet
- `from_decoding_key()`: Build from single key (testing)
- `validate()`: Validate JWT token string

**Validation Flow**:
```
1. Decode token header to get `kid` (key ID)
2. Find matching keys:
   - If token has kid, match against key IDs
   - If token has no kid, use all available keys
3. For each matching key:
   - Attempt full JWT validation
   - Check signature
   - Verify issuer (if configured)
   - Verify not expired
4. Return validated claims or error
```

**Bearer Token Extraction**:
- Supports both `Bearer` and `bearer` prefixes
- Validates non-empty token value
- Returns clean token string without prefix

---

### 3. **policy.rs** - Policy Evaluation Engine
**Responsibility**: Determine access control decisions

**Key Types**:
- `PolicyRequirement`: What the route requires
  - `PermitAll`: No authentication needed
  - `DenyAll`: Explicit denial
  - `Authenticated`: Valid JWT required
  - `AnyAuthority`: Specific roles required
- `PolicyDecision`: What to implement
  - `Allow`: Request proceeds (200)
  - `Unauthorized`: No credentials (401)
  - `Forbidden`: Insufficient permissions (403)
- `SecurityPolicy`: Evaluates policy
  - Wraps `SecurityConfig`
  - Implements policy evaluation order

**Policy Evaluation Order** (matches Java library):
1. **Blacklist**: Deny if matches blacklist pattern
2. **Whitelist**: Allow if matches whitelist pattern
3. **Allowed Endpoints**: Allow if method + path match
4. **Secure Endpoints**: Check authentication + roles
5. **Other Endpoints**: Apply default policy (Allow/Deny/Authenticated)

**Path Matching** (Spring-style):
- `*` = matches single segment (up to next `/`)
- `**` = matches zero or more segments
- Examples:
  - `/orders/*/details` → `/orders/123/details` ✓, `/orders/123/456/details` ✗
  - `/admin/**` → `/admin/users`, `/admin/users/list` ✓
  - `/*.json` → `/config.json` ✓, `/data/config.json` ✗

---

### 4. **principal.rs** - Authenticated User Representation
**Responsibility**: Extract authenticated principal from JWT claims

**Key Type**:
- `Principal`: Represents authenticated user
  - `name`: String (username/email/subject)
  - `authorities`: HashSet<String> (roles/permissions)
  - `claims`: Complete serde_json::Value (raw JWT claims)

**Key Methods**:
- `from_claims()`: Build Principal from JWT claims
  - Attempts user_claim first
  - Falls back to fallback_user_claims in order
  - Final fallback to "sub" claim
- `has_any_authority()`: Check if principal has any required role

**Principal Resolution Order**:
```
1. Try: config.user_claim (e.g., "email")
2. Try: First fallback_user_claim (e.g., "client_id")
3. Try: Second fallback_user_claim (e.g., "azp")
4. Try: "sub" (JWT standard subject claim)
5. If all fail: Principal creation fails (returns None)
```

---

### 5. **claims.rs** - JWT Claim Extraction
**Responsibility**: Extract and parse individual claims

**Key Functions**:
- `claim_value()`: Get nested claim value
  - Supports dot notation: `realm_access.roles`
  - Supports colon in names: `cognito:groups`
  - Returns `Option<&Value>`
- `claim_as_string()`: Extract claim as string
  - Converts numbers/bools to strings
  - Returns `Option<String>`
- `claim_as_string_list()`: Extract claim as string array
  - Handles both single strings and arrays
  - Converts numbers/bools within arrays
  - Returns `Vec<String>`

**Supported Claim Formats**:
```json
{
  "simple_claim": "value",
  "nested.claim": "value",
  "claim:with:colons": "value",
  "array_claim": ["role1", "role2"],
  "nested": {
    "claim": ["role1", "role2"]
  }
}
```

---

### 6. **error.rs** - Error Types
**Responsibility**: Define security-related errors

**Error Hierarchy**:
```
ConfigError
├─ MissingJwksConfiguration: Neither jwk-set-uri nor issuer-uri
├─ InvalidPath: Path doesn't start with /
└─ Yaml: YAML parsing error

JwtError
├─ MissingBearerToken: No Authorization header
├─ DiscoveryFetch: OIDC discovery HTTP failure
├─ MissingJwksUri: Discovery doc lacks jwks_uri
├─ JwksFetch: JWKS endpoint HTTP failure
├─ JwksParse: JWKS JSON parse failure
├─ Header: JWT header decode failure
├─ NoMatchingKey: No key matched token KID
└─ Validation: Token signature/expiry/issuer check failed

AuthError
├─ Unauthorized: (401) No valid credentials
├─ Forbidden: (403) Insufficient permissions
├─ MissingPrincipal: Valid JWT but no extractable principal
└─ Jwt: Wraps JwtError for propagation
```

**HTTP Status Mapping**:
- `401 Unauthorized`: AuthError::Unauthorized, AuthError::MissingPrincipal, AuthError::Jwt(*)
- `403 Forbidden`: AuthError::Forbidden

---

### 7. **axum.rs** - Axum Integration Layer
**Responsibility**: Tower middleware for Axum integration

**Key Types**:
- `OpenTmfSecurityLayer`: Tower Layer implementation
  - Cloneable for use in `Router::layer()`
  - Wraps `SecurityPolicy` and `JwtValidator` in Arc
- `OpenTmfSecurityService<S>`: Tower Service implementation
  - Generic over inner service S
  - Implements `Service<Request<Body>>`
  - Async middleware with pinned futures

**Request Flow**:
```
1. Clone inner service, policy, validator
2. Extract method and URI path
3. Get policy requirement for route
4. Branch on requirement:
   ├─ PermitAll → pass through (no auth needed)
   ├─ DenyAll → return 403 Forbidden
   └─ Authenticated/AnyAuthority:
      ├─ Extract bearer token from header
      ├─ Validate JWT signature
      ├─ Extract principal from claims
      ├─ Authorize against required roles
      └─ Insert Principal into request extensions
5. Call inner service or return error
```

**Tracing Integration**:
- DEBUG: Policy requirement determination
- DEBUG: Successful token validation
- DEBUG: Successful principal extraction
- DEBUG: Authorization decisions
- WARN: Missing/invalid bearer tokens
- WARN: JWT validation failures
- WARN: Principal extraction failures
- WARN: Forbidden requests (insufficient permissions)

**Response Codes**:
- 200 OK: Request authorized and processed
- 401 Unauthorized: No credentials or invalid JWT
- 403 Forbidden: Valid JWT but insufficient permissions or blacklisted

---

## Data Flow Example

### Scenario: POST /orders with role check

```
1. HTTP Request arrives
   ├─ Method: POST
   ├─ Path: /orders
   └─ Header: Authorization: Bearer <jwt>

2. OpenTmfSecurityService::call()
   ├─ Get requirement for POST /orders
   │  └─> [Checks secure_endpoints]
   │      └─> Requirement: AnyAuthority(["order:write"])
   │
   ├─ Extract bearer token "abc.def.ghi"
   │
   ├─ JwtValidator::validate("abc.def.ghi")
   │  ├─ Decode header → alg=HS256, kid=none
   │  ├─ Find matching keys → [key1]
   │  ├─ Verify signature → OK
   │  ├─ Check expiry → OK
   │  └─ Return claims: {sub: "user1", roles: ["order:write"]}
   │
   ├─ Principal::from_claims()
   │  ├─ Extract name from user_claim="sub" → "user1"
   │  ├─ Extract authorities from authorities_claim="roles"
   │  │  └─> HashSet{"order:write"}
   │  └─ Build Principal(name="user1", authorities={...})
   │
   ├─ SecurityPolicy::authorize()
   │  ├─ Check requirement: AnyAuthority(["order:write"])
   │  ├─ Check principal.has_any_authority(["order:write"])
   │  │  └─> true (found in HashSet)
   │  └─> Decision: Allow
   │
   ├─ Insert principal into req.extensions
   │
   └─ Call inner service with request
      └─ Handler receives Principal via extractors

3. Handler Response
   ├─ Accesses Extension<Principal>
   ├─ Uses principal.name in business logic
   └─ Returns 200 OK
```

---

## Security Model

### Authentication (Who you are)
- Bearer JWT tokens in `Authorization: Bearer <token>` header
- JWT validated with JWK Set (RSA, ECDSA, symmetric keys)
- Issuer verification optional
- Key rotation supported via JWKS endpoint

### Authorization (What you can do)
- Roles/permissions extracted from configurable JWT claims
- Role hierarchy not supported (roles are flat strings)
- Policy engine checks required roles for endpoints
- Support for provider-neutral claim extraction

### Default Security Posture
- **Deny by default** for undefined endpoints
- Authentication required unless explicitly whitelisted
- Role-based access control (RBAC)
- No implicit privilege escalation

---

## Dependency Graph

```
opentmf-rbac-security-rs
├─ axum (HTTP framework)
│  ├─ tower (middleware abstraction)
│  ├─ http (HTTP types)
│  ├─ tokio (async runtime)
│  └─ hyper (HTTP client/server)
├─ jsonwebtoken (JWT validation)
│  ├─ serde (serialization)
│  └─ jsonwebtoken crypto backends
├─ reqwest (HTTPS client for OIDC discovery)
│  ├─ tokio
│  └─ rustls (TLS)
├─ serde_json (JSON parsing)
├─ serde_yaml (YAML parsing)
├─ thiserror (error macros)
├─ tracing (observability)
└─ http (HTTP primitives)

[dev-dependencies]
├─ tokio (for tests)
└─ tower (for test utilities)
```

---

## Extension Points

### For Future Versions

1. **Actix Integration**: New `actix.rs` module
   - Would reuse `config`, `jwt`, `policy`, `principal`, `claims` modules
   - Middleware using actix-web patterns

2. **Custom Policy Engine**: Extensions to `policy.rs`
   - Policy expressions / DSL
   - Conditional authorization
   - Attribute-based access control (ABAC)

3. **Caching**: Performance optimization
   - Cache JWKS sets with TTL
   - Cache JWT validation results (short-lived)

4. **Rate Limiting**: Built-in token validation limits
   - Prevent brute force attacks
   - Protect against DoS

5. **Audit Logging**: Structured security events
   - Who (principal) accessed what (resource)
   - When and whether authorized
   - Integration with logging backends

---

## Testing Strategy

### Unit Tests (28 total)
- **config.rs**: YAML parsing, validation, defaults
- **jwt.rs**: Token extraction, validation, key matching
- **policy.rs**: Path matching, policy evaluation order
- **principal.rs**: Principal extraction, fallback claims
- **claims.rs**: Nested claims, type coercion
- **axum.rs**: Middleware integration, status codes

### Integration Tests (2 total)
- Happy path: public + authorized requests
- Rejection path: missing/insufficient auth

### Areas Well-Tested
✓ Path matching (Spring-style wildcards)
✓ JWT validation (signature, expiry, issuer, key matching)
✓ Principal extraction (primary + fallback claims)
✓ Policy evaluation order
✓ Bearer token extraction (case insensitivity)
✓ Configuration parsing and validation

### Areas for Enhanced Testing (Future)
- Real OIDC provider integration
- Large configuration load testing
- Concurrent token validation performance
- Error recovery and resilience

---

## Performance Characteristics

### Time Complexity
- **Path matching**: O(n*m) where n=pattern segments, m=path segments
- **Authority checking**: O(1) with HashSet (previously O(log n) with BTreeSet)
- **Key selection**: O(k) where k=number of keys in JWKS set
- **JWT validation**: Dominated by crypto operations

### Memory Usage
- **Per-middleware instance**: ~1KB (Arc pointers)
- **Per-config**: ~100-500 bytes depending on endpoint count
- **Per-request**: ~1KB (parsed JWT claims)
- **Per-principal**: ~200 bytes + authority strings

### Optimization Opportunities
1. JWKS caching with TTL
2. Compiled path patterns (instead of re-parsing)
3. Principal cache per token hash
4. Async JWKS refresh in background

---

**Last Updated**: May 20, 2026  
**Architecture Version**: 1.0  
**Reviewed By**: GitHub Copilot (Senior Rust Engineer)

