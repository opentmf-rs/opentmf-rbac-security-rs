//! Provider-neutral OpenID/JWT RBAC middleware for Axum.
//!
//! The crate mirrors the policy model of OpenTMF's Java `openid-rbac-security`
//! library while staying independent from any single identity provider.

pub mod axum;
pub mod claims;
pub mod config;
pub mod error;
pub mod jwt;
pub mod policy;
pub mod principal;

pub use crate::axum::OpenTmfSecurityLayer;
pub use crate::config::{
    ConfigFile, Endpoint, OpenTmfConfig, OtherEndpoints, SecureEndpoint, SecurityConfig,
};
pub use crate::error::{AuthError, ConfigError, JwtError};
pub use crate::jwt::JwtValidator;
pub use crate::policy::{PolicyDecision, PolicyRequirement, SecurityPolicy};
pub use crate::principal::Principal;
