use crate::config::{OtherEndpoints, SecurityConfig};
use crate::principal::Principal;
use http::Method;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRequirement {
    PermitAll,
    DenyAll,
    Authenticated,
    AnyAuthority(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Unauthorized,
    Forbidden,
}

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    config: SecurityConfig,
}

impl SecurityPolicy {
    pub fn new(config: SecurityConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }

    pub fn requirement(&self, method: &Method, path: &str) -> PolicyRequirement {
        if self
            .config
            .blacklist
            .iter()
            .any(|pattern| path_matches(pattern, path))
        {
            return PolicyRequirement::DenyAll;
        }

        if self
            .config
            .whitelist
            .iter()
            .any(|pattern| path_matches(pattern, path))
        {
            return PolicyRequirement::PermitAll;
        }

        if self
            .config
            .allowed_endpoints
            .iter()
            .any(|endpoint| endpoint.method == *method && path_matches(&endpoint.path, path))
        {
            return PolicyRequirement::PermitAll;
        }

        if let Some(endpoint) = self
            .config
            .secure_endpoints
            .iter()
            .find(|endpoint| endpoint.method == *method && path_matches(&endpoint.path, path))
        {
            return PolicyRequirement::AnyAuthority(endpoint.roles.clone());
        }

        match self.config.other_endpoints {
            OtherEndpoints::Allow => PolicyRequirement::PermitAll,
            OtherEndpoints::Deny => PolicyRequirement::DenyAll,
            OtherEndpoints::Authenticated => PolicyRequirement::Authenticated,
        }
    }

    pub fn authorize(
        &self,
        method: &Method,
        path: &str,
        principal: Option<&Principal>,
    ) -> PolicyDecision {
        match self.requirement(method, path) {
            PolicyRequirement::PermitAll => PolicyDecision::Allow,
            PolicyRequirement::DenyAll => PolicyDecision::Forbidden,
            PolicyRequirement::Authenticated => principal
                .map(|_| PolicyDecision::Allow)
                .unwrap_or(PolicyDecision::Unauthorized),
            PolicyRequirement::AnyAuthority(required) => match principal {
                Some(principal) if principal.has_any_authority(required.iter()) => {
                    PolicyDecision::Allow
                }
                Some(_) => PolicyDecision::Forbidden,
                None => PolicyDecision::Unauthorized,
            },
        }
    }
}

/// Matches paths using Spring-style wildcards.
///
/// # Wildcard patterns
///
/// - `*` matches any single path segment, up to the next `/`.
/// - `**` matches zero or more path segments.
/// - `/` is the path separator.
///
/// # Examples
///
/// - `/orders/*/details` matches `/orders/123/details`, but not `/orders/123/456/details`.
/// - `/orders/**` matches `/orders/123` and `/orders/123/456`.
/// - `/swagger-ui/**` matches `/swagger-ui/index.html` and `/swagger-ui/css/theme.css`.
/// - `/files/*.json` matches `/files/config.json`, but not `/files/data.yaml`.
/// - `/**` and `**` match any path.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == path || pattern == "/**" || pattern == "**" {
        return true;
    }

    let pattern_parts = split_path(pattern);
    let path_parts = split_path(path);
    matches_parts(&pattern_parts, &path_parts)
}

fn split_path(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect()
}

fn matches_parts(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.split_first(), path.split_first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some((pattern_head, rest)), _) if *pattern_head == "**" => {
            matches_parts(rest, path)
                || path
                    .split_first()
                    .map(|(_, path_rest)| matches_parts(pattern, path_rest))
                    .unwrap_or(false)
        }
        (Some((pattern_head, pattern_rest)), Some((_, path_rest))) if *pattern_head == "*" => {
            matches_parts(pattern_rest, path_rest)
        }
        (Some((pattern_head, pattern_rest)), Some((path_head, path_rest)))
            if segment_matches(pattern_head, path_head) =>
        {
            matches_parts(pattern_rest, path_rest)
        }
        _ => false,
    }
}

fn segment_matches(pattern: &str, segment: &str) -> bool {
    if pattern == "*" || pattern == segment {
        return true;
    }

    if !pattern.contains('*') {
        return false;
    }

    let mut remainder = segment;
    let mut first = true;
    for part in pattern.split('*') {
        if part.is_empty() {
            continue;
        }
        if first && !pattern.starts_with('*') {
            if !remainder.starts_with(part) {
                return false;
            }
            remainder = &remainder[part.len()..];
        } else if let Some(index) = remainder.find(part) {
            remainder = &remainder[index + part.len()..];
        } else {
            return false;
        }
        first = false;
    }

    pattern.ends_with('*') || remainder.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Endpoint, SecureEndpoint};
    use serde_json::json;

    #[test]
    fn matches_spring_style_paths() {
        assert!(path_matches("/orders/*/details", "/orders/123/details"));
        assert!(!path_matches(
            "/orders/*/details",
            "/orders/123/extra/details"
        ));
        assert!(path_matches("/orders/**", "/orders/123/extra/details"));
        assert!(path_matches("/swagger-ui/**", "/swagger-ui/index.html"));
        assert!(path_matches("/files/*.json", "/files/a.json"));
    }

    #[test]
    fn evaluates_policy_in_expected_order() {
        let policy = SecurityPolicy::new(SecurityConfig {
            blacklist: vec!["/admin/**".into()],
            whitelist: vec!["/health".into()],
            allowed_endpoints: vec![Endpoint {
                method: Method::GET,
                path: "/orders/**".into(),
            }],
            secure_endpoints: vec![SecureEndpoint {
                method: Method::POST,
                path: "/orders".into(),
                roles: vec!["order:write".into()],
            }],
            other_endpoints: OtherEndpoints::Authenticated,
            ..SecurityConfig::default()
        });

        let principal = Principal::from_claims(
            json!({"sub": "u1", "roles": ["order:write"]}),
            policy.config(),
        )
        .unwrap();

        assert_eq!(
            policy.authorize(&Method::GET, "/admin/status", Some(&principal)),
            PolicyDecision::Forbidden
        );
        assert_eq!(
            policy.authorize(&Method::GET, "/health", None),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.authorize(&Method::GET, "/orders/1", None),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.authorize(&Method::POST, "/orders", Some(&principal)),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.authorize(&Method::DELETE, "/unknown", None),
            PolicyDecision::Unauthorized
        );
    }
}
