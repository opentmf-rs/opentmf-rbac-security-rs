use crate::claims::{claim_as_string, claim_as_string_list};
use crate::config::SecurityConfig;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Principal {
    pub name: String,
    pub authorities: HashSet<String>,
    pub claims: serde_json::Value,
}

impl Principal {
    pub fn from_claims(claims: serde_json::Value, config: &SecurityConfig) -> Option<Self> {
        let name = principal_name(&claims, config)?;
        let authorities = claim_as_string_list(&claims, &config.authorities_claim)
            .into_iter()
            .collect();

        Some(Self {
            name,
            authorities,
            claims,
        })
    }

    pub fn has_any_authority<I, S>(&self, required: I) -> bool
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        required
            .into_iter()
            .any(|authority| self.authorities.contains(authority.as_ref()))
    }
}

fn principal_name(claims: &serde_json::Value, config: &SecurityConfig) -> Option<String> {
    claim_as_string(claims, &config.user_claim)
        .or_else(|| {
            config
                .fallback_user_claims
                .iter()
                .find_map(|claim| claim_as_string(claims, claim))
        })
        .or_else(|| claim_as_string(claims, "sub"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uses_fallback_user_claims_before_sub() {
        let config = SecurityConfig {
            user_claim: "email".into(),
            fallback_user_claims: vec!["client_id".into(), "azp".into()],
            authorities_claim: "permissions".into(),
            ..SecurityConfig::default()
        };
        let claims = json!({
            "sub": "subject",
            "client_id": "service-a",
            "permissions": ["read", "write"]
        });

        let principal = Principal::from_claims(claims, &config).unwrap();

        assert_eq!(principal.name, "service-a");
        assert!(principal.has_any_authority(["write"]));
    }
}
