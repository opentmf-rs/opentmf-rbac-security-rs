use crate::error::ConfigError;
use http::Method;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    pub opentmf: OpenTmfConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenTmfConfig {
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecurityConfig {
    #[serde(default)]
    pub issuer_uri: Option<String>,
    #[serde(default)]
    pub jwk_set_uri: Option<String>,
    #[serde(default = "default_user_claim")]
    pub user_claim: String,
    #[serde(default)]
    pub fallback_user_claims: Vec<String>,
    #[serde(default = "default_authorities_claim")]
    pub authorities_claim: String,
    #[serde(default)]
    pub secure_endpoints: Vec<SecureEndpoint>,
    #[serde(default)]
    pub allowed_endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub blacklist: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub other_endpoints: OtherEndpoints,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            issuer_uri: None,
            jwk_set_uri: None,
            user_claim: default_user_claim(),
            fallback_user_claims: Vec::new(),
            authorities_claim: default_authorities_claim(),
            secure_endpoints: Vec::new(),
            allowed_endpoints: Vec::new(),
            blacklist: Vec::new(),
            whitelist: Vec::new(),
            other_endpoints: OtherEndpoints::Deny,
        }
    }
}

impl SecurityConfig {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ConfigError> {
        let file: ConfigFile = serde_yaml::from_str(yaml)?;
        file.opentmf.security.validate()?;
        Ok(file.opentmf.security)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for path in self.blacklist.iter().chain(self.whitelist.iter()) {
            validate_path(path)?;
        }
        for endpoint in &self.allowed_endpoints {
            validate_path(&endpoint.path)?;
        }
        for endpoint in &self.secure_endpoints {
            validate_path(&endpoint.path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OtherEndpoints {
    Allow,
    Deny,
    Authenticated,
}

impl Default for OtherEndpoints {
    fn default() -> Self {
        Self::Deny
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    #[serde(with = "method_serde")]
    pub method: Method,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureEndpoint {
    #[serde(with = "method_serde")]
    pub method: Method,
    pub path: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

impl SecureEndpoint {
    pub fn as_endpoint(&self) -> Endpoint {
        Endpoint {
            method: self.method.clone(),
            path: self.path.clone(),
        }
    }
}

fn default_user_claim() -> String {
    "sub".to_string()
}

fn default_authorities_claim() -> String {
    "roles".to_string()
}

fn validate_path(path: &str) -> Result<(), ConfigError> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(ConfigError::InvalidPath(path.to_string()))
    }
}

mod method_serde {
    use http::Method;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(method: &Method, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(method.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Method, D::Error>
    where
        D: Deserializer<'de>,
    {
        let method = String::deserialize(deserializer)?;
        method
            .to_ascii_uppercase()
            .parse::<Method>()
            .map_err(|error| serde::de::Error::custom(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_opentmf_defaults() {
        let config = SecurityConfig::default();

        assert_eq!(config.user_claim, "sub");
        assert_eq!(config.authorities_claim, "roles");
        assert_eq!(config.other_endpoints, OtherEndpoints::Deny);
        assert!(config.issuer_uri.is_none());
        assert!(config.jwk_set_uri.is_none());
        assert!(config.secure_endpoints.is_empty());
        assert!(config.allowed_endpoints.is_empty());
        assert!(config.blacklist.is_empty());
        assert!(config.whitelist.is_empty());
    }

    #[test]
    fn parses_opentmf_yaml_shape() {
        let yaml = r#"
opentmf:
  security:
    jwk-set-uri: https://issuer.example.com/jwks
    user-claim: email
    fallback-user-claims: [client_id, azp, sub]
    authorities-claim: permissions
    secure-endpoints:
      - method: POST
        path: /orders
        roles: [order:write, admin]
    whitelist:
      - /health
    other-endpoints: authenticated
"#;

        let config = SecurityConfig::from_yaml_str(yaml).unwrap();

        assert_eq!(
            config.jwk_set_uri.as_deref(),
            Some("https://issuer.example.com/jwks")
        );
        assert_eq!(config.user_claim, "email");
        assert_eq!(config.authorities_claim, "permissions");
        assert_eq!(config.secure_endpoints[0].method, Method::POST);
        assert_eq!(config.other_endpoints, OtherEndpoints::Authenticated);
    }

    #[test]
    fn parses_lowercase_http_methods_from_yaml() {
        let yaml = r#"
opentmf:
  security:
    allowed-endpoints:
      - method: get
        path: /catalog/**
    secure-endpoints:
      - method: post
        path: /orders
        roles: [writer]
"#;

        let config = SecurityConfig::from_yaml_str(yaml).unwrap();

        assert_eq!(config.allowed_endpoints[0].method, Method::GET);
        assert_eq!(config.secure_endpoints[0].method, Method::POST);
    }

    #[test]
    fn rejects_invalid_paths_in_all_endpoint_groups() {
        let invalid_configs = [
            SecurityConfig {
                blacklist: vec!["admin/**".into()],
                ..SecurityConfig::default()
            },
            SecurityConfig {
                whitelist: vec!["health".into()],
                ..SecurityConfig::default()
            },
            SecurityConfig {
                allowed_endpoints: vec![Endpoint {
                    method: Method::GET,
                    path: "catalog/**".into(),
                }],
                ..SecurityConfig::default()
            },
            SecurityConfig {
                secure_endpoints: vec![SecureEndpoint {
                    method: Method::POST,
                    path: "orders".into(),
                    roles: vec!["writer".into()],
                }],
                ..SecurityConfig::default()
            },
        ];

        for config in invalid_configs {
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidPath(_))
            ));
        }
    }

    #[test]
    fn secure_endpoint_can_be_viewed_as_endpoint() {
        let secure = SecureEndpoint {
            method: Method::PATCH,
            path: "/orders/*".into(),
            roles: vec!["writer".into()],
        };

        let endpoint = secure.as_endpoint();

        assert_eq!(endpoint.method, Method::PATCH);
        assert_eq!(endpoint.path, "/orders/*");
    }

    #[test]
    fn malformed_yaml_returns_parse_error() {
        let error = SecurityConfig::from_yaml_str("opentmf: [").unwrap_err();

        assert!(matches!(error, ConfigError::Yaml(_)));
    }
}
