use serde_json::Value;

pub fn claim_value<'a>(claims: &'a Value, claim_path: &str) -> Option<&'a Value> {
    if claim_path.is_empty() {
        return None;
    }

    let mut current = claims;
    for part in claim_path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

pub fn claim_as_string(claims: &Value, claim_path: &str) -> Option<String> {
    match claim_value(claims, claim_path)? {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub fn claim_as_string_list(claims: &Value, claim_path: &str) -> Vec<String> {
    match claim_value(claims, claim_path) {
        Some(Value::String(value)) if !value.is_empty() => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| match value {
                Value::String(value) if !value.is_empty() => Some(value.clone()),
                Value::Number(value) => Some(value.to_string()),
                Value::Bool(value) => Some(value.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_nested_claim_values() {
        let claims = json!({
            "realm_access": {
                "roles": ["admin", "writer"]
            },
            "cognito:groups": ["ops"],
            "email": "user@example.com"
        });

        assert_eq!(
            claim_as_string_list(&claims, "realm_access.roles"),
            vec!["admin", "writer"]
        );
        assert_eq!(claim_as_string_list(&claims, "cognito:groups"), vec!["ops"]);
        assert_eq!(
            claim_as_string(&claims, "email").as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn missing_or_wrong_shape_claims_are_empty() {
        let claims = json!({"realm_access": "not-a-map", "roles": {"bad": true}});

        assert!(claim_as_string_list(&claims, "realm_access.roles").is_empty());
        assert!(claim_as_string_list(&claims, "roles").is_empty());
        assert!(claim_as_string(&claims, "missing").is_none());
    }
}
