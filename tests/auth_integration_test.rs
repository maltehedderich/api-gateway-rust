use api_gateway_rust::auth::UserContext;
use api_gateway_rust::config::AuthConfig;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    username: Option<String>,
    roles: Vec<String>,
    permissions: Vec<String>,
    exp: usize,
    iat: Option<usize>,
    iss: Option<String>,
    aud: Option<String>,
}

/// Helper function to create a test JWT token
fn create_test_token(
    user_id: &str,
    roles: Vec<String>,
    permissions: Vec<String>,
    secret: &str,
    expired: bool,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let exp = if expired {
        now - 3600 // Expired 1 hour ago
    } else {
        now + 3600 // Expires in 1 hour
    };

    let claims = TestClaims {
        sub: user_id.to_string(),
        username: Some(format!("user_{}", user_id)),
        roles,
        permissions,
        exp,
        iat: Some(now),
        iss: None,
        aud: None,
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode token")
}

/// Helper function to create a token with issuer and audience claims
fn create_token_with_claims(
    user_id: &str,
    roles: Vec<String>,
    permissions: Vec<String>,
    secret: &str,
    issuer: Option<String>,
    audience: Option<String>,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = TestClaims {
        sub: user_id.to_string(),
        username: Some(format!("user_{}", user_id)),
        roles,
        permissions,
        exp: now + 3600,
        iat: Some(now),
        iss: issuer,
        aud: audience,
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode token")
}

#[test]
fn test_authentication_flow_success() {
    let secret = "test-secret-key-for-integration-testing";
    let user_id = "user123";
    let roles = vec!["user".to_string(), "admin".to_string()];
    let permissions = vec!["read".to_string(), "write".to_string()];

    let token = create_test_token(user_id, roles.clone(), permissions.clone(), secret, false);

    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
    };

    let result = api_gateway_rust::auth::validate_jwt_token(&token, &auth_config);
    assert!(result.is_ok(), "Authentication should succeed");

    let user_context = result.unwrap();
    assert_eq!(user_context.user_id, user_id);
    assert_eq!(user_context.roles, roles);
    assert_eq!(user_context.permissions, permissions);
}

#[test]
fn test_authentication_flow_expired_token() {
    let secret = "test-secret-key-for-integration-testing";
    let user_id = "user123";
    let roles = vec!["user".to_string()];
    let permissions = vec!["read".to_string()];

    let token = create_test_token(user_id, roles, permissions, secret, true);

    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
    };

    let result = api_gateway_rust::auth::validate_jwt_token(&token, &auth_config);
    assert!(result.is_err(), "Expired token should fail validation");
}

#[test]
fn test_authentication_with_issuer_validation() {
    let secret = "test-secret-key-for-integration-testing";
    let user_id = "user123";
    let expected_issuer = "https://auth.example.com";

    let token = create_token_with_claims(
        user_id,
        vec!["user".to_string()],
        vec![],
        secret,
        Some(expected_issuer.to_string()),
        None,
    );

    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: Some(expected_issuer.to_string()),
        jwt_audience: None,
    };

    let result = api_gateway_rust::auth::validate_jwt_token(&token, &auth_config);
    assert!(result.is_ok(), "Token with correct issuer should validate");

    // Test with wrong issuer
    let wrong_token = create_token_with_claims(
        user_id,
        vec!["user".to_string()],
        vec![],
        secret,
        Some("https://wrong-issuer.com".to_string()),
        None,
    );

    let result = api_gateway_rust::auth::validate_jwt_token(&wrong_token, &auth_config);
    assert!(
        result.is_err(),
        "Token with wrong issuer should fail validation"
    );
}

#[test]
fn test_authentication_with_audience_validation() {
    let secret = "test-secret-key-for-integration-testing";
    let user_id = "user123";
    let expected_audience = "api-gateway";

    let token = create_token_with_claims(
        user_id,
        vec!["user".to_string()],
        vec![],
        secret,
        None,
        Some(expected_audience.to_string()),
    );

    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: Some(expected_audience.to_string()),
    };

    let result = api_gateway_rust::auth::validate_jwt_token(&token, &auth_config);
    assert!(
        result.is_ok(),
        "Token with correct audience should validate"
    );

    // Test with wrong audience
    let wrong_token = create_token_with_claims(
        user_id,
        vec!["user".to_string()],
        vec![],
        secret,
        None,
        Some("wrong-audience".to_string()),
    );

    let result = api_gateway_rust::auth::validate_jwt_token(&wrong_token, &auth_config);
    assert!(
        result.is_err(),
        "Token with wrong audience should fail validation"
    );
}

#[test]
fn test_rbac_authorization() {
    // Test that a user with 'admin' role can access admin routes
    let user_context = UserContext {
        user_id: "user123".to_string(),
        username: Some("admin_user".to_string()),
        roles: vec!["admin".to_string(), "user".to_string()],
        permissions: vec![],
        extra: serde_json::json!({}),
    };

    let required_roles = ["admin".to_string()];

    // User has admin role, should pass
    let has_role = user_context
        .roles
        .iter()
        .any(|role| required_roles.contains(role));
    assert!(has_role, "User with admin role should be authorized");

    // Test user without required role
    let user_context_no_role = UserContext {
        user_id: "user456".to_string(),
        username: Some("regular_user".to_string()),
        roles: vec!["user".to_string()],
        permissions: vec![],
        extra: serde_json::json!({}),
    };

    let has_role = user_context_no_role
        .roles
        .iter()
        .any(|role| required_roles.contains(role));
    assert!(
        !has_role,
        "User without admin role should not be authorized"
    );
}

#[test]
fn test_pbac_authorization() {
    // Test permission-based access control
    let user_context = UserContext {
        user_id: "user123".to_string(),
        username: Some("test_user".to_string()),
        roles: vec![],
        permissions: vec!["orders:create".to_string(), "orders:read".to_string()],
        extra: serde_json::json!({}),
    };

    let required_permissions = ["orders:create".to_string()];

    // User has required permission
    let has_all = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));
    assert!(has_all, "User should have required permission");

    // Test user without all required permissions
    let required_multiple = ["orders:create".to_string(), "orders:delete".to_string()];

    let has_all = required_multiple
        .iter()
        .all(|perm| user_context.permissions.contains(perm));
    assert!(
        !has_all,
        "User should not have all required permissions (missing orders:delete)"
    );
}

#[test]
fn test_combined_rbac_and_pbac() {
    // Test combined role and permission checks
    let user_context = UserContext {
        user_id: "user123".to_string(),
        username: Some("admin_user".to_string()),
        roles: vec!["admin".to_string()],
        permissions: vec!["data:delete".to_string()],
        extra: serde_json::json!({}),
    };

    let required_roles = ["admin".to_string()];
    let required_permissions = ["data:delete".to_string()];

    let has_role = user_context
        .roles
        .iter()
        .any(|role| required_roles.contains(role));
    let has_permissions = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));

    assert!(
        has_role && has_permissions,
        "User should have both required role and permission"
    );

    // Test user with role but not permission
    let user_context_no_perm = UserContext {
        user_id: "user456".to_string(),
        username: Some("admin_no_perm".to_string()),
        roles: vec!["admin".to_string()],
        permissions: vec![],
        extra: serde_json::json!({}),
    };

    let has_role = user_context_no_perm
        .roles
        .iter()
        .any(|role| required_roles.contains(role));
    let has_permissions = required_permissions
        .iter()
        .all(|perm| user_context_no_perm.permissions.contains(perm));

    assert!(
        has_role && !has_permissions,
        "User should have role but not permission"
    );
}

#[test]
fn test_user_context_serialization() {
    // Test that UserContext can be serialized and deserialized correctly
    let user_context = UserContext {
        user_id: "user123".to_string(),
        username: Some("test_user".to_string()),
        roles: vec!["admin".to_string(), "user".to_string()],
        permissions: vec!["read".to_string(), "write".to_string()],
        extra: serde_json::json!({
            "tenant_id": "tenant123",
            "plan": "premium"
        }),
    };

    let json = serde_json::to_string(&user_context).expect("Failed to serialize");
    let deserialized: UserContext = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(user_context.user_id, deserialized.user_id);
    assert_eq!(user_context.username, deserialized.username);
    assert_eq!(user_context.roles, deserialized.roles);
    assert_eq!(user_context.permissions, deserialized.permissions);
}

#[test]
fn test_invalid_token_signature() {
    let secret = "correct-secret";
    let wrong_secret = "wrong-secret";

    let token = create_test_token("user123", vec!["user".to_string()], vec![], secret, false);

    let auth_config = AuthConfig {
        jwt_secret: Some(wrong_secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
    };

    let result = api_gateway_rust::auth::validate_jwt_token(&token, &auth_config);
    assert!(
        result.is_err(),
        "Token with invalid signature should fail validation"
    );
}
