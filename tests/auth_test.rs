use api_gateway_rust::auth::validate_jwt_token;
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
}

#[test]
fn test_valid_hs256_token() {
    let secret = "test-secret-key-for-testing-purposes";

    // Create auth config
    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
    };

    // Create test claims
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = TestClaims {
        sub: "user123".to_string(),
        username: Some("testuser".to_string()),
        roles: vec!["admin".to_string(), "user".to_string()],
        permissions: vec!["read".to_string(), "write".to_string()],
        exp: now + 3600, // Expires in 1 hour
        iat: Some(now),
    };

    // Encode the token
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode token");

    // Validate the token
    let result = validate_jwt_token(&token, &auth_config);
    assert!(result.is_ok(), "Token validation should succeed");

    let user_context = result.unwrap();
    assert_eq!(user_context.user_id, "user123");
    assert_eq!(user_context.username, Some("testuser".to_string()));
    assert_eq!(user_context.roles, vec!["admin", "user"]);
    assert_eq!(user_context.permissions, vec!["read", "write"]);
}

#[test]
fn test_expired_token() {
    let secret = "test-secret-key-for-testing-purposes";

    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
    };

    // Create expired claims (exp in the past)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = TestClaims {
        sub: "user123".to_string(),
        username: Some("testuser".to_string()),
        roles: vec![],
        permissions: vec![],
        exp: now - 3600, // Expired 1 hour ago
        iat: Some(now - 7200),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode token");

    // Validate the token - should fail due to expiration
    let result = validate_jwt_token(&token, &auth_config);
    assert!(result.is_err(), "Expired token validation should fail");
}

#[test]
fn test_invalid_signature() {
    let secret = "test-secret-key";
    let wrong_secret = "wrong-secret-key";

    let auth_config = AuthConfig {
        jwt_secret: Some(wrong_secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = TestClaims {
        sub: "user123".to_string(),
        username: Some("testuser".to_string()),
        roles: vec![],
        permissions: vec![],
        exp: now + 3600,
        iat: Some(now),
    };

    // Encode with one secret
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode token");

    // Try to validate with different secret - should fail
    let result = validate_jwt_token(&token, &auth_config);
    assert!(
        result.is_err(),
        "Token with invalid signature should fail validation"
    );
}

#[test]
fn test_token_with_issuer_validation() {
    let secret = "test-secret-key";
    let expected_issuer = "https://auth.example.com";

    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: Some(expected_issuer.to_string()),
        jwt_audience: None,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    #[derive(Debug, Serialize, Deserialize)]
    struct ClaimsWithIssuer {
        sub: String,
        iss: String,
        exp: usize,
        #[serde(default)]
        roles: Vec<String>,
        #[serde(default)]
        permissions: Vec<String>,
    }

    let claims = ClaimsWithIssuer {
        sub: "user123".to_string(),
        iss: expected_issuer.to_string(),
        exp: now + 3600,
        roles: vec![],
        permissions: vec![],
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode token");

    // Should succeed with correct issuer
    let result = validate_jwt_token(&token, &auth_config);
    assert!(result.is_ok(), "Token with correct issuer should validate");

    // Try with wrong issuer
    let claims_wrong_issuer = ClaimsWithIssuer {
        sub: "user123".to_string(),
        iss: "https://wrong-issuer.com".to_string(),
        exp: now + 3600,
        roles: vec![],
        permissions: vec![],
    };

    let token_wrong_issuer = encode(
        &Header::new(Algorithm::HS256),
        &claims_wrong_issuer,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode token");

    let result = validate_jwt_token(&token_wrong_issuer, &auth_config);
    assert!(
        result.is_err(),
        "Token with wrong issuer should fail validation"
    );
}
