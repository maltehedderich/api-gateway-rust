use api_gateway_rust::auth::{SessionData, TokenValidator};
use api_gateway_rust::config::{AuthConfig, SessionStoreConfig, TokenCacheConfig};
use chrono::Utc;
use redis::AsyncCommands;
use std::sync::Arc;

/// Helper function to create a test auth config for JWT tokens
fn create_jwt_auth_config() -> AuthConfig {
    AuthConfig {
        token_format: "jwt".to_string(),
        jwt_secret: Some("test-secret-key-for-testing-purposes".to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: Some("test-issuer".to_string()),
        jwt_audience: Some("test-audience".to_string()),
        session_store: None,
        cache: Some(TokenCacheConfig {
            enabled: true,
            max_capacity: 100,
            ttl_secs: 300,
        }),
    }
}

/// Helper function to create a test auth config for opaque tokens
fn create_opaque_auth_config(redis_url: String) -> AuthConfig {
    AuthConfig {
        token_format: "opaque".to_string(),
        jwt_secret: None,
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
        session_store: Some(SessionStoreConfig {
            redis_url,
            key_prefix: "session:".to_string(),
            failure_mode: "fail_closed".to_string(),
        }),
        cache: Some(TokenCacheConfig {
            enabled: true,
            max_capacity: 100,
            ttl_secs: 60,
        }),
    }
}

/// Helper function to create a JWT token for testing
fn create_test_jwt() -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        username: String,
        iss: String,
        aud: String,
        exp: usize,
        roles: Vec<String>,
        permissions: Vec<String>,
    }

    let claims = TestClaims {
        sub: "user123".to_string(),
        username: "testuser".to_string(),
        iss: "test-issuer".to_string(),
        aud: "test-audience".to_string(),
        exp: (Utc::now().timestamp() + 3600) as usize,
        roles: vec!["admin".to_string()],
        permissions: vec!["read".to_string(), "write".to_string()],
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret-key-for-testing-purposes".as_bytes());

    encode(&header, &claims, &key).unwrap()
}

#[tokio::test]
async fn test_jwt_token_validation() {
    let auth_config = create_jwt_auth_config();
    let validator = TokenValidator::new(Arc::new(auth_config))
        .await
        .expect("Failed to create token validator");

    let token = create_test_jwt();
    let result = validator.validate_token(&token).await;

    assert!(result.is_ok(), "JWT validation should succeed");
    let user_context = result.unwrap();
    assert_eq!(user_context.user_id, "user123");
    assert_eq!(user_context.username, Some("testuser".to_string()));
    assert_eq!(user_context.roles, vec!["admin".to_string()]);
}

#[tokio::test]
async fn test_jwt_token_validation_with_cache() {
    let auth_config = create_jwt_auth_config();
    let validator = Arc::new(
        TokenValidator::new(Arc::new(auth_config))
            .await
            .expect("Failed to create token validator"),
    );

    let token = create_test_jwt();

    // First validation - should hit the validator
    let result1 = validator.validate_token(&token).await;
    assert!(result1.is_ok(), "First JWT validation should succeed");

    // Second validation - should hit the cache
    let result2 = validator.validate_token(&token).await;
    assert!(result2.is_ok(), "Second JWT validation should succeed (from cache)");

    let user_context = result2.unwrap();
    assert_eq!(user_context.user_id, "user123");
}

#[tokio::test]
async fn test_invalid_jwt_token() {
    let auth_config = create_jwt_auth_config();
    let validator = TokenValidator::new(Arc::new(auth_config))
        .await
        .expect("Failed to create token validator");

    let invalid_token = "invalid.jwt.token";
    let result = validator.validate_token(invalid_token).await;

    assert!(result.is_err(), "Invalid JWT should fail validation");
}

// Test opaque token validation (requires Redis)
#[tokio::test]
#[ignore] // Ignore by default as it requires Redis
async fn test_opaque_token_validation() {
    // This test requires a running Redis instance
    let redis_url = "redis://127.0.0.1:6379".to_string();

    // Try to connect to Redis first
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(_) => {
            println!("Skipping test: Redis not available");
            return;
        }
    };

    let mut conn = match client.get_async_connection().await {
        Ok(c) => c,
        Err(_) => {
            println!("Skipping test: Could not connect to Redis");
            return;
        }
    };

    // Set up test session data in Redis
    let token = "test-opaque-token-123";
    let session_data = SessionData {
        user_id: "user456".to_string(),
        username: Some("opaqueuser".to_string()),
        roles: vec!["user".to_string()],
        permissions: vec!["read".to_string()],
        created_at: Utc::now().timestamp(),
        expires_at: Utc::now().timestamp() + 3600,
        extra: serde_json::json!({}),
    };

    let session_json = serde_json::to_string(&session_data).unwrap();
    let redis_key = format!("session:{}", token);

    // Store session in Redis
    let _: () = conn.set(&redis_key, session_json).await.unwrap();

    // Create validator
    let auth_config = create_opaque_auth_config(redis_url);
    let validator = TokenValidator::new(Arc::new(auth_config))
        .await
        .expect("Failed to create token validator");

    // Validate the opaque token
    let result = validator.validate_token(token).await;
    assert!(result.is_ok(), "Opaque token validation should succeed");

    let user_context = result.unwrap();
    assert_eq!(user_context.user_id, "user456");
    assert_eq!(user_context.username, Some("opaqueuser".to_string()));

    // Clean up
    let _: () = conn.del(&redis_key).await.unwrap();
}

#[tokio::test]
#[ignore] // Ignore by default as it requires Redis
async fn test_opaque_token_expired() {
    let redis_url = "redis://127.0.0.1:6379".to_string();

    // Try to connect to Redis first
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(_) => {
            println!("Skipping test: Redis not available");
            return;
        }
    };

    let mut conn = match client.get_async_connection().await {
        Ok(c) => c,
        Err(_) => {
            println!("Skipping test: Could not connect to Redis");
            return;
        }
    };

    // Set up expired session data in Redis
    let token = "test-expired-token-456";
    let session_data = SessionData {
        user_id: "user789".to_string(),
        username: Some("expireduser".to_string()),
        roles: vec!["user".to_string()],
        permissions: vec!["read".to_string()],
        created_at: Utc::now().timestamp() - 7200,
        expires_at: Utc::now().timestamp() - 3600, // Expired 1 hour ago
        extra: serde_json::json!({}),
    };

    let session_json = serde_json::to_string(&session_data).unwrap();
    let redis_key = format!("session:{}", token);

    // Store expired session in Redis
    let _: () = conn.set(&redis_key, session_json).await.unwrap();

    // Create validator
    let auth_config = create_opaque_auth_config(redis_url);
    let validator = TokenValidator::new(Arc::new(auth_config))
        .await
        .expect("Failed to create token validator");

    // Validate the expired opaque token
    let result = validator.validate_token(token).await;
    assert!(result.is_err(), "Expired opaque token should fail validation");

    // Clean up
    let _: () = conn.del(&redis_key).await.unwrap();
}

#[tokio::test]
async fn test_token_cache_invalidation() {
    let auth_config = create_jwt_auth_config();
    let validator = Arc::new(
        TokenValidator::new(Arc::new(auth_config))
            .await
            .expect("Failed to create token validator"),
    );

    let token = create_test_jwt();

    // Validate and cache the token
    let result1 = validator.validate_token(&token).await;
    assert!(result1.is_ok());

    // Invalidate the token
    validator.invalidate_token(&token).await;

    // The token should still validate (it's still valid, just not in cache)
    let result2 = validator.validate_token(&token).await;
    assert!(result2.is_ok());
}
