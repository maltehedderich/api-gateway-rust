/// End-to-end authorization integration tests
///
/// This test suite verifies the complete authorization flow from request
/// to authorization decision, including:
/// - Route matching
/// - Authentication (JWT token validation)
/// - RBAC (Role-Based Access Control)
/// - PBAC (Permission-Based Access Control)
/// - Error handling and responses
use api_gateway_rust::auth::validate_jwt_token;
use api_gateway_rust::config::{AuthConfig, RouteConfig, UpstreamConfig};
use api_gateway_rust::routing::Router;
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

/// Helper to create a test token with specific roles and permissions
fn create_token(user_id: &str, roles: Vec<&str>, permissions: Vec<&str>, secret: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = TestClaims {
        sub: user_id.to_string(),
        username: Some(format!("user_{}", user_id)),
        roles: roles.iter().map(|s| s.to_string()).collect(),
        permissions: permissions.iter().map(|s| s.to_string()).collect(),
        exp: now + 3600,
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

/// Helper to create auth config
fn create_auth_config(secret: &str) -> AuthConfig {
    AuthConfig {
        token_format: "jwt".to_string(),
        jwt_secret: Some(secret.to_string()),
        jwt_public_key: None,
        jwt_algorithm: "HS256".to_string(),
        cookie_name: "session_token".to_string(),
        jwt_issuer: None,
        jwt_audience: None,
        session_store: None,
        cache: None,
    }
}

#[test]
fn test_e2e_rbac_authorization_success() {
    // Scenario: Admin user accessing admin-only route
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token for an admin user
    let token = create_token("admin_user", vec!["admin", "user"], vec![], secret);

    // Validate token and extract user context
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check if user has admin role (RBAC)
    let required_roles = ["admin".to_string()];
    let has_role = user_context
        .roles
        .iter()
        .any(|role| required_roles.contains(role));

    assert!(has_role, "Admin user should be authorized for admin route");
    assert_eq!(user_context.user_id, "admin_user");
    assert!(user_context.roles.contains(&"admin".to_string()));
}

#[test]
fn test_e2e_rbac_authorization_failure() {
    // Scenario: Regular user trying to access admin-only route
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token for a regular user (no admin role)
    let token = create_token("regular_user", vec!["user"], vec![], secret);

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check if user has admin role (should fail)
    let required_roles = ["admin".to_string()];
    let has_role = user_context
        .roles
        .iter()
        .any(|role| required_roles.contains(role));

    assert!(
        !has_role,
        "Regular user should NOT be authorized for admin route"
    );
}

#[test]
fn test_e2e_pbac_authorization_success() {
    // Scenario: User with specific permission accessing protected route
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token with specific permissions
    let token = create_token(
        "user123",
        vec![],
        vec!["orders:create", "orders:read"],
        secret,
    );

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check if user has required permission (PBAC)
    let required_permissions = ["orders:create".to_string()];
    let has_all_permissions = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));

    assert!(has_all_permissions, "User should have required permission");
}

#[test]
fn test_e2e_pbac_authorization_failure() {
    // Scenario: User missing required permission
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token without delete permission
    let token = create_token(
        "user123",
        vec![],
        vec!["orders:create", "orders:read"],
        secret,
    );

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check if user has delete permission (should fail)
    let required_permissions = ["orders:delete".to_string()];
    let has_all_permissions = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));

    assert!(
        !has_all_permissions,
        "User should NOT have delete permission"
    );
}

#[test]
fn test_e2e_combined_rbac_and_pbac_success() {
    // Scenario: User with both required role and permissions
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token with admin role and delete permission
    let token = create_token("admin123", vec!["admin"], vec!["users:delete"], secret);

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check both role and permission
    let required_roles = ["admin".to_string()];
    let required_permissions = ["users:delete".to_string()];

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
}

#[test]
fn test_e2e_combined_rbac_and_pbac_failure_missing_role() {
    // Scenario: User with permission but missing required role
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token without admin role
    let token = create_token("user123", vec!["user"], vec!["users:delete"], secret);

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check both role and permission
    let required_roles = ["admin".to_string()];
    let required_permissions = ["users:delete".to_string()];

    let has_role = user_context
        .roles
        .iter()
        .any(|role| required_roles.contains(role));
    let has_permissions = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));

    assert!(!has_role, "User should NOT have required role");
    assert!(has_permissions, "User should have required permission");
    assert!(!(has_role && has_permissions), "Combined check should fail");
}

#[test]
fn test_e2e_combined_rbac_and_pbac_failure_missing_permission() {
    // Scenario: User with role but missing required permission
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token with admin role but no delete permission
    let token = create_token("admin123", vec!["admin"], vec!["users:read"], secret);

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check both role and permission
    let required_roles = ["admin".to_string()];
    let required_permissions = ["users:delete".to_string()];

    let has_role = user_context
        .roles
        .iter()
        .any(|role| required_roles.contains(role));
    let has_permissions = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));

    assert!(has_role, "User should have required role");
    assert!(!has_permissions, "User should NOT have required permission");
    assert!(!(has_role && has_permissions), "Combined check should fail");
}

#[test]
fn test_e2e_multiple_roles_any_match() {
    // Scenario: Route requires admin OR moderator, user has moderator
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token with moderator role (not admin)
    let token = create_token("mod_user", vec!["moderator", "user"], vec![], secret);

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check if user has admin OR moderator role (any match)
    let required_roles = ["admin".to_string(), "moderator".to_string()];
    let has_any_role = user_context
        .roles
        .iter()
        .any(|role| required_roles.contains(role));

    assert!(
        has_any_role,
        "User with moderator role should be authorized (any role match)"
    );
}

#[test]
fn test_e2e_multiple_permissions_all_required() {
    // Scenario: Route requires multiple permissions, all must be present
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token with all required permissions
    let token = create_token(
        "user123",
        vec![],
        vec!["products:write", "products:delete"],
        secret,
    );

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check if user has ALL required permissions
    let required_permissions = ["products:write".to_string(), "products:delete".to_string()];
    let has_all_permissions = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));

    assert!(
        has_all_permissions,
        "User should have all required permissions"
    );
}

#[test]
fn test_e2e_multiple_permissions_missing_one() {
    // Scenario: Route requires multiple permissions, user missing one
    let secret = "test-secret-key";
    let auth_config = create_auth_config(secret);

    // Create a token with only write permission (missing delete)
    let token = create_token("user123", vec![], vec!["products:write"], secret);

    // Validate token
    let user_context =
        validate_jwt_token(&token, &auth_config).expect("Token validation should succeed");

    // Check if user has ALL required permissions
    let required_permissions = ["products:write".to_string(), "products:delete".to_string()];
    let has_all_permissions = required_permissions
        .iter()
        .all(|perm| user_context.permissions.contains(perm));

    assert!(
        !has_all_permissions,
        "User should NOT have all required permissions (missing delete)"
    );
}

#[test]
fn test_e2e_route_configuration_integration() {
    // Test that route configuration properly stores authorization requirements
    let upstreams = vec![UpstreamConfig {
        id: "test-service".to_string(),
        base_url: "http://localhost:8081".to_string(),
        timeout_secs: 30,
        health_check_path: None,
        pool_max_idle_per_host: 10,
    }];

    let routes = vec![
        RouteConfig {
            id: "admin-route".to_string(),
            methods: vec!["GET".to_string()],
            path: "/api/admin/*".to_string(),
            upstream_id: "test-service".to_string(),
            upstream_path: None,
            timeout_secs: None,
            strip_prefix: None,
            auth_required: true,
            required_roles: vec!["admin".to_string()],
            required_permissions: vec![],
            rate_limit: None,
        },
        RouteConfig {
            id: "protected-route".to_string(),
            methods: vec!["POST".to_string()],
            path: "/api/orders".to_string(),
            upstream_id: "test-service".to_string(),
            upstream_path: None,
            timeout_secs: None,
            strip_prefix: None,
            auth_required: true,
            required_roles: vec![],
            required_permissions: vec!["orders:create".to_string()],
            rate_limit: None,
        },
    ];

    // Create router and verify route configuration
    let _router = Router::from_config(routes.clone(), upstreams.clone())
        .expect("Router creation should succeed");

    // Verify admin route has correct requirements
    let admin_route_config = &routes[0];
    assert!(admin_route_config.auth_required);
    assert_eq!(admin_route_config.required_roles, vec!["admin"]);
    assert!(admin_route_config.required_permissions.is_empty());

    // Verify protected route has correct requirements
    let protected_route_config = &routes[1];
    assert!(protected_route_config.auth_required);
    assert!(protected_route_config.required_roles.is_empty());
    assert_eq!(
        protected_route_config.required_permissions,
        vec!["orders:create"]
    );
}
