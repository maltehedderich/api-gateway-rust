/// Comprehensive tests for the rate limiter module
///
/// These tests verify:
/// - Key construction for different key types
/// - Rate limit decision making
/// - Header generation
/// - Failure modes
use api_gateway_rust::rate_limiter::{
    add_rate_limit_headers, KeyType, RateLimitContext, RateLimitDecision,
};
use axum::http::HeaderMap;

#[test]
fn test_rate_limit_context_creation() {
    let context = RateLimitContext {
        client_ip: "192.168.1.100".to_string(),
        user_id: Some("user123".to_string()),
        route_id: "POST /api/orders".to_string(),
    };

    assert_eq!(context.client_ip, "192.168.1.100");
    assert_eq!(context.user_id, Some("user123".to_string()));
    assert_eq!(context.route_id, "POST /api/orders");
}

#[test]
fn test_rate_limit_context_without_user() {
    let context = RateLimitContext {
        client_ip: "203.0.113.42".to_string(),
        user_id: None,
        route_id: "GET /api/public".to_string(),
    };

    assert_eq!(context.client_ip, "203.0.113.42");
    assert!(context.user_id.is_none());
}

#[test]
fn test_key_type_parsing() {
    // Valid key types
    assert_eq!(KeyType::from_string("ip").unwrap(), KeyType::Ip);
    assert_eq!(KeyType::from_string("user").unwrap(), KeyType::User);
    assert_eq!(KeyType::from_string("endpoint").unwrap(), KeyType::Endpoint);
    assert_eq!(
        KeyType::from_string("user_endpoint").unwrap(),
        KeyType::UserEndpoint
    );
    assert_eq!(
        KeyType::from_string("ip_endpoint").unwrap(),
        KeyType::IpEndpoint
    );

    // Invalid key type
    let result = KeyType::from_string("invalid_type");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid key type"));
}

#[test]
fn test_key_type_case_sensitivity() {
    // Key types should be case-sensitive
    let result = KeyType::from_string("IP");
    assert!(result.is_err());

    let result = KeyType::from_string("User");
    assert!(result.is_err());
}

#[test]
fn test_rate_limit_decision_allowed() {
    let decision = RateLimitDecision {
        allowed: true,
        current_count: 50,
        limit: 100,
        reset_at: 1700000000,
        remaining: 50,
        retry_after_secs: 0,
    };

    assert!(decision.allowed);
    assert_eq!(decision.current_count, 50);
    assert_eq!(decision.limit, 100);
    assert_eq!(decision.remaining, 50);
    assert_eq!(decision.retry_after_secs, 0);
}

#[test]
fn test_rate_limit_decision_denied() {
    let decision = RateLimitDecision {
        allowed: false,
        current_count: 100,
        limit: 100,
        reset_at: 1700000060,
        remaining: 0,
        retry_after_secs: 60,
    };

    assert!(!decision.allowed);
    assert_eq!(decision.current_count, 100);
    assert_eq!(decision.limit, 100);
    assert_eq!(decision.remaining, 0);
    assert_eq!(decision.retry_after_secs, 60);
}

#[test]
fn test_add_rate_limit_headers_allowed() {
    let decision = RateLimitDecision {
        allowed: true,
        current_count: 75,
        limit: 100,
        reset_at: 1700000000,
        remaining: 25,
        retry_after_secs: 0,
    };

    let mut headers = HeaderMap::new();
    add_rate_limit_headers(&mut headers, &decision);

    assert_eq!(headers.get("X-RateLimit-Limit").unwrap(), "100");
    assert_eq!(headers.get("X-RateLimit-Remaining").unwrap(), "25");
    assert_eq!(headers.get("X-RateLimit-Reset").unwrap(), "1700000000");

    // Retry-After should not be present for allowed requests
    assert!(headers.get("Retry-After").is_none());
}

#[test]
fn test_add_rate_limit_headers_denied() {
    let decision = RateLimitDecision {
        allowed: false,
        current_count: 100,
        limit: 100,
        reset_at: 1700000120,
        remaining: 0,
        retry_after_secs: 120,
    };

    let mut headers = HeaderMap::new();
    add_rate_limit_headers(&mut headers, &decision);

    assert_eq!(headers.get("X-RateLimit-Limit").unwrap(), "100");
    assert_eq!(headers.get("X-RateLimit-Remaining").unwrap(), "0");
    assert_eq!(headers.get("X-RateLimit-Reset").unwrap(), "1700000120");

    // Retry-After should be present for denied requests
    assert_eq!(headers.get("Retry-After").unwrap(), "120");
}

#[test]
fn test_add_rate_limit_headers_at_limit() {
    // Test the edge case where we're at the limit (last request)
    let decision = RateLimitDecision {
        allowed: true,
        current_count: 100,
        limit: 100,
        reset_at: 1700000060,
        remaining: 0,
        retry_after_secs: 0,
    };

    let mut headers = HeaderMap::new();
    add_rate_limit_headers(&mut headers, &decision);

    assert_eq!(headers.get("X-RateLimit-Limit").unwrap(), "100");
    assert_eq!(headers.get("X-RateLimit-Remaining").unwrap(), "0");
    assert!(headers.get("Retry-After").is_none());
}

#[test]
fn test_add_rate_limit_headers_multiple_calls() {
    // Test that headers can be updated/replaced
    let decision1 = RateLimitDecision {
        allowed: true,
        current_count: 50,
        limit: 100,
        reset_at: 1700000000,
        remaining: 50,
        retry_after_secs: 0,
    };

    let mut headers = HeaderMap::new();
    add_rate_limit_headers(&mut headers, &decision1);
    assert_eq!(headers.get("X-RateLimit-Remaining").unwrap(), "50");

    // Update with new decision
    let decision2 = RateLimitDecision {
        allowed: true,
        current_count: 51,
        limit: 100,
        reset_at: 1700000000,
        remaining: 49,
        retry_after_secs: 0,
    };

    add_rate_limit_headers(&mut headers, &decision2);
    assert_eq!(headers.get("X-RateLimit-Remaining").unwrap(), "49");
}

#[test]
fn test_rate_limit_decision_clone() {
    let decision = RateLimitDecision {
        allowed: true,
        current_count: 50,
        limit: 100,
        reset_at: 1700000000,
        remaining: 50,
        retry_after_secs: 0,
    };

    let cloned = decision.clone();
    assert_eq!(decision.allowed, cloned.allowed);
    assert_eq!(decision.current_count, cloned.current_count);
    assert_eq!(decision.limit, cloned.limit);
    assert_eq!(decision.remaining, cloned.remaining);
}

#[test]
fn test_rate_limit_context_clone() {
    let context = RateLimitContext {
        client_ip: "192.168.1.100".to_string(),
        user_id: Some("user123".to_string()),
        route_id: "POST /api/orders".to_string(),
    };

    let cloned = context.clone();
    assert_eq!(context.client_ip, cloned.client_ip);
    assert_eq!(context.user_id, cloned.user_id);
    assert_eq!(context.route_id, cloned.route_id);
}

#[test]
fn test_key_type_equality() {
    assert_eq!(KeyType::Ip, KeyType::Ip);
    assert_eq!(KeyType::User, KeyType::User);
    assert_ne!(KeyType::Ip, KeyType::User);
    assert_ne!(KeyType::Endpoint, KeyType::UserEndpoint);
}

#[test]
fn test_rate_limit_decision_with_zero_limit() {
    // Edge case: zero limit (should effectively deny all requests)
    let decision = RateLimitDecision {
        allowed: false,
        current_count: 0,
        limit: 0,
        reset_at: 1700000000,
        remaining: 0,
        retry_after_secs: 60,
    };

    let mut headers = HeaderMap::new();
    add_rate_limit_headers(&mut headers, &decision);

    assert_eq!(headers.get("X-RateLimit-Limit").unwrap(), "0");
    assert_eq!(headers.get("X-RateLimit-Remaining").unwrap(), "0");
}

#[test]
fn test_rate_limit_decision_large_numbers() {
    // Test with large limit values
    let decision = RateLimitDecision {
        allowed: true,
        current_count: 500000,
        limit: 1000000,
        reset_at: 1700000000,
        remaining: 500000,
        retry_after_secs: 0,
    };

    let mut headers = HeaderMap::new();
    add_rate_limit_headers(&mut headers, &decision);

    assert_eq!(headers.get("X-RateLimit-Limit").unwrap(), "1000000");
    assert_eq!(headers.get("X-RateLimit-Remaining").unwrap(), "500000");
}

#[test]
fn test_rate_limit_context_with_special_characters() {
    // Test that context handles special characters in route IDs
    let context = RateLimitContext {
        client_ip: "192.168.1.100".to_string(),
        user_id: Some("user@example.com".to_string()),
        route_id: "POST /api/v1/users/{id}/orders".to_string(),
    };

    assert!(context.route_id.contains("{id}"));
    assert!(context.user_id.unwrap().contains("@"));
}

#[test]
fn test_rate_limit_context_with_ipv6() {
    // Test IPv6 addresses
    let context = RateLimitContext {
        client_ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
        user_id: None,
        route_id: "GET /api/data".to_string(),
    };

    assert!(context.client_ip.contains(":"));
    assert_eq!(context.client_ip.len(), 39); // Full IPv6 address
}
