/// Security hardening tests
///
/// This module tests security features including:
/// - Security headers
/// - Sensitive data redaction
/// - TLS configuration
/// - Input validation
///
/// NOTE: This file contains TEST FIXTURES ONLY - not real secrets.
/// The tokens, API keys, and credentials below are intentionally fake
/// and used to test the security redaction functionality.
use api_gateway_rust::logging::{
    is_sensitive_header, redact_auth_header, redact_cookie, redact_ip_address,
    redact_sensitive_data,
};

#[test]
fn test_redact_bearer_token_full() {
    // ggshield:ignore - This is a test fixture, not a real secret
    let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let output = redact_sensitive_data(input);

    // Should keep first 4 characters after "Bearer "
    assert!(output.contains("Bearer eyJh"));
    assert!(output.contains("[REDACTED]"));
    // Should not contain the full token
    assert!(!output
        .contains("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"));
}

#[test]
fn test_redact_api_key_in_query() {
    // ggshield:ignore - This is a test fixture, not a real API key
    let input = "GET /api/users?api_key=test_key_1234567890abcdefghijklmnop";
    let output = redact_sensitive_data(input);

    assert!(output.contains("api_key=[REDACTED]"));
    assert!(!output.contains("test_key_1234567890abcdefghijklmnop"));
}

#[test]
fn test_redact_api_key_in_header() {
    // ggshield:ignore - This is a test fixture, not a real API key
    let input = "X-API-Key: test_header_abcdefghijklmnopqrstuvwxyz123456";
    let output = redact_sensitive_data(input);

    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("test_header_abcdefghijklmnopqrstuvwxyz123456"));
}

#[test]
fn test_redact_password_json() {
    let input = r#"{"username": "admin", "password": "super_secret_pass_123!"}"#;
    let output = redact_sensitive_data(input);

    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("super_secret_pass_123!"));
}

#[test]
fn test_redact_password_form() {
    let input = "username=admin&password=my_secure_password_2024";
    let output = redact_sensitive_data(input);

    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("my_secure_password_2024"));
}

#[test]
fn test_redact_email_address() {
    let input = "User email: john.doe@example.com requested access";
    let output = redact_sensitive_data(input);

    // Should keep first character and domain
    assert!(output.contains("j***@example.com"));
    assert!(!output.contains("john.doe@example.com"));
}

#[test]
fn test_redact_multiple_emails() {
    let input = "From: alice@company.com To: bob@company.com";
    let output = redact_sensitive_data(input);

    assert!(output.contains("a***@company.com"));
    assert!(output.contains("b***@company.com"));
    assert!(!output.contains("alice@company.com"));
    assert!(!output.contains("bob@company.com"));
}

#[test]
fn test_redact_session_token() {
    let input = "session_token=abc123def456ghi789jkl012mno345pqr678";
    let output = redact_sensitive_data(input);

    assert!(output.contains("session_token=[REDACTED]"));
    assert!(!output.contains("abc123def456ghi789jkl012mno345pqr678"));
}

#[test]
fn test_redact_multiple_sensitive_fields() {
    // ggshield:ignore - These are test fixtures, not real secrets
    let input = r#"{
        "email": "user@example.com",
        "password": "secret123",
        "api_key": "testkey_abc123",
        "session_token": "sess_abc123"
    }"#;
    let output = redact_sensitive_data(input);

    // Email should be partially redacted
    assert!(output.contains("u***@example.com"));

    // Password should be fully redacted
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("secret123"));

    // API key should be fully redacted
    assert!(!output.contains("testkey_abc123"));

    // Session token should be fully redacted
    assert!(!output.contains("sess_abc123"));
}

#[test]
fn test_redact_auth_header_function() {
    let value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
    let output = redact_auth_header(value);

    assert!(output.contains("Bearer eyJh"));
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("payload.signature"));
}

#[test]
fn test_redact_short_auth_header() {
    let value = "Bearer abc";
    let output = redact_auth_header(value);

    assert_eq!(output, "Bearer [REDACTED]");
}

#[test]
fn test_redact_cookie_long() {
    let value = "session_abc123def456ghi789jkl012";
    let output = redact_cookie(value);

    assert_eq!(output, "sess...[REDACTED]");
    assert!(!output.contains("abc123def456ghi789jkl012"));
}

#[test]
fn test_redact_cookie_short() {
    let value = "abc";
    let output = redact_cookie(value);

    assert_eq!(output, "[REDACTED]");
}

#[test]
fn test_redact_ip_address_ipv4() {
    let ip = "192.168.1.100";
    let output = redact_ip_address(ip);

    assert_eq!(output, "192.168.XXX.XXX");
}

#[test]
fn test_redact_ip_address_public() {
    let ip = "203.0.113.42";
    let output = redact_ip_address(ip);

    assert_eq!(output, "203.0.XXX.XXX");
}

#[test]
fn test_redact_ip_address_ipv6() {
    let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let output = redact_ip_address(ip);

    // IPv6 should be fully redacted
    assert_eq!(output, "XXX.XXX.XXX.XXX");
}

#[test]
fn test_is_sensitive_header_authorization() {
    assert!(is_sensitive_header("Authorization"));
    assert!(is_sensitive_header("authorization"));
    assert!(is_sensitive_header("AUTHORIZATION"));
}

#[test]
fn test_is_sensitive_header_cookie() {
    assert!(is_sensitive_header("Cookie"));
    assert!(is_sensitive_header("cookie"));
    assert!(is_sensitive_header("Set-Cookie"));
    assert!(is_sensitive_header("set-cookie"));
}

#[test]
fn test_is_sensitive_header_api_key() {
    assert!(is_sensitive_header("X-API-Key"));
    assert!(is_sensitive_header("x-api-key"));
}

#[test]
fn test_is_sensitive_header_tokens() {
    assert!(is_sensitive_header("X-Auth-Token"));
    assert!(is_sensitive_header("X-Session-Token"));
    assert!(is_sensitive_header("x-auth-token"));
    assert!(is_sensitive_header("x-session-token"));
}

#[test]
fn test_is_sensitive_header_safe_headers() {
    assert!(!is_sensitive_header("Content-Type"));
    assert!(!is_sensitive_header("Accept"));
    assert!(!is_sensitive_header("User-Agent"));
    assert!(!is_sensitive_header("X-Request-ID"));
    assert!(!is_sensitive_header("X-Correlation-ID"));
}

#[test]
fn test_redact_preserves_non_sensitive_data() {
    let input = "GET /api/users?page=1&limit=10 HTTP/1.1";
    let output = redact_sensitive_data(input);

    // Should preserve query parameters that are not sensitive
    assert_eq!(output, input);
}

#[test]
fn test_redact_mixed_content() {
    let input = "Request to /api/login with email=user@example.com password=secret123 from IP 192.168.1.100";
    let output = redact_sensitive_data(input);

    // Email should be partially redacted
    assert!(output.contains("u***@example.com"));

    // Password should be redacted
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("secret123"));

    // IP address should remain (redaction is optional and applied separately)
    assert!(output.contains("192.168.1.100"));
}

#[test]
fn test_redact_log_message() {
    // ggshield:ignore - These are test fixtures, not real secrets
    let input = r#"
        INFO Request received
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
        Cookie: session_token=abc123def456
        User email: admin@company.com
        Query: api_key=testkey_abc123
    "#;
    let output = redact_sensitive_data(input);

    // Check that all sensitive data is redacted
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("payload.signature"));
    assert!(!output.contains("abc123def456"));
    assert!(!output.contains("testkey_abc123"));

    // Email should be partially redacted
    assert!(output.contains("a***@company.com"));
}

// Note: TLS configuration validation tests are in src/config.rs since they
// require actual certificate files to be present. The config module has unit
// tests that properly test TLS version validation.
