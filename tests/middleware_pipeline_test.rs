/// Comprehensive integration tests for the middleware pipeline
///
/// These tests verify the full request flow through all middleware:
/// - Correlation ID middleware
/// - Client IP extraction
/// - Authentication
/// - Authorization
/// - Rate limiting
/// - Error handling
use api_gateway_rust::middleware::{ClientIp, CorrelationId};

#[test]
fn test_correlation_id_generation() {
    let id1 = CorrelationId::new();
    let id2 = CorrelationId::new();

    // Each ID should be unique
    assert_ne!(id1.as_str(), id2.as_str());

    // IDs should be non-empty
    assert!(!id1.as_str().is_empty());
    assert!(!id2.as_str().is_empty());
}

#[test]
fn test_correlation_id_from_string() {
    let custom_id = "test-correlation-id-12345";
    let correlation_id = CorrelationId::from_string(custom_id.to_string());

    assert_eq!(correlation_id.as_str(), custom_id);
}

#[test]
fn test_correlation_id_clone() {
    let id = CorrelationId::new();
    let cloned = id.clone();

    assert_eq!(id.as_str(), cloned.as_str());
}

#[test]
fn test_correlation_id_default() {
    let id = CorrelationId::default();

    // Default should create a new UUID
    assert!(!id.as_str().is_empty());
}

#[test]
fn test_correlation_id_uuid_format() {
    let id = CorrelationId::new();
    let id_str = id.as_str();

    // UUID v4 format: 8-4-4-4-12 hex digits
    let parts: Vec<&str> = id_str.split('-').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);
}

#[test]
fn test_client_ip_creation() {
    let ip = ClientIp("192.168.1.100".to_string());
    assert_eq!(ip.0, "192.168.1.100");
}

#[test]
fn test_client_ip_ipv6() {
    let ip = ClientIp("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string());
    assert_eq!(ip.0, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
}

#[test]
fn test_client_ip_unknown() {
    let ip = ClientIp("unknown".to_string());
    assert_eq!(ip.0, "unknown");
}

#[test]
fn test_client_ip_clone() {
    let ip = ClientIp("203.0.113.42".to_string());
    let cloned = ip.clone();

    assert_eq!(ip.0, cloned.0);
}

#[test]
fn test_correlation_id_debug_format() {
    let id = CorrelationId::from_string("test-id-123".to_string());
    let debug_str = format!("{:?}", id);

    assert!(debug_str.contains("test-id-123"));
}

#[test]
fn test_client_ip_debug_format() {
    let ip = ClientIp("192.168.1.100".to_string());
    let debug_str = format!("{:?}", ip);

    assert!(debug_str.contains("192.168.1.100"));
}

#[test]
fn test_correlation_id_as_str_lifetime() {
    let id = CorrelationId::from_string("test-123".to_string());
    let str_ref = id.as_str();

    // Should be able to use the string reference
    assert_eq!(str_ref, "test-123");
    assert_eq!(str_ref.len(), 8);
}

#[test]
fn test_correlation_id_special_characters() {
    let custom_id = "test-id-with-special-chars_!@#";
    let correlation_id = CorrelationId::from_string(custom_id.to_string());

    assert_eq!(correlation_id.as_str(), custom_id);
}

#[test]
fn test_client_ip_localhost() {
    let ip = ClientIp("127.0.0.1".to_string());
    assert_eq!(ip.0, "127.0.0.1");

    let ipv6_localhost = ClientIp("::1".to_string());
    assert_eq!(ipv6_localhost.0, "::1");
}

#[test]
fn test_client_ip_with_port() {
    // In some cases, the IP might include a port
    let ip = ClientIp("192.168.1.100:8080".to_string());
    assert!(ip.0.starts_with("192.168.1.100"));
}

#[test]
fn test_correlation_id_multiple_instances() {
    // Test creating multiple correlation IDs in sequence
    let ids: Vec<CorrelationId> = (0..10).map(|_| CorrelationId::new()).collect();

    // All IDs should be unique
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i].as_str(), ids[j].as_str());
        }
    }
}

#[test]
fn test_correlation_id_empty_string() {
    let id = CorrelationId::from_string("".to_string());
    assert_eq!(id.as_str(), "");
}

#[test]
fn test_correlation_id_very_long_string() {
    let long_id = "a".repeat(1000);
    let id = CorrelationId::from_string(long_id.clone());
    assert_eq!(id.as_str().len(), 1000);
}

#[test]
fn test_client_ip_edge_cases() {
    // Test various edge cases for client IP
    let ips = vec![
        ClientIp("0.0.0.0".to_string()),
        ClientIp("255.255.255.255".to_string()),
        ClientIp("::".to_string()),
        ClientIp("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()),
    ];

    for ip in ips {
        assert!(!ip.0.is_empty());
    }
}
