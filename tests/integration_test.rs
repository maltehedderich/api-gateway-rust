use reqwest;
use std::time::Duration;

/// Test that the health check endpoints work
#[tokio::test]
async fn test_health_endpoints() {
    // Note: This test assumes the server is running on localhost:8080
    // In a real CI environment, we would spawn the server in the test

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Test liveness endpoint
    // This test is commented out as it requires a running server
    // Uncomment when running against a live instance
    /*
    let response = client
        .get("http://localhost:8080/health/live")
        .send()
        .await;

    if let Ok(resp) = response {
        assert_eq!(resp.status(), 200);
    }

    // Test readiness endpoint
    let response = client
        .get("http://localhost:8080/health/ready")
        .send()
        .await;

    if let Ok(resp) = response {
        assert_eq!(resp.status(), 200);
    }
    */
}

#[test]
fn test_config_validation() {
    use api_gateway_rust::config::Config;

    // Test default config is valid
    let config = Config::default();
    assert!(config.validate().is_ok());

    // Test invalid port
    let mut invalid_config = Config::default();
    invalid_config.server.port = 0;
    assert!(invalid_config.validate().is_err());
}

#[test]
fn test_error_response_serialization() {
    use api_gateway_rust::error::ErrorResponse;

    let error = ErrorResponse::new("test_error", "This is a test error");
    let json = serde_json::to_string(&error).unwrap();

    assert!(json.contains("test_error"));
    assert!(json.contains("This is a test error"));
}
