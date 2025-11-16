use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

/// Extension type for storing correlation ID in request
#[derive(Clone, Debug)]
pub struct CorrelationId(pub String);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Middleware to handle correlation ID
///
/// This middleware:
/// 1. Extracts correlation ID from X-Correlation-ID or X-Request-ID headers
/// 2. Generates a new UUID if no correlation ID is provided
/// 3. Adds the correlation ID to request extensions
/// 4. Adds X-Correlation-ID header to the response
pub async fn correlation_id_middleware(mut request: Request, next: Next) -> Response {
    // Try to extract correlation ID from headers
    let correlation_id = request
        .headers()
        .get("x-correlation-id")
        .or_else(|| request.headers().get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(|s| CorrelationId::from_string(s.to_string()))
        .unwrap_or_else(CorrelationId::new);

    let correlation_id_value = correlation_id.0.clone();

    // Insert correlation ID into request extensions
    request.extensions_mut().insert(correlation_id);

    // Process the request
    let mut response = next.run(request).await;

    // Add correlation ID to response headers
    if let Ok(header_value) = HeaderValue::from_str(&correlation_id_value) {
        response
            .headers_mut()
            .insert("x-correlation-id", header_value);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_id_new() {
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::new();
        // Each new ID should be unique
        assert_ne!(id1.0, id2.0);
        // Should be valid UUIDs
        assert!(Uuid::parse_str(&id1.0).is_ok());
        assert!(Uuid::parse_str(&id2.0).is_ok());
    }

    #[test]
    fn test_correlation_id_from_string() {
        let custom_id = "my-custom-id-123";
        let id = CorrelationId::from_string(custom_id.to_string());
        assert_eq!(id.0, custom_id);
    }
}
