use axum::{
    extract::Request,
    http::HeaderValue,
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::auth::UserContext;
use crate::config::RateLimitPolicy;
use crate::error::GatewayError;
use crate::metrics::{self, DurationTimer};
use crate::rate_limiter::{add_rate_limit_headers, RateLimitContext, RateLimiter};
use tracing::{debug, error};

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
pub async fn correlation_id_middleware(
    mut request: Request,
    next: Next,
) -> Response {
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
        response.headers_mut().insert("x-correlation-id", header_value);
    }

    response
}

/// Extension type for storing client IP in request
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

/// Middleware to extract and store client IP address
///
/// This middleware:
/// 1. Extracts client IP from X-Forwarded-For or X-Real-IP headers
/// 2. Falls back to connection remote address if headers are not present
/// 3. Adds the IP to request extensions for use by other middleware
pub async fn client_ip_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    // Try to extract IP from headers (for proxied requests)
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next()) // Take first IP in X-Forwarded-For chain
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    debug!("Client IP: {}", client_ip);

    // Insert client IP into request extensions
    request.extensions_mut().insert(ClientIp(client_ip));

    // Process the request
    next.run(request).await
}

/// Rate limiting middleware
///
/// This middleware:
/// 1. Constructs rate limit context from request
/// 2. Checks rate limit using configured policy
/// 3. Adds rate limit headers to response
/// 4. Returns 429 Too Many Requests if limit is exceeded
pub async fn rate_limit_middleware(
    rate_limiter: RateLimiter,
    policy: RateLimitPolicy,
    route_id: String,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> + Clone {
    move |request: Request, next: Next| {
        let rate_limiter = rate_limiter.clone();
        let policy = policy.clone();
        let route_id = route_id.clone();

        Box::pin(async move {
            let timer = DurationTimer::new();

            // Extract client IP from request extensions
            let client_ip = request
                .extensions()
                .get::<ClientIp>()
                .map(|ip| ip.0.clone())
                .unwrap_or_else(|| "unknown".to_string());

            // Extract user ID from request extensions (if authenticated)
            let user_id = request
                .extensions()
                .get::<UserContext>()
                .map(|ctx| ctx.user_id.clone());

            // Construct rate limit context
            let context = RateLimitContext {
                client_ip: client_ip.clone(),
                user_id: user_id.clone(),
                route_id: route_id.clone(),
            };

            // Check rate limit
            let decision = match rate_limiter.check_limit(&context, &policy).await {
                Ok(decision) => decision,
                Err(e) => {
                    error!("Rate limit check failed: {}", e);
                    timer.observe_duration(&metrics::RATE_LIMIT_DURATION_SECONDS, &["check_failed"]);

                    // Return error response
                    return e.into_response();
                }
            };

            // Record metrics
            metrics::record_rate_limit_decision(decision.allowed, &route_id, &policy.key_type);
            timer.observe_duration(&metrics::RATE_LIMIT_DURATION_SECONDS, &["check"]);

            if !decision.allowed {
                // Rate limit exceeded
                debug!(
                    "Rate limit exceeded for route: {}, client_ip: {}, user_id: {:?}",
                    route_id, client_ip, user_id
                );

                let error = GatewayError::RateLimitExceeded {
                    limit: decision.limit,
                    window_secs: policy.window_secs,
                    reset_at: decision.reset_at,
                    retry_after_secs: decision.retry_after_secs,
                };

                let mut response = error.into_response();
                add_rate_limit_headers(response.headers_mut(), &decision);
                return response;
            }

            // Rate limit passed, process request
            let mut response = next.run(request).await;

            // Add rate limit headers to response
            add_rate_limit_headers(response.headers_mut(), &decision);

            response
        })
    }
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
