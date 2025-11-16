use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Error types for the API Gateway
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Not found")]
    NotFound,

    #[error("Method not allowed")]
    MethodNotAllowed(Vec<String>),

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("Bad gateway: {0}")]
    BadGateway(String),

    #[error("Gateway timeout")]
    GatewayTimeout,

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // Authentication and Authorization errors
    #[error("Missing authentication token")]
    MissingToken,

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Token revoked")]
    TokenRevoked,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Insufficient permissions")]
    InsufficientPermissions {
        required_roles: Vec<String>,
        user_roles: Vec<String>,
    },

    // Rate limiting errors
    #[error("Rate limit exceeded")]
    RateLimitExceeded {
        limit: u64,
        window_secs: u64,
        reset_at: u64,
        retry_after_secs: u64,
    },

    #[error("Rate limiting error: {0}")]
    RateLimiting(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

/// Error response structure returned to clients
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub correlation_id: Option<String>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
                correlation_id: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
                details: None,
            },
        }
    }

    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.error.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.error.details = Some(details);
        self
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, error_response) = match self {
            GatewayError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("bad_request", &msg),
            ),
            GatewayError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorResponse::new("not_found", "The requested resource was not found"),
            ),
            GatewayError::MethodNotAllowed(methods) => {
                let details = serde_json::json!({
                    "allowed_methods": methods
                });
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    ErrorResponse::new(
                        "method_not_allowed",
                        "Method not allowed for this resource",
                    )
                    .with_details(details),
                )
            }
            GatewayError::ConnectionTimeout => (
                StatusCode::REQUEST_TIMEOUT,
                ErrorResponse::new("request_timeout", "Connection timeout"),
            ),
            GatewayError::BadGateway(msg) => (
                StatusCode::BAD_GATEWAY,
                ErrorResponse::new("bad_gateway", &format!("Bad gateway: {}", msg)),
            ),
            GatewayError::GatewayTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                ErrorResponse::new("gateway_timeout", "Gateway timeout"),
            ),
            GatewayError::TlsConfig(_msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::new("internal_error", "TLS configuration error"),
            ),
            GatewayError::Config(_msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::new("internal_error", "Configuration error"),
            ),
            GatewayError::Internal(_msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::new("internal_error", "An internal error occurred"),
            ),
            GatewayError::Io(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::new("internal_error", "An internal error occurred"),
            ),
            GatewayError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("missing_token", "Authentication token is required"),
            ),
            GatewayError::InvalidToken(msg) => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("invalid_token", &msg),
            ),
            GatewayError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new(
                    "token_expired",
                    "Authentication token has expired. Please refresh your token.",
                ),
            ),
            GatewayError::TokenRevoked => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("token_revoked", "Authentication token has been revoked"),
            ),
            GatewayError::AuthenticationFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("authentication_failed", &msg),
            ),
            GatewayError::InsufficientPermissions {
                required_roles,
                user_roles,
            } => {
                let details = serde_json::json!({
                    "required_roles": required_roles,
                    "user_roles": user_roles,
                });
                (
                    StatusCode::FORBIDDEN,
                    ErrorResponse::new(
                        "insufficient_permissions",
                        "You do not have permission to access this resource",
                    )
                    .with_details(details),
                )
            }
            GatewayError::RateLimitExceeded {
                limit,
                window_secs,
                reset_at,
                retry_after_secs,
            } => {
                let details = serde_json::json!({
                    "limit": limit,
                    "window": format!("{}s", window_secs),
                    "reset_at": reset_at,
                });
                let error_response = ErrorResponse::new(
                    "rate_limit_exceeded",
                    &format!(
                        "Rate limit exceeded. Please retry after {} seconds.",
                        retry_after_secs
                    ),
                )
                .with_details(details);

                (StatusCode::TOO_MANY_REQUESTS, error_response)
            }
            GatewayError::RateLimiting(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::new("rate_limiting_error", &msg),
            ),
            GatewayError::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorResponse::new("service_unavailable", &msg),
            ),
        };

        // Add WWW-Authenticate header for 401 responses
        let mut response = (status, Json(error_response)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"api-gateway\""),
            );
        }

        response
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error.code, self.error.message)
    }
}
