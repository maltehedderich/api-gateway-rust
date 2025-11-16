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

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
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
            GatewayError::ConnectionTimeout => (
                StatusCode::REQUEST_TIMEOUT,
                ErrorResponse::new("request_timeout", "Connection timeout"),
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
        };

        (status, Json(error_response)).into_response()
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error.code, self.error.message)
    }
}
