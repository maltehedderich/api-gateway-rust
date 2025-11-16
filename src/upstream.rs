use crate::config::UpstreamConfig;
use crate::error::GatewayError;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, error, info};

/// HTTP client for forwarding requests to upstream services
#[derive(Clone)]
pub struct UpstreamClient {
    client: Client,
}

impl UpstreamClient {
    /// Create a new upstream client with connection pooling
    pub fn new(pool_max_idle_per_host: usize) -> Result<Self, GatewayError> {
        let client = Client::builder()
            .pool_max_idle_per_host(pool_max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(90))
            .timeout(Duration::from_secs(30)) // Default timeout
            .build()
            .map_err(|e| GatewayError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client })
    }

    /// Forward a request to an upstream service
    pub async fn forward_request(
        &self,
        request: Request<Body>,
        upstream: &UpstreamConfig,
        upstream_uri: String,
        timeout_secs: Option<u64>,
        correlation_id: &str,
    ) -> Result<Response<Body>, GatewayError> {
        let method = request.method().clone();
        let headers = request.headers().clone();

        info!(
            correlation_id = %correlation_id,
            method = %method,
            upstream_uri = %upstream_uri,
            upstream_id = %upstream.id,
            "Forwarding request to upstream"
        );

        // Build upstream URL
        let upstream_url = format!(
            "{}{}",
            upstream.base_url.trim_end_matches('/'),
            upstream_uri
        );

        debug!(
            correlation_id = %correlation_id,
            upstream_url = %upstream_url,
            "Built upstream URL"
        );

        // Convert axum Request to reqwest Request
        let mut req_builder = match method {
            Method::GET => self.client.get(&upstream_url),
            Method::POST => self.client.post(&upstream_url),
            Method::PUT => self.client.put(&upstream_url),
            Method::DELETE => self.client.delete(&upstream_url),
            Method::PATCH => self.client.patch(&upstream_url),
            Method::HEAD => self.client.head(&upstream_url),
            Method::OPTIONS => self.client.request(reqwest::Method::OPTIONS, &upstream_url),
            _ => {
                return Err(GatewayError::BadRequest(format!(
                    "Unsupported HTTP method: {}",
                    method
                )))
            }
        };

        // Set timeout
        let timeout_duration = Duration::from_secs(timeout_secs.unwrap_or(upstream.timeout_secs));
        req_builder = req_builder.timeout(timeout_duration);

        // Forward headers (excluding hop-by-hop headers)
        req_builder = forward_headers(req_builder, &headers, correlation_id);

        // Convert body
        let (_parts, body) = request.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|e| GatewayError::BadRequest(format!("Failed to read request body: {}", e)))?;

        if !body_bytes.is_empty() {
            req_builder = req_builder.body(body_bytes.to_vec());
        }

        // Send request to upstream
        let start = std::time::Instant::now();
        let upstream_response = req_builder.send().await.map_err(|e| {
            let elapsed = start.elapsed();
            error!(
                correlation_id = %correlation_id,
                upstream_url = %upstream_url,
                error = %e,
                elapsed_ms = %elapsed.as_millis(),
                "Upstream request failed"
            );

            if e.is_timeout() {
                GatewayError::GatewayTimeout
            } else if e.is_connect() {
                GatewayError::BadGateway(format!("Failed to connect to upstream: {}", e))
            } else {
                GatewayError::BadGateway(format!("Upstream error: {}", e))
            }
        })?;

        let elapsed = start.elapsed();
        let status = upstream_response.status();

        info!(
            correlation_id = %correlation_id,
            upstream_url = %upstream_url,
            status = %status,
            elapsed_ms = %elapsed.as_millis(),
            "Upstream response received"
        );

        // Convert reqwest Response to axum Response
        let mut response_builder = Response::builder().status(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        );

        // Copy response headers (excluding hop-by-hop headers)
        for (key, value) in upstream_response.headers() {
            if !is_hop_by_hop_header(key.as_str()) {
                response_builder = response_builder.header(key.as_str(), value.as_bytes());
            }
        }

        // Add gateway-specific headers
        response_builder = response_builder
            .header("X-Gateway-Upstream", upstream.id.as_str())
            .header("X-Correlation-ID", correlation_id);

        // Get response body
        let response_bytes = upstream_response.bytes().await.map_err(|e| {
            error!(
                correlation_id = %correlation_id,
                error = %e,
                "Failed to read upstream response body"
            );
            GatewayError::BadGateway("Failed to read upstream response".to_string())
        })?;

        let response = response_builder
            .body(Body::from(response_bytes))
            .map_err(|e| GatewayError::Internal(format!("Failed to build response: {}", e)))?;

        Ok(response)
    }
}

/// Forward headers to upstream, excluding hop-by-hop headers
fn forward_headers(
    mut req_builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    correlation_id: &str,
) -> reqwest::RequestBuilder {
    // Add correlation ID
    req_builder = req_builder.header("X-Correlation-ID", correlation_id);

    // Forward original headers
    for (key, value) in headers {
        let key_str = key.as_str();

        // Skip hop-by-hop headers
        if is_hop_by_hop_header(key_str) {
            continue;
        }

        // Skip host header (will be set by reqwest)
        if key_str.eq_ignore_ascii_case("host") {
            continue;
        }

        if let Ok(value_str) = value.to_str() {
            req_builder = req_builder.header(key_str, value_str);
        }
    }

    req_builder
}

/// Check if a header is a hop-by-hop header that should not be forwarded
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Build upstream URI from original request URI and route configuration
pub fn build_upstream_uri(
    original_uri: &Uri,
    strip_prefix: Option<&String>,
    upstream_path: Option<&String>,
) -> String {
    let path = original_uri.path();
    let query = original_uri.query();

    // Determine the path to use
    let upstream_path_str = if let Some(custom_path) = upstream_path {
        // Use custom upstream path
        custom_path.clone()
    } else if let Some(prefix) = strip_prefix {
        // Strip prefix from original path
        path.strip_prefix(prefix).unwrap_or(path).to_string()
    } else {
        // Use original path as-is
        path.to_string()
    };

    // Ensure path starts with /
    let upstream_path_final = if upstream_path_str.starts_with('/') {
        upstream_path_str
    } else {
        format!("/{}", upstream_path_str)
    };

    // Add query string if present
    if let Some(q) = query {
        format!("{}?{}", upstream_path_final, q)
    } else {
        upstream_path_final
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hop_by_hop_header() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("Keep-Alive"));
        assert!(is_hop_by_hop_header("Transfer-Encoding"));
        assert!(!is_hop_by_hop_header("Content-Type"));
        assert!(!is_hop_by_hop_header("Authorization"));
    }

    #[test]
    fn test_build_upstream_uri_no_modifications() {
        let uri: Uri = "/api/users".parse().unwrap();
        let result = build_upstream_uri(&uri, None, None);
        assert_eq!(result, "/api/users");
    }

    #[test]
    fn test_build_upstream_uri_with_query() {
        let uri: Uri = "/api/users?page=1&limit=10".parse().unwrap();
        let result = build_upstream_uri(&uri, None, None);
        assert_eq!(result, "/api/users?page=1&limit=10");
    }

    #[test]
    fn test_build_upstream_uri_strip_prefix() {
        let uri: Uri = "/api/v1/users".parse().unwrap();
        let prefix = "/api/v1".to_string();
        let result = build_upstream_uri(&uri, Some(&prefix), None);
        assert_eq!(result, "/users");
    }

    #[test]
    fn test_build_upstream_uri_custom_path() {
        let uri: Uri = "/anything".parse().unwrap();
        let custom = "/custom/path".to_string();
        let result = build_upstream_uri(&uri, None, Some(&custom));
        assert_eq!(result, "/custom/path");
    }
}
