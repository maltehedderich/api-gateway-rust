use crate::error::GatewayError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for the API Gateway
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub rate_limiting: Option<RateLimitingConfig>,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the server to
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// TLS configuration
    pub tls: Option<TlsConfig>,

    /// Connection timeout in seconds
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    /// Maximum concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Request timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to TLS certificate file
    pub cert_path: PathBuf,

    /// Path to TLS private key file
    pub key_path: PathBuf,

    /// Minimum TLS version (1.2 or 1.3)
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT secret key for validating signed tokens (HS256)
    /// For production, this should be loaded from environment variable
    #[serde(default)]
    pub jwt_secret: Option<String>,

    /// JWT public key for validating signed tokens (RS256, ES256)
    #[serde(default)]
    pub jwt_public_key: Option<String>,

    /// JWT algorithm (HS256, RS256, ES256)
    #[serde(default = "default_jwt_algorithm")]
    pub jwt_algorithm: String,

    /// Cookie name for session token
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// JWT issuer (iss claim validation)
    #[serde(default)]
    pub jwt_issuer: Option<String>,

    /// JWT audience (aud claim validation)
    #[serde(default)]
    pub jwt_audience: Option<String>,
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

fn default_cookie_name() -> String {
    "session_token".to_string()
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Redis connection URL (e.g., "redis://localhost:6379")
    pub redis_url: String,

    /// Global default rate limit (applied if no route-specific limit is configured)
    #[serde(default)]
    pub default_limit: Option<RateLimitPolicy>,

    /// Failure mode when Redis is unavailable
    /// - "fail_open": Allow requests to proceed (log warning)
    /// - "fail_closed": Reject requests with 503 Service Unavailable
    #[serde(default = "default_failure_mode")]
    pub failure_mode: String,
}

fn default_failure_mode() -> String {
    "fail_closed".to_string()
}

/// Rate limit policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    /// Maximum number of requests allowed
    pub limit: u64,

    /// Time window in seconds
    pub window_secs: u64,

    /// Rate limiting algorithm
    /// - "token_bucket": Token bucket algorithm (allows bursts)
    /// - "sliding_window": Sliding window counter algorithm (strict)
    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    /// Burst capacity for token bucket algorithm (defaults to limit if not specified)
    #[serde(default)]
    pub burst_capacity: Option<u64>,

    /// Key type for rate limiting
    /// - "ip": Rate limit by client IP address
    /// - "user": Rate limit by authenticated user ID
    /// - "endpoint": Rate limit by route/endpoint
    /// - "user_endpoint": Composite key (user + endpoint)
    /// - "ip_endpoint": Composite key (IP + endpoint)
    #[serde(default = "default_key_type")]
    pub key_type: String,
}

fn default_algorithm() -> String {
    "token_bucket".to_string()
}

fn default_key_type() -> String {
    "ip".to_string()
}

// Default values
fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8443
}

fn default_connection_timeout() -> u64 {
    60
}

fn default_max_connections() -> usize {
    10000
}

fn default_request_timeout() -> u64 {
    30
}

fn default_min_tls_version() -> String {
    "1.2".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            port: default_port(),
            tls: None,
            connection_timeout_secs: default_connection_timeout(),
            max_connections: default_max_connections(),
            request_timeout_secs: default_request_timeout(),
        }
    }
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Unique identifier for the route
    pub id: String,

    /// HTTP methods this route accepts (GET, POST, etc.)
    pub methods: Vec<String>,

    /// Path pattern for matching (supports exact, prefix, and parameter extraction)
    pub path: String,

    /// Upstream service identifier
    pub upstream_id: String,

    /// Path transformation for upstream (optional, defaults to original path)
    #[serde(default)]
    pub upstream_path: Option<String>,

    /// Upstream timeout in seconds (optional, overrides upstream default)
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    /// Strip path prefix when forwarding to upstream
    #[serde(default)]
    pub strip_prefix: Option<String>,

    /// Authentication requirement (optional, defaults to no authentication)
    #[serde(default)]
    pub auth_required: bool,

    /// Required roles for authorization (RBAC - any role in list grants access)
    #[serde(default)]
    pub required_roles: Vec<String>,

    /// Required permissions for authorization (PBAC - all permissions required)
    #[serde(default)]
    pub required_permissions: Vec<String>,

    /// Rate limit policy for this route (overrides global default)
    #[serde(default)]
    pub rate_limit: Option<RateLimitPolicy>,
}

/// Upstream service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Unique identifier for the upstream service
    pub id: String,

    /// Base URL of the upstream service (e.g., "http://service:8080")
    pub base_url: String,

    /// Timeout for requests to this upstream in seconds
    #[serde(default = "default_upstream_timeout")]
    pub timeout_secs: u64,

    /// Health check endpoint path (optional)
    #[serde(default)]
    pub health_check_path: Option<String>,

    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub pool_max_idle_per_host: usize,
}

fn default_upstream_timeout() -> u64 {
    30
}

fn default_pool_size() -> usize {
    10
}

impl Config {
    /// Load configuration from environment variables and default values
    pub fn from_env() -> Result<Self, GatewayError> {
        let mut config = Config::default();

        // Override with environment variables if present
        if let Ok(bind_address) = std::env::var("GATEWAY_BIND_ADDRESS") {
            config.server.bind_address = bind_address;
        }

        if let Ok(port) = std::env::var("GATEWAY_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| GatewayError::Config(format!("Invalid port: {}", e)))?;
        }

        // TLS configuration from environment
        if let (Ok(cert_path), Ok(key_path)) = (
            std::env::var("GATEWAY_TLS_CERT_PATH"),
            std::env::var("GATEWAY_TLS_KEY_PATH"),
        ) {
            config.server.tls = Some(TlsConfig {
                cert_path: PathBuf::from(cert_path),
                key_path: PathBuf::from(key_path),
                min_version: std::env::var("GATEWAY_TLS_MIN_VERSION")
                    .unwrap_or_else(|_| default_min_tls_version()),
            });
        }

        if let Ok(timeout) = std::env::var("GATEWAY_CONNECTION_TIMEOUT_SECS") {
            config.server.connection_timeout_secs = timeout
                .parse()
                .map_err(|e| GatewayError::Config(format!("Invalid timeout: {}", e)))?;
        }

        if let Ok(max_conn) = std::env::var("GATEWAY_MAX_CONNECTIONS") {
            config.server.max_connections = max_conn
                .parse()
                .map_err(|e| GatewayError::Config(format!("Invalid max connections: {}", e)))?;
        }

        // Authentication configuration from environment
        if let Ok(jwt_secret) = std::env::var("GATEWAY_JWT_SECRET") {
            let mut auth_config = config.auth.take().unwrap_or_else(|| AuthConfig {
                jwt_secret: None,
                jwt_public_key: None,
                jwt_algorithm: default_jwt_algorithm(),
                cookie_name: default_cookie_name(),
                jwt_issuer: None,
                jwt_audience: None,
            });
            auth_config.jwt_secret = Some(jwt_secret);

            if let Ok(jwt_algorithm) = std::env::var("GATEWAY_JWT_ALGORITHM") {
                auth_config.jwt_algorithm = jwt_algorithm;
            }

            if let Ok(cookie_name) = std::env::var("GATEWAY_COOKIE_NAME") {
                auth_config.cookie_name = cookie_name;
            }

            if let Ok(jwt_issuer) = std::env::var("GATEWAY_JWT_ISSUER") {
                auth_config.jwt_issuer = Some(jwt_issuer);
            }

            if let Ok(jwt_audience) = std::env::var("GATEWAY_JWT_AUDIENCE") {
                auth_config.jwt_audience = Some(jwt_audience);
            }

            config.auth = Some(auth_config);
        }

        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.server.port == 0 {
            return Err(GatewayError::Config("Port cannot be 0".to_string()));
        }

        if self.server.connection_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "Connection timeout must be greater than 0".to_string(),
            ));
        }

        if self.server.max_connections == 0 {
            return Err(GatewayError::Config(
                "Max connections must be greater than 0".to_string(),
            ));
        }

        // Validate TLS configuration if present
        if let Some(ref tls) = self.server.tls {
            if !tls.cert_path.exists() {
                return Err(GatewayError::Config(format!(
                    "TLS certificate file not found: {:?}",
                    tls.cert_path
                )));
            }

            if !tls.key_path.exists() {
                return Err(GatewayError::Config(format!(
                    "TLS key file not found: {:?}",
                    tls.key_path
                )));
            }

            if tls.min_version != "1.2" && tls.min_version != "1.3" {
                return Err(GatewayError::Config(format!(
                    "Invalid TLS version: {}. Must be '1.2' or '1.3'",
                    tls.min_version
                )));
            }
        }

        // Validate authentication configuration
        if let Some(ref auth) = self.auth {
            // Validate JWT algorithm
            if !["HS256", "RS256", "ES256"].contains(&auth.jwt_algorithm.as_str()) {
                return Err(GatewayError::Config(format!(
                    "Invalid JWT algorithm: {}. Must be HS256, RS256, or ES256",
                    auth.jwt_algorithm
                )));
            }

            // Ensure appropriate key is configured for algorithm
            if auth.jwt_algorithm == "HS256" && auth.jwt_secret.is_none() {
                return Err(GatewayError::Config(
                    "JWT secret is required for HS256 algorithm".to_string(),
                ));
            }

            if (auth.jwt_algorithm == "RS256" || auth.jwt_algorithm == "ES256")
                && auth.jwt_public_key.is_none()
            {
                return Err(GatewayError::Config(format!(
                    "JWT public key is required for {} algorithm",
                    auth.jwt_algorithm
                )));
            }
        }

        // Validate upstreams
        for upstream in &self.upstreams {
            if upstream.id.is_empty() {
                return Err(GatewayError::Config(
                    "Upstream ID cannot be empty".to_string(),
                ));
            }

            if upstream.base_url.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Upstream '{}' base_url cannot be empty",
                    upstream.id
                )));
            }

            // Validate URL format
            if !upstream.base_url.starts_with("http://")
                && !upstream.base_url.starts_with("https://")
            {
                return Err(GatewayError::Config(format!(
                    "Upstream '{}' base_url must start with http:// or https://",
                    upstream.id
                )));
            }
        }

        // Validate routes
        for route in &self.routes {
            if route.id.is_empty() {
                return Err(GatewayError::Config("Route ID cannot be empty".to_string()));
            }

            if route.path.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Route '{}' path cannot be empty",
                    route.id
                )));
            }

            if route.methods.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Route '{}' must have at least one method",
                    route.id
                )));
            }

            // Validate that the upstream exists
            if !self.upstreams.iter().any(|u| u.id == route.upstream_id) {
                return Err(GatewayError::Config(format!(
                    "Route '{}' references unknown upstream '{}'",
                    route.id, route.upstream_id
                )));
            }

            // Validate rate limit policy if present
            if let Some(ref rate_limit) = route.rate_limit {
                Self::validate_rate_limit_policy(rate_limit, &format!("Route '{}'", route.id))?;
            }
        }

        // Validate rate limiting configuration
        if let Some(ref rate_limiting) = self.rate_limiting {
            if rate_limiting.redis_url.is_empty() {
                return Err(GatewayError::Config(
                    "Rate limiting Redis URL cannot be empty".to_string(),
                ));
            }

            if !rate_limiting.redis_url.starts_with("redis://")
                && !rate_limiting.redis_url.starts_with("rediss://")
            {
                return Err(GatewayError::Config(
                    "Rate limiting Redis URL must start with redis:// or rediss://".to_string(),
                ));
            }

            if rate_limiting.failure_mode != "fail_open"
                && rate_limiting.failure_mode != "fail_closed"
            {
                return Err(GatewayError::Config(format!(
                    "Invalid failure mode: {}. Must be 'fail_open' or 'fail_closed'",
                    rate_limiting.failure_mode
                )));
            }

            if let Some(ref default_limit) = rate_limiting.default_limit {
                Self::validate_rate_limit_policy(default_limit, "Global default rate limit")?;
            }
        }

        Ok(())
    }

    fn validate_rate_limit_policy(
        policy: &RateLimitPolicy,
        context: &str,
    ) -> Result<(), GatewayError> {
        if policy.limit == 0 {
            return Err(GatewayError::Config(format!(
                "{}: Rate limit must be greater than 0",
                context
            )));
        }

        if policy.window_secs == 0 {
            return Err(GatewayError::Config(format!(
                "{}: Window duration must be greater than 0",
                context
            )));
        }

        if !["token_bucket", "sliding_window"].contains(&policy.algorithm.as_str()) {
            return Err(GatewayError::Config(format!(
                "{}: Invalid algorithm '{}'. Must be 'token_bucket' or 'sliding_window'",
                context, policy.algorithm
            )));
        }

        if !["ip", "user", "endpoint", "user_endpoint", "ip_endpoint"]
            .contains(&policy.key_type.as_str())
        {
            return Err(GatewayError::Config(format!(
                "{}: Invalid key type '{}'. Must be one of: ip, user, endpoint, user_endpoint, ip_endpoint",
                context, policy.key_type
            )));
        }

        if let Some(burst) = policy.burst_capacity {
            if burst == 0 {
                return Err(GatewayError::Config(format!(
                    "{}: Burst capacity must be greater than 0 if specified",
                    context
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.bind_address, "0.0.0.0");
        assert_eq!(config.server.port, 8443);
        assert_eq!(config.server.connection_timeout_secs, 60);
        assert_eq!(config.server.max_connections, 10000);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_port() {
        let mut config = Config::default();
        config.server.port = 0;
        assert!(config.validate().is_err());
    }
}
