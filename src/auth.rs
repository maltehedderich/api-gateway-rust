use crate::config::AuthConfig;
use crate::error::GatewayError;
use axum::{
    extract::Request,
    http::header,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use moka::future::Cache;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// User context containing identity and authorization information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserContext {
    /// Unique user identifier
    pub user_id: String,

    /// Username (human-readable identifier)
    #[serde(default)]
    pub username: Option<String>,

    /// User roles for RBAC
    #[serde(default)]
    pub roles: Vec<String>,

    /// User permissions for PBAC
    #[serde(default)]
    pub permissions: Vec<String>,

    /// Additional custom claims
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject (user ID)
    sub: String,

    /// Username
    #[serde(default)]
    username: Option<String>,

    /// Issuer
    #[serde(default)]
    iss: Option<String>,

    /// Audience
    #[serde(default)]
    aud: Option<String>,

    /// Expiration time (Unix timestamp)
    exp: usize,

    /// Not before (Unix timestamp)
    #[serde(default)]
    nbf: Option<usize>,

    /// Issued at (Unix timestamp)
    #[serde(default)]
    iat: Option<usize>,

    /// JWT ID
    #[serde(default)]
    jti: Option<String>,

    /// Roles (custom claim)
    #[serde(default)]
    roles: Vec<String>,

    /// Permissions (custom claim)
    #[serde(default)]
    permissions: Vec<String>,

    /// Additional custom claims
    #[serde(flatten)]
    extra: serde_json::Value,
}

impl From<Claims> for UserContext {
    fn from(claims: Claims) -> Self {
        UserContext {
            user_id: claims.sub,
            username: claims.username,
            roles: claims.roles,
            permissions: claims.permissions,
            extra: claims.extra,
        }
    }
}

/// Session data stored in Redis for opaque tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// User ID
    pub user_id: String,

    /// Username
    #[serde(default)]
    pub username: Option<String>,

    /// User roles
    #[serde(default)]
    pub roles: Vec<String>,

    /// User permissions
    #[serde(default)]
    pub permissions: Vec<String>,

    /// Session creation timestamp (Unix timestamp)
    #[serde(default)]
    pub created_at: i64,

    /// Session expiration timestamp (Unix timestamp)
    pub expires_at: i64,

    /// Additional session data
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

impl From<SessionData> for UserContext {
    fn from(session: SessionData) -> Self {
        UserContext {
            user_id: session.user_id,
            username: session.username,
            roles: session.roles,
            permissions: session.permissions,
            extra: session.extra,
        }
    }
}

/// Token validator with caching and opaque token support
pub struct TokenValidator {
    /// Authentication configuration
    auth_config: Arc<AuthConfig>,

    /// Redis connection manager for opaque token validation
    redis_client: Option<ConnectionManager>,

    /// Token validation cache
    cache: Option<Cache<String, UserContext>>,
}

impl TokenValidator {
    /// Create a new token validator
    pub async fn new(auth_config: Arc<AuthConfig>) -> Result<Self, GatewayError> {
        // Initialize Redis client for opaque tokens
        let redis_client = if auth_config.token_format == "opaque" {
            if let Some(ref session_store) = auth_config.session_store {
                let client = redis::Client::open(session_store.redis_url.as_str()).map_err(|e| {
                    GatewayError::Config(format!("Failed to create Redis client: {}", e))
                })?;

                let conn_manager = ConnectionManager::new(client).await.map_err(|e| {
                    GatewayError::Config(format!("Failed to connect to Redis: {}", e))
                })?;

                info!("Connected to Redis session store");
                Some(conn_manager)
            } else {
                return Err(GatewayError::Config(
                    "Session store configuration required for opaque tokens".to_string(),
                ));
            }
        } else {
            None
        };

        // Initialize cache if enabled
        let cache = if let Some(ref cache_config) = auth_config.cache {
            if cache_config.enabled {
                let cache = Cache::builder()
                    .max_capacity(cache_config.max_capacity)
                    .time_to_live(Duration::from_secs(cache_config.ttl_secs))
                    .build();

                info!(
                    "Token validation cache initialized (capacity: {}, TTL: {}s)",
                    cache_config.max_capacity, cache_config.ttl_secs
                );
                Some(cache)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            auth_config,
            redis_client,
            cache,
        })
    }

    /// Validate a token and return user context
    pub async fn validate_token(&self, token: &str) -> Result<UserContext, GatewayError> {
        // Check cache first if enabled
        if let Some(ref cache) = self.cache {
            if let Some(user_context) = cache.get(token).await {
                debug!("Token validation cache hit");
                return Ok(user_context);
            }
        }

        // Validate token based on format
        let user_context = match self.auth_config.token_format.as_str() {
            "jwt" => self.validate_jwt_token(token).await?,
            "opaque" => self.validate_opaque_token(token).await?,
            _ => {
                return Err(GatewayError::Config(format!(
                    "Unsupported token format: {}",
                    self.auth_config.token_format
                )))
            }
        };

        // Store in cache if enabled
        if let Some(ref cache) = self.cache {
            cache.insert(token.to_string(), user_context.clone()).await;
            debug!("Token validation result cached");
        }

        Ok(user_context)
    }

    /// Validate JWT token
    async fn validate_jwt_token(&self, token: &str) -> Result<UserContext, GatewayError> {
        validate_jwt_token(token, &self.auth_config)
    }

    /// Validate opaque token by looking up session in Redis
    async fn validate_opaque_token(&self, token: &str) -> Result<UserContext, GatewayError> {
        let session_store = self
            .auth_config
            .session_store
            .as_ref()
            .ok_or_else(|| GatewayError::Config("Session store not configured".to_string()))?;

        let mut redis_conn = self.redis_client.as_ref().ok_or_else(|| {
            GatewayError::AuthenticationFailed("Redis connection not available".to_string())
        })?
        .clone();

        // Construct Redis key
        let redis_key = format!("{}{}", session_store.key_prefix, token);

        // Look up session data in Redis
        let session_json: Option<String> = redis_conn
            .get(&redis_key)
            .await
            .map_err(|e| {
                // Handle Redis unavailability based on failure mode
                if session_store.failure_mode == "fail_open" {
                    warn!(
                        "Redis lookup failed (fail-open mode): {}. Allowing request without validation.",
                        e
                    );
                    // In fail-open mode, we could return a default user context
                    // For security, we'll still return an error but log it differently
                    GatewayError::ServiceUnavailable(format!("Session store unavailable: {}", e))
                } else {
                    error!("Redis lookup failed (fail-closed mode): {}", e);
                    GatewayError::ServiceUnavailable(format!("Session store unavailable: {}", e))
                }
            })?;

        // Check if session exists
        let session_json = session_json.ok_or_else(|| {
            debug!("Session not found in Redis for token");
            GatewayError::InvalidToken("Session not found".to_string())
        })?;

        // Parse session data
        let session_data: SessionData = serde_json::from_str(&session_json).map_err(|e| {
            error!("Failed to parse session data from Redis: {}", e);
            GatewayError::InvalidToken("Invalid session data".to_string())
        })?;

        // Check if session is expired
        let now = chrono::Utc::now().timestamp();
        if session_data.expires_at < now {
            debug!("Session expired (expires_at: {}, now: {})", session_data.expires_at, now);
            return Err(GatewayError::TokenExpired);
        }

        debug!(
            "Opaque token validated successfully for user: {}",
            session_data.user_id
        );

        Ok(session_data.into())
    }

    /// Invalidate cached token (useful for logout or token revocation)
    pub async fn invalidate_token(&self, token: &str) {
        if let Some(ref cache) = self.cache {
            cache.invalidate(token).await;
            debug!("Token invalidated from cache");
        }
    }
}

/// Extract session token from request
///
/// Looks for token in:
/// 1. Cookie (with configured cookie name)
/// 2. Authorization header (Bearer scheme)
fn extract_token(request: &Request, cookie_name: &str) -> Option<String> {
    // Try cookie first
    if let Some(cookie_header) = request.headers().get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Parse cookies
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some((name, value)) = cookie.split_once('=') {
                    if name == cookie_name {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }

    // Try Authorization header (Bearer token)
    if let Some(auth_header) = request.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    None
}

/// Validate JWT token and extract user context
pub fn validate_jwt_token(
    token: &str,
    auth_config: &AuthConfig,
) -> Result<UserContext, GatewayError> {
    // Determine the algorithm from config
    let algorithm = match auth_config.jwt_algorithm.as_str() {
        "HS256" => Algorithm::HS256,
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        _ => {
            return Err(GatewayError::AuthenticationFailed(format!(
                "Unsupported JWT algorithm: {}",
                auth_config.jwt_algorithm
            )))
        }
    };

    // Create decoding key based on algorithm
    let decoding_key = match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let secret = auth_config.jwt_secret.as_ref().ok_or_else(|| {
                GatewayError::AuthenticationFailed("JWT secret not configured".to_string())
            })?;
            DecodingKey::from_secret(secret.as_bytes())
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let public_key = auth_config.jwt_public_key.as_ref().ok_or_else(|| {
                GatewayError::AuthenticationFailed("JWT public key not configured".to_string())
            })?;
            DecodingKey::from_rsa_pem(public_key.as_bytes()).map_err(|e| {
                GatewayError::AuthenticationFailed(format!("Invalid public key: {}", e))
            })?
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let public_key = auth_config.jwt_public_key.as_ref().ok_or_else(|| {
                GatewayError::AuthenticationFailed("JWT public key not configured".to_string())
            })?;
            DecodingKey::from_ec_pem(public_key.as_bytes()).map_err(|e| {
                GatewayError::AuthenticationFailed(format!("Invalid public key: {}", e))
            })?
        }
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 | Algorithm::EdDSA => {
            return Err(GatewayError::AuthenticationFailed(format!(
                "Unsupported JWT algorithm: {:?}. Use HS256, RS256, or ES256",
                algorithm
            )))
        }
    };

    // Create validation rules
    let mut validation = Validation::new(algorithm);

    // Set issuer validation if configured
    if let Some(ref issuer) = auth_config.jwt_issuer {
        validation.set_issuer(&[issuer]);
    }

    // Set audience validation if configured
    if let Some(ref audience) = auth_config.jwt_audience {
        validation.set_audience(&[audience]);
    }

    // Decode and validate token
    let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                GatewayError::TokenExpired
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                GatewayError::InvalidToken("Invalid signature".to_string())
            }
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                GatewayError::InvalidToken("Invalid issuer".to_string())
            }
            jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                GatewayError::InvalidToken("Invalid audience".to_string())
            }
            _ => GatewayError::InvalidToken(format!("Token validation failed: {}", e)),
        }
    })?;

    Ok(token_data.claims.into())
}

/// Authentication middleware
///
/// This middleware:
/// 1. Extracts session token from request (cookie or Authorization header)
/// 2. Validates the token (JWT or opaque)
/// 3. Extracts user context from token
/// 4. Attaches user context to request extensions
/// 5. Returns 401 Unauthorized if authentication fails
pub async fn authentication_middleware(
    token_validator: Arc<TokenValidator>,
    mut request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    // Extract correlation ID for logging
    let correlation_id = request
        .extensions()
        .get::<crate::middleware::CorrelationId>()
        .map(|id| id.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    debug!(
        correlation_id = %correlation_id,
        "Attempting authentication"
    );

    // Extract token from request
    let token = extract_token(&request, &token_validator.auth_config.cookie_name).ok_or_else(|| {
        warn!(
            correlation_id = %correlation_id,
            "Authentication failed: missing token"
        );
        GatewayError::MissingToken
    })?;

    // Log token presence (not the value!)
    debug!(
        correlation_id = %correlation_id,
        token_length = token.len(),
        "Token extracted"
    );

    // Validate token and extract user context
    let user_context = token_validator.validate_token(&token).await.map_err(|e| {
        warn!(
            correlation_id = %correlation_id,
            error = %e,
            "Authentication failed: token validation error"
        );
        e
    })?;

    info!(
        correlation_id = %correlation_id,
        user_id = %user_context.user_id,
        roles = ?user_context.roles,
        token_format = %token_validator.auth_config.token_format,
        "Authentication successful"
    );

    // Attach user context to request extensions
    request.extensions_mut().insert(user_context);

    // Continue to next middleware
    Ok(next.run(request).await)
}

/// Authentication middleware factory (for backward compatibility with existing code)
pub async fn authentication_middleware_legacy(
    auth_config: Arc<AuthConfig>,
    mut request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    // Extract correlation ID for logging
    let correlation_id = request
        .extensions()
        .get::<crate::middleware::CorrelationId>()
        .map(|id| id.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    debug!(
        correlation_id = %correlation_id,
        "Attempting authentication (legacy mode)"
    );

    // Extract token from request
    let token = extract_token(&request, &auth_config.cookie_name).ok_or_else(|| {
        warn!(
            correlation_id = %correlation_id,
            "Authentication failed: missing token"
        );
        GatewayError::MissingToken
    })?;

    // Log token presence (not the value!)
    debug!(
        correlation_id = %correlation_id,
        token_length = token.len(),
        "Token extracted"
    );

    // Validate token and extract user context
    let user_context = validate_jwt_token(&token, &auth_config).map_err(|e| {
        warn!(
            correlation_id = %correlation_id,
            error = %e,
            "Authentication failed: token validation error"
        );
        e
    })?;

    info!(
        correlation_id = %correlation_id,
        user_id = %user_context.user_id,
        roles = ?user_context.roles,
        "Authentication successful"
    );

    // Attach user context to request extensions
    request.extensions_mut().insert(user_context);

    // Continue to next middleware
    Ok(next.run(request).await)
}

/// Authorization middleware
///
/// This middleware checks if the authenticated user has required roles or permissions.
/// It should be applied after authentication middleware.
pub async fn authorization_middleware(
    required_roles: Vec<String>,
    required_permissions: Vec<String>,
    request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    // Extract correlation ID for logging
    let correlation_id = request
        .extensions()
        .get::<crate::middleware::CorrelationId>()
        .map(|id| id.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract user context (should be present if authentication succeeded)
    let user_context = request
        .extensions()
        .get::<UserContext>()
        .ok_or_else(|| {
            error!(
                correlation_id = %correlation_id,
                "Authorization failed: user context not found (authentication missing?)"
            );
            GatewayError::AuthenticationFailed(
                "User context not found. Authentication required.".to_string(),
            )
        })?;

    debug!(
        correlation_id = %correlation_id,
        user_id = %user_context.user_id,
        user_roles = ?user_context.roles,
        user_permissions = ?user_context.permissions,
        required_roles = ?required_roles,
        required_permissions = ?required_permissions,
        "Checking authorization"
    );

    // Check roles (RBAC - any matching role grants access)
    if !required_roles.is_empty() {
        let has_required_role = user_context
            .roles
            .iter()
            .any(|role| required_roles.contains(role));

        if !has_required_role {
            warn!(
                correlation_id = %correlation_id,
                user_id = %user_context.user_id,
                user_roles = ?user_context.roles,
                required_roles = ?required_roles,
                "Authorization failed: insufficient roles"
            );
            return Err(GatewayError::InsufficientPermissions {
                required_roles,
                user_roles: user_context.roles.clone(),
            });
        }
    }

    // Check permissions (PBAC - all required permissions must be present)
    if !required_permissions.is_empty() {
        let has_all_permissions = required_permissions
            .iter()
            .all(|perm| user_context.permissions.contains(perm));

        if !has_all_permissions {
            warn!(
                correlation_id = %correlation_id,
                user_id = %user_context.user_id,
                user_permissions = ?user_context.permissions,
                required_permissions = ?required_permissions,
                "Authorization failed: insufficient permissions"
            );
            return Err(GatewayError::InsufficientPermissions {
                required_roles: vec![],
                user_roles: vec![],
            });
        }
    }

    info!(
        correlation_id = %correlation_id,
        user_id = %user_context.user_id,
        "Authorization successful"
    );

    // Authorization successful, continue to next middleware
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_context_serialization() {
        let user = UserContext {
            user_id: "user123".to_string(),
            username: Some("john_doe".to_string()),
            roles: vec!["admin".to_string(), "user".to_string()],
            permissions: vec!["read".to_string(), "write".to_string()],
            extra: serde_json::json!({}),
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: UserContext = serde_json::from_str(&json).unwrap();

        assert_eq!(user.user_id, deserialized.user_id);
        assert_eq!(user.username, deserialized.username);
        assert_eq!(user.roles, deserialized.roles);
        assert_eq!(user.permissions, deserialized.permissions);
    }
}
