use crate::config::AuthConfig;
use crate::error::GatewayError;
use axum::{
    extract::Request,
    http::header,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
/// 2. Validates the JWT token
/// 3. Extracts user context from token claims
/// 4. Attaches user context to request extensions
/// 5. Returns 401 Unauthorized if authentication fails
pub async fn authentication_middleware(
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
        "Attempting authentication"
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
