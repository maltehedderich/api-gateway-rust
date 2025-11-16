use crate::auth::validate_jwt_token;
use crate::config::AuthConfig;
use crate::error::GatewayError;
use crate::metrics::{
    self, record_auth_error, record_auth_failure, record_auth_success, record_authz_decision,
    DurationTimer, AUTHZ_DURATION_SECONDS, AUTH_DURATION_SECONDS,
};
use crate::middleware::{ClientIp, CorrelationId};
use crate::rate_limiter::{add_rate_limit_headers, RateLimitContext, RateLimiter};
use crate::routing::Router;
use crate::upstream::{build_upstream_uri, UpstreamClient};
use axum::{
    extract::{Request, State},
    http::header,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub router: Router,
    pub upstream_client: UpstreamClient,
    pub auth_config: Option<Arc<AuthConfig>>,
    pub rate_limiter: Option<RateLimiter>,
}

/// Main request handler that routes and forwards requests to upstream services
pub async fn handle_request(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, GatewayError> {
    let method = request.method().clone();
    let uri = request.uri().clone();

    // Extract correlation ID from request extensions
    let correlation_id = request
        .extensions()
        .get::<CorrelationId>()
        .map(|id| id.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    debug!(
        correlation_id = %correlation_id,
        method = %method,
        uri = %uri.path(),
        "Processing request"
    );

    // Find matching route
    let route_match = state.router.find_route(&method, &uri);

    match route_match {
        Some(route_match) => {
            let route = route_match.route;

            info!(
                correlation_id = %correlation_id,
                route_id = %route.id,
                upstream_id = %route.upstream.id,
                method = %method,
                path = %uri.path(),
                auth_required = route.auth_required,
                "Route matched"
            );

            // Perform authentication if required for this route
            let user_context = if route.auth_required {
                let auth_timer = DurationTimer::new();

                debug!(
                    correlation_id = %correlation_id,
                    route_id = %route.id,
                    "Authentication required for route"
                );

                // Extract token from request
                let token = extract_token(&request, &state.auth_config).ok_or_else(|| {
                    warn!(
                        correlation_id = %correlation_id,
                        route_id = %route.id,
                        "Authentication failed: missing token"
                    );
                    record_auth_failure("missing_token");
                    GatewayError::MissingToken
                })?;

                // Validate token
                let auth_config = state.auth_config.as_ref().ok_or_else(|| {
                    error!(
                        correlation_id = %correlation_id,
                        "Authentication required but auth config not found"
                    );
                    record_auth_error();
                    GatewayError::AuthenticationFailed("Authentication not configured".to_string())
                })?;

                let user = validate_jwt_token(&token, auth_config).map_err(|e| {
                    warn!(
                        correlation_id = %correlation_id,
                        route_id = %route.id,
                        error = %e,
                        "Authentication failed: token validation error"
                    );

                    // Record specific failure reason based on error type
                    match &e {
                        GatewayError::TokenExpired => record_auth_failure("token_expired"),
                        GatewayError::InvalidToken(_) => record_auth_failure("invalid_token"),
                        GatewayError::TokenRevoked => record_auth_failure("token_revoked"),
                        _ => record_auth_failure("validation_error"),
                    }

                    e
                })?;

                // Record successful authentication
                record_auth_success();
                auth_timer.observe_duration(&AUTH_DURATION_SECONDS, &["validate_token"]);

                info!(
                    correlation_id = %correlation_id,
                    route_id = %route.id,
                    user_id = %user.user_id,
                    roles = ?user.roles,
                    "Authentication successful"
                );

                Some(user)
            } else {
                None
            };

            // Perform authorization if required (check roles and permissions)
            if let Some(ref user) = user_context {
                let authz_timer = DurationTimer::new();

                // Check roles (RBAC - any matching role grants access)
                if !route.required_roles.is_empty() {
                    let has_required_role = user
                        .roles
                        .iter()
                        .any(|role| route.required_roles.contains(role));

                    if !has_required_role {
                        warn!(
                            correlation_id = %correlation_id,
                            route_id = %route.id,
                            user_id = %user.user_id,
                            user_roles = ?user.roles,
                            required_roles = ?route.required_roles,
                            "Authorization failed: insufficient roles"
                        );
                        record_authz_decision(false);
                        authz_timer.observe_duration(&AUTHZ_DURATION_SECONDS, &["check_roles"]);
                        return Err(GatewayError::InsufficientPermissions {
                            required_roles: route.required_roles.clone(),
                            user_roles: user.roles.clone(),
                        });
                    }
                }

                // Check permissions (PBAC - all required permissions must be present)
                if !route.required_permissions.is_empty() {
                    let has_all_permissions = route
                        .required_permissions
                        .iter()
                        .all(|perm| user.permissions.contains(perm));

                    if !has_all_permissions {
                        warn!(
                            correlation_id = %correlation_id,
                            route_id = %route.id,
                            user_id = %user.user_id,
                            user_permissions = ?user.permissions,
                            required_permissions = ?route.required_permissions,
                            "Authorization failed: insufficient permissions"
                        );
                        record_authz_decision(false);
                        authz_timer
                            .observe_duration(&AUTHZ_DURATION_SECONDS, &["check_permissions"]);
                        return Err(GatewayError::InsufficientPermissions {
                            required_roles: vec![],
                            user_roles: vec![],
                        });
                    }
                }

                // Record successful authorization
                record_authz_decision(true);
                authz_timer.observe_duration(&AUTHZ_DURATION_SECONDS, &["check_success"]);

                info!(
                    correlation_id = %correlation_id,
                    route_id = %route.id,
                    user_id = %user.user_id,
                    "Authorization successful"
                );
            }

            // Rate limiting check
            if let Some(ref rate_limiter) = state.rate_limiter {
                // Determine which rate limit policy to use (route-specific or global)
                let rate_limit_policy = route.rate_limit.as_ref().or({
                    // Try to get global default policy
                    // Note: We would need to store this in AppState, but for now we'll just skip if no route policy
                    None
                });

                if let Some(policy) = rate_limit_policy {
                    let rate_limit_timer = DurationTimer::new();

                    // Extract client IP
                    let client_ip = request
                        .extensions()
                        .get::<ClientIp>()
                        .map(|ip| ip.0.clone())
                        .unwrap_or_else(|| "unknown".to_string());

                    // Extract user ID from user context
                    let user_id = user_context.as_ref().map(|u| u.user_id.clone());

                    // Construct rate limit context
                    let rate_limit_ctx = RateLimitContext {
                        client_ip: client_ip.clone(),
                        user_id: user_id.clone(),
                        route_id: route.id.clone(),
                    };

                    debug!(
                        correlation_id = %correlation_id,
                        route_id = %route.id,
                        client_ip = %client_ip,
                        user_id = ?user_id,
                        "Checking rate limit"
                    );

                    // Check rate limit
                    let decision = match rate_limiter.check_limit(&rate_limit_ctx, policy).await {
                        Ok(decision) => decision,
                        Err(e) => {
                            error!(
                                correlation_id = %correlation_id,
                                route_id = %route.id,
                                error = %e,
                                "Rate limit check failed"
                            );
                            rate_limit_timer.observe_duration(
                                &metrics::RATE_LIMIT_DURATION_SECONDS,
                                &["check_failed"],
                            );
                            return Err(e);
                        }
                    };

                    // Record metrics
                    metrics::record_rate_limit_decision(
                        decision.allowed,
                        &route.id,
                        &policy.key_type,
                    );
                    rate_limit_timer
                        .observe_duration(&metrics::RATE_LIMIT_DURATION_SECONDS, &["check"]);

                    if !decision.allowed {
                        // Rate limit exceeded
                        warn!(
                            correlation_id = %correlation_id,
                            route_id = %route.id,
                            client_ip = %client_ip,
                            user_id = ?user_id,
                            current_count = decision.current_count,
                            limit = decision.limit,
                            "Rate limit exceeded"
                        );

                        let error = GatewayError::RateLimitExceeded {
                            limit: decision.limit,
                            window_secs: policy.window_secs,
                            reset_at: decision.reset_at,
                            retry_after_secs: decision.retry_after_secs,
                        };

                        let mut response = error.into_response();
                        add_rate_limit_headers(response.headers_mut(), &decision);
                        return Ok(response);
                    }

                    info!(
                        correlation_id = %correlation_id,
                        route_id = %route.id,
                        remaining = decision.remaining,
                        limit = decision.limit,
                        "Rate limit check passed"
                    );
                }
            }

            // Build upstream URI
            let upstream_uri = build_upstream_uri(
                &uri,
                route.strip_prefix.as_ref(),
                route.upstream_path.as_ref(),
            );

            debug!(
                correlation_id = %correlation_id,
                upstream_uri = %upstream_uri,
                "Built upstream URI"
            );

            // Forward request to upstream
            let response = state
                .upstream_client
                .forward_request(
                    request,
                    &route.upstream,
                    upstream_uri,
                    route.timeout_secs,
                    &correlation_id,
                )
                .await?;

            Ok(response)
        }
        None => {
            // Check if route exists for path but with different method (405)
            if state.router.has_route_for_path(&uri) {
                error!(
                    correlation_id = %correlation_id,
                    method = %method,
                    path = %uri.path(),
                    "Method not allowed"
                );
                // In a full implementation, we would collect allowed methods here
                Err(GatewayError::MethodNotAllowed(vec![]))
            } else {
                error!(
                    correlation_id = %correlation_id,
                    method = %method,
                    path = %uri.path(),
                    "Route not found"
                );
                Err(GatewayError::NotFound)
            }
        }
    }
}

/// Extract session token from request
///
/// Looks for token in:
/// 1. Cookie (with configured cookie name)
/// 2. Authorization header (Bearer scheme)
fn extract_token(request: &Request, auth_config: &Option<Arc<AuthConfig>>) -> Option<String> {
    let cookie_name = auth_config
        .as_ref()
        .map(|c| c.cookie_name.as_str())
        .unwrap_or("session_token");

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
