use crate::error::GatewayError;
use crate::middleware::CorrelationId;
use crate::routing::Router;
use crate::upstream::{build_upstream_uri, UpstreamClient};
use axum::{
    extract::{Request, State},
    response::Response,
};
use std::sync::Arc;
use tracing::{debug, error, info};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub router: Router,
    pub upstream_client: UpstreamClient,
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
                "Route matched"
            );

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
