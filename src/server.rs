use crate::config::{Config, TlsConfig};
use crate::error::GatewayError;
use crate::handler::{handle_request, AppState};
use crate::metrics::export_metrics;
use crate::middleware::{client_ip_middleware, correlation_id_middleware};
use crate::rate_limiter::RateLimiter;
use crate::routing::Router as GatewayRouter;
use crate::upstream::UpstreamClient;
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{any, get},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig as RustlsServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, error, info, warn};

/// HTTP Server for the API Gateway
pub struct Server {
    config: Config,
}

impl Server {
    /// Create a new server with the given configuration
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Start the server
    pub async fn run(self) -> Result<(), GatewayError> {
        let addr: SocketAddr = format!(
            "{}:{}",
            self.config.server.bind_address, self.config.server.port
        )
        .parse()
        .map_err(|e| GatewayError::Config(format!("Invalid bind address: {}", e)))?;

        // Build the application router
        let app = self.build_app();

        info!("Starting API Gateway server");
        info!("Listening on {}", addr);

        // Start server with or without TLS
        if let Some(ref tls_config) = self.config.server.tls {
            info!("TLS enabled - HTTPS mode");
            self.run_with_tls(addr, app, tls_config).await?;
        } else {
            warn!("TLS disabled - HTTP mode (not recommended for production)");
            self.run_without_tls(addr, app).await?;
        }

        Ok(())
    }

    /// Build the application router with middleware
    fn build_app(&self) -> Router {
        // Create the gateway router from configuration
        let gateway_router =
            GatewayRouter::from_config(self.config.routes.clone(), self.config.upstreams.clone())
                .expect("Failed to create gateway router");

        // Determine pool size (use first upstream's config or default)
        let pool_size = self
            .config
            .upstreams
            .first()
            .map(|u| u.pool_max_idle_per_host)
            .unwrap_or(10);

        // Create upstream client
        let upstream_client =
            UpstreamClient::new(pool_size).expect("Failed to create upstream client");

        // Create application state with optional auth config
        let auth_config = self.config.auth.clone().map(Arc::new);

        // Create rate limiter if rate limiting is configured
        let rate_limiter = if let Some(ref rate_limiting_config) = self.config.rate_limiting {
            match tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { RateLimiter::new(rate_limiting_config.clone()).await })
            }) {
                Ok(limiter) => {
                    info!("Rate limiter initialized successfully");
                    Some(limiter)
                }
                Err(e) => {
                    error!("Failed to initialize rate limiter: {}", e);
                    warn!("Rate limiting will be disabled");
                    None
                }
            }
        } else {
            info!("Rate limiting not configured");
            None
        };

        let app_state = Arc::new(AppState {
            router: gateway_router,
            upstream_client,
            auth_config,
            rate_limiter,
        });

        info!(
            routes_count = self.config.routes.len(),
            upstreams_count = self.config.upstreams.len(),
            "Gateway routing configured"
        );

        // Create the main router
        Router::new()
            .route("/health/live", any(health_live))
            .route("/health/ready", any(health_ready))
            .route("/metrics", get(metrics_handler))
            .fallback(handle_request)
            .with_state(app_state)
            // Add client IP extraction middleware
            .layer(middleware::from_fn(client_ip_middleware))
            // Add correlation ID middleware
            .layer(middleware::from_fn(correlation_id_middleware))
            // Add tracing layer for request logging
            .layer(
                TraceLayer::new_for_http()
                    .on_request(|request: &Request, _span: &tracing::Span| {
                        debug!(
                            method = %request.method(),
                            uri = %request.uri(),
                            "Incoming request"
                        );
                    })
                    .on_response(
                        |response: &axum::response::Response,
                         latency: Duration,
                         _span: &tracing::Span| {
                            info!(
                                status = %response.status(),
                                latency_ms = %latency.as_millis(),
                                "Request completed"
                            );
                        },
                    )
                    .on_failure(
                        |error: tower_http::classify::ServerErrorsFailureClass,
                         latency: Duration,
                         _span: &tracing::Span| {
                            error!(
                                error = %error,
                                latency_ms = %latency.as_millis(),
                                "Request failed"
                            );
                        },
                    ),
            )
            // Add timeout layer
            .layer(TimeoutLayer::new(Duration::from_secs(
                self.config.server.request_timeout_secs,
            )))
    }

    /// Run the server with TLS
    async fn run_with_tls(
        &self,
        addr: SocketAddr,
        app: Router,
        tls_config: &TlsConfig,
    ) -> Result<(), GatewayError> {
        // Load TLS configuration
        let rustls_config = load_tls_config(tls_config).await?;

        // Create the server
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| GatewayError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }

    /// Run the server without TLS (HTTP only)
    async fn run_without_tls(&self, addr: SocketAddr, app: Router) -> Result<(), GatewayError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| GatewayError::Io(e))?;

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| GatewayError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }
}

/// Load TLS configuration from certificate and key files
async fn load_tls_config(tls_config: &TlsConfig) -> Result<RustlsConfig, GatewayError> {
    info!("Loading TLS certificate from: {:?}", tls_config.cert_path);
    info!("Loading TLS private key from: {:?}", tls_config.key_path);

    // Read certificate and key files
    let cert_data = tokio::fs::read(&tls_config.cert_path).await.map_err(|e| {
        GatewayError::TlsConfig(format!(
            "Failed to read certificate file {:?}: {}",
            tls_config.cert_path, e
        ))
    })?;

    let key_data = tokio::fs::read(&tls_config.key_path).await.map_err(|e| {
        GatewayError::TlsConfig(format!(
            "Failed to read key file {:?}: {}",
            tls_config.key_path, e
        ))
    })?;

    // Parse certificates
    let certs = rustls_pemfile::certs(&mut cert_data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| GatewayError::TlsConfig(format!("Failed to parse certificate: {}", e)))?;

    if certs.is_empty() {
        return Err(GatewayError::TlsConfig(
            "No certificates found in certificate file".to_string(),
        ));
    }

    // Parse private key
    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| GatewayError::TlsConfig(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| GatewayError::TlsConfig("No private key found in key file".to_string()))?;

    // Build TLS server config
    let config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| GatewayError::TlsConfig(format!("Failed to build TLS config: {}", e)))?;

    info!("TLS configuration loaded successfully");

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

/// Health check endpoint - liveness probe
async fn health_live() -> impl IntoResponse {
    StatusCode::OK
}

/// Health check endpoint - readiness probe
async fn health_ready() -> impl IntoResponse {
    // For now, just return OK. In future phases, this will check dependencies
    StatusCode::OK
}

/// Metrics endpoint - Prometheus-compatible metrics export
async fn metrics_handler() -> impl IntoResponse {
    match export_metrics() {
        Ok(metrics) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            metrics,
        )
            .into_response(),
        Err(e) => {
            error!("Failed to export metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to export metrics",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = Config::default();
        let server = Server::new(config);
        assert_eq!(server.config.server.port, 8443);
    }
}
