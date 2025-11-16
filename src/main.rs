use api_gateway_rust::config::Config;
use api_gateway_rust::server::Server;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    // Initialize tracing/logging
    init_tracing();

    info!("API Gateway starting...");

    // Load configuration
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Invalid configuration: {}", e);
        std::process::exit(1);
    }

    info!("Configuration loaded and validated");

    // Create and run server
    let server = Server::new(config);

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

/// Initialize tracing/logging subsystem
fn init_tracing() {
    // Set up environment filter
    // Default to INFO level, can be overridden with RUST_LOG environment variable
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,api_gateway_rust=debug"));

    // Create JSON formatter for structured logging
    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_level(true)
        .with_file(true)
        .with_line_number(true);

    // Initialize the subscriber
    tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        .init();
}
