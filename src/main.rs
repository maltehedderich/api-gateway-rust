use api_gateway_rust::config::Config;
use api_gateway_rust::server::Server;
use std::fs;
use tracing::{error, info};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    // Load configuration first (before logging) to configure log sinks
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Invalid configuration: {}", e);
        std::process::exit(1);
    }

    // Initialize tracing/logging with configuration
    init_tracing(&config);

    info!("API Gateway starting...");
    info!("Configuration loaded and validated");

    // Create and run server
    let server = Server::new(config);

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

/// Initialize tracing/logging subsystem based on configuration
fn init_tracing(config: &Config) {
    // Determine log level from config or environment
    let log_level = config
        .logging
        .as_ref()
        .map(|l| l.level.as_str())
        .unwrap_or("INFO");

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "{},api_gateway_rust=debug",
            log_level.to_lowercase()
        ))
    });

    // Check if we have logging configuration
    let logging_config = config.logging.as_ref();

    // Check which sinks are enabled
    let (_has_stdout, has_file, file_config_opt) = if let Some(logging) = logging_config {
        if logging.sinks.is_empty() {
            // Default to stdout
            (true, false, None)
        } else {
            let mut stdout = false;
            let mut file = false;
            let mut file_cfg = None;

            for sink in &logging.sinks {
                if !sink.enabled {
                    continue;
                }

                match sink.sink_type.as_str() {
                    "stdout" => stdout = true,
                    "file" => {
                        if let Some(fc) = &sink.file {
                            file = true;
                            file_cfg = Some(fc.clone());
                        }
                    }
                    "elasticsearch" | "cloudwatch" | "splunk" => {
                        // Log warning about remote sinks not being implemented
                        eprintln!(
                            "WARNING: Remote log sink '{}' not implemented in application.\n\
                             Use container log drivers or log shippers (Fluentd, Filebeat) \
                             to forward stdout logs to remote destinations.\n\
                             See OPERATIONAL_READINESS.md for integration examples.",
                            sink.sink_type
                        );
                    }
                    _ => {
                        eprintln!("WARNING: Unknown log sink type: {}", sink.sink_type);
                    }
                }
            }

            (stdout, file, file_cfg)
        }
    } else {
        // No logging config, use default stdout
        (true, false, None)
    };

    // Build subscriber based on enabled sinks
    // Note: Currently supports one primary sink at a time
    // For multiple sinks, use infrastructure-level log forwarding
    if has_file {
        // File logging takes priority if configured
        if let Some(file_config) = file_config_opt {
            match create_file_appender(&file_config) {
                Ok(file_appender) => {
                    eprintln!("File logging enabled: {}", file_config.path.display());
                    let file_layer = create_file_layer(file_appender);
                    tracing_subscriber::registry()
                        .with(file_layer)
                        .with(env_filter)
                        .init();
                }
                Err(e) => {
                    eprintln!(
                        "Failed to create file log sink: {}, falling back to stdout",
                        e
                    );
                    let stdout_layer = create_stdout_layer();
                    tracing_subscriber::registry()
                        .with(stdout_layer)
                        .with(env_filter)
                        .init();
                }
            }
        } else {
            // File sink enabled but no config, use stdout
            let stdout_layer = create_stdout_layer();
            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(env_filter)
                .init();
        }
    } else {
        // Stdout logging (default)
        let stdout_layer = create_stdout_layer();
        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(env_filter)
            .init();
    }
}

/// Create stdout logging layer with JSON structured logging
fn create_stdout_layer() -> impl tracing_subscriber::Layer<tracing_subscriber::Registry> {
    tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_level(true)
        .with_file(true)
        .with_line_number(true)
}

/// Create file appender
fn create_file_appender(
    file_config: &api_gateway_rust::config::FileLogConfig,
) -> Result<RollingFileAppender, Box<dyn std::error::Error>> {
    // Ensure log directory exists
    if let Some(parent) = file_config.path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Determine rotation strategy
    // tracing-appender supports daily, hourly, minutely, never
    let rotation = if file_config.rotation_enabled {
        Rotation::DAILY
    } else {
        Rotation::NEVER
    };

    // Extract directory and file prefix
    let directory = file_config
        .path
        .parent()
        .ok_or("Invalid log file path: missing parent directory")?;

    let file_prefix = file_config
        .path
        .file_stem()
        .ok_or("Invalid log file path: missing file name")?
        .to_str()
        .ok_or("Invalid log file path: non-UTF8 file name")?;

    // Create rolling file appender
    Ok(RollingFileAppender::new(rotation, directory, file_prefix))
}

/// Create file logging layer with JSON structured logging and rotation
fn create_file_layer(
    file_appender: RollingFileAppender,
) -> impl tracing_subscriber::Layer<tracing_subscriber::Registry> {
    tracing_subscriber::fmt::layer()
        .json()
        .with_writer(file_appender)
        .with_ansi(false) // No ANSI color codes in files
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_level(true)
        .with_file(true)
        .with_line_number(true)
}
