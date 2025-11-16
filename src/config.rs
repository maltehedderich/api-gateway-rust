use crate::error::GatewayError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for the API Gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
        }
    }
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
