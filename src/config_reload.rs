use crate::config::Config;
use crate::error::GatewayError;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Configuration manager with hot-reload capability
pub struct ConfigManager {
    /// Current configuration
    config: Arc<RwLock<Config>>,
    /// Path to configuration file
    config_path: Option<PathBuf>,
    /// File watcher for configuration changes
    _watcher: Option<RecommendedWatcher>,
}

impl ConfigManager {
    /// Create a new configuration manager from environment variables
    pub fn from_env() -> Result<Self, GatewayError> {
        let config = Config::from_env()?;
        config.validate()?;

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path: None,
            _watcher: None,
        })
    }

    /// Create a new configuration manager from a file with hot-reload support
    pub fn from_file(path: PathBuf, enable_hot_reload: bool) -> Result<Self, GatewayError> {
        // Load initial configuration
        let config = Config::from_file(&path)?;
        config.validate()?;

        let config_arc = Arc::new(RwLock::new(config));

        // Set up file watcher if hot-reload is enabled
        let watcher = if enable_hot_reload {
            let config_clone = Arc::clone(&config_arc);
            let path_clone = path.clone();

            match Self::setup_watcher(path_clone, config_clone) {
                Ok(w) => {
                    info!("Configuration hot-reload enabled for {:?}", path);
                    Some(w)
                }
                Err(e) => {
                    warn!("Failed to setup configuration hot-reload: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config: config_arc,
            config_path: Some(path),
            _watcher: watcher,
        })
    }

    /// Get the current configuration (read-only access)
    pub fn get_config(&self) -> Arc<RwLock<Config>> {
        Arc::clone(&self.config)
    }

    /// Reload configuration from file
    pub async fn reload(&self) -> Result<(), GatewayError> {
        let path = self
            .config_path
            .as_ref()
            .ok_or_else(|| GatewayError::Config("No configuration file path set".to_string()))?;

        info!("Reloading configuration from {:?}", path);

        // Load new configuration
        let new_config = Config::from_file(path)?;

        // Validate new configuration before applying
        new_config.validate().map_err(|e| {
            error!("Configuration validation failed: {}", e);
            e
        })?;

        // Atomically swap the configuration
        let mut config_guard = self.config.write().await;
        *config_guard = new_config;

        info!("Configuration reloaded successfully");
        Ok(())
    }

    /// Set up file watcher for configuration changes
    fn setup_watcher(
        path: PathBuf,
        config: Arc<RwLock<Config>>,
    ) -> Result<RecommendedWatcher, GatewayError> {
        use notify::EventKind;

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                // Only reload on modify and create events
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    let _ = tx.blocking_send(());
                }
            }
        })
        .map_err(|e| GatewayError::Config(format!("Failed to create file watcher: {}", e)))?;

        // Watch the configuration file
        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(|e| GatewayError::Config(format!("Failed to watch config file: {}", e)))?;

        // Spawn task to handle reload events
        let path_clone = path.clone();
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                info!("Configuration file changed, reloading...");

                // Load and validate new configuration
                match Config::from_file(&path_clone) {
                    Ok(new_config) => match new_config.validate() {
                        Ok(()) => {
                            // Atomically swap the configuration
                            let mut config_guard = config.write().await;
                            *config_guard = new_config;
                            info!("Configuration reloaded successfully");
                        }
                        Err(e) => {
                            error!("Configuration validation failed, keeping old config: {}", e);
                        }
                    },
                    Err(e) => {
                        error!(
                            "Failed to load new configuration, keeping old config: {}",
                            e
                        );
                    }
                }
            }
        });

        Ok(watcher)
    }

    /// Handle SIGHUP signal for manual reload
    pub async fn handle_sighup_signal(config_manager: Arc<Self>) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to register SIGHUP handler: {}", e);
                    return;
                }
            };

            info!("SIGHUP handler registered");

            loop {
                sighup.recv().await;
                info!("Received SIGHUP signal, reloading configuration...");

                if let Err(e) = config_manager.reload().await {
                    error!("Failed to reload configuration: {}", e);
                } else {
                    info!("Configuration reloaded successfully via SIGHUP");
                }
            }
        }

        #[cfg(not(unix))]
        {
            warn!("SIGHUP signal handling is only supported on Unix systems");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_manager_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"
server:
  bind_address: "0.0.0.0"
  port: 8443
routes: []
upstreams: []
"#
        )
        .unwrap();

        let manager = ConfigManager::from_file(temp_file.path().to_path_buf(), false).unwrap();
        let config = manager.get_config();
        let config_guard = config.read().await;

        assert_eq!(config_guard.server.port, 8443);
    }

    #[tokio::test]
    async fn test_config_reload() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"
server:
  bind_address: "0.0.0.0"
  port: 8443
routes: []
upstreams: []
"#
        )
        .unwrap();

        let manager = ConfigManager::from_file(temp_file.path().to_path_buf(), false).unwrap();

        // Modify the config file by writing new content
        let path = temp_file.path().to_path_buf();
        drop(temp_file); // Close the file first

        // Write new content
        std::fs::write(
            &path,
            r#"
server:
  bind_address: "0.0.0.0"
  port: 9443
routes: []
upstreams: []
"#,
        )
        .unwrap();

        // Reload configuration
        manager.reload().await.unwrap();

        let config = manager.get_config();
        let config_guard = config.read().await;
        assert_eq!(config_guard.server.port, 9443);
    }
}
