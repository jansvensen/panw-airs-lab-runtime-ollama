/// Configuration loading and management for the application.
///
/// This module handles loading, parsing, and validating configuration settings
/// from a YAML configuration file. It provides strongly typed access to
/// application settings for server properties, Ollama API integration,
/// and security services.
///
/// # Configuration Flow
///
/// 1. Load configuration from YAML file
/// 2. Parse into structured types
/// 3. Validate all required settings
/// 4. Make configuration available to application components
use serde::Deserialize;
use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};

/// Errors that can occur when loading or validating configuration.
///
/// This enum encapsulates the various failure modes when dealing with
/// configuration, including file access errors, YAML parsing issues,
/// and validation of configuration values.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File I/O errors when reading the configuration file
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    /// YAML parsing errors in the configuration file
    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] serde_yaml::Error),

    /// Configuration validation errors
    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Root configuration structure containing all application settings.
///
/// This structure is the top-level container for all configuration settings
/// used by the application, organized into logical sections.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Server configuration settings
    pub server: ServerConfig,

    /// Ollama API integration settings
    pub ollama: OllamaConfig,

    /// Security and content filtering settings
    pub security: SecurityConfig,
}

/// Server configuration settings.
///
/// Controls how the proxy server listens for connections and processes requests.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// IP address to bind the server to
    pub host: String,

    /// Port number to listen on
    pub port: u16,

    /// Logging level (e.g., "INFO", "DEBUG", "ERROR")
    pub debug_level: String,
}

/// Ollama API integration settings.
///
/// Configuration for connecting to and interacting with the Ollama API service.
#[derive(Debug, Clone, Deserialize)]
pub struct OllamaConfig {
    /// Base URL of the Ollama API service
    pub base_url: String,
}

/// Security and content filtering settings.
///
/// Configuration for connecting to the PANW AI Runtime security service
/// and setting up content security scanning.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Base URL of the PANW AI Runtime security API
    pub base_url: String,

    /// API key for authenticating with the security service
    pub api_key: String,

    /// Security profile name to use for assessments
    pub profile_name: String,

    /// Application name for telemetry and audit
    pub app_name: String,

    /// Application user identifier
    pub app_user: String,
}

/// Loads configuration from a YAML file.
///
/// This function reads the configuration file from the specified path,
/// parses it into a structured Config object, and validates all settings.
///
/// # Arguments
///
/// * `path` - Path to the YAML configuration file
///
/// # Returns
///
/// * `Ok(Config)` - Validated configuration object
/// * `Err(ConfigError)` - If loading or validation fails
///
/// # Example
///
/// ```
/// let config = config::load_config("config.yaml")?;
/// println!("Server will listen on {}:{}", config.server.host, config.server.port);
/// ```
pub fn load_config(path: &str) -> Result<Config, ConfigError> {
    info!("Loading configuration from {}", path);

    // Check if file exists
    if !Path::new(path).exists() {
        return Err(ConfigError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Configuration file not found: {}", path),
        )));
    }

    // Read file content
    let content = fs::read_to_string(path)?;
    debug!("Successfully read configuration file");

    // Parse YAML
    let config: Config = serde_yaml::from_str(&content)?;
    debug!("Successfully parsed YAML configuration");

    // Validate configuration
    config.validate()?;
    info!("Configuration validated successfully");

    Ok(config)
}

impl Config {
    /// Validates all configuration settings.
    ///
    /// This method checks that all required configuration values are present
    /// and valid, returning an error if any validation fails.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all validation checks pass
    /// * `Err(ConfigError)` - If any validation check fails
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate server config
        if self.server.host.is_empty() {
            return Err(ConfigError::ValidationError(
                "Server host cannot be empty".into(),
            ));
        }

        // Validate ollama config
        if self.ollama.base_url.is_empty() {
            return Err(ConfigError::ValidationError(
                "Ollama base URL cannot be empty".into(),
            ));
        }

        // Ensure Ollama URL is properly formatted
        if !self.ollama.base_url.starts_with("http") {
            return Err(ConfigError::ValidationError(
                "Ollama base URL must start with http:// or https://".into(),
            ));
        }

        // Validate security config - API credentials
        if self.security.base_url.is_empty() || self.security.api_key.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security credentials missing (base_url or api_key)".into(),
            ));
        }

        // Ensure security URL is properly formatted
        if !self.security.base_url.starts_with("http") {
            return Err(ConfigError::ValidationError(
                "Security base URL must start with http:// or https://".into(),
            ));
        }

        // Validate PANW AI profile config
        if self.security.profile_name.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security profile_name is required".into(),
            ));
        }

        if self.security.app_name.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security app_name is required".into(),
            ));
        }

        if self.security.app_user.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security app_user is required".into(),
            ));
        }

        Ok(())
    }
}
