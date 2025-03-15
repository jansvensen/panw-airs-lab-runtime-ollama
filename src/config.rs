use serde::Deserialize;
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub ollama: OllamaConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OllamaConfig {
    pub base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub base_url: String,
    pub api_key: String,
    pub profile_name: String,
    pub app_name: String,
    pub app_user: String,
}

pub fn load_config(path: &str) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)?;
    config.validate()?;
    Ok(config)
}

impl Config {
    // Validate configuration values
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

        // Validate security config
        if self.security.base_url.is_empty() || self.security.api_key.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security credentials missing".into(),
            ));
        }

        // Validate PANW AI AI profile config
        if self.security.profile_name.is_empty()
            || self.security.app_name.is_empty()
            || self.security.app_user.is_empty()
        {
            return Err(ConfigError::ValidationError(
                "AI Profile settings missing".into(),
            ));
        }

        Ok(())
    }
}
