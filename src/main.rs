// Configuration loading and management.
mod config;

// HTTP request handlers for API endpoints.
mod handlers;

// Client for interacting with Ollama API services.
mod ollama;

// Security assessment and content filtering using PANW AI Runtime API.
mod security;

// Utilities for handling streaming responses.
mod stream;

// Common type definitions used throughout the application.
mod types;

use crate::handlers::*;
use crate::ollama::OllamaClient;
use crate::security::SecurityClient;
use axum::{
    routing::{get, post},
    Router,
};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tower_http::trace::TraceLayer;
use tracing::info;

// Shared application state containing clients for external services.
#[derive(Clone)]
pub struct AppState {
    ollama_client: OllamaClient,
    security_client: SecurityClient,
}

impl AppState {
    // Creates a new builder for constructing AppState with a fluent API.
    pub fn builder() -> AppStateBuilder {
        AppStateBuilder::default()
    }
}

// Builder for creating AppState instances with a fluent API.
#[derive(Default)]
pub struct AppStateBuilder {
    ollama_client: Option<OllamaClient>,
    security_client: Option<SecurityClient>,
}

impl AppStateBuilder {
    // Sets the Ollama client for the application state.
    pub fn with_ollama_client(mut self, client: OllamaClient) -> Self {
        self.ollama_client = Some(client);
        self
    }

    // Sets the security client for the application state.
    pub fn with_security_client(mut self, client: SecurityClient) -> Self {
        self.security_client = Some(client);
        self
    }

    // Builds the AppState from the configured components.
    pub fn build(self) -> Result<AppState, &'static str> {
        let ollama_client = self.ollama_client.ok_or("OllamaClient is required")?;
        let security_client = self.security_client.ok_or("SecurityClient is required")?;
        Ok(AppState {
            ollama_client,
            security_client,
        })
    }
}

// Application entry point that initializes and runs the server.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = config::load_config("config.yaml")?;

    // Parse the debug level from config
    let debug_level = tracing::Level::from_str(&config.server.debug_level).unwrap_or_else(|_| {
        eprintln!(
            "Unknown debug level: {}, defaulting to ERROR",
            config.server.debug_level
        );
        tracing::Level::ERROR
    });

    // Initialize logging with the configured level
    tracing_subscriber::fmt().with_max_level(debug_level).init();
    info!(
        "Starting panw-api-ollama server with log level: {}",
        debug_level
    );

    // Create application state
    let state = AppState::builder()
        .with_ollama_client(OllamaClient::new(&config.ollama.base_url))
        .with_security_client(SecurityClient::new(
            &config.security.base_url,
            &config.security.api_key,
            &config.security.profile_name,
            &config.security.app_name,
            &config.security.app_user,
        ))
        .build()?;

    // Build router with all the Ollama API endpoints
    let app = Router::new()
        .route("/api/generate", post(generate::handle_generate))
        .route("/api/chat", post(chat::handle_chat))
        .route("/api/tags", get(models::handle_list_models))
        .route("/api/show", post(models::handle_show_model))
        .route("/api/create", post(models::handle_create_model))
        .route("/api/copy", post(models::handle_copy_model))
        .route("/api/delete", post(models::handle_delete_model))
        .route("/api/pull", post(models::handle_pull_model))
        .route("/api/push", post(models::handle_push_model))
        .route("/api/embeddings", post(embeddings::handle_embeddings))
        .route("/api/version", get(version::handle_version))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start the server using the new Axum 0.7 API
    let addr = SocketAddr::new(IpAddr::from_str(&config.server.host)?, config.server.port);
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
