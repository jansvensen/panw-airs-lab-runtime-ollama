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
//
// This state is shared across all request handlers and contains
// initialized clients for communicating with Ollama and security services.
// The PANW AI Runtime API is used for security assessments of prompts and responses.
#[derive(Clone)]
pub struct AppState {
    ollama_client: OllamaClient,
    security_client: SecurityClient,
}

impl AppState {
    // Creates a new builder for constructing AppState with a fluent API.
    //
    // # Returns
    //
    // A new AppStateBuilder instance for configuring and building the application state.
    //
    // # Examples
    //
    // ```
    // let state = AppState::builder()
    //     .with_ollama_client(ollama_client)
    //     .with_security_client(security_client)
    //     .build()?;
    // ```
    pub fn builder() -> AppStateBuilder {
        AppStateBuilder::default()
    }
}

// Builder for creating AppState instances with a fluent API.
//
// This builder ensures that all required components are provided
// before constructing the final AppState.
#[derive(Default)]
pub struct AppStateBuilder {
    ollama_client: Option<OllamaClient>,
    security_client: Option<SecurityClient>,
}

impl AppStateBuilder {
    // Sets the Ollama client for the application state.
    //
    // # Arguments
    //
    // * `client` - An initialized OllamaClient instance
    //
    // # Returns
    //
    // The builder instance for method chaining
    pub fn with_ollama_client(mut self, client: OllamaClient) -> Self {
        self.ollama_client = Some(client);
        self
    }

    // Sets the security client for the application state.
    //
    // # Arguments
    //
    // * `client` - An initialized SecurityClient instance for PANW AI Runtime API
    //
    // # Returns
    //
    // The builder instance for method chaining
    pub fn with_security_client(mut self, client: SecurityClient) -> Self {
        self.security_client = Some(client);
        self
    }

    // Builds the AppState from the configured components.
    //
    // # Returns
    //
    // * `Ok(AppState)` - The fully constructed application state
    // * `Err(&'static str)` - Error message if any required component is missing
    //
    // # Errors
    //
    // Returns an error if either the Ollama client or security client is not provided
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
//
// This function:
// 1. Initializes logging
// 2. Loads the application configuration
// 3. Creates clients for Ollama and PANW AI Runtime security services
// 4. Sets up the HTTP router with all API endpoints
// 5. Starts the server listening for connections
//
// # Returns
//
// * `Ok(())` - Server started successfully
// * `Err(Box<dyn std::error::Error>)` - Error during initialization or execution
//
// # Errors
//
// May return errors if:
// - Configuration loading fails
// - Server address binding fails
// - Other I/O errors occur during server startup
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();
    info!("Starting panw-api-ollama server");

    // Load configuration
    let config = config::load_config("config.yaml").map_err(|e| {
        eprintln!("Failed to load configuration: {}", e);
        e
    })?;

    // Create application state
    let state = AppState {
        ollama_client: OllamaClient::new(&config.ollama.base_url),
        security_client: SecurityClient::new(
            &config.security.base_url,
            &config.security.api_key,
            &config.security.profile_name,
            &config.security.app_name,
            &config.security.app_user,
        ),
    };

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
