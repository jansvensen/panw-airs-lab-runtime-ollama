use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::error;

pub mod chat;
pub mod embeddings;
pub mod generate;
pub mod models;
pub mod utils;
pub mod version;

// Custom error types for API handling
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Ollama error: {0}")]
    OllamaError(#[from] crate::ollama::OllamaError),
    #[error("Security error: {0}")]
    SecurityError(#[from] crate::security::SecurityError),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::OllamaError(e) => (StatusCode::BAD_GATEWAY, format!("Ollama error: {}", e)),
            ApiError::SecurityError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Security error: {}", e),
            ),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({ "error": error_message }));
        (status, body).into_response()
    }
}
