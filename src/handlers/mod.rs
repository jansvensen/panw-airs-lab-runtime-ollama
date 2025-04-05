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
#[derive(Debug)]
pub enum ApiError {
    OllamaError(crate::ollama::OllamaError),
    SecurityError(crate::security::SecurityError),
    InternalError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Determine the status code and error message based on the error type
        let (status, error_message) = match self {
            ApiError::OllamaError(err) => {
                error!("Ollama error: {}", err);
                (StatusCode::BAD_GATEWAY, format!("Ollama error: {}", err))
            }
            ApiError::SecurityError(err) => {
                error!("Security error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Security error: {}", err),
                )
            }
            ApiError::InternalError(msg) => {
                error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal error: {}", msg),
                )
            }
        };

        // Construct the JSON response body
        let body = Json(json!({
            "error": error_message,
        }));

        // Return the response with status and body
        (status, body).into_response()
    }
}

// Implement From trait for converting `OllamaError` to `ApiError`
impl From<crate::ollama::OllamaError> for ApiError {
    fn from(err: crate::ollama::OllamaError) -> Self {
        ApiError::OllamaError(err)
    }
}

// Implement From trait for converting `SecurityError` to `ApiError`
impl From<crate::security::SecurityError> for ApiError {
    fn from(err: crate::security::SecurityError) -> Self {
        ApiError::SecurityError(err)
    }
}
