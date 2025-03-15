pub mod chat;
pub mod embeddings;
pub mod generate;
pub mod models;
pub mod utils;
pub mod version;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::{error, info};

pub enum ApiError {
    OllamaError(crate::ollama::OllamaError),
    SecurityError(crate::security::SecurityError),
    SecurityIssue(String),
    InternalError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
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
            ApiError::SecurityIssue(msg) => {
                info!("Security issue detected: {}", msg);
                (StatusCode::FORBIDDEN, format!("Security issue: {}", msg))
            }
            ApiError::InternalError(msg) => {
                error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal error: {}", msg),
                )
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl From<crate::ollama::OllamaError> for ApiError {
    fn from(err: crate::ollama::OllamaError) -> Self {
        ApiError::OllamaError(err)
    }
}

impl From<crate::security::SecurityError> for ApiError {
    fn from(err: crate::security::SecurityError) -> Self {
        ApiError::SecurityError(err)
    }
}
