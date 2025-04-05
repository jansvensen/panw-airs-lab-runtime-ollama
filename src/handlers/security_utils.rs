use axum::response::Response;
use tracing::{error, info};

use crate::handlers::ApiError;
use crate::handlers::utils::build_json_response;

/// Formats a standard security violation message
pub fn format_security_violation_message(category: &str, action: &str) -> String {
    format!(
        "⚠️ This response was blocked due to security policy violations:\n\n\
        • Category: {}\n\
        • Action: {}\n\n\
        Please reformulate your request to comply with security policies.",
        category, action
    )
}

/// Logs security assessment failures
pub fn log_security_failure(context: &str, category: &str, action: &str) {
    info!(
        "Security issue detected in {}: category={}, action={}",
        context, category, action
    );
}

/// Builds a response with serialized data for a security violation
pub fn build_violation_response<T: serde::Serialize>(
    data: T,
) -> Result<Response, ApiError> {
    let json_bytes = serde_json::to_vec(&data).map_err(|e| {
        error!("Failed to serialize response: {}", e);
        ApiError::InternalError("Failed to serialize response".to_string())
    })?;

    build_json_response(bytes::Bytes::from(json_bytes))
}
