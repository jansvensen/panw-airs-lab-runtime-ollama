use crate::{
    handlers::ApiError,
    stream::{SecurityAssessable, SecurityAssessedStream, StreamError},
    AppState,
};

use axum::{body::Body, response::Response};
use bytes::Bytes;
use futures_util::stream::StreamExt;
use http_body_util::StreamBody;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{error, info};

// Builds an HTTP response with JSON content type from the provided bytes.
pub fn build_json_response(bytes: Bytes) -> Result<Response<Body>, ApiError> {
    Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from(bytes))
        .map_err(|e| ApiError::InternalError(format!("Failed to create response: {}", e)))
}

// Helper function to convert `reqwest::Error` to `StreamError`.
fn convert_stream_error(_err: reqwest::Error) -> StreamError {
    StreamError::Unknown
}

// Handles streaming requests to API endpoints, applying security assessment to the streamed responses.
pub async fn handle_streaming_request<T, R>(
    state: &AppState,
    request: T,
    endpoint: &str,
    model: &str,
) -> Result<Response<Body>, ApiError>
where
    T: Serialize + Send + 'static,
    R: SecurityAssessable + DeserializeOwned + Serialize + Send + Sync + Unpin + 'static,
{
    // Get the original stream from ollama client
    let stream = state.ollama_client.stream(endpoint, &request).await?;

    // Convert the stream to the expected type by mapping the error type
    let converted_stream = stream.map(|result| match result {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(convert_stream_error(e)),
    });

    // Create the security-assessed stream
    let assessed_stream = SecurityAssessedStream::<_, R>::new(
        converted_stream,
        state.security_client.clone(),
        model.to_string(),
    );

    // Clone the model string for use in the closure
    let model_string = model.to_string();

    // Map any errors to bytes for the final stream - add 'move' to take ownership
    let mapped_stream = assessed_stream.map(move |result| match result {
        Ok(bytes) => Ok::<_, std::convert::Infallible>(bytes),
        Err(e) => {
            error!("Error in security assessment stream: {:?}", e);
            // Convert error to a user-friendly message
            let error_message = match e {
                _ => "Error processing response",
            };
            let error_json = serde_json::json!({
                "model": model_string, // Use the cloned string here
                "error": error_message,
                "done": true
            });
            let error_bytes = serde_json::to_vec(&error_json)
                .unwrap_or_else(|_| error_message.as_bytes().to_vec());
            Ok(Bytes::from(error_bytes))
        }
    });

    // Create and return the streaming response
    let stream_body = StreamBody::new(mapped_stream);
    let body = Body::from_stream(stream_body);

    Response::builder()
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| ApiError::InternalError(format!("Failed to create response: {}", e)))
}

// Formats a standard security violation message.
pub fn format_security_violation_message(category: &str, action: &str) -> String {
    format!(
        "⚠️ This response was blocked due to security policy violations:\n\n\
         • Category: {}\n\
         • Action: {}\n\n\
         Please reformulate your request to comply with security policies.",
        category, action
    )
}

// Logs security assessment failures.
pub fn log_security_failure(context: &str, category: &str, action: &str) {
    info!(
        "Security issue detected in {}: category={}, action={}",
        context, category, action
    );
}

// Builds a response with serialized data for a security violation.
pub fn build_violation_response<T>(data: T) -> Result<Response<Body>, ApiError>
where
    T: Serialize,
{
    let json_bytes = serde_json::to_vec(&data).map_err(|e| {
        error!("Failed to serialize response: {}", e);
        ApiError::InternalError("Failed to serialize response".to_string())
    })?;
    build_json_response(Bytes::from(json_bytes))
}
