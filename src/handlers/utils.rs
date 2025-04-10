use crate::{handlers::ApiError, stream::SecurityAssessedStream, AppState};

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
fn convert_stream_error(err: reqwest::Error) -> reqwest::Error {
    err // Maintain original error type
}

// Handles streaming requests to API endpoints, applying security assessment to the streamed responses.
pub async fn handle_streaming_request<T, R>(
    state: &AppState,
    request: T,
    endpoint: &str,
    model: &str,
    is_prompt: bool,
) -> Result<Response<Body>, ApiError>
where
    T: Serialize + Send + 'static,
    R: DeserializeOwned + Serialize + Send + Sync + Unpin + 'static,
{
    // Get the original stream from ollama client
    let stream = state.ollama_client.stream(endpoint, &request).await?;

    // Convert the stream to the expected type by mapping the error type
    let converted_stream = stream.map(|result| result.map_err(convert_stream_error));

    // Create the security-assessed stream
    let assessed_stream = SecurityAssessedStream::new(
        converted_stream,
        state.security_client.clone(),
        model.to_string(),
        is_prompt,
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
                "model": model_string,
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

// Formats a comprehensive security violation message with detailed detection reasons.
pub fn format_security_violation_message(assessment: &crate::security::Assessment) -> String {
    let mut reasons = Vec::new();

    // Check prompt detection reasons
    if assessment.details.prompt_detected.url_cats {
        reasons.push("Prompt contains malicious URLs");
    }
    if assessment.details.prompt_detected.dlp {
        reasons.push("Prompt contains sensitive information");
    }
    if assessment.details.prompt_detected.injection {
        reasons.push("Prompt contains injection threats");
    }
    if assessment.details.prompt_detected.toxic_content {
        reasons.push("Prompt contains harmful content");
    }
    if assessment.details.prompt_detected.malicious_code {
        reasons.push("Prompt contains malicious code");
    }

    // Check response detection reasons
    if assessment.details.response_detected.url_cats {
        reasons.push("Response contains malicious URLs");
    }
    if assessment.details.response_detected.dlp {
        reasons.push("Response contains sensitive information");
    }
    if assessment.details.response_detected.db_security {
        reasons.push("Response contains database security threats");
    }
    if assessment.details.response_detected.toxic_content {
        reasons.push("Response contains harmful content");
    }
    if assessment.details.response_detected.malicious_code {
        reasons.push("Response contains malicious code");
    }

    let reasons_text = if reasons.is_empty() {
        "Unspecified security concern".to_string()
    } else {
        reasons.join("\n• ")
    };

    format!(
        "⚠️ This content was blocked due to security policy violations:\n\n\
         • Category: {}\n\
         • Action: {}\n\
         • Reasons: {}\n\n\
         Please reformulate your request to comply with security policies.",
        assessment.category, assessment.action, reasons_text
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
