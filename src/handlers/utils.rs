use axum::{body::Body, response::Response};
use bytes::Bytes;
use futures_util::stream::StreamExt;
use http_body_util::StreamBody;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use tracing::error;

use crate::{
    handlers::ApiError,
    stream::{SecurityAssessable, SecurityAssessedStream},
    AppState,
};

//Builds an HTTP response with JSON content type from the provided bytes.
pub fn build_json_response(bytes: Bytes) -> Result<Response, ApiError> {
    Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from(bytes))
        .map_err(|e| ApiError::InternalError(format!("Failed to create response: {}", e)))
}

// Handles streaming requests to API endpoints, applying security assessment to the streamed responses.
//
// This function takes a request payload, sends it to the specified endpoint using the Ollama client,
// wraps the resulting stream with security assessment functionality, and returns a properly configured
// HTTP response that streams the assessed results.
pub async fn handle_streaming_request<T, R>(
    state: &AppState,
    request: T,
    endpoint: &str,
    model: &str,
) -> Result<Response, ApiError>
where
    T: Serialize + Send + 'static,
    R: SecurityAssessable + DeserializeOwned + Serialize + Send + Sync + Unpin + 'static,
{
    // No need to clone, we already own the data
    let stream = state.ollama_client.stream(endpoint, &request).await?;

    let assessed_stream = SecurityAssessedStream::<_, R>::new(
        stream,
        state.security_client.clone(),
        model.to_string(),
    );

    let mapped_stream = StreamExt::map(assessed_stream, |result| match result {
        Ok(bytes) => Ok::<_, std::convert::Infallible>(bytes),
        Err(e) => {
            error!("Error in stream: {:?}", e);
            Ok(Bytes::from(
                json!({
                    "error": format!("Stream processing error: {}", e)
                })
                .to_string(),
            ))
        }
    });

    let stream_body = StreamBody::new(mapped_stream);
    let body = Body::from_stream(stream_body);

    Response::builder()
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| ApiError::InternalError(format!("Failed to create response: {}", e)))
}
