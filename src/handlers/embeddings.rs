use crate::handlers::utils::build_json_response;
use crate::handlers::ApiError;
use crate::types::EmbeddingsRequest;
use crate::AppState;
use axum::{extract::State, response::Response, Json};
use tracing::debug;

pub async fn handle_embeddings(
    State(state): State<AppState>,
    Json(request): Json<EmbeddingsRequest>,
) -> Result<Response, ApiError> {
    debug!("Received embeddings request for model: {}", request.model);

    let assessment = state
        .security_client
        .assess_content(
            &request.prompt,
            &request.model,
            true, // This is a prompt
        )
        .await?;

    if !assessment.is_safe {
        // Create a formatted response instead of returning error
        let _blocked_message = format!(
            "⚠️ This embedding request was blocked due to security policy violations:\n\n\
            • Category: {}\n\
            • Action: {}\n\n\
            Please reformulate your request to comply with security policies.",
            assessment.category, assessment.action
        );

        // Return a mock embedding response with zeros
        let response = crate::types::EmbeddingsResponse {
            embedding: vec![0.0; 10], // A small vector of zeros as placeholder
        };

        let json_bytes = serde_json::to_vec(&response)
            .map_err(|e| ApiError::InternalError(format!("Failed to serialize response: {}", e)))?;

        return Ok(build_json_response(bytes::Bytes::from(json_bytes))?);
    }

    // Forward to Ollama
    let response = state
        .ollama_client
        .forward("/api/embeddings", &request)
        .await?;
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    Ok(build_json_response(body_bytes)?)
}
