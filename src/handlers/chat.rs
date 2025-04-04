use axum::{extract::State, response::Response, Json};
use tracing::{debug, error, info};

use crate::handlers::utils::{build_json_response, handle_streaming_request};
use crate::handlers::ApiError;
use crate::stream::SecurityAssessable;
use crate::types::{ChatRequest, ChatResponse, Message};
use crate::AppState;

impl SecurityAssessable for crate::types::ChatResponse {
    fn get_content_for_assessment(&self) -> Option<(&str, &str)> {
        Some((&self.message.content, "chat_response"))
    }
}

pub async fn handle_chat(
    State(state): State<AppState>,
    Json(mut request): Json<ChatRequest>,
) -> Result<Response, ApiError> {

    request.stream = Some(false);

    debug!("Received chat request for model: {}", request.model);

    for message in &request.messages {
        let assessment = state
            .security_client
            .assess_content(&message.content, &request.model, true)
            .await?;

        if !assessment.is_safe {
            info!(
                "Security issue detected in chat message: category={}, action={}",
                assessment.category, assessment.action
            );

            // Instead of returning an error, create a response with explanation
            let blocked_message = format!(
                "⚠️ This response was blocked due to security policy violations:\n\n\
                • Category: {}\n\
                • Action: {}\n\n\
                Please reformulate your request to comply with security policies.",
                assessment.category, assessment.action
            );

            let response = ChatResponse {
                model: request.model.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                message: Message {
                    role: "assistant".to_string(),
                    content: blocked_message,
                },
                done: true,
            };

            let json_bytes = serde_json::to_vec(&response).map_err(|e| {
                error!("Failed to serialize response: {}", e);
                ApiError::InternalError("Failed to serialize response".to_string())
            })?;

            return Ok(build_json_response(bytes::Bytes::from(json_bytes))?);
        }
    }

    // Handle streaming requests
    if request.stream.unwrap_or(false) {
        debug!("Handling streaming chat request");
        return handle_streaming_chat(State(state), Json(request)).await;
    }

    // Handle non-streaming requests
    debug!("Handling non-streaming chat request");
    let response = state.ollama_client.forward("/api/chat", &request).await?;
    let body_bytes = response.bytes().await.map_err(|e| {
        error!("Failed to read response body: {}", e);
        ApiError::InternalError("Failed to read response body".to_string())
    })?;

    let mut response_body: crate::types::ChatResponse = serde_json::from_slice(&body_bytes)
        .map_err(|e| {
            error!("Failed to parse response: {}", e);
            ApiError::InternalError("Failed to parse response".to_string())
        })?;

    let assessment = state
        .security_client
        .assess_content(&response_body.message.content, &request.model, false)
        .await?;

    if !assessment.is_safe {
        info!(
            "Security issue detected in chat response: category={}, action={}",
            assessment.category, assessment.action
        );

        // Replace the content with security message instead of returning error
        let blocked_message = format!(
            "⚠️ This response was blocked due to security policy violations:\n\n\
            • Category: {}\n\
            • Action: {}\n\n\
            Please reformulate your request to comply with security policies.",
            assessment.category, assessment.action
        );

        response_body.message.content = blocked_message;

        let json_bytes = serde_json::to_vec(&response_body).map_err(|e| {
            error!("Failed to serialize response: {}", e);
            ApiError::InternalError("Failed to serialize response".to_string())
        })?;

        return Ok(build_json_response(bytes::Bytes::from(json_bytes))?);
    }

    Ok(build_json_response(body_bytes)?)
}

async fn handle_streaming_chat(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Response, ApiError> {
    debug!("Handling streaming chat request");

    let model = request.model.clone();
    handle_streaming_request::<ChatRequest, ChatResponse>(&state, request, "/api/chat", &model)
        .await
}
