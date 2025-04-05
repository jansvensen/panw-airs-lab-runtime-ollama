use axum::{extract::State, response::Response, Json};
use tracing::{debug, error};

use crate::handlers::utils::{
    build_json_response, build_violation_response, format_security_violation_message,
    handle_streaming_request, log_security_failure,
};
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

    // Check input messages for security violations
    for message in &request.messages {
        let assessment = state
            .security_client
            .assess_content(&message.content, &request.model, true)
            .await?;

        if !assessment.is_safe {
            log_security_failure("chat message", &assessment.category, &assessment.action);

            let blocked_message =
                format_security_violation_message(&assessment.category, &assessment.action);

            let response = ChatResponse {
                model: request.model.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                message: Message {
                    role: "assistant".to_string(),
                    content: blocked_message,
                },
                done: true,
            };

            return build_violation_response(response);
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

    let mut response_body: ChatResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
        error!("Failed to parse response: {}", e);
        ApiError::InternalError("Failed to parse response".to_string())
    })?;

    // Check response for security violations
    let assessment = state
        .security_client
        .assess_content(&response_body.message.content, &request.model, false)
        .await?;

    if !assessment.is_safe {
        log_security_failure("chat response", &assessment.category, &assessment.action);

        // Replace the content with security message
        response_body.message.content =
            format_security_violation_message(&assessment.category, &assessment.action);

        return build_violation_response(response_body);
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
