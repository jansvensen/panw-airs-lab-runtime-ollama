use axum::{extract::State, response::Response, Json};
use tracing::{debug, error, info};

use crate::handlers::utils::{build_json_response, handle_streaming_request};
use crate::handlers::ApiError;
use crate::stream::SecurityAssessable;
use crate::types::ChatRequest;
use crate::AppState;

impl SecurityAssessable for crate::types::ChatResponse {
    fn get_content_for_assessment(&self) -> Option<(&str, &str)> {
        Some((&self.message.content, "chat_response"))
    }
}

pub async fn handle_chat(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Response, ApiError> {
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
            return Err(ApiError::SecurityIssue(format!(
                "Message content violates security policy. Category: {}, Action: {}",
                assessment.category, assessment.action
            )));
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

    let response_body: crate::types::ChatResponse =
        serde_json::from_slice(&body_bytes).map_err(|e| {
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
        return Err(ApiError::SecurityIssue(format!(
            "Response content violates security policy. Category: {}, Action: {}",
            assessment.category, assessment.action
        )));
    }

    Ok(build_json_response(body_bytes)?)
}

async fn handle_streaming_chat(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Response, ApiError> {
    debug!("Handling streaming chat request");

    let model = request.model.clone();
    handle_streaming_request::<ChatRequest, crate::types::ChatResponse>(
        &state,
        request,
        "/api/chat",
        &model,
    )
    .await
}
