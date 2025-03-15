use axum::{extract::State, response::Response, Json};
use tracing::{debug, error, info};

use crate::handlers::utils::{build_json_response, handle_streaming_request};
use crate::handlers::ApiError;
use crate::stream::SecurityAssessable;
use crate::types::GenerateRequest;
use crate::AppState;

impl SecurityAssessable for crate::types::GenerateResponse {
    fn get_content_for_assessment(&self) -> Option<(&str, &str)> {
        Some((&self.response, "generate_response"))
    }
}

pub async fn handle_generate(
    State(state): State<AppState>,
    Json(request): Json<GenerateRequest>,
) -> Result<Response, ApiError> {
    debug!("Received generate request for model: {}", request.model);

    let assessment = state
        .security_client
        .assess_content(&request.prompt, &request.model, true)
        .await?;

    if !assessment.is_safe {
        info!(
            "Security issue detected in prompt: category={}, action={}",
            assessment.category, assessment.action
        );
        return Err(ApiError::SecurityIssue(format!(
            "Content violates security policy. Category: {}, Action: {}",
            assessment.category, assessment.action
        )));
    }

    // Handle streaming requests
    if request.stream.unwrap_or(false) {
        debug!("Handling streaming generate request");
        return handle_streaming_generate(State(state), Json(request)).await;
    }

    // Handle non-streaming requests
    debug!("Handling non-streaming generate request");
    let response = state
        .ollama_client
        .forward("/api/generate", &request)
        .await?;

    let body_bytes = response.bytes().await.map_err(|e| {
        error!("Failed to read response body: {}", e);
        ApiError::InternalError("Failed to read response body".to_string())
    })?;

    let response_body: crate::types::GenerateResponse = serde_json::from_slice(&body_bytes)
        .map_err(|e| {
            error!("Failed to parse response: {}", e);
            ApiError::InternalError("Failed to parse response".to_string())
        })?;

    let assessment = state
        .security_client
        .assess_content(&response_body.response, &request.model, false)
        .await?;

    if !assessment.is_safe {
        info!(
            "Security issue detected in response: category={}, action={}",
            assessment.category, assessment.action
        );
        return Err(ApiError::SecurityIssue(format!(
            "Response content violates security policy. Category: {}, Action: {}",
            assessment.category, assessment.action
        )));
    }

    Ok(build_json_response(body_bytes)?)
}

async fn handle_streaming_generate(
    State(state): State<AppState>,
    Json(request): Json<GenerateRequest>,
) -> Result<Response, ApiError> {
    debug!("Handling streaming generate request");

    let model = request.model.clone();
    handle_streaming_request::<GenerateRequest, crate::types::GenerateResponse>(
        &state,
        request,
        "/api/generate",
        &model,
    )
    .await
}
