use axum::{extract::State, response::Response, Json};
use tracing::{debug, error};

use crate::handlers::security_utils::{
    build_violation_response, format_security_violation_message, log_security_failure,
};
use crate::handlers::utils::{build_json_response, handle_streaming_request};
use crate::handlers::ApiError;
use crate::stream::SecurityAssessable;
use crate::types::{GenerateRequest, GenerateResponse};
use crate::AppState;

impl SecurityAssessable for crate::types::GenerateResponse {
    fn get_content_for_assessment(&self) -> Option<(&str, &str)> {
        Some((&self.response, "generate_response"))
    }
}

pub async fn handle_generate(
    State(state): State<AppState>,
    Json(mut request): Json<GenerateRequest>,
) -> Result<Response, ApiError> {
    request.stream = Some(false);

    debug!("Received generate request for model: {}", request.model);

    // Check input prompt
    let assessment = state
        .security_client
        .assess_content(&request.prompt, &request.model, true)
        .await?;

    if !assessment.is_safe {
        log_security_failure("prompt", &assessment.category, &assessment.action);

        let blocked_message = format_security_violation_message(&assessment.category, &assessment.action);
        
        let response = GenerateResponse {
            model: request.model.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            response: blocked_message,
            context: None,
            done: true,
        };

        return build_violation_response(response);
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

    let mut response_body: GenerateResponse = serde_json::from_slice(&body_bytes)
        .map_err(|e| {
            error!("Failed to parse response: {}", e);
            ApiError::InternalError("Failed to parse response".to_string())
        })?;

    // Check model output
    let assessment = state
        .security_client
        .assess_content(&response_body.response, &request.model, false)
        .await?;

    if !assessment.is_safe {
        log_security_failure("response", &assessment.category, &assessment.action);

        // Replace the content with security message
        response_body.response = format_security_violation_message(&assessment.category, &assessment.action);
        
        return build_violation_response(response_body);
    }

    Ok(build_json_response(body_bytes)?)
}

async fn handle_streaming_generate(
    State(state): State<AppState>,
    Json(request): Json<GenerateRequest>,
) -> Result<Response, ApiError> {
    debug!("Handling streaming generate request");

    let model = request.model.clone();
    handle_streaming_request::<GenerateRequest, GenerateResponse>(
        &state,
        request,
        "/api/generate",
        &model,
    )
    .await
}
