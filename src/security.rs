// Security assessment and content filtering using PANW AI Runtime API.
//
// This module provides integration with Palo Alto Networks' AI Runtime security API
// to assess and filter content for security threats and policy violations.
use crate::types::{AiProfile, Content, Metadata, ScanRequest, ScanResponse};
use reqwest::Client;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Represents errors that can occur during security assessments with the PANW AI Runtime API.
//
// This enum covers various failure modes when assessing content security using Palo Alto Networks'
// AI Runtime security services, including network failures, API errors, and content policy violations.
#[derive(Debug, Error)]
pub enum SecurityError {
// Network or HTTP protocol errors
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

// Errors from the PANW AI Runtime API security service
    #[error("PANW security assessment error: {0}")]
    AssessmentError(String),

// JSON parsing errors when handling API responses
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

// Content that has been blocked by security policy
    #[error("Content blocked by PANW AI security policy")]
    BlockedContent,
}

// Represents the result of a security assessment from PANW AI Runtime API.
//
// This struct contains the outcome of evaluating content against Palo Alto Networks' security policies,
// including categorization of potential threats and recommended actions.
#[derive(Debug, Clone)]
pub struct Assessment {
// Whether the assessed content is considered safe
    pub is_safe: bool,

    // Security category assigned to the content (e.g., "benign", "malicious")
    pub category: String,

    // Recommended action to take ("allow", "block", etc.)
    pub action: String,

    // Complete findings from the PANW AI security scan
    pub details: ScanResponse,
}

// Client for performing security assessments using the PANW AI Runtime API.
//
// This client connects to Palo Alto Networks' AI Runtime security API to evaluate prompts and responses
// for potential security threats, malicious content, or policy violations.
#[derive(Clone)]
pub struct SecurityClient {
// HTTP client for making API requests
    client: Client,

    // Base URL for the PANW API service
    base_url: String,

    // API key for authenticating with PANW services
    api_key: String,

    // Security profile name to use for assessments
    profile_name: String,

    // Application name for telemetry and audit
    app_name: String,

    // Application user identifier
    app_user: String,
}

impl Content {
// Creates a new Content object containing either a prompt or a response or both.
    //
    // # Arguments
//
// * `prompt` - Optional text representing a prompt to an AI model
// * `response` - Optional text representing a response from an AI model
// * `code_prompt` - Extracted code from prompt
// * `code_response` - Extracted code from response
//
// # Returns
//
// * `Ok(Self)` - A valid Content object with at least one field populated
// * `Err` - An error if all fields are None
    pub fn new(
        prompt: Option<String>,
        response: Option<String>,
        code_prompt: Option<String>,
        code_response: Option<String>,
    ) -> Result<Self, &'static str> {
        if prompt.is_none()
            && response.is_none()
            && code_prompt.is_none()
            && code_response.is_none()
        {
            return Err("Content must have at least one field populated");
        }
        Ok(Self {
            prompt,
            response,
            code_prompt,
            code_response,
        })
    }
}

impl SecurityClient {
// Creates a new instance of the SecurityClient for performing content security assessments.
    //
    // # Arguments
//
// * `base_url` - The base URL of the PANW AI Runtime security API endpoint
// * `api_key` - Palo Alto Networks API token for accessing the security services
// * `profile_name` - Name of the AI security profile to use for assessments
// * `app_name` - Name of the application using this security client
// * `app_user` - Identifier for the user or context within the application
        pub fn new(
        base_url: &str,
        api_key: &str,
        profile_name: &str,
        app_name: &str,
        app_user: &str,
    ) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            api_key: api_key.to_string(),
            profile_name: profile_name.to_string(),
            app_name: app_name.to_string(),
            app_user: app_user.to_string(),
        }
    }

// Creates a default safe assessment for empty content.
//
// This is an optimization to avoid unnecessary API calls for empty content.
    fn create_safe_assessment(&self) -> Assessment {
        Assessment {
            is_safe: true,
            category: "benign".to_string(),
            action: "allow".to_string(),
            details: ScanResponse::default_safe_response(),
        }
    }

// Extracts code blocks from text using simple Markdown parsing.
    //
// # Arguments
    //
    // * `content` - The text to extract code blocks from
    //
// # Returns
//
    // String containing all extracted code blocks concatenated together
    fn extract_code_blocks(&self, content: &str) -> String {
        let mut code_content = String::new();
        let mut in_code_block = false;
        let mut buffer = String::new();

        for line in content.lines() {
            if line.trim().starts_with("```") {
                if in_code_block {
                    // End of code block
                    code_content.push_str(&buffer);
                    code_content.push('\n');
                    buffer.clear();
                    in_code_block = false;
                } else {
                    // Start of code block
                    in_code_block = true;
                }
            } else if in_code_block {
                buffer.push_str(line);
                buffer.push('\n');
            }
        }

        // Append any remaining buffer if the input ends with an open code block
        if in_code_block {
            code_content.push_str(&buffer);
            code_content.push('\n');
        }

        code_content
    }

// Prepares a Content object for PANW assessment based on the provided text.
//
// # Arguments
//
// * `content` - The text content to be assessed
    // * `is_prompt` - If true, content is treated as a prompt; otherwise as a response
//
// # Returns
//
// Structured Content object ready for assessment
    fn prepare_content(&self, content: &str, is_prompt: bool) -> Result<Content, SecurityError> {
        // Extract any code blocks
        let code_blocks = self.extract_code_blocks(content);

        if is_prompt {
            Content::new(
                Some(content.to_string()),
                None,
                if !code_blocks.is_empty() {
                    Some(code_blocks)
                } else {
                    None
                },
                None,
            )
        } else {
            Content::new(
                None,
                Some(content.to_string()),
                None,
                if !code_blocks.is_empty() {
                    Some(code_blocks)
                } else {
                    None
                },
            )
        }
        .map_err(|e| SecurityError::AssessmentError(e.to_string()))
    }

// Processes scan results from the PANW AI Runtime API into an Assessment.
//
// # Arguments
//
// * `scan_result` - The scan response from the PANW AI Runtime API
//
// # Returns
//
// Assessment object with security evaluation results
    fn process_scan_result(&self, scan_result: ScanResponse) -> Result<Assessment, SecurityError> {
        let assessment = Assessment {
            is_safe: scan_result.category == "benign" && scan_result.action != "block",
            category: scan_result.category.clone(),
            action: scan_result.action.clone(),
            details: scan_result,
        };

        if !assessment.is_safe {
            warn!(
                "PANW Security threat detected! Category: {}, Findings: {:#?}",
                assessment.category, assessment.details.prompt_detected
            );
        }

        Ok(assessment)
    }

// Performs a security assessment on the provided content using PANW AI Runtime API.
    //
    // # Arguments
//
// * `content` - The text content to assess with PANW AI Runtime API
// * `model_name` - Name of the AI model associated with this content
// * `is_prompt` - If `true`, content is treated as a prompt to an AI; if `false`, as an AI response
//
// # Returns
    //
    // Security assessment results
    //
    // # Errors
    //
    // Returns error if assessment fails or content is blocked by security policy
    pub async fn assess_content(
        &self,
        content: &str,
        model_name: &str,
        is_prompt: bool,
    ) -> Result<Assessment, SecurityError> {
        // Optimization: Skip assessment for empty content
        if content.trim().is_empty() {
            debug!("Skipping PANW assessment for empty content");
            return Ok(self.create_safe_assessment());
        }

        // Prepare content for assessment
        let content_obj = self.prepare_content(content, is_prompt)?;

        info!("Prepared content for PANW assessment: {:#?}", content_obj);

        // Create and send the request payload
        let payload = self.create_scan_request(content_obj, model_name);
        let scan_result = self.send_security_request(&payload).await?;

        // Process results
        self.process_scan_result(scan_result)
    }

// Creates a scan request payload for the PANW AI Runtime API.
    //
    // # Arguments
//
// * `content_obj` - Content object containing text to assess
// * `model_name` - Name of the AI model associated with this content
        fn create_scan_request(&self, content_obj: Content, model_name: &str) -> ScanRequest {
        ScanRequest {
            tr_id: Uuid::new_v4().to_string(),
            ai_profile: AiProfile {
                profile_name: self.profile_name.clone(),
            },
            metadata: Metadata {
                app_name: self.app_name.to_string(),
                app_user: self.app_user.to_string(),
                ai_model: model_name.to_string(),
            },
            contents: vec![content_obj],
        }
    }

// Makes an HTTP request to the PANW AI Runtime API.
    //
    // # Arguments
//
// * `payload` - The request payload to send
    //
// # Returns
//
// Status code and response body from the API
        async fn make_api_request(
        &self,
        payload: &ScanRequest,
    ) -> Result<(reqwest::StatusCode, String), SecurityError> {
        let response = self
            .client
            .post(&format!("{}/v1/scan/sync/request", self.base_url))
            .header("Content-Type", "application/json")
            .header("x-pan-token", &self.api_key)
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                error!("PANW security assessment request failed: {}", e);
                SecurityError::RequestError(e)
            })?;

        let status = response.status();
        let body_text = response.text().await.map_err(|e| {
            error!("Failed to read PANW response body: {}", e);
            SecurityError::RequestError(e)
        })?;

        Ok((status, body_text))
    }

// Parses the PANW AI Runtime API response and handles different status codes.
    //
    // # Arguments
//
// * `status` - The HTTP status code from the API response
// * `body_text` - The raw response body text
//
// # Returns
//
// Parsed scan response object
    fn parse_api_response(
        &self,
        status: reqwest::StatusCode,
        body_text: String,
    ) -> Result<ScanResponse, SecurityError> {
        // Log the raw response in debug mode
        debug!("Raw PANW response body:\n{}", body_text);

// Handle error status codes
        if !status.is_success() {
            error!("PANW security assessment error: {} - {}", status, body_text);
            return Err(SecurityError::AssessmentError(format!(
                "{}: {}",
                status, body_text
            )));
        }

// Parse JSON response
        serde_json::from_str(&body_text).map_err(|e| {
            error!("Failed to parse PANW security assessment response");
            SecurityError::JsonError(e)
        })
    }

// Sends a security assessment request to the PANW AI Runtime API and processes the response.
    //
    // # Arguments
    //
    // * `payload` - The request payload to send
    //
    // # Returns
    //
    // Parsed scan response from the API
    async fn send_security_request(
        &self,
        payload: &ScanRequest,
    ) -> Result<ScanResponse, SecurityError> {
        let (status, body_text) = self.make_api_request(payload).await?;
        self.parse_api_response(status, body_text)
    }
}
