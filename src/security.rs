use crate::types::{AiProfile, Content, Metadata, ScanRequest, ScanResponse};
use reqwest::Client;
use thiserror::Error;
use tracing::{debug, error, warn};
use uuid::Uuid;

// Represents errors that can occur during security assessments with the PANW AI Runtime API.
//
// This enum covers various failure modes when assessing content security using Palo Alto Networks'
// AI Runtime security services, including network failures, API errors, and content policy violations.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("PANW security assessment error: {0}")]
    AssessmentError(String),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Content blocked by PANW AI security policy")]
    BlockedContent,
}

// Represents the result of a security assessment from PANW AI Runtime API.
//
// This struct contains the outcome of evaluating content against Palo Alto Networks' security policies,
// including categorization of potential threats and recommended actions.
//
// # Fields
//
// * `is_safe` - Indicates whether the assessed content is considered safe
// * `category` - Security category assigned to the content (e.g., "benign", "malicious")
// * `action` - Recommended action to take ("allow", "block", etc.)
// * `details` - Complete findings from the PANW AI security scan
#[derive(Debug, Clone)]
pub struct Assessment {
    pub is_safe: bool,
    pub category: String,
    pub action: String,
    pub details: ScanResponse,
}

// Client for performing security assessments using the PANW AI Runtime API.
//
// This client connects to Palo Alto Networks' AI Runtime security API to evaluate prompts and responses
// for potential security threats, malicious content, or policy violations.
// It provides an abstraction over the underlying API communication details.
//
// # Examples
//
// ```
// let client = SecurityClient::new(
//     "https://api.paloaltonetworks.com/ai-runtime",
//     "your-pan-api-key",
//     "standard_profile",
//     "my_application",
//     "user_123"
// );
// ```
#[derive(Clone)]
pub struct SecurityClient {
    client: Client,
    base_url: String,
    api_key: String,
    profile_name: String,
    app_name: String,
    app_user: String,
}

impl Content {
    // Creates a new Content object containing either a prompt or a response or both.
    //
    // This function allows creating Content with a prompt, response, or both for PANW AI Runtime security evaluation.
    // In the typical workflow, prompts are assessed before reaching the LLM to prevent security compromises,
    // and responses are assessed after generation.
    //
    // # Arguments
    //
    // * `prompt` - Optional text representing a prompt to an AI model
    // * `response` - Optional text representing a response from an AI model
    // * `code_prompt`: Extracted code from prompt
    // * `code_response`: Extracted code from response
    //
    // # Returns
    //
    // * `Ok(Self)` - A valid Content object with at least one field populated
    // * `Err` - An error if both fields are None
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
    // Creates a new instance of the SecurityClient for performing content security assessments with PANW AI Runtime API.
    //
    // This client connects to Palo Alto Networks' AI Runtime security API endpoint to evaluate prompts and responses
    // for potential security threats or policy violations.
    //
    // # Arguments
    //
    // * `base_url` - The base URL of the PANW AI Runtime security API endpoint
    // * `api_key` - Palo Alto Networks API token for accessing the security services
    // * `profile_name` - Name of the AI security profile to use for assessments
    // * `app_name` - Name of the application using this security client
    // * `app_user` - Identifier for the user or context within the application
    //
    // # Returns
    //
    // A configured SecurityClient instance ready to perform PANW AI Runtime security assessments.
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
    // When empty content is provided for assessment, this function returns
    // a pre-defined safe assessment to avoid unnecessary API calls to the PANW service.
    //
    // # Returns
    //
    // An Assessment object indicating the content is safe.
    fn create_safe_assessment(&self) -> Assessment {
        Assessment {
            is_safe: true,
            category: "benign".to_string(),
            action: "allow".to_string(),
            details: ScanResponse::default_safe_response(),
        }
    }

    // Extracts code blocks from text using simple Markdown parsing
    //
    // # Parameters
    // * `content`: Input text containing potential code blocks
    //
    // # Returns
    // String containing concatenated code blocks without Markdown syntax
    //
    // # Notes
    // * Uses line-by-line parsing rather than full Markdown AST
    // * Handles nested code blocks sequentially
    // * Trims whitespace from code blocks
    fn extract_code_blocks(&self, content: &str) -> String {
        let mut code_content = String::new();

        // Simple regex-free parsing of code blocks
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

        code_content
    }

    // Prepares a Content object for PANW assessment based on the provided text.
    //
    // # Arguments
    //
    // * `content` - The text content to be assessed by PANW AI Runtime API
    // * `is_prompt` - If true, content is treated as a prompt; otherwise as a response
    //
    // # Returns
    //
    // * `Ok(Content)` - A properly configured Content object
    // * `Err(SecurityError)` - If content object creation fails
    //
    // # Process Flow
    // 1. Extract code blocks using simple Markdown parser
    // 2. Create Content struct with original + code fields
    // 3. Validate content structure
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
    // * `scan_result` - The raw scan response from the PANW AI Runtime API
    //
    // # Returns
    //
    // * `Ok(Assessment)` - Assessment created from the scan result
    // * `Err(SecurityError)` - If content is blocked by PANW security policy
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
    // This method evaluates text for security threats, policy violations, or other
    // potentially problematic content using Palo Alto Networks' AI security services.
    // It assesses either prompts sent to AI models or responses generated by them.
    //
    // # Arguments
    //
    // * `content` - The text content to assess with PANW AI Runtime API
    // * `model_name` - Name of the AI model associated with this content
    // * `is_prompt` - If `true`, content is treated as a prompt to an AI; if `false`, as an AI response
    //
    // # Returns
    //
    // * `Ok(Assessment)` - Details about the security evaluation and its findings
    // * `Err(SecurityError)` - If assessment fails or if content is blocked by PANW security policy
    //
    // # Errors
    //
    // Returns `SecurityError::BlockedContent` if the content violates PANW security policies.
    // Other possible errors include network failures, API errors, or parsing failures.
    //
    // # Notes
    //
    // Empty content is automatically considered safe and will return a default safe assessment.
    pub async fn assess_content(
        &self,
        content: &str,
        model_name: &str,
        is_prompt: bool,
    ) -> Result<Assessment, SecurityError> {
        // Skip assessment for empty content early
        if content.trim().is_empty() {
            debug!("Skipping PANW assessment for empty content");
            return Ok(self.create_safe_assessment());
        }

        // Create the content object
        let content_obj = self.prepare_content(content, is_prompt)?;

        // Create and send the request payload
        let payload = self.create_scan_request(content_obj, model_name);
        let scan_result = self.send_security_request(&payload).await?;

        // Process results into an assessment
        self.process_scan_result(scan_result)
    }

    // Creates a scan request payload for the PANW AI Runtime API.
    //
    // This internal helper function constructs a properly formatted request object
    // with all the necessary metadata for content assessment using Palo Alto Networks' specifications.
    //
    // # Arguments
    //
    // * `content_obj` - Content object containing prompt or response text to assess
    // * `model_name` - Name of the AI model associated with this content
    //
    // # Returns
    //
    // A `ScanRequest` object ready to be serialized and sent to the PANW AI Runtime API.
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
    // This function handles the actual HTTP communication with the Palo Alto Networks API,
    // including setting appropriate headers and handling network-level errors.
    //
    // # Arguments
    //
    // * `payload` - The `ScanRequest` object to send to the PANW AI Runtime API
    //
    // # Returns
    //
    // * `Ok((StatusCode, String))` - The status code and raw response text from the API
    // * `Err(SecurityError)` - If the request fails
    async fn make_api_request(
        &self,
        payload: &ScanRequest,
    ) -> Result<(reqwest::StatusCode, String), SecurityError> {
        let response = self
            .client
            .post(&format!("{}/v1/scan/sync/request", self.base_url))
            .header("Content-Type", "application/json")
            .header("x-pan-token", &self.api_key) // PANW specific authentication header
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
    // This function processes the raw HTTP response from Palo Alto Networks, handles errors,
    // and converts successful responses to ScanResponse objects.
    //
    // # Arguments
    //
    // * `status` - The HTTP status code from the API response
    // * `body_text` - The raw response body text
    //
    // # Returns
    //
    // * `Ok(ScanResponse)` - The parsed scan response
    // * `Err(SecurityError)` - If the response indicates an error or can't be parsed
    fn parse_api_response(
        &self,
        status: reqwest::StatusCode,
        body_text: String,
    ) -> Result<ScanResponse, SecurityError> {
        // Debug the raw response only when debug is enabled
        debug!("Raw PANW response body:\n{}", body_text);

        if !status.is_success() {
            error!("PANW security assessment error: {} - {}", status, body_text);
            return Err(SecurityError::AssessmentError(format!(
                "{}: {}",
                status, body_text
            )));
        }

        serde_json::from_str(&body_text).map_err(|e| {
            error!("Failed to parse PANW security assessment response");
            SecurityError::JsonError(e)
        })
    }

    // Sends a security assessment request to the PANW AI Runtime API endpoint and processes the response.
    //
    // This internal helper function coordinates the HTTP communication with the Palo Alto Networks
    // security service by calling the appropriate sub-functions for request and response handling.
    //
    // # Arguments
    //
    // * `payload` - The `ScanRequest` object to send to the PANW AI Runtime API
    //
    // # Returns
    //
    // * `Ok(ScanResponse)` - The parsed response from the PANW AI Runtime API
    // * `Err(SecurityError)` - If the request fails, returns an error with details
    //
    // # Errors
    //
    // May return errors for network failures, non-200 status codes,
    // or issues parsing the JSON response from the PANW service.
    async fn send_security_request(
        &self,
        payload: &ScanRequest,
    ) -> Result<ScanResponse, SecurityError> {
        let (status, body_text) = self.make_api_request(payload).await?;
        self.parse_api_response(status, body_text)
    }
}
