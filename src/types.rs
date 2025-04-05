use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Ollama API types

// Request parameters for generating text with Ollama models.
//
// This struct encapsulates all parameters needed to make a text generation request
// to the Ollama API, including the model to use, prompt text, and various optional
// configuration settings.
//
// # Fields
//
// * `model` - Name of the Ollama model to use for generation
// * `prompt` - The text prompt to send to the model
// * `system` - Optional system message to guide model behavior
// * `template` - Optional template to format the prompt
// * `context` - Optional context tokens from previous interactions
// * `stream` - Optional flag to enable streaming responses
// * `raw` - Optional flag to get raw, unfiltered model output
// * `format` - Optional output format specification
// * `options` - Optional model-specific parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateRequest {
    pub model: String,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

// Response from an Ollama text generation request.
//
// Contains the generated text and related metadata returned by the Ollama API
// after processing a generation request.
//
// # Fields
//
// * `model` - Name of the model that generated the response
// * `created_at` - Timestamp when the response was created
// * `response` - The generated text content
// * `context` - Optional context tokens for continuing the conversation
// * `done` - Indicates whether the generation is complete
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateResponse {
    pub model: String,
    pub created_at: String,
    pub response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<u32>>,
    pub done: bool,
}

// Request parameters for chat-based interactions with Ollama models.
//
// This struct encapsulates all parameters needed for a multi-turn conversation
// with an Ollama model, using the chat completion API format.
//
// # Fields
//
// * `model` - Name of the Ollama model to use
// * `messages` - Array of conversation messages with roles and content
// * `stream` - Optional flag to enable streaming responses
// * `format` - Optional output format specification
// * `options` - Optional model-specific parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

// Represents a single message in a chat conversation.
//
// Each message has a role (who is speaking) and content (what is said).
// Common roles include "system", "user", and "assistant".
//
// # Fields
//
// * `role` - Identifies the sender of the message (e.g., "user", "assistant")
// * `content` - The actual text content of the message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

// Response from an Ollama chat request.
//
// Contains the model's reply as a message and related metadata.
//
// # Fields
//
// * `model` - Name of the model that generated the response
// * `created_at` - Timestamp when the response was created
// * `message` - The model's response as a Message object
// * `done` - Indicates whether the generation is complete
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub model: String,
    pub created_at: String,
    pub message: Message,
    pub done: bool,
}

// Request parameters for generating text embeddings with Ollama models.
//
// Text embeddings are vector representations of text that capture semantic meaning,
// useful for similarity comparisons, clustering, and other NLP tasks.
//
// # Fields
//
// * `model` - Name of the Ollama embedding model to use
// * `prompt` - The text to generate embeddings for
// * `options` - Optional model-specific parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    pub model: String,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

// Response containing vector embeddings generated by an Ollama model.
//
// # Fields
//
// * `embedding` - Vector of floating-point values representing the text embedding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsResponse {
    pub embedding: Vec<f32>,
}

// Response containing a list of available models from the Ollama API.
//
// # Fields
//
// * `models` - Array of ModelInfo objects with details about each available model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListModelsResponse {
    pub models: Vec<ModelInfo>,
}

// Detailed information about a specific Ollama model.
//
// Contains both basic metadata and detailed specifications about the model.
//
// # Fields
//
// * `name` - The model's name/identifier
// * `modified_at` - Timestamp when the model was last modified
// * `size` - Size of the model in bytes
// * `digest` - Unique hash identifying this version of the model
// * `details` - Additional technical specifications of the model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub modified_at: String,
    pub size: u64,
    pub digest: String,
    pub details: ModelDetails,
}

// Technical specifications of an Ollama model.
//
// Contains details about the model's architecture, size, and quantization.
//
// # Fields
//
// * `format` - Model format (e.g., "gguf")
// * `family` - Model family/architecture (e.g., "llama")
// * `families` - All compatible model families
// * `parameter_size` - Human-readable parameter count (e.g., "7B")
// * `quantization_level` - Level of precision reduction applied (e.g., "Q4_0")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDetails {
    pub format: String,
    pub family: String,
    pub families: Vec<String>,
    pub parameter_size: String,
    pub quantization_level: String,
}

// Response containing the Ollama API version information.
//
// # Fields
//
// * `version` - Version string of the Ollama API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
}

// Request payload for PANW AI Runtime security assessment.
//
// This struct contains all data needed to request a security scan of AI content,
// including the content to scan, profile information, and metadata.
//
// # Fields
//
// * `tr_id` - Transaction ID for tracking the request
// * `ai_profile` - Configuration profile for the security assessment
// * `metadata` - Additional context about the application and user
// * `contents` - Array of content objects to be scanned
#[derive(Debug, Clone, Serialize)]
pub struct ScanRequest {
    pub tr_id: String,
    pub ai_profile: AiProfile,
    pub metadata: Metadata,
    pub contents: Vec<Content>,
}

// Creates a default safe response for use when assessment isn't needed.
//
// This implementation method creates a pre-populated ScanResponse object
// that indicates content is safe, used for empty content or other scenarios
// where a full API scan is unnecessary.
//
// # Returns
//
// A ScanResponse object with default safe values.
impl ScanResponse {
    pub fn default_safe_response() -> Self {
        Self {
            report_id: String::new(),
            scan_id: uuid::Uuid::default(),
            tr_id: None,
            profile_id: None,
            profile_name: None,
            category: "benign".to_string(),
            action: "allow".to_string(),
            prompt_detected: PromptDetected::default(),
            response_detected: ResponseDetected::default(),
            created_at: None,
            completed_at: None,
        }
    }
}

// AI security profile configuration for PANW security scans.
//
// Specifies which security profile should be used when evaluating content.
//
// # Fields
//
// * `profile_name` - Name of the security profile to apply
#[derive(Debug, Clone, Serialize)]
pub struct AiProfile {
    pub profile_name: String,
}

// Metadata providing context for PANW security assessments.
//
// Contains information about the application, user, and AI model involved
// in generating or processing the content being assessed.
//
// # Fields
//
// * `app_name` - Name of the application requesting the assessment
// * `app_user` - Identifier of the user in the context of the application
// * `ai_model` - Name of the AI model that generated or will process the content
#[derive(Debug, Clone, Serialize)]
pub struct Metadata {
    pub app_name: String,
    pub app_user: String,
    pub ai_model: String,
}

// Content to be assessed by the PANW AI Runtime security API.
//
// This struct can contain either a prompt sent to an AI model, a response
// generated by an AI model, or both, depending on what needs to be assessed.
//
// # Fields
//
// * `prompt` - Optional text representing a prompt to an AI model
// * `response` - Optional text representing a response from an AI model
// * `code_prompt`: Extracted code blocks from prompt (Markdown ``` blocks)
// * `code_response`: Extracted code blocks from response (Markdown ``` blocks)
#[derive(Debug, Clone, Serialize)]
pub struct Content {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_response: Option<String>,
}

// Response from a PANW AI Runtime security assessment.
//
// Contains the results of evaluating content against security policies,
// including categorization and detected issues.
//
// # Fields
//
// * `report_id` - Unique identifier for the assessment report
// * `scan_id` - UUID of this particular scan
// * `tr_id` - Optional transaction ID matching the request
// * `profile_id` - Optional identifier of the security profile used
// * `profile_name` - Optional name of the security profile used
// * `category` - Security category assigned (e.g., "benign", "malicious")
// * `action` - Recommended action ("allow", "block", etc.)
// * `prompt_detected` - Security issues found in the prompt
// * `response_detected` - Security issues found in the response
// * `created_at` - Optional timestamp when assessment was created
// * `completed_at` - Optional timestamp when assessment was completed
#[derive(Debug, Clone, Deserialize)]
pub struct ScanResponse {
    #[serde(default)]
    pub report_id: String,
    #[serde(default)]
    pub scan_id: uuid::Uuid,
    #[serde(default)]
    pub tr_id: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub profile_name: Option<String>,
    pub category: String,
    pub action: String,
    #[serde(default)]
    pub prompt_detected: PromptDetected,
    #[serde(default)]
    pub response_detected: ResponseDetected,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

// Security issues detected in an AI prompt during PANW assessment.
//
// This struct contains flags for various types of security concerns
// that may be present in a prompt submitted to an AI model.
//
// # Fields
//
// * `url_cats` - Whether problematic URL categories were detected
// * `dlp` - Whether data loss prevention issues were detected
// * `injection` - Whether prompt injection attempts were detected
// * `toxic_content` - Whether toxic or harmful content was detected
// * `malicious_code` - Whether malicious code was detected
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PromptDetected {
    #[serde(default)]
    pub url_cats: bool,
    #[serde(default)]
    pub dlp: bool,
    #[serde(default)]
    pub injection: bool,
    #[serde(default)]
    pub toxic_content: bool,
    #[serde(default)]
    pub malicious_code: bool,
}

// Security issues detected in an AI response during PANW assessment.
//
// This struct contains flags for various types of security concerns
// that may be present in a response generated by an AI model.
//
// # Fields
//
// * `url_cats` - Whether problematic URL categories were detected
// * `dlp` - Whether data loss prevention issues were detected
// * `db_security` - Whether database security issues were detected
// * `toxic_content` - Whether toxic or harmful content was detected
// * `malicious_code` - Whether malicious code was detected
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResponseDetected {
    #[serde(default)]
    pub url_cats: bool,
    #[serde(default)]
    pub dlp: bool,
    #[serde(default)]
    pub db_security: bool,
    #[serde(default)]
    pub toxic_content: bool,
    #[serde(default)]
    pub malicious_code: bool,
}
