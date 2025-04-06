// Streaming functionality with security assessment integration.
//
// This module provides streaming support for the API proxy, with integrated
// security assessment of streamed content from Ollama API.
//
// # Module Overview
//
// The stream module implements:
// - A wrapper for streams that performs security assessments on each item
// - Real-time content filtering based on security policies
// - Support for streaming API responses with security checks
use crate::security::SecurityClient;
use bytes::Bytes;
use futures_util::Stream;
use serde::{de::DeserializeOwned, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tracing::{debug, error, warn};

// Errors that can occur during stream processing
//
// This enum represents various error conditions that may occur when
// processing streaming responses, including JSON parsing issues and
// security assessment failures.
#[derive(Debug, Error)]
pub enum StreamError {
    // JSON parsing errors when handling streaming data
    #[error("Failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),

    // Security assessment errors in streaming content
    #[error("Security assessment failed: {0}")]
    SecurityError(#[from] crate::security::SecurityError),

    // Unknown errors with no specific details
    #[error("Unknown error occurred during stream processing")]
    Unknown,
}

// Trait for types that can have their content assessed for security issues.
//
// This trait is implemented by response types that contain content that
// should be assessed by the PANW AI Runtime security API.
//
// # Examples
//
// ```
// impl SecurityAssessable for ChatResponse {
//     fn get_content_for_assessment(&self) -> Option<(&str, &str)> {
//         Some((&self.message.content, "chat_response"))
//     }
// }
// ```
pub trait SecurityAssessable {
    // Returns content to be assessed and its type.
    //
    // # Returns
    //
    // A tuple containing:
    // - The content to be assessed
    // - A string identifying the type of content (e.g., "chat_response", "prompt")
    fn get_content_for_assessment(&self) -> Option<(&str, &str)>;
}

// A stream wrapper that performs security assessments on each streamed item.
//
// This wrapper intercepts items from the underlying stream, performs
// security assessments on them, and either passes them through if they're
// safe or replaces them with a security violation message.
pub struct SecurityAssessedStream<S, T>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
    T: DeserializeOwned + SecurityAssessable + Serialize + Send + Sync + 'static,
{
    // The underlying stream of bytes
    inner: Pin<Box<S>>,

    // Client for performing security assessments
    security_client: SecurityClient,

    // Model name for security assessments
    model_name: String,

    // Buffer for items being processed
    buffer: Option<T>,

    // Whether the stream has finished
    finished: bool,
}

impl<S, T> SecurityAssessedStream<S, T>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
    T: DeserializeOwned + SecurityAssessable + Serialize + Send + Sync + 'static,
{
    // Creates a new security-assessed stream.
    //
    // # Arguments
    //
    // * `stream` - The underlying stream to wrap
    // * `security_client` - Client for performing security assessments
    // * `model_name` - Name of the model generating the content
    //
    // # Returns
    //
    // A new SecurityAssessedStream that wraps the provided stream
    pub fn new(stream: S, security_client: SecurityClient, model_name: String) -> Self {
        debug!(
            "Creating new security-assessed stream for model: {}",
            model_name
        );
        Self {
            inner: Box::pin(stream),
            security_client,
            model_name,
            buffer: None,
            finished: false,
        }
    }

    // Creates a formatted message for blocked content.
    //
    // This generates a user-friendly message explaining why the content
    // was blocked, including the security category and action.
    //
    // # Arguments
    //
    // * `category` - The security category of the violation
    // * `action` - The recommended action for the violation
    //
    // # Returns
    //
    // A bytes object containing the formatted message as JSON
    fn create_blocked_response(&self, category: &str, action: &str) -> Bytes {
        debug!(
            "Creating blocked response for category: {}, action: {}",
            category, action
        );

        // Format the blocking message
        let blocked_message = format!(
            "⚠️ This response was blocked due to security policy violations:\n\n\
             • Category: {}\n\
             • Action: {}\n\n\
             Please reformulate your request to comply with security policies.",
            category, action
        );

        // Create a standard response structure
        let response = serde_json::json!({
            "model": self.model_name,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "message": {
                "role": "assistant",
                "content": blocked_message
            },
            "done": true
        });

        // Convert to bytes
        let json_bytes = serde_json::to_vec(&response).unwrap_or_else(|e| {
            error!("Failed to serialize blocked response: {}", e);
            blocked_message.as_bytes().to_vec()
        });

        Bytes::from(json_bytes)
    }

    // Assesses content for security issues.
    //
    // This method performs a synchronous security assessment of the content
    // and returns a blocked response if the content violates security policies.
    //
    // # Arguments
    //
    // * `content` - The content to assess
    // * `content_type` - The type of content (e.g., "prompt", "chat_response")
    //
    // # Returns
    //
    // * `Some(Bytes)` - If the content violates security policies, a formatted blocked response
    // * `None` - If the content is safe or couldn't be assessed
    fn assess_content(&self, content: &str, content_type: &str) -> Option<Bytes> {
        debug!("Assessing content of type: {}", content_type);

        // Determine if this is a prompt
        let is_prompt = content_type.contains("prompt");

        // Perform the assessment synchronously to avoid threading issues
        match futures::executor::block_on(async {
            self.security_client
                .assess_content(content, &self.model_name, is_prompt)
                .await
        }) {
            Ok(assessment) if !assessment.is_safe => {
                // Content is blocked, return a formatted message
                warn!(
                    "Security violation detected in stream: category={}, action={}",
                    assessment.category, assessment.action
                );
                Some(self.create_blocked_response(&assessment.category, &assessment.action))
            }
            Ok(_) => {
                // Content is safe
                debug!("Content passed security assessment");
                None
            }
            Err(e) => {
                // Error during assessment, continue with original content
                error!("Failed to assess content: {}", e);
                None
            }
        }
    }
}

impl<S, T> Stream for SecurityAssessedStream<S, T>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
    T: DeserializeOwned + SecurityAssessable + Serialize + Unpin + Send + Sync + 'static,
{
    type Item = Result<Bytes, StreamError>;

    // Polls for the next item in the stream.
    //
    // This implementation:
    // 1. Checks if there are any buffered items and returns them first
    // 2. Polls the underlying stream for the next item
    // 3. If an item is available, parses it and performs a security assessment
    // 4. Either passes the item through or replaces it with a blocked response
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Handle finished state
        if self.finished {
            return Poll::Ready(None);
        }

        // Process any buffered items first
        if let Some(item) = self.buffer.take() {
            match serde_json::to_vec(&item) {
                Ok(json) => return Poll::Ready(Some(Ok(Bytes::from(json)))),
                Err(e) => {
                    error!("Failed to serialize buffered item: {}", e);
                    return Poll::Ready(Some(Err(StreamError::JsonError(e))));
                }
            }
        }

        // Poll the inner stream
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Try to parse the bytes
                match serde_json::from_slice::<T>(&bytes) {
                    Ok(chunk) => {
                        // Check if there's content to assess
                        if let Some((content, content_type)) = chunk.get_content_for_assessment() {
                            if !content.is_empty() {
                                debug!(
                                    "Processing stream chunk with content of type: {}",
                                    content_type
                                );

                                // Assess content for security issues
                                if let Some(blocked_response) =
                                    self.assess_content(content, content_type)
                                {
                                    // Content blocked - return blocked response
                                    self.finished = true; // End the stream after sending the blocked response
                                    return Poll::Ready(Some(Ok(blocked_response)));
                                }
                            }
                        }

                        // If we reach here, content is safe or couldn't be assessed
                        Poll::Ready(Some(Ok(bytes)))
                    }
                    Err(e) => {
                        error!("Failed to parse JSON in stream: {}", e);
                        Poll::Ready(Some(Err(StreamError::JsonError(e))))
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => {
                error!("Error from inner stream: {:?}", e);
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                debug!("Inner stream completed");
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
