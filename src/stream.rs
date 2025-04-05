use crate::security::SecurityClient;
use bytes::Bytes;
use futures_util::Stream;
use serde::{de::DeserializeOwned, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tracing::error;

// Errors that can occur during stream processing
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Security assessment failed: {0}")]
    SecurityError(#[from] crate::security::SecurityError),

    #[error("Unknown error")]
    Unknown,
}

// Trait for types that can have their content assessed for security issues
pub trait SecurityAssessable {
    // Returns content to be assessed and its type
    fn get_content_for_assessment(&self) -> Option<(&str, &str)>;
}

// A stream wrapper that performs security assessments on each item
pub struct SecurityAssessedStream<S, T>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
    T: DeserializeOwned + SecurityAssessable + Serialize + Send + Sync + 'static,
{
    // The underlying stream
    inner: Pin<Box<S>>,

    // Client for security assessments
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
    // Create a new security-assessed stream
    pub fn new(stream: S, security_client: SecurityClient, model_name: String) -> Self {
        Self {
            inner: Box::pin(stream),
            security_client,
            model_name,
            buffer: None,
            finished: false,
        }
    }

    // Create a formatted message for blocked content
    fn create_blocked_response(&self, category: &str, action: &str) -> Bytes {
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
        let json_bytes =
            serde_json::to_vec(&response).unwrap_or_else(|_| blocked_message.as_bytes().to_vec());

        Bytes::from(json_bytes)
    }

    // Assess content for security issues
    fn assess_content(&self, content: &str, content_type: &str) -> Option<Bytes> {
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
                Some(self.create_blocked_response(&assessment.category, &assessment.action))
            }
            Ok(_) => {
                // Content is safe
                None
            }
            Err(_) => {
                // Error during assessment, continue with original content
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

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Handle finished state
        if self.finished {
            return Poll::Ready(None);
        }

        // Process any buffered items first
        if let Some(item) = self.buffer.take() {
            match serde_json::to_vec(&item) {
                Ok(json) => return Poll::Ready(Some(Ok(Bytes::from(json)))),
                Err(e) => return Poll::Ready(Some(Err(StreamError::JsonError(e)))),
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
                                // Assess content for security issues
                                if let Some(blocked_response) =
                                    self.assess_content(content, content_type)
                                {
                                    // Return blocked response
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
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
