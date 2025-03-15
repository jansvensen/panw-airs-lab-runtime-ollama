use crate::security::{Assessment, SecurityClient};
use crate::types::{PromptDetected, ResponseDetected, ScanResponse};
use bytes::Bytes;
use futures_util::Stream;
use serde::{de::DeserializeOwned, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tracing::{debug, error};

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Security assessment failed: {0}")]
    SecurityError(#[from] crate::security::SecurityError),

    #[error("Security issue detected")]
    SecurityIssue,

    #[error("Unknown error")]
    Unknown,
}

pub struct SecurityAssessedStream<S, T>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
    T: DeserializeOwned + SecurityAssessable + Serialize + Send + Sync + 'static,
{
    inner: Pin<Box<S>>,
    security_client: SecurityClient,
    model_name: String,
    buffer: Option<T>,
    error: Option<StreamError>,
    finished: bool,
}

pub trait SecurityAssessable {
    fn get_content_for_assessment(&self) -> Option<(&str, &str)>;
}

impl<S, T> SecurityAssessedStream<S, T>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
    T: DeserializeOwned + SecurityAssessable + Serialize + Send + Sync + 'static,
{
    pub fn new(stream: S, security_client: SecurityClient, model_name: String) -> Self {
        Self {
            inner: Box::pin(stream),
            security_client,
            model_name,
            buffer: None,
            error: None,
            finished: false,
        }
    }

    // Static method to assess content
    async fn assess_content(
        security_client: &SecurityClient,
        model_name: &str,
        chunk: T,
    ) -> Result<Assessment, StreamError> {
        if let Some((content, content_type)) = chunk.get_content_for_assessment() {
            if !content.is_empty() {
                debug!("Assessing streaming content of type: {}", content_type);
                // Determine if this is a prompt or response based on content_type
                let is_prompt = content_type.contains("prompt");
                let assessment = security_client
                    .assess_content(content, model_name, is_prompt)
                    .await?;
                if !assessment.is_safe {
                    error!(
                        "Security issue detected in streaming content: category={}, action={}",
                        assessment.category, assessment.action
                    );
                    return Err(StreamError::SecurityIssue);
                }
                return Ok(assessment);
            }
        }

        // If there's no content to assess or it's empty, consider it safe
        Ok(Assessment {
            is_safe: true,
            category: "benign".to_string(),
            action: "allow".to_string(),
            details: ScanResponse {
                report_id: "".to_string(),
                scan_id: uuid::Uuid::default(),
                tr_id: None,
                profile_id: None,
                profile_name: None,
                category: "benign".to_string(),
                action: "allow".to_string(),
                prompt_detected: PromptDetected {
                    url_cats: false,
                    dlp: false,
                    injection: false,
                    toxic_content: false,
                    malicious_code: false,
                },
                response_detected: ResponseDetected {
                    url_cats: false,
                    dlp: false,
                    db_security: false,
                    toxic_content: false,
                    malicious_code: false,
                },
                created_at: None,
                completed_at: None,
            },
        })
    }
}

impl<S, T> Stream for SecurityAssessedStream<S, T>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
    T: DeserializeOwned + SecurityAssessable + Serialize + Unpin + Send + Sync + 'static,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Early return for finished state
        if self.finished {
            return Poll::Ready(None);
        }

        // Handle pending errors first
        if let Some(err) = self.error.take() {
            self.finished = true;
            return Poll::Ready(Some(Err(err)));
        }

        // Process buffered items before polling the inner stream
        if let Some(item) = self.buffer.take() {
            let json = match serde_json::to_vec(&item) {
                Ok(json) => json,
                Err(e) => return Poll::Ready(Some(Err(StreamError::JsonError(e)))),
            };
            return Poll::Ready(Some(Ok(Bytes::from(json))));
        }

        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                match serde_json::from_slice::<T>(&bytes) {
                    Ok(chunk) => {
                        // Clone bytes before moving to async task
                        let bytes_clone = bytes.clone();

                        // We need to return to the executor to do the async assessment
                        let this = self.get_mut();
                        let security_client = this.security_client.clone();
                        let model_name = this.model_name.clone();

                        tokio::spawn(async move {
                            // Use the static method to avoid type mismatch issues
                            // Pass chunk by value instead of reference
                            let result = match SecurityAssessedStream::<S, T>::assess_content(
                                &security_client,
                                &model_name,
                                chunk,
                            )
                            .await
                            {
                                Ok(_) => Ok(bytes_clone),
                                Err(e) => Err(e),
                            };
                            result
                        });

                        // Return the original bytes without waiting for assessment
                        Poll::Ready(Some(Ok(bytes)))
                    }
                    Err(e) => {
                        error!("Failed to parse JSON in stream: {}", e);
                        Poll::Ready(Some(Err(StreamError::JsonError(e))))
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => {
                error!("Error in stream: {}", e);
                Poll::Ready(Some(Err(StreamError::Unknown)))
            }
            Poll::Ready(None) => {
                debug!("Stream ended");
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
