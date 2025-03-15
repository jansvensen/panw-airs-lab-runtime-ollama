use bytes::Bytes;
use futures_util::Stream;
use reqwest::{Client, Response, StatusCode};
use serde::Serialize;
use thiserror::Error;
use tracing::{debug, error};

#[derive(Debug, Error)]
pub enum OllamaError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Ollama API error: {status} - {message}")]
    ApiError { status: StatusCode, message: String },
}

#[derive(Clone)]
pub struct OllamaClient {
    client: Client,
    base_url: String,
}

impl OllamaClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
        }
    }

    pub async fn forward<T: Serialize>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<Response, OllamaError> {
        let url = format!("{}{}", self.base_url, endpoint);
        debug!("Forwarding request to {}", url);

        let response = self.client.post(&url).json(body).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Ollama API error: {} - {}", status, message);
            return Err(OllamaError::ApiError { status, message });
        }

        Ok(response)
    }

    pub async fn forward_get(&self, endpoint: &str) -> Result<Response, OllamaError> {
        debug!("Forwarding GET request to {}{}", self.base_url, endpoint);
        let response = self
            .client
            .get(&format!("{}{}", self.base_url, endpoint))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Ollama API error: {} - {}", status, message);
            return Err(OllamaError::ApiError { status, message });
        }

        Ok(response)
    }

    pub async fn stream<T: Serialize>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<impl Stream<Item = Result<Bytes, reqwest::Error>>, OllamaError> {
        debug!("Streaming from {}{}", self.base_url, endpoint);
        let response = self
            .client
            .post(&format!("{}{}", self.base_url, endpoint))
            .json(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Ollama API error: {} - {}", status, message);
            return Err(OllamaError::ApiError { status, message });
        }

        Ok(response.bytes_stream())
    }
}
