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

    // Forwards a POST request to the specified endpoint with the provided body.
    pub async fn forward<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<Response, OllamaError> {
        self.forward_request(endpoint, |url| self.client.post(url).json(body))
            .await
    }

    // Forwards a GET request to the specified endpoint.
    pub async fn forward_get(&self, endpoint: &str) -> Result<Response, OllamaError> {
        self.forward_request(endpoint, |url| self.client.get(url))
            .await
    }

    // Streams data from the specified endpoint with the provided body.
    pub async fn stream<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<impl Stream<Item = Result<Bytes, reqwest::Error>>, OllamaError> {
        let response = self
            .forward_request(endpoint, |url| self.client.post(url).json(body))
            .await?;
        Ok(response.bytes_stream())
    }

    // Generic method to handle both GET and POST requests, reducing code duplication.
    async fn forward_request<F>(
        &self,
        endpoint: &str,
        request_builder: F,
    ) -> Result<Response, OllamaError>
    where
        F: FnOnce(&str) -> reqwest::RequestBuilder,
    {
        let url = format!("{}{}", self.base_url, endpoint);
        debug!("Forwarding request to {}", url);

        let response = request_builder(&url).send().await?;
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
}
