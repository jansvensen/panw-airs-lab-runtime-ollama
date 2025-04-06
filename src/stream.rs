use crate::{
    security::{Assessment, SecurityClient},
    types::StreamError,
};
use bytes::Bytes;
use futures_util::{ready, Future, Stream};
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

// Content struct for assessment
pub struct Content<'a> {
    pub prompt: Option<&'a str>,
    pub response: Option<&'a str>,
    pub code_prompt: Option<&'a str>,
    pub code_response: Option<&'a str>,
}

#[derive(Debug)]
struct StreamBuffer {
    text_buffer: String,
    code_buffer: String,
    in_code_block: bool,
    read_pos: usize,
    assessment_window: usize, // Increased window size
}

impl StreamBuffer {
    fn new() -> Self {
        Self {
            text_buffer: String::new(),
            code_buffer: String::new(),
            in_code_block: false,
            read_pos: 0,
            assessment_window: 1000, // Increased to buffer more content
        }
    }

    fn process(&mut self, chunk: &str) {
        let processing_buffer = if self.in_code_block {
            &mut self.code_buffer
        } else {
            &mut self.text_buffer
        };

        // Parse Ollama's JSON response chunk
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
            if let Some(content) = json["message"]["content"].as_str() {
                processing_buffer.push_str(content);
            }
        }

        // Existing code block detection logic
        self.detect_code_blocks();
    }

    fn detect_code_blocks(&mut self) {
        let buffer = if self.in_code_block {
            &self.code_buffer
        } else {
            &self.text_buffer
        };

        let mut backticks = 0;
        for c in buffer.chars() {
            if c == '`' {
                backticks += 1;
                if backticks == 3 {
                    self.in_code_block = !self.in_code_block;
                    backticks = 0;
                }
            } else {
                backticks = 0;
            }
        }
    }

    fn prepare_assessment_content(&self) -> Content {
        Content {
            prompt: None,
            response: Some(&self.text_buffer),
            code_prompt: None,
            code_response: if !self.code_buffer.is_empty() {
                Some(&self.code_buffer)
            } else {
                None
            },
        }
    }

    fn get_assessable_chunk(&self) -> Option<Content> {
        if self.text_buffer.len() >= self.assessment_window
            || self.code_buffer.len() >= self.assessment_window
            || !self.in_code_block
        {
            Some(self.prepare_assessment_content())
        } else {
            None
        }
    }

    fn get_text_content(&self) -> String {
        // Combine text and code buffer for security assessment
        let mut full_content = self.text_buffer.clone();
        if !self.code_buffer.is_empty() {
            if !full_content.is_empty() {
                full_content.push_str("\n\n");
            }
            full_content.push_str("```");
            full_content.push_str(&self.code_buffer);
            full_content.push_str("\n```");
        }
        full_content
    }

    fn commit(&mut self, is_safe: bool) {
        // If content is safe, we can reset buffers or handle accordingly
        if is_safe {
            self.read_pos = self.text_buffer.len();
        }
        // If not safe, we keep buffers as is to potentially modify them
    }
}

#[pin_project]
pub struct SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
{
    #[pin]
    inner: S,
    security_client: SecurityClient,
    model_name: String,
    buffer: StreamBuffer,
    assessment_fut: Option<Pin<Box<dyn Future<Output = Result<Assessment, StreamError>> + Send>>>,
    finished: bool,
    retry_count: u32,
}

impl<S> SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
{
    pub fn new(inner: S, security_client: SecurityClient, model_name: String) -> Self {
        Self {
            inner,
            security_client,
            model_name,
            buffer: StreamBuffer::new(),
            assessment_fut: None,
            finished: false,
            retry_count: 0,
        }
    }
}

fn create_blocked_response(category: &str, action: &str) -> Bytes {
    Bytes::from(format!(
        "BLOCKED - Category: {}, Action: {}",
        category, action
    ))
}

impl<S> Stream for SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            if *this.finished {
                return Poll::Ready(None);
            }

            // Process pending security assessments
            if let Some(fut) = this.assessment_fut.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(assessment)) => {
                        if !assessment.is_safe {
                            let blocked =
                                create_blocked_response(&assessment.category, &assessment.action);
                            *this.retry_count = 0;
                            return Poll::Ready(Some(Ok(blocked)));
                        }
                        this.buffer.commit(true);
                        this.assessment_fut.take();
                    }
                    Poll::Ready(Err(e)) => {
                        this.assessment_fut.take();
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Process incoming stream chunks
            match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(Ok(bytes)) => {
                    if let Ok(chunk) = std::str::from_utf8(&bytes) {
                        this.buffer.process(chunk);

                        if let Some(_content) = this.buffer.get_assessable_chunk() {
                            let client = this.security_client.clone();
                            let model = this.model_name.clone();
                            let content_text = this.buffer.get_text_content();

                            *this.assessment_fut = Some(Box::pin(async move {
                                client
                                    .assess_content(&content_text, &model, false)
                                    .await
                                    .map_err(|e| StreamError::SecurityError(e.to_string()))
                            }));

                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }

                        // Forward chunk if no immediate assessment needed
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                }
                Some(Err(e)) => {
                    return Poll::Ready(Some(Err(StreamError::NetworkError(e.to_string()))));
                }
                None => {
                    // Final assessment on stream end
                    if let Some(_content) = this.buffer.get_assessable_chunk() {
                        let client = this.security_client.clone();
                        let model = this.model_name.clone();
                        let content_text = this.buffer.get_text_content();

                        *this.assessment_fut = Some(Box::pin(async move {
                            client
                                .assess_content(&content_text, &model, false)
                                .await
                                .map_err(|e| StreamError::SecurityError(e.to_string()))
                        }));

                        *this.finished = true;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    return Poll::Ready(None);
                }
            }
        }
    }
}
