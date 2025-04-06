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
    assessment_window: usize,
    sentence_boundary_chars: &'static [char],
    last_was_boundary: bool,
}

impl StreamBuffer {
    fn new() -> Self {
        Self {
            text_buffer: String::new(),
            code_buffer: String::new(),
            in_code_block: false,
            read_pos: 0,
            assessment_window: 1000,
            sentence_boundary_chars: &['.', '!', '?', '\n'],
            last_was_boundary: false,
        }
    }

    fn process(&mut self, chunk: &str) {
        // Parse Ollama's JSON response chunk
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
            if let Some(content) = json["message"]["content"].as_str() {
                // Look for code block markers in the incoming content
                if content.contains("```") {
                    // Contains a code block marker, need special processing
                    let mut in_block = self.in_code_block;
                    let parts: Vec<&str> = content.split("```").collect();

                    for (i, part) in parts.iter().enumerate() {
                        if i == 0 && !in_block {
                            // First part before any code block
                            if !part.is_empty() {
                                self.text_buffer.push_str(part);
                            }
                        } else if i == 0 && in_block {
                            // First part is continuation of a code block
                            if !part.is_empty() {
                                self.code_buffer.push_str(part);
                            }
                        } else if in_block {
                            // This is code block content
                            if !part.is_empty() {
                                self.code_buffer.push_str(part);
                            }
                            in_block = false;
                        } else {
                            // This is regular text
                            if !part.is_empty() {
                                self.text_buffer.push_str(part);
                            }
                            in_block = true;
                        }
                    }

                    // Update the code block state
                    self.in_code_block = in_block;
                } else {
                    // No code block markers, add to the appropriate buffer
                    if self.in_code_block {
                        self.code_buffer.push_str(content);
                    } else {
                        self.text_buffer.push_str(content);
                    }
                }
            }
        }
    }

    fn detect_code_blocks(&mut self) {
        // Look for triple backticks in the current active buffer
        let active_buffer = if self.in_code_block {
            &self.code_buffer
        } else {
            &self.text_buffer
        };

        // Make a copy of the buffer to search to avoid borrow issues
        let buffer_copy = active_buffer.clone();

        // Find code block markers
        if let Some(pos) = buffer_copy.find("```") {
            if self.in_code_block {
                // End of a code block
                // Extract content before the marker and clear the buffer
                let code_content = active_buffer[..pos].to_string();
                if self.in_code_block {
                    self.code_buffer.clear();
                    self.code_buffer.push_str(&code_content);
                }

                // Add content after the marker to the text buffer
                if pos + 3 < buffer_copy.len() {
                    let remaining = &buffer_copy[pos + 3..];
                    self.text_buffer.push_str(remaining);
                }
            } else {
                // Start of a code block
                // Extract content before the marker
                let text_content = active_buffer[..pos].to_string();
                if !self.in_code_block {
                    self.text_buffer.clear();
                    self.text_buffer.push_str(&text_content);
                }

                // Add content after the marker to the code buffer
                if pos + 3 < buffer_copy.len() {
                    let remaining = &buffer_copy[pos + 3..];
                    self.code_buffer.push_str(remaining);
                }
            }

            // Toggle code block state
            self.in_code_block = !self.in_code_block;
        }
    }

    fn prepare_assessment_content(&self) -> Content {
        Content {
            prompt: None,
            // Regular text should NOT include code blocks
            response: Some(&self.text_buffer),
            code_prompt: None,
            code_response: if !self.code_buffer.is_empty() {
                Some(&self.code_buffer)
            } else {
                None
            },
        }
    }

    fn get_assessable_chunk(&mut self) -> Option<Content> {
        // Now &mut self
        // Always assess if we've accumulated a large amount of content
        if self.text_buffer.len() >= self.assessment_window
            || self.code_buffer.len() >= self.assessment_window
        {
            return Some(self.prepare_assessment_content());
        }

        // If we've completed a code block, assess it
        if !self.in_code_block && !self.code_buffer.is_empty() {
            return Some(self.prepare_assessment_content());
        }

        // Check for semantic boundaries in text
        if !self.text_buffer.is_empty() {
            let last_char = self.text_buffer.chars().last().unwrap_or(' ');
            if self.sentence_boundary_chars.contains(&last_char)
                && self.text_buffer.len() > 15
                && !self.last_was_boundary
            {
                self.last_was_boundary = true; // Now allowed with mut self
                return Some(self.prepare_assessment_content());
            } else if !self.sentence_boundary_chars.contains(&last_char) {
                self.last_was_boundary = false; // Now allowed
            }
        }

        None
    }

    fn get_text_content(&self) -> String {
        // Combine text and code buffer for security assessment
        let mut full_content = self.text_buffer.clone();
        if !self.code_buffer.is_empty() {
            if !full_content.is_empty() {
                full_content.push_str("\n\n");
            }
            full_content.push_str("```\n");
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
                        // Process the chunk which will now properly separate text and code
                        this.buffer.process(chunk);

                        // Call detect_code_blocks to find and handle code block markers
                        this.buffer.detect_code_blocks();

                        if let Some(_content) = this.buffer.get_assessable_chunk() {
                            // Assessment logic remains unchanged
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

                        // Create a modified response to ensure we keep text and code blocks separate
                        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(chunk) {
                            if let Some(obj) = json["message"].as_object_mut() {
                                if obj.contains_key("content") {
                                    // Get the content string before we mutate json
                                    let original_content =
                                        if let Some(content_val) = obj.get("content") {
                                            content_val.as_str().unwrap_or("").to_string()
                                        } else {
                                            "".to_string()
                                        };

                                    // If there's no actual content in this chunk, pass it through as-is
                                    if original_content.trim().is_empty() {
                                        return Poll::Ready(Some(Ok(bytes)));
                                    }

                                    // Check if this chunk has code block markers
                                    if original_content.contains("```") {
                                        // Process each part separately for cleaner separation
                                        let parts: Vec<&str> =
                                            original_content.split("```").collect();
                                        if parts.len() > 1 {
                                            // Has code block markers, provide clean separation
                                            if !parts[0].trim().is_empty() {
                                                // Regular text before code
                                                obj["content"] =
                                                    serde_json::Value::String(parts[0].to_string());
                                                let text_result = serde_json::to_string(&json)
                                                    .map(Bytes::from)
                                                    .unwrap_or(bytes);
                                                return Poll::Ready(Some(Ok(text_result)));
                                            } else if parts.len() > 1 && !parts[1].trim().is_empty()
                                            {
                                                // Code content
                                                obj["content"] = serde_json::Value::String(
                                                    format!("```\n{}\n```", parts[1]),
                                                );
                                                obj["is_code"] = serde_json::Value::Bool(true);
                                                let code_result = serde_json::to_string(&json)
                                                    .map(Bytes::from)
                                                    .unwrap_or(bytes);
                                                return Poll::Ready(Some(Ok(code_result)));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // If we get here, just pass through the original bytes
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                }
                Some(Err(e)) => {
                    return Poll::Ready(Some(Err(StreamError::NetworkError(e.to_string()))));
                }
                None => {
                    // Final assessment on stream end
                    if let Some(_content) = this.buffer.get_assessable_chunk() {
                        // Assessment logic remains unchanged
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
                    return Poll::Ready(None);
                }
            }
        }
    }
}
