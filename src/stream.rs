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
            assessment_window: 100000,
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

    fn prepare_assessment_content(&self, is_prompt: bool) -> Content {
        // Check if we have code blocks
        let has_code = !self.code_buffer.is_empty();

        if is_prompt {
            // For prompt content
            Content {
                prompt: Some(&self.text_buffer),
                response: None,
                code_prompt: if has_code {
                    Some(&self.code_buffer)
                } else {
                    None
                },
                code_response: None,
            }
        } else {
            // For response content
            Content {
                prompt: None,
                response: Some(&self.text_buffer),
                code_prompt: None,
                code_response: if has_code {
                    Some(&self.code_buffer)
                } else {
                    None
                },
            }
        }
    }

    fn get_assessable_chunk(&mut self, is_prompt: bool) -> Option<Content> {
        // Always assess if we've accumulated a large amount of content
        if self.text_buffer.len() >= self.assessment_window
            || self.code_buffer.len() >= self.assessment_window
        {
            return Some(self.prepare_assessment_content(is_prompt));
        }

        // If we've completed a code block, assess it
        if !self.in_code_block && !self.code_buffer.is_empty() {
            return Some(self.prepare_assessment_content(is_prompt));
        }

        // Check for semantic boundaries in text
        if !self.text_buffer.is_empty() {
            let last_char = self.text_buffer.chars().last().unwrap_or(' ');
            if self.sentence_boundary_chars.contains(&last_char)
                && self.text_buffer.len() > 15
                && !self.last_was_boundary
            {
                self.last_was_boundary = true;
                return Some(self.prepare_assessment_content(is_prompt));
            } else if !self.sentence_boundary_chars.contains(&last_char) {
                self.last_was_boundary = false;
            }
        }

        None
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
    is_prompt: bool,
}

// Helper function moved outside of impl blocks
fn create_blocked_response(category: &str, action: &str) -> Bytes {
    Bytes::from(format!(
        "BLOCKED - Category: {}, Action: {}",
        category, action
    ))
}

// Create properly formatted content for security assessment
fn create_security_assessment_future(
    buffer: &StreamBuffer,
    security_client: &SecurityClient,
    model_name: &str,
    is_prompt: bool,
) -> Pin<Box<dyn Future<Output = Result<Assessment, StreamError>> + Send>> {
    // Get the separate content buffers
    let text_content = buffer.text_buffer.clone();
    let code_content = buffer.code_buffer.clone();

    // Clone what we need for the async block
    let client = security_client.clone();
    let model = model_name.to_string();

    // Create assessment future - pass the is_prompt flag to correctly identify the content type
    Box::pin(async move {
        client
            .assess_content(&text_content, &model, is_prompt)
            .await
            .map_err(|e| StreamError::SecurityError(e.to_string()))
    })
}

impl<S> SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
{
    pub fn new(
        inner: S,
        security_client: SecurityClient,
        model_name: String,
        is_prompt: bool,
    ) -> Self {
        Self {
            inner,
            security_client,
            model_name,
            buffer: StreamBuffer::new(),
            assessment_fut: None,
            finished: false,
            retry_count: 0,
            is_prompt,
        }
    }

    // Process assessment results
    fn process_assessment_result(
        assessment: Assessment,
        buffer: &mut StreamBuffer,
        assessment_fut: &mut Option<
            Pin<Box<dyn Future<Output = Result<Assessment, StreamError>> + Send>>,
        >,
        retry_count: &mut u32,
    ) -> Option<Result<Bytes, StreamError>> {
        // Important: Always clear the future after processing to avoid "resumed after completion" panic
        *assessment_fut = None;

        if !assessment.is_safe {
            let blocked = create_blocked_response(&assessment.category, &assessment.action);
            *retry_count = 0;
            return Some(Ok(blocked));
        }

        // Don't try to send content if the buffer is empty
        if buffer.text_buffer.is_empty() {
            buffer.commit(true);
            return None;
        }

        // Don't clear the text buffer - we still need to send the original chunks
        // Just mark the content as safe to avoid sending it again
        buffer.commit(true);
        
        // We don't return a result here - we'll let the original chunks flow through
        None
    }

    // Process a chunk from the stream and return a response if available
    fn process_stream_chunk(
        bytes: Bytes,
        buffer: &mut StreamBuffer,
        assessment_fut: &mut Option<
            Pin<Box<dyn Future<Output = Result<Assessment, StreamError>> + Send>>,
        >,
        security_client: &SecurityClient,
        model_name: &str,
        is_prompt: bool,
    ) -> Option<Result<Bytes, StreamError>> {
        if let Ok(chunk) = std::str::from_utf8(&bytes) {
            // Process the chunk which will now properly separate text and code
            buffer.process(chunk);

            // Call detect_code_blocks to find and handle code block markers
            buffer.detect_code_blocks();

            // Check if we need to trigger an assessment
            if buffer.get_assessable_chunk(is_prompt).is_some() {
                *assessment_fut = Some(create_security_assessment_future(
                    buffer,
                    security_client,
                    model_name,
                    is_prompt,
                ));
                return None;
            }

            // Transform the JSON response if needed - create a clone to avoid borrow issues
            let bytes_clone = bytes.clone();
            return Self::transform_json_response(chunk, bytes_clone);
        }

        // If we couldn't process as UTF-8, just pass through the original bytes
        Some(Ok(bytes))
    }

    // Transform JSON response to separate text and code blocks
    fn transform_json_response(chunk: &str, bytes: Bytes) -> Option<Result<Bytes, StreamError>> {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
            // Process potential code blocks
            if let Some(content) = json["message"]["content"].as_str() {
                // Return the original bytes directly to preserve all characters including punctuation
                if !content.contains("```") {
                    return Some(Ok(bytes));
                }

                // Only do special processing for code blocks
                if content.contains("```") {
                    // Clone the json for processing since we need to modify it
                    let json_clone = json.clone();
                    let original_content = content.to_string();

                    // If there's no actual content in this chunk, pass it through as-is
                    if original_content.trim().is_empty() {
                        return Some(Ok(bytes));
                    }

                    // Handle code block markers
                    return Self::process_code_blocks(&original_content, json_clone);
                }
            }
        }

        // If we get here, just pass through the original bytes
        Some(Ok(bytes))
    }

    // Process code blocks in content
    fn process_code_blocks(
        original_content: &str,
        mut json: serde_json::Value,
    ) -> Option<Result<Bytes, StreamError>> {
        // Get the object reference inside the function to avoid borrowing issues
        let obj = if let Some(obj) = json["message"].as_object_mut() {
            obj
        } else {
            return Some(Ok(Bytes::new()));
        };

        // Process each part separately for cleaner separation
        let parts: Vec<&str> = original_content.split("```").collect();
        if parts.len() > 1 {
            // Has code block markers, provide clean separation
            if !parts[0].trim().is_empty() {
                // Regular text before code
                obj["content"] = serde_json::Value::String(parts[0].to_string());
                if let Ok(text_json) = serde_json::to_string(&json) {
                    return Some(Ok(Bytes::from(text_json)));
                }
            } else if parts.len() > 1 && !parts[1].trim().is_empty() {
                // Code content
                obj["content"] = serde_json::Value::String(format!("```\n{}\n```", parts[1]));
                obj["is_code"] = serde_json::Value::Bool(true);
                if let Ok(code_json) = serde_json::to_string(&json) {
                    return Some(Ok(Bytes::from(code_json)));
                }
            }
        }

        // Default to empty response if we couldn't process
        Some(Ok(Bytes::new()))
    }

    // Process stream end and trigger final assessment if needed
    fn process_stream_end(
        buffer: &mut StreamBuffer,
        assessment_fut: &mut Option<
            Pin<Box<dyn Future<Output = Result<Assessment, StreamError>> + Send>>,
        >,
        security_client: &SecurityClient,
        model_name: &str,
        is_prompt: bool,
    ) -> Option<Result<Bytes, StreamError>> {
        if let Some(_content) = buffer.get_assessable_chunk(is_prompt) {
            *assessment_fut = Some(create_security_assessment_future(
                buffer,
                security_client,
                model_name,
                is_prompt,
            ));
            None
        } else {
            None
        }
    }

    // Stream implementation merged into the main impl block
    fn poll_next_impl(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, StreamError>>>
    where
        S: Unpin,
    {
        let mut this = self.project();

        loop {
            if *this.finished {
                return Poll::Ready(None);
            }

            // Process pending security assessments
            if let Some(fut) = this.assessment_fut.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(assessment)) => {
                        if let Some(result) = Self::process_assessment_result(
                            assessment,
                            this.buffer,
                            this.assessment_fut,
                            this.retry_count,
                        ) {
                            return Poll::Ready(Some(result));
                        }
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
                    if let Some(result) = Self::process_stream_chunk(
                        bytes,
                        this.buffer,
                        this.assessment_fut,
                        this.security_client,
                        &this.model_name,
                        *this.is_prompt, // Use the is_prompt flag from the struct
                    ) {
                        return Poll::Ready(Some(result));
                    }
                    // If process_stream_chunk returned None, it means we started an assessment
                    // and need to wait for it to complete
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(Err(e)) => {
                    return Poll::Ready(Some(Err(StreamError::NetworkError(e.to_string()))));
                }
                None => {
                    // Final assessment on stream end
                    if let Some(result) = Self::process_stream_end(
                        this.buffer,
                        this.assessment_fut,
                        this.security_client,
                        &this.model_name,
                        *this.is_prompt, // Use the is_prompt flag from the struct
                    ) {
                        return Poll::Ready(Some(result));
                    } else if this.assessment_fut.is_some() {
                        // If we started a final assessment, wait for it to complete
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    } else {
                        *this.finished = true;
                        return Poll::Ready(None);
                    }
                }
            }
        }
    }
}

impl<S> Stream for SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_next_impl(cx)
    }
}
