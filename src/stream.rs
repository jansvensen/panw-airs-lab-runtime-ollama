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
    output_buffer: Vec<Bytes>,        // General output buffer
    text_buffer_complete: Vec<Bytes>, // Buffer for complete text responses
    code_buffer_complete: Vec<Bytes>, // Buffer for complete code blocks
    pending_buffer: Vec<Bytes>,       // Buffer for content waiting for assessment
    assessment_window: usize,
    sentence_boundary_chars: &'static [char],
    last_was_boundary: bool,
    waiting_for_assessment: bool, // Flag indicating we're waiting for assessment
    has_complete_text: bool,      // Flag indicating we have complete text
    has_complete_code: bool,      // Flag indicating we have complete code
    batch_ready: bool,            // Flag indicating a batch is ready to send
    accumulating: bool,           // Flag indicating we're accumulating chunks
}

impl StreamBuffer {
    fn new() -> Self {
        Self {
            text_buffer: String::new(),
            code_buffer: String::new(),
            in_code_block: false,
            read_pos: 0,
            output_buffer: Vec::new(),
            text_buffer_complete: Vec::new(),
            code_buffer_complete: Vec::new(),
            pending_buffer: Vec::new(),
            assessment_window: 100000,
            sentence_boundary_chars: &['.', '!', '?', '\n'],
            last_was_boundary: false,
            waiting_for_assessment: false,
            has_complete_text: false,
            has_complete_code: false,
            batch_ready: false,
            accumulating: false,
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

                // Mark that we have a complete code block
                self.has_complete_code = true;
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
            // Also clear the code buffer since it has been assessed
            self.code_buffer.clear();
        }
        // If not safe, we keep buffers as is to potentially modify them
    }

    // Add chunk to the pending buffer instead of the output buffer
    fn buffer_pending_chunk(&mut self, bytes: Bytes) {
        self.pending_buffer.push(bytes);
        self.waiting_for_assessment = true;
    }

    // Transform an incoming chunk to maintain all punctuation and code blocks
    fn buffer_raw_chunk(&mut self, bytes: Bytes) {
        // Always store the raw bytes to preserve all punctuation and formatting
        self.output_buffer.push(bytes);
    }

    // Move all pending chunks to the appropriate buffer once assessment is complete
    fn release_pending_chunks(&mut self) {
        // First, find what kind of content we have in pending buffer
        let mut has_code = false;

        for bytes in &self.pending_buffer {
            if let Ok(chunk) = std::str::from_utf8(bytes) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
                    if let Some(content) = json["message"]["content"].as_str() {
                        if content.contains("```") || self.in_code_block {
                            has_code = true;
                            break;
                        }
                    }
                }
            }
        }

        // Move pending chunks to the appropriate buffer based on content type
        if has_code {
            // Move to code buffer
            for chunk in self.pending_buffer.drain(..) {
                self.code_buffer_complete.push(chunk);
            }
            self.has_complete_code = true;
        } else {
            // Move to text buffer
            for chunk in self.pending_buffer.drain(..) {
                self.text_buffer_complete.push(chunk);
            }
            self.has_complete_text = true;
        }

        // Mark the content as ready to send
        self.mark_batch_ready();
        self.waiting_for_assessment = false;
    }

    // Check if we should release buffered content after processing
    fn mark_batch_ready(&mut self) {
        // If we have completed code blocks or text, mark the batch as ready
        if self.has_complete_code || self.has_complete_text {
            self.batch_ready = true;
            self.accumulating = false;
        }
    }

    // Create a single chunk from all accumulated content
    fn create_complete_response(&mut self) -> Option<Bytes> {
        let mut combined_data = Vec::new();

        // If we have complete code, prioritize that
        if self.has_complete_code {
            // Combine all code chunks
            for chunk in self.code_buffer_complete.drain(..) {
                combined_data.extend_from_slice(&chunk);
            }
            self.has_complete_code = false;
        } else if self.has_complete_text {
            // Combine all text chunks
            for chunk in self.text_buffer_complete.drain(..) {
                combined_data.extend_from_slice(&chunk);
            }
            self.has_complete_text = false;
        } else {
            // Combine all general output chunks
            for chunk in self.output_buffer.drain(..) {
                combined_data.extend_from_slice(&chunk);
            }
        }

        self.batch_ready = false;

        if !combined_data.is_empty() {
            Some(Bytes::from(combined_data))
        } else {
            None
        }
    }

    // Get next chunk only if a complete batch is ready
    fn get_next_chunk(&mut self) -> Option<Bytes> {
        if self.batch_ready {
            return self.create_complete_response();
        }

        // Not returning individual chunks - accumulate until batch is ready
        None
    }

    // Determine content type from a chunk and buffer accordingly
    fn buffer_content(&mut self, bytes: Bytes) {
        // Start accumulating content
        if !self.accumulating {
            self.accumulating = true;
        }

        if let Ok(chunk) = std::str::from_utf8(&bytes) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
                if let Some(content) = json["message"]["content"].as_str() {
                    // If content contains a code block marker, buffer it in code buffer
                    if content.contains("```") || self.in_code_block {
                        self.code_buffer_complete.push(bytes);
                        // Only mark complete if we've reached the end of a code block
                        if !self.in_code_block && !self.code_buffer.is_empty() {
                            self.has_complete_code = true;
                            // Mark batch as ready when we've got a complete code block
                            self.mark_batch_ready();
                        }
                    } else {
                        // Regular text content
                        self.text_buffer_complete.push(bytes);

                        // Check if this text chunk is a complete sentence
                        if content.ends_with(".")
                            || content.ends_with("!")
                            || content.ends_with("?")
                            || content.ends_with("\n")
                        {
                            self.has_complete_text = true;
                            // Mark batch as ready when we've got complete text
                            self.mark_batch_ready();
                        }
                    }
                    return;
                }
            }
        }

        // If we couldn't determine the content type, add to the main output buffer
        self.output_buffer.push(bytes);
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

    // Create assessment future with appropriate content based on what we have
    Box::pin(async move {
        // If we have code content, include it in the assessment
        if !code_content.is_empty() {
            client
                .assess_content_with_code(&text_content, &code_content, &model, is_prompt)
                .await
                .map_err(|e| StreamError::SecurityError(e.to_string()))
        } else {
            // Otherwise just assess the text
            client
                .assess_content(&text_content, &model, is_prompt)
                .await
                .map_err(|e| StreamError::SecurityError(e.to_string()))
        }
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
            // Clear the pending buffer since we're not going to send these chunks
            buffer.pending_buffer.clear();
            buffer.waiting_for_assessment = false;
            buffer.accumulating = false;
            return Some(Ok(blocked));
        }

        // Don't try to send content if the buffer is empty
        if buffer.text_buffer.is_empty()
            && buffer.code_buffer.is_empty()
            && buffer.pending_buffer.is_empty()
        {
            buffer.commit(true);
            return None;
        }

        // Mark the content as safe by updating the read position and clearing code buffer
        buffer.commit(true);

        // Release all pending chunks now that assessment is complete
        buffer.release_pending_chunks();

        // We don't return a result here - we'll let the chunks flow through via get_next_chunk
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
            // Process the chunk which will now properly separate text and code for assessment
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
                // Add to pending buffer when we're waiting for assessment
                buffer.buffer_pending_chunk(bytes);
                return None;
            }

            // If we're waiting for assessment, continue buffering chunks until assessment completes
            if buffer.waiting_for_assessment {
                buffer.buffer_pending_chunk(bytes);
            } else {
                // Use our new buffer_content method to properly separate text and code
                buffer.buffer_content(bytes);
            }

            return None;
        }

        // If we couldn't process as UTF-8, add to appropriate buffer based on assessment status
        if buffer.waiting_for_assessment {
            buffer.buffer_pending_chunk(bytes);
        } else {
            buffer.buffer_raw_chunk(bytes);
        }

        None
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

        // First check if we have any buffered chunks ready to return
        if let Some(bytes) = this.buffer.get_next_chunk() {
            return Poll::Ready(Some(Ok(bytes)));
        }

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
                        // After processing assessment, check if we have buffered chunks to return
                        if let Some(bytes) = this.buffer.get_next_chunk() {
                            return Poll::Ready(Some(Ok(bytes)));
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
                    Self::process_stream_chunk(
                        bytes,
                        this.buffer,
                        this.assessment_fut,
                        this.security_client,
                        &this.model_name,
                        *this.is_prompt,
                    );

                    // After processing the chunk, check if we have any completed content to return
                    if this.assessment_fut.is_some() {
                        // If we started an assessment, wait for it to complete
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    } else if let Some(bytes) = this.buffer.get_next_chunk() {
                        // If we have a chunk ready to return, return it
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                    // Otherwise continue processing more chunks
                    continue;
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
                        *this.is_prompt,
                    ) {
                        return Poll::Ready(Some(result));
                    } else if this.assessment_fut.is_some() {
                        // If we started a final assessment, wait for it to complete
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    } else if let Some(bytes) = this.buffer.get_next_chunk() {
                        // Try to return any remaining buffered chunks
                        return Poll::Ready(Some(Ok(bytes)));
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
