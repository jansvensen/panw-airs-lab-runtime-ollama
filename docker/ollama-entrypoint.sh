#!/bin/bash

# Start Ollama in the background.
/bin/ollama serve &
# Record Process ID.
pid=$!

# Pause for Ollama to start.
sleep 5

echo "Retrieving model..."
ollama pull llama2-uncensored:latest
# ollama pull llama3.2:1b
echo "Done."

# Wait for Ollama process to finish.
wait $pid