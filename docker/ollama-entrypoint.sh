#!/bin/bash

# Start Ollama in the background.
/bin/ollama serve &
# Record Process ID.
pid=$!

# Pause for Ollama to start.
sleep 5

echo "Retrieving model (llama2-uncensored)..."
ollama pull llama2-uncensored:latest
echo "Done."

# Wait for Ollama process to finish.
wait $pid