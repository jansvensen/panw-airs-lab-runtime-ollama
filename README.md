# panw-api-ollama

![file](https://github.com/user-attachments/assets/b54e6622-97e7-4ef8-8cd7-09dd2c5d89f3)

Enhance your Ollama deployment with enterprise-grade AI security using Palo Alto Networks AI Runtime Security.

## What is this?

panw-api-ollama is a security proxy that sits between your [OpenWebUI](https://openwebui.com/) interface and [Ollama](https://ollama.com/) instance. It works by intercepting all prompts and responses, analyzing them with Palo Alto Networks' AI RUNTIME security technology, and protecting your system from:

- Prompt injection attacks
- Data exfiltration attempts
- Harmful or toxic content
- Personally identifiable information (PII) leakage
- Other AI-specific security threats

The best part? It's completely transparent to your existing setup - [Ollama](https://ollama.com/) will still work just as before, but with an added layer of security.

## Why use this?

- **Prevent Security Incidents**: Detect and block malicious prompts before they reach your LLM
- **Protect Sensitive Data**: Ensure responses don't contain unauthorized information
- **Maintain Compliance**: Implement guardrails for safe AI usage in enterprise environments
- **Visibility**: Gain insights into usage patterns and potential threats

## Use Cases

- **Secure AI models in production**: Validate prompt requests and responses to protect deployed AI models.
- **Detect data poisoning**: Identify contaminated training data before fine-tuning.
- **Protect adversarial input**: Safeguard AI agents from malicious inputs and outputs while maintaining workflow flexibility.
- **Prevent sensitive data leakage**: Use API-based threat detection to block sensitive data leaks during AI interactions.

## Quick Start

### Step 1: Install

```
git clone https://github.com/lenoxys/panw-api-ollama.git
cd panw-api-ollama
cargo build --release
```

### Step 2: Get a Palo Alto Networks API Key

Follow [this tutorial](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/ai-runtime-security-api-intercept-overview/onboard-api-runtime-security-api-intercept-in-scm), specifically step 13, to obtain your API key.

### Step 3: Configure

Rename `config.yaml.example` to `config.yaml` and update it with your API key:

```
cp config.yaml.example config.yaml
```

Then edit the file to add your Palo Alto Networks API key:

```yaml
pan_api:
  key: "your-pan-api-key-here"
```

### Step 4: Update OpenWebUI

Change the Ollama port in OpenWebUI from 11434 to 11435 by updating your environment settings:
[OpenWebUI Environment Configuration](https://docs.openwebui.com/getting-started/env-configuration#ollama_base_urls)

### Step 5: Run

```
./target/release/panw-api-ollama
```

You're all set! You can now use OpenWebUI as normal, but with enterprise security scanning all interactions.

## Docker Setup

You can easily run this entire stack (Ollama, panw-api-ollama, and OpenWebUI) using Docker Compose:

### Step 1: Configure your environment variables

Create a `.env` file in the root directory with your configuration:

```bash
# Required for security
SECURITY_API_KEY=your_panw_api_key_here
SECURITY_PROFILE_NAME=your_profile_name

# Optional configuration (defaults shown)
SERVER_HOST=0.0.0.0
SERVER_PORT=11435
SERVER_DEBUG_LEVEL=INFO
OLLAMA_BASE_URL=http://ollama:11434
SECURITY_BASE_URL=https://service.api.aisecurity.paloaltonetworks.com
SECURITY_APP_NAME=panw-api-ollama
SECURITY_APP_USER=docker
RUST_LOG=info

# OpenWebUI and Ollama settings
OPEN_WEBUI_PORT=3000
OLLAMA_DOCKER_TAG=latest
WEBUI_DOCKER_TAG=main
```

### Step 2: Start the Docker stack

```bash
docker-compose up -d
```

This will start three containers:
- **ollama**: The Ollama service on port 11434 (internal only, not exposed to host)
- **panw-api-ollama**: The security broker service on port 11435 (internal only, not exposed to host)
- **open-webui**: The UI running on port 3000, connected to your security broker and exposed to the host system

### Platform-Specific Docker Configurations

The project includes optimized Docker Compose configurations for different platforms:

#### Standard Configuration (All Platforms)
```bash
docker-compose up -d
```

#### Windows with NVIDIA GPU
For Windows users with NVIDIA GPUs:
```bash
docker-compose -f docker-compose.win.yaml up -d
```

### Apple Silicon Native Installation

For optimal performance on Apple Silicon Macs (M1/M2/M3/M4), using native Ollama installation is recommended:

#### Step 1: Install Ollama natively
Download and install Ollama from [ollama.com/download](https://ollama.com/download)

#### Step 2: Start native Ollama
Launch the Ollama app on your Mac or start it from terminal:
```bash
ollama serve
```

#### Step 3: Run Docker components with native Ollama
Use the special Docker Compose file that connects to your native Ollama instance:
```bash
docker-compose -f docker-compose.apple.yaml up -d
```

This configuration:
- Uses your natively installed Ollama with full Apple Silicon hardware acceleration
- Runs panw-api-ollama and OpenWebUI in containers
- Connects the containerized components to your native Ollama instance

### Step 3: Access OpenWebUI

Open your browser and navigate to:
```
http://localhost:3000
```

OpenWebUI will automatically connect to your panw-api-ollama broker, which then securely connects to Ollama.

### Environment Variables

You can customize your Docker deployment using these environment variables:

#### Required Environment Variables:
- `SECURITY_API_KEY`: Your Palo Alto Networks API key
- `SECURITY_PROFILE_NAME`: Your security profile name

#### Optional Environment Variables:
- **Server Configuration**:
  - `SERVER_HOST`: Host to bind the server to (default: 0.0.0.0)
  - `SERVER_PORT`: Port to listen on (default: 11435)
  - `SERVER_DEBUG_LEVEL`: Logging level: INFO, DEBUG, ERROR (default: INFO)
  
- **Ollama Configuration**:
  - `OLLAMA_BASE_URL`: URL to connect to Ollama (default: http://ollama:11434)
  
- **Security Configuration**:
  - `SECURITY_BASE_URL`: Base URL for the security API (default: https://service.api.aisecurity.paloaltonetworks.com)
  - `SECURITY_APP_NAME`: Application name (default: panw-api-ollama)
  - `SECURITY_APP_USER`: Application user identifier (default: docker)
  
- **Docker Image Tags**:
  - `OLLAMA_DOCKER_TAG`: Specify the Ollama image version (default: latest)
  - `WEBUI_DOCKER_TAG`: Specify the OpenWebUI image version (default: main)
  
- **Port Mappings**:
  - `OPEN_WEBUI_PORT`: Change the port for OpenWebUI (default: 3000)
  - `PANW_API_PORT`: Change the port for panw-api-ollama (default: 11435)
  
- **Logging**:
  - `RUST_LOG`: Set the logging level for panw-api-ollama (default: info)

Example with custom settings:
```bash
OPEN_WEBUI_PORT=8080 RUST_LOG=debug SECURITY_APP_USER=custom-user docker-compose up -d
```

## GitHub Container Registry

This project publishes Docker images to the GitHub Container Registry (ghcr.io), making it easy to deploy without building the image yourself.

### Using the Pre-built Image

You can use the pre-built Docker image from GitHub Container Registry in your docker-compose.yaml:

```bash
# Pull and run using the latest image
docker-compose up -d
```

By default, docker-compose will use the latest image from `ghcr.io/paloaltonetworks/panw-api-ollama`. You can specify a different version tag using the `PANW_API_IMAGE` environment variable:

```bash
# Use a specific version
PANW_API_IMAGE=ghcr.io/paloaltonetworks/panw-api-ollama:v0.9.0 docker-compose up -d

# Or build from local source instead of using the registry
PANW_API_IMAGE='' docker-compose up -d
```

### Container Image Release Tags

The following tags are available for the Docker image:

- `latest`: Points to the most recent release
- `vX.Y.Z`: Specific version (e.g., `v0.9.0`)
- `vX.Y`: Minor version release (e.g., `v0.9`)
- `vX`: Major version release (e.g., `v0`)

### For Contributors: Publishing to GitHub Container Registry

The project uses GitHub Actions to automatically build and publish Docker images to ghcr.io. Images are built and published when:

1. You push to the `main` branch
2. You create a tag with a version number (e.g., `v0.9.1`)
3. You manually trigger the "Multi-Platform Docker Build" workflow

To release a new version:

```bash
# Tag the release
git tag -a v0.9.1 -m "Release version 0.9.1"

# Push the tag to GitHub
git push origin v0.9.1
```

This will trigger the GitHub Actions workflow to build and publish multi-platform Docker images.

## Resources

- [Product Information](https://www.paloaltonetworks.com/network-security/ai-runtime-security)
- [Documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- [API Reference](https://pan.dev/ai-runtime-security/scan/api/)

## Support

For issues related to this integration, please file an issue on GitHub.
For questions about Palo Alto Networks AI Runtime Security, please refer to official support channels.
