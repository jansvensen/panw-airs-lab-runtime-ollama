# Docker Setup for panw-api-ollama

## Prerequisites

### Install Docker

I use docker CLI on Ubuntu for this project. Chose whatever you prefer.

## Components

This folder contains all Docker-related files for running the panw-api-ollama stack:
- Ollama: The AI model server
- panw-api-ollama: The security proxy 
- OpenWebUI: The web interface

## Docker Deployment Options Summary

| Configuration | Docker File | Description | Best For |
|---------------|------------|-------------|----------|
| Standard | `docker-compose.yaml` | All components (Ollama, panw-api-ollama, OpenWebUI) run in containers | Most platforms, simple setup |

## Quick Start

### Step 1: Prepare configuration files

Copy the required configuration files within the docker folder:

```bash
# Copy environment variables file (required)
cd docker
cp .env.example ./.env
```

### Step 2: Configure your environment variables

Edit the `.env` file in the root directory with your configuration:

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
CUSTOM_CONFIG_PATH=./custom-config.json  # Path to your OpenWebUI config
```

### Step 3: Start the Docker stack

```bash
cd docker
docker-compose up -d
```

This will start three containers:
- **ollama**: The Ollama service on port 11434 (internal only, not exposed to host)
  - Automatically downloads the llama2-uncensored:latest model on startup
- **panw-api-ollama**: The security broker service on port 11435 (internal only, not exposed to host)
- **open-webui**: The UI running on port 3000, connected to your security broker and exposed to the host system

## Understanding Docker Compose Configurations

Each Docker Compose file is designed for specific use cases:

### docker-compose.yaml (Standard Configuration)

The default configuration suitable for most users, which:
- Runs all three components in containers: Ollama, panw-api-ollama, and OpenWebUI
- Connects OpenWebUI to panw-api-ollama using the internal Docker network
- panw-api-ollama connects to Ollama using the internal Docker network
- Automatically downloads the llama2-uncensored:latest model on startup

This setup is ideal for:
- First-time users
- Linux, macOS (Intel), and Windows without GPU
- Testing and development environments
- Production deployments on standard servers

## Access OpenWebUI

Open your browser and navigate to:
```
http://localhost:3000
```

OpenWebUI will automatically connect to your panw-api-ollama broker, which then securely connects to Ollama.

Note: The Docker-specific hostnames like `panw-api-ollama` and `host.docker.internal` only work in Docker environments.

## Environment Variables

You can customize your Docker deployment using these environment variables:

### Required Environment Variables:
- `SECURITY_API_KEY`: Your Palo Alto Networks API key
- `SECURITY_PROFILE_NAME`: Your security profile name

### Optional Environment Variables:
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

## Additional Information

For more details about the panw-api-ollama project, including non-Docker installation methods, please refer to the [main README.md](../README.md) in the project root.