### Discalimer: This is a fork of 'https://github.com/PaloAltoNetworks/panw-api-ollama/fork' by the great 'https://github.com/lenoxys'. I adjusted it to fit my LAB a bit better (e.g. I'm using Docker CLI on Linux, instead of Docker Desktop). 

# panw-api-ollama

![file](https://github.com/user-attachments/assets/b54e6622-97e7-4ef8-8cd7-09dd2c5d89f3)

Enhance your Ollama deployment with enterprise-grade AI security using Palo Alto Networks Prisma AIRS AI Runtime API Intercept.

## What is this?

panw-api-ollama is a security proxy that sits between your [OpenWebUI](https://openwebui.com/) interface and [Ollama](https://ollama.com/) instance. It works by intercepting all prompts and responses, analyzing them with Palo Alto Networks' Prisma AIRS AI Runtime security technology, and protecting your system from:

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

## Setup using Docker

Docker is the recommended installation method as it:
- Handles all permissions automatically
- Provides a pre-configured environment
- Eliminates system-level dependency issues
- Makes updates and maintenance easier

For Docker-based deployment, please refer to the instructions in the [Docker Setup README](docker/README.md).

## Configuration Examples

The project includes example configuration files in the `config-examples` directory that demonstrate different setup options:

### OpenWebUI Global Configuration

The `config-1747909231428.json` file shows how to set up OpenWebUI with both secured and unsecured Ollama connections:

```json
{
    "ollama": {
        "enable": true,
        "base_urls": [
            "http://panw-api-ollama:11435",  // Secure connection through panw-api-ollama
            "http://host.docker.internal:11434"  // Direct connection to Ollama
        ],
        "api_configs": {
            "0": {
                "enable": true,
                "tags": [],
                "prefix_id": "PANW",  // Models with this prefix use the security proxy
                "model_ids": [
                    "llama2-uncensored:latest"
                ],
                "key": ""
            },
            "1": {
                "enable": true,
                "tags": [],
                "prefix_id": "NOPAWN",  // Models with this prefix bypass the security proxy
                "model_ids": [
                    "nomic-embed-text:latest",
                    "llama2-uncensored:latest"
                ],
                "key": ""
            }
        }
    }
}
```

### Model Configurations

Two example model configurations are included to demonstrate before/after comparisons:

1. `PANW.llama2-uncensored_latest-1747909321539.json` - A model using the security proxy
2. `NOPAWN.llama2-uncensored_latest-1747909327080.json` - The same model bypassing the security proxy

These configurations allow you to perform side-by-side comparisons and demonstrations of how the Palo Alto Networks Prisma AIRS AI Runtime Security affects the model responses.

## Resources

- [Product Information](https://www.paloaltonetworks.com/prisma/prisma-ai-runtime-security)
- [Documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- [API Reference](https://pan.dev/prisma-airs/scan/api/)

## Support

For issues related to this integration, please file an issue on GitHub.
For questions about Palo Alto Networks Prisma AIRS AI Runtime API Intercept, please refer to official support channels.