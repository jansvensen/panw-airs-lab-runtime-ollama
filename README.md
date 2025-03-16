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

## How it Works

panw-api-ollama acts as a transparent proxy:

1. It receives requests from OpenWebUI meant for Ollama
2. It sends the prompt to Palo Alto Networks AI Runtime Security for analysis
3. If the prompt passes security checks, it forwards the request to Ollama
4. It receives Ollama's response and checks it for security issues
5. It delivers the response back to OpenWebUI

All this happens with minimal latency impact while providing maximum security.

## Resources

- [Product Information](https://www.paloaltonetworks.com/network-security/ai-runtime-security)
- [Documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- [API Reference](https://pan.dev/ai-runtime-security/scan/api/)

## Support

For issues related to this integration, please file an issue on GitHub.
For questions about Palo Alto Networks AI Runtime Security, please refer to official support channels.
