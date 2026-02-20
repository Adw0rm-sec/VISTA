---
layout: default
title: AI Providers
parent: Configuration
nav_order: 1
---

# AI Provider Configuration
{: .no_toc }

Configure OpenAI, Azure OpenAI, or OpenRouter for VISTA's AI capabilities.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Supported Providers

| Provider | Models | Cost | Best For |
|:---------|:-------|:-----|:---------|
| **OpenAI** | GPT-4, GPT-4o, GPT-4o-mini | Pay-per-use | Direct API access, production use |
| **Azure OpenAI** | GPT-4, GPT-4o (via deployment) | Pay-per-use | Enterprise, compliance, SLA |
| **OpenRouter** | 500+ models, 2 free | Free + paid tiers | Everyone, free option |

---

## OpenAI Configuration

### Getting an API Key

1. Go to [platform.openai.com](https://platform.openai.com)
2. Sign up or log in
3. Navigate to **API Keys**
4. Click **"Create new secret key"**
5. Copy the key (starts with `sk-...`)

### Settings

| Setting | Value |
|:--------|:------|
| Provider | `OpenAI` |
| API Key | `sk-...` |
| Model | `gpt-4o-mini` (recommended) |

### Recommended Models

| Model | Context | Cost | Best For |
|:------|:--------|:-----|:---------|
| `gpt-4o-mini` | 128K | ~$0.001/req | Cost-effective, fast |
| `gpt-4o` | 128K | ~$0.01/req | Highest quality |
| `gpt-4` | 8K | ~$0.03/req | Legacy, proven |

---

## Azure OpenAI Configuration

### Prerequisites

1. Azure subscription with OpenAI access approved
2. Azure OpenAI resource created
3. Model deployed in Azure OpenAI Studio

### Settings

| Setting | Value |
|:--------|:------|
| Provider | `Azure AI` |
| API Key | Your Azure key |
| Endpoint | `https://your-resource.openai.azure.com` |
| Deployment | Your deployment name |

### Finding Your Credentials

- **API Key:** Azure Portal → Your OpenAI Resource → Keys and Endpoint
- **Endpoint:** Same location, copy the endpoint URL
- **Deployment:** Azure OpenAI Studio → Deployments → Your deployment name

---

## OpenRouter Configuration

### Getting an API Key

1. Go to [openrouter.ai](https://openrouter.ai)
2. Sign up (no credit card required for free models)
3. Visit [openrouter.ai/keys](https://openrouter.ai/keys)
4. Click **"Create Key"**
5. Copy the key (starts with `sk-or-v1-...`)

### Settings

| Setting | Value |
|:--------|:------|
| Provider | `OpenRouter` |
| API Key | `sk-or-v1-...` |
| Model | `meta-llama/llama-3.3-70b-instruct:free` |

### Free Models

| Model | Quality | Speed |
|:------|:--------|:------|
| `meta-llama/llama-3.3-70b-instruct:free` | ⭐⭐⭐⭐⭐ | Fast |
| `tngtech/deepseek-r1t2-chimera:free` | ⭐⭐⭐⭐⭐ | Medium (reasoning) |

---

## Advanced Settings

### Temperature

Controls response randomness:

| Value | Behavior | Use Case |
|:------|:---------|:---------|
| `0.0` | Deterministic, focused | Consistent analysis |
| `0.3` | Slightly creative (default) | Balanced testing guidance |
| `0.7` | Creative | Exploring unusual bypass vectors |
| `1.0` | Maximum creativity | Brainstorming only |

{: .tip }
> The default temperature of `0.3` is optimal for security testing. Lower values give more consistent results.

### Max Tokens

Controls maximum response length:

| Value | Approximate Length |
|:------|:------------------|
| `1000` | Short, focused response |
| `2000` | Standard analysis (default) |
| `4000` | Detailed methodology |
| `8000` | Comprehensive deep dive |

### Connection Testing

After configuring any provider:

1. Click **"Test Connection"** in Settings
2. VISTA sends a test request to verify credentials
3. Success: Status bar shows 🟢 with provider/model info
4. Failure: Error message displayed with troubleshooting hints

---

## Configuration Storage

AI configuration is stored at `~/.vista-ai-config.json`:

```json
{
  "provider": "openrouter",
  "apiKey": "sk-or-v1-...",
  "model": "meta-llama/llama-3.3-70b-instruct:free",
  "endpoint": "",
  "deployment": "",
  "temperature": 0.3,
  "maxTokens": 2000
}
```

{: .warning }
> The API key is stored in plaintext in this file. Ensure appropriate file permissions on shared systems.

---

## Switching Providers

Switching between providers is instant:

1. Go to **Settings** tab
2. Change the Provider dropdown
3. Enter the new provider's credentials
4. Click **"Test Connection"**
5. All VISTA features immediately use the new provider

No restart required. Active conversations continue with the new provider.
