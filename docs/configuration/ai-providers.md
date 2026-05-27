---
layout: default
title: AI Providers
parent: Configuration
nav_order: 1
---

# AI Provider Configuration
{: .no_toc }

Configure OpenAI, Azure AI, or OpenRouter for VISTA's AI capabilities.
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
| **OpenAI** | GPT-4o, GPT-4o-mini, GPT-5, o1/o3/o4 | Pay-per-use | Direct API, latest models |
| **Azure AI** | Any deployed model incl. GPT-5, o-series | Pay-per-use | Enterprise, compliance, Azure Identity |
| **OpenRouter** | 500+ models, free tier available | Free + paid | Everyone — fastest way to start |

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
| Model | `gpt-4o-mini` (recommended for cost) |

### Recommended Models

| Model | Context | Cost | Notes |
|:------|:--------|:-----|:------|
| `gpt-4o-mini` | 128K | ~$0.001/req | Cost-effective, fast — good default |
| `gpt-4o` | 128K | ~$0.01/req | Higher quality analysis |
| `gpt-5.2` | 128K | varies | Latest GPT-5 family |
| `o4-mini` | 128K | varies | Reasoning model — temperature omitted automatically |
| `o3` | 128K | varies | Reasoning model — temperature omitted automatically |

{: .tip }
> VISTA automatically detects `o1`, `o3`, and `o4`-series models and omits the `temperature` parameter, which these models reject. No manual configuration needed.

---

## Azure AI Configuration

VISTA supports **two Azure endpoint flavours** and **two auth modes**, auto-detected from your endpoint URL.

### Endpoint Types

#### Azure AI Foundry (New — Recommended)

Endpoints on `*.services.ai.azure.com`:

```
Endpoint:   https://your-resource.services.ai.azure.com/openai/v1
Deployment: gpt-5.2   (or any deployed model name)
```

VISTA sends the model name in the request body, matching the Azure AI Foundry OpenAI-compatible API format.

#### Classic Azure OpenAI

Endpoints on `*.openai.azure.com`:

```
Endpoint:   https://your-resource.openai.azure.com
Deployment: your-deployment-name
API Version: 2025-01-01-preview  (configurable)
```

VISTA puts the deployment name in the URL path, matching the classic Azure OpenAI format.

{: .note }
> VISTA auto-detects the endpoint type from your URL — no manual selection needed. Just paste your endpoint and it routes correctly.

### Auth Modes

#### API Key (Default)

Standard key-based authentication:

| Setting | Value |
|:--------|:------|
| Provider | `Azure AI` |
| Auth Mode | `API Key` |
| API Key | Your Azure key |
| Endpoint | Your endpoint URL |
| Deployment | Your deployment / model name |

**Finding your credentials:**
- Azure Portal → Your AI resource → **Keys and Endpoint**
- Copy Key 1 or Key 2 and the Endpoint URL
- Deployment name: Azure AI Foundry Portal → Deployments tab

#### Azure Identity (Keyless / Entra ID)

Authenticate without an API key using Microsoft Entra ID. VISTA implements the DefaultAzureCredential chain in pure Java:

1. **Environment variables** — `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`
2. **Azure CLI** — `az login` (fallback; runs `az account get-access-token`)

| Setting | Value |
|:--------|:------|
| Provider | `Azure AI` |
| Auth Mode | `Azure Identity` |
| Endpoint | Your endpoint URL |
| Deployment | Your deployment / model name |
| API Key | *(leave blank — not needed)* |

{: .tip }
> **Azure Identity setup:** Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` in your environment before launching Burp Suite, or run `az login` in a terminal. Tokens are cached and refreshed automatically.

### API Version

The API version is configurable in Settings (default: `2025-01-01-preview`). Only applies to Classic Azure OpenAI endpoints — Foundry endpoints don't need it.

### Settings Summary

| Setting | Classic Azure OpenAI | Azure AI Foundry |
|:--------|:---------------------|:-----------------|
| Endpoint | `https://xxx.openai.azure.com` | `https://xxx.services.ai.azure.com/openai/v1` |
| Deployment | Deployment name from Studio | Model name (e.g. `gpt-5.2`) |
| API Version | `2025-01-01-preview` | N/A (auto) |
| Auth Mode | API Key or Azure Identity | API Key or Azure Identity |

---

## OpenRouter Configuration

### Getting an API Key

1. Go to [openrouter.ai](https://openrouter.ai)
2. Sign up — no credit card required for free models
3. Visit [openrouter.ai/keys](https://openrouter.ai/keys)
4. Click **"Create Key"**
5. Copy the key (starts with `sk-or-v1-...`)

### Settings

| Setting | Value |
|:--------|:------|
| Provider | `OpenRouter` |
| API Key | `sk-or-v1-...` |
| Model | `deepseek/deepseek-r1-0528:free` |

### Recommended Free Models

| Model | ID | Quality | Speed |
|:------|:---|:--------|:------|
| **DeepSeek R1 0528** ⭐ | `deepseek/deepseek-r1-0528:free` | ⭐⭐⭐⭐⭐ | Medium (reasoning) |
| **Llama 3.3 70B** | `meta-llama/llama-3.3-70b-instruct:free` | ⭐⭐⭐⭐⭐ | Fast |
| **DeepSeek R1T2 Chimera** | `tngtech/deepseek-r1t2-chimera:free` | ⭐⭐⭐⭐⭐ | Medium |

{: .tip }
> Free models on OpenRouter rotate periodically. If a model returns a 404, switch to another from the list above.

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
> The default temperature of `0.3` is optimal for security testing. For reasoning models (o1, o3, o4-series), temperature is omitted automatically.

### Max Tokens

Controls maximum response length (uses `max_completion_tokens` — the current API standard):

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
3. Success: Status bar shows 🟢 with `(Provider / model-name)`
4. Failure: Detailed error message with troubleshooting hints

The status bar model name shows the **correct model for each provider** — deployment name for Azure AI, OpenRouter model for OpenRouter, and model name for OpenAI.

---

## Configuration Storage

AI configuration is stored at `~/.vista-ai-config.json`:

```json
{
  "provider": "Azure AI",
  "openaiApiKey": "",
  "azureApiKey": "your-azure-key",
  "model": "gpt-4o-mini",
  "endpoint": "https://your-resource.services.ai.azure.com/openai/v1",
  "deployment": "gpt-5.2",
  "azureApiVersion": "2025-01-01-preview",
  "azureAuthMode": "api-key",
  "openRouterApiKey": "",
  "openRouterModel": "deepseek/deepseek-r1-0528:free",
  "temperature": 0.3,
  "maxTokens": 2000
}
```

{: .warning }
> The API key is stored in plaintext in this file. Ensure appropriate file permissions on shared systems. Consider using Azure Identity auth mode to avoid storing keys on disk.

---

## Switching Providers

Switching between providers is instant:

1. Go to **Settings** tab
2. Change the Provider dropdown
3. Enter the new provider's credentials
4. Click **"Test Connection"**
5. All VISTA features immediately use the new provider

No restart required. Active conversations continue with the new provider.
