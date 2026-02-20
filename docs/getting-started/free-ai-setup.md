---
layout: default
title: Free AI Setup
parent: Getting Started
nav_order: 3
---

# Free AI Setup with OpenRouter
{: .no_toc }

Use VISTA with powerful AI models completely free — no credit card required.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Why OpenRouter?

| Feature | OpenRouter | OpenAI | Azure AI |
|:--------|:----------:|:------:|:--------:|
| **Cost** | 🆓 FREE | 💰 Paid | 💰 Paid |
| **Credit Card** | ❌ Not Required | ✅ Required | ✅ Required |
| **Setup Time** | ⚡ 5 minutes | ⏱️ 10 minutes | ⏱️ 30+ minutes |
| **Quality** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Context Window** | 128K+ tokens | 128K tokens | 128K tokens |
| **Best For** | Everyone | Production | Enterprise |

OpenRouter provides access to 500+ AI models, including **free models** that rival GPT-4 in quality. Perfect for bug bounty hunters, students, and anyone who wants powerful AI security testing at zero cost.

---

## Setup Steps (5 Minutes)

### 1. Create OpenRouter Account

1. Go to [openrouter.ai](https://openrouter.ai)
2. Click **"Sign Up"**
3. Sign up with Google, GitHub, or email
4. No credit card or payment information needed

### 2. Generate API Key

1. Visit [openrouter.ai/keys](https://openrouter.ai/keys)
2. Click **"Create Key"**
3. Give it a name (e.g., "VISTA")
4. Copy the key — it starts with `sk-or-v1-...`

{: .warning }
> Save your API key somewhere safe. OpenRouter won't show it again after creation.

### 3. Configure VISTA

1. Open VISTA in Burp Suite → go to **Settings** tab
2. Set Provider to **OpenRouter**
3. Paste your API key
4. Set model to one of the free models below
5. Click **"Test Connection"** → should show 🟢

---

## Recommended Free Models

| Model | ID | Best For |
|:------|:---|:---------|
| **Llama 3.3 70B** ⭐ | `meta-llama/llama-3.3-70b-instruct:free` | General testing, fast responses |
| **DeepSeek R1T2 Chimera** | `tngtech/deepseek-r1t2-chimera:free` | Complex analysis, WAF bypasses, deep reasoning |

{: .tip }
> **Recommended:** Start with `meta-llama/llama-3.3-70b-instruct:free` — it provides fast, accurate responses for most security testing scenarios.

---

## Free Model Limits

Free models on OpenRouter have generous limits:

- **Rate limit:** ~20 requests per minute
- **Daily limit:** ~200 requests per day
- **Context:** 128K+ tokens per request
- **Quality:** Comparable to GPT-4o-mini

These limits are more than sufficient for typical bug bounty testing sessions.

---

## Tips for Best Results

1. **Use Expert Templates** — Templates provide structured prompts that get better responses from free models
2. **Be Specific** — Include relevant request details in your queries
3. **Use Follow-Up Questions** — Free models handle conversation context well
4. **Scope Your Analysis** — Use scope management to avoid wasting requests on irrelevant traffic

---

## Upgrading Later

If you outgrow free limits, you can:

- **Stay on OpenRouter** — Add credits ($5 minimum) for access to GPT-4, Claude, and other premium models
- **Switch to OpenAI** — Direct API access to GPT-4o family
- **Use Azure** — Enterprise deployments with SLA guarantees

Switching providers takes 30 seconds — just update the Settings tab.
