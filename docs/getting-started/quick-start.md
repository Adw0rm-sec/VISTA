---
layout: default
title: Quick Start
parent: Getting Started
nav_order: 2
---

# Quick Start Guide
{: .no_toc }

Configure AI and start testing in 5 minutes.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Step 1: Configure AI Provider

Go to **VISTA → Settings** tab (or click ⚙ in the status bar).

### OpenAI

```
Provider: OpenAI
API Key:  sk-...
Model:    gpt-4o-mini (recommended for cost-effectiveness)
```

| Setting | Recommended Value |
|:--------|:-----------------|
| Model | `gpt-4o-mini` |
| Temperature | `0.3` (focused responses) |
| Cost | ~$0.001–$0.003 per interaction |

### Azure OpenAI

```
Provider:   Azure AI
API Key:    your-azure-key
Endpoint:   https://your-resource.openai.azure.com
Deployment: your-deployment-name
```

### OpenRouter (Free Option) ⭐

```
Provider: OpenRouter
API Key:  sk-or-v1-... (Get free at openrouter.ai/keys)
Model:    meta-llama/llama-3.3-70b-instruct:free
```

{: .tip }
> OpenRouter is the fastest way to start — **no credit card required** and provides GPT-4 level quality. See the [detailed Free AI Setup guide]({% link getting-started/free-ai-setup.md %}).

### Test Your Connection

After entering your credentials:
1. Click **"Test Connection"** in Settings
2. Status bar should change from 🔴 to 🟢
3. Provider and model name appear in the status bar

---

## Step 2: Start Testing

### Method 1: Traffic Monitor (Passive Analysis)

Best for discovering vulnerabilities during browsing.

1. Go to the **Traffic Monitor** tab
2. Click **"▶ Start Monitoring"**
3. Configure scope — add your target domains
4. Browse the target application in your browser (through Burp proxy)
5. VISTA automatically intercepts and analyzes traffic with AI
6. Check the **Findings** tree for detected vulnerabilities
7. Tab badge shows `Findings (5)` when new issues are detected

### Method 2: AI Advisor (Interactive Analysis)

Best for deep-dive testing of specific requests.

1. Capture a request in Burp Suite (Proxy, Repeater, or Target)
2. Right-click the request → **"💡 Send to VISTA AI Advisor"**
3. AI automatically analyzes the request
4. Review testing suggestions and payloads
5. Ask follow-up questions for deeper analysis
6. Attach additional requests with **"📎 Attach"** for multi-request analysis

### Method 3: Template-Driven Testing

Best for systematic, vulnerability-specific testing.

1. Go to the **Prompt Templates** tab
2. Browse the 12 built-in expert templates
3. Select a template (e.g., "SSRF (Expert)")
4. Click **"Use Template"**
5. The template is applied to your next AI interaction
6. AI provides targeted, methodology-driven testing guidance

---

## Step 3: Use Payloads

1. Go to the **Payload Library** tab
2. Browse 80+ pre-built payloads across 8 categories
3. Click any payload to copy it
4. Use in Repeater, Intruder, or manual testing
5. AI suggests relevant payloads based on context

---

## What's Next?

- 📖 Learn about [Templates]({% link templates/index.md %}) for focused testing
- 🌐 Explore [Traffic Monitor]({% link features/traffic-monitor.md %}) in detail
- 🤖 Master the [AI Advisor]({% link features/ai-advisor.md %})
- 🛡️ Understand [WAF Detection]({% link features/waf-detection.md %})
