---
layout: default
title: Features
nav_order: 3
has_children: true
---

# Core Features
{: .no_toc }

VISTA provides five integrated tools for AI-powered security testing.
{: .fs-6 .fw-300 }

---

## Feature Overview

| Feature | Tab | Description |
|:--------|:----|:------------|
| [Traffic Monitor]({% link features/traffic-monitor.md %}) | 🌐 Traffic Monitor | Passive AI traffic analysis with automatic vulnerability detection |
| [AI Advisor]({% link features/ai-advisor.md %}) | 💡 AI Advisor | Interactive testing assistant with conversation history |
| [Payload Library]({% link features/payload-library.md %}) | 🎯 Payload Library | 80+ payloads across 8 categories with AI suggestions |
| [WAF Detection]({% link features/waf-detection.md %}) | Built-in | Automatic WAF identification with 250+ bypass techniques |
| [Prompt Templates]({% link templates/index.md %}) | 📝 Templates | 12 expert templates + custom template creation |

---

## How They Work Together

```
                    ┌─────────────────────────┐
                    │    Burp Suite Proxy      │
                    └────────────┬────────────┘
                                 │ HTTP Traffic
                    ┌────────────▼────────────┐
                    │   VISTA Core Engine      │
                    │  ┌──────────────────┐    │
                    │  │  WAF Detection   │    │
                    │  │  Scope Filtering │    │
                    │  └──────────────────┘    │
                    └──┬─────────────────┬────┘
                       │                 │
          ┌────────────▼──┐    ┌────────▼──────────┐
          │Traffic Monitor│    │    AI Advisor      │
          │ (Passive)     │    │  (Interactive)     │
          │               │    │                    │
          │ Auto-analyze  │    │ Send request →     │
          │ all traffic   │    │ Get AI guidance →  │
          │ Flag vulns    │    │ Follow-up chat     │
          └───────┬───────┘    └────────┬───────────┘
                  │                     │
          ┌───────▼─────────────────────▼───────┐
          │         AI Provider (API)           │
          │   OpenAI / Azure / OpenRouter       │
          └───────┬─────────────────────┬───────┘
                  │                     │
          ┌───────▼───────┐    ┌───────▼───────┐
          │  Findings     │    │  Suggestions  │
          │  Tree View    │    │  + Payloads   │
          └───────────────┘    └───────────────┘
```

The **Traffic Monitor** runs passively in the background, while the **AI Advisor** provides on-demand interactive analysis. Both use the same AI provider, WAF detection, and scope management systems.
