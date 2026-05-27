---
layout: default
title: Home
nav_order: 1
permalink: /
---

# 🎯 VISTA Documentation
{: .fs-9 }

**Vulnerability Insight & Strategic Test Assistant** — AI-Powered Security Testing for Burp Suite.
{: .fs-6 .fw-300 }

[Get Started]({% link getting-started/installation.md %}){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/Adw0rm-sec/VISTA){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What is VISTA?

VISTA is a professional Burp Suite extension that enhances security testing with AI-powered intelligence. It combines real-time traffic analysis, interactive AI guidance, and practical pentesting tools to help you test faster, smarter, and more systematically.

**Version:** 2.10.28 · **License:** MIT · **Java:** 17+ · **Size:** ~1.3MB · **Zero Dependencies**

> **New in v2.10.28:** Azure AI Foundry support (new endpoint format), Azure Identity (DefaultAzureCredential) auth, configurable API version, status bar shows correct model name per provider, `+ New Chat` properly creates a new session, `max_completion_tokens` for all providers, reasoning model temperature fix (o1/o3/o4), errors now surface correctly from OpenAI.

---

## ✨ Key Capabilities

| Feature | Description |
|:--------|:------------|
| 🌐 **Traffic Monitor** | Real-time HTTP traffic analysis with AI-driven vulnerability detection |
| 🤖 **AI Advisor** | Context-aware interactive testing suggestions with conversation history |
| 📝 **12 Expert Templates** | Built-in prompt templates covering the most common bug bounty vulnerabilities |
| 🎯 **80+ Payloads** | Pre-built payloads across 8 categories with AI-powered suggestions |
| 🛡️ **WAF Detection** | Detect and bypass 8 major WAFs with 250+ bypass techniques |
| 🆓 **Free AI** | Use OpenRouter with no credit card — powerful AI at zero cost |

---

## 🚀 Quick Navigation

### Getting Started
- [Installation]({% link getting-started/installation.md %}) — Download, build, and install VISTA
- [Quick Start]({% link getting-started/quick-start.md %}) — Configure AI and start testing in 5 minutes
- [Free AI Setup]({% link getting-started/free-ai-setup.md %}) — Use VISTA completely free with OpenRouter

### Core Features
- [Traffic Monitor]({% link features/traffic-monitor.md %}) — Passive AI traffic analysis
- [AI Advisor]({% link features/ai-advisor.md %}) — Interactive testing assistant
- [Payload Library]({% link features/payload-library.md %}) — Manage and deploy payloads
- [WAF Detection]({% link features/waf-detection.md %}) — Identify and bypass WAFs

### Templates
- [Template Overview]({% link templates/index.md %}) — How the template system works
- [Built-in Templates]({% link templates/built-in-templates.md %}) — All 12 expert templates
- [Custom Templates]({% link templates/custom-templates.md %}) — Create your own templates

### Configuration
- [AI Providers]({% link configuration/ai-providers.md %}) — Configure OpenAI, Azure, or OpenRouter
- [Scope Management]({% link configuration/scope-management.md %}) — Target scope configuration
- [Data & Backup]({% link configuration/data-persistence.md %}) — Data storage, backup, and restore

### Reference
- [Architecture]({% link architecture/overview.md %}) — How VISTA works under the hood
- [Contributing]({% link contributing.md %}) — Contribute to VISTA

---

## 🎯 Supported Vulnerabilities

| Vulnerability | AI Guidance | Payloads | Expert Template | Bypass Techniques |
|:-------------|:----------:|:--------:|:---------------:|:-----------------:|
| Cross-Site Scripting (XSS) | ✅ | ✅ | ✅ DOM + Reflected | ✅ |
| SQL Injection | ✅ | ✅ | ✅ | ✅ |
| Server-Side Template Injection | ✅ | ✅ | ✅ | ✅ |
| Server-Side Request Forgery | ✅ | ✅ | ✅ | ✅ |
| IDOR / BOLA | ✅ | — | ✅ | ✅ |
| Authentication Bypass | ✅ | — | ✅ | ✅ |
| File Upload | ✅ | — | ✅ | ✅ |
| Race Conditions | ✅ | — | ✅ | — |
| JWT / OAuth | ✅ | — | ✅ | ✅ |
| API Security (OWASP Top 10) | ✅ | — | ✅ | ✅ |
| Command Injection | ✅ | ✅ | — | ✅ |
| XXE | ✅ | ✅ | — | ✅ |

---

{: .note }
> VISTA is designed for **authorized security testing only**. Always obtain proper authorization before testing any target.
