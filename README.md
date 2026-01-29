<div align="center">

# VISTA

### AI-Powered Security Testing Assistant

[![CI Build](https://github.com/rajrathod-code/VISTA/actions/workflows/build.yml/badge.svg)](https://github.com/rajrathod-code/VISTA/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/rajrathod-code/VISTA?include_prereleases)](https://github.com/rajrathod-code/VISTA/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange)](https://openjdk.org/)

**Burp Suite extension with AI-powered vulnerability testing**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Configuration](#configuration)

</div>

---

## Overview

VISTA is a Burp Suite extension that uses AI to accelerate penetration testing. It analyzes HTTP requests, generates targeted payloads, and provides evidence-based vulnerability assessments.

## Features

### 🎯 Dual-Mode AI Assistant
VISTA offers **two distinct modes** to match your testing workflow:

#### 1. Quick Suggestions Mode
- Get immediate methodology and payload suggestions
- 10-20+ payloads in a single response
- Complete testing approach at once
- Perfect for experienced testers

#### 2. Interactive Assistant Mode
- AI guides you step-by-step through testing
- You test in Burp Repeater and report results
- AI adapts based on what you observe
- Perfect for learning and complex scenarios

[📖 Read the Dual-Mode Guide](DUAL_MODE_GUIDE.md)

### 🚀 Advanced Testing Features
- **WAF Detection** - Detects 8 major WAFs (Cloudflare, AWS, ModSecurity, etc.)
- **Bypass Knowledge** - 500+ real-world techniques from PayloadsAllTheThings
- **Systematic Methodologies** - Step-by-step testing approaches
- **Headless Browser Verification** - Verify XSS actually executes
- **Conversation Mode** - Follow-up questions with context awareness

### 📝 Custom AI Prompt Templates
- **20+ Built-in Templates** - XSS, SQLi, SSRF, Auth Bypass, API Testing, etc.
- **Custom Templates** - Create your own specialized testing templates
- **Variable System** - 24 dynamic variables (URL, METHOD, HEADERS, etc.)
- **Template Management** - Search, filter, import/export templates
- **Usage Tracking** - See which templates work best

[📖 Read the Prompt Templates Guide](PROMPT_TEMPLATES_USER_GUIDE.md)

### 🎯 Payload Library Manager
- **100+ Built-in Payloads** - XSS, SQLi, SSTI, SSRF, Command Injection, XXE
- **Custom Libraries** - Create and manage your own payload collections
- **Bulk Import** - Paste multiple payloads at once with auto-detection
- **AI Integration** - AI automatically suggests relevant payloads
- **Success Tracking** - Track which payloads work best
- **Context-Aware** - Payloads filtered by vulnerability type and context

[📖 Read the Payload Library Guide](PAYLOAD_LIBRARY_USER_GUIDE.md)

### 📁 Request Collection Engine
- **Organize Requests** - Group similar requests into named collections
- **Testing Tracking** - Mark requests as tested/success
- **Comparison View** - Side-by-side request/response comparison
- **Notes System** - Add observations to individual requests
- **Export/Import** - Share collections with team as JSON
- **Pattern Detection** - Auto-detect similar requests
- **Context Menu** - Right-click any request → "Add to Collection"

[📖 Read the Collections User Guide](REQUEST_COLLECTION_USER_GUIDE.md)

### 🎨 Modern UI/UX
- **Dashboard** - Quick stats and actions
- **AI Advisor** - Dual-mode testing interface
- **Findings** - Track confirmed vulnerabilities
- **Settings** - Easy AI configuration

### 🔍 Supported Vulnerabilities
- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Server-Side Template Injection (SSTI)
- Command Injection
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Local File Inclusion (LFI)
- Insecure Direct Object Reference (IDOR)
- Authentication Bypass

## Installation

### Requirements
- Java 17+
- Burp Suite Professional or Community

### Download
1. Get the latest JAR from [Releases](https://github.com/rajrathod-code/VISTA/releases)
2. In Burp: **Extensions → Add → Java → Select JAR**

### Build from Source
```bash
git clone https://github.com/rajrathod-code/VISTA.git
cd VISTA
mvn package -DskipTests
```

## Quick Start

### Quick Suggestions Mode
1. **Configure AI** - Go to VISTA → Settings tab → Enter your API key
2. **Send Request** - Right-click any request → "Send to VISTA AI Advisor"
3. **Select Mode** - Choose "Quick Suggestions" from dropdown
4. **Ask** - "How to test for XSS?" or click quick action buttons
5. **Get Results** - Receive complete methodology + payloads instantly

### Interactive Assistant Mode
1. **Configure AI** - Go to VISTA → Settings tab → Enter your API key
2. **Send Request** - Right-click any request → "Send to VISTA AI Advisor"
3. **Select Mode** - Choose "Interactive Assistant" from dropdown
4. **Start** - "Test for SQL injection"
5. **Follow Steps** - AI gives you STEP 1 to test
6. **Test** - Try it in Burp Repeater
7. **Report** - Tell AI what you observed
8. **Continue** - AI adapts and gives you STEP 2
9. **Repeat** - Until exploitation succeeds

## Configuration

### OpenAI
```
Provider: OpenAI
API Key: sk-...
Model: gpt-4o-mini (recommended for cost)
```

### Azure AI
```
Provider: Azure AI
API Key: your-key
Endpoint: https://your-resource.openai.azure.com
Deployment: your-deployment-name
```

### Cost Optimization
- Default temperature: 0.3 (focused responses)
- Efficient prompts with truncated request/response
- Recommended model: gpt-4o-mini (~$0.001-0.003 per interaction)
- Interactive mode uses multiple calls but provides deeper guidance

## Tabs

| Tab | Purpose |
|-----|---------|
| 🏠 Dashboard | Quick stats, system status, and actions |
| 💡 AI Advisor | Dual-mode testing (Quick Suggestions + Interactive Assistant) |
| 🎯 Findings | Track and manage confirmed vulnerabilities |
| ⚙️ Settings | Configure AI provider (OpenAI or Azure AI) |

## Documentation

- [📖 Dual-Mode Guide](DUAL_MODE_GUIDE.md) - Complete guide to Quick Suggestions vs Interactive Assistant
- [🚀 Advanced Features](ADVANCED_FEATURES.md) - WAF detection, bypass knowledge, browser verification
- [🧪 Systematic Testing](SYSTEMATIC_TESTING.md) - Step-by-step methodologies for each vulnerability
- [🎨 UI Redesign](UI_REDESIGN.md) - Modern interface details

## Project Structure

```
src/main/java/
├── burp/                                    # Burp Suite interfaces
│   └── BurpExtender.java                    # Extension entry point
└── com/vista/security/
    ├── core/
    │   ├── AIConfigManager.java             # Centralized AI config
    │   ├── WAFDetector.java                 # WAF detection & bypass
    │   ├── BypassKnowledgeBase.java         # PayloadsAllTheThings
    │   ├── SystematicTestingEngine.java     # Testing methodologies
    │   ├── InteractiveExploitAdvisor.java   # Context-aware Q&A
    │   ├── HeadlessBrowserVerifier.java     # XSS verification
    │   └── ...
    ├── model/
    ├── service/
    │   ├── OpenAIService.java
    │   └── AzureAIService.java
    └── ui/
        ├── DashboardPanel.java              # Dashboard tab
        ├── TestingSuggestionsPanel.java     # AI Advisor (dual-mode)
        ├── FindingsPanel.java               # Findings tab
        ├── SettingsPanel.java               # Settings tab
        └── ...
```

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

For authorized security testing only. Users are responsible for proper authorization.

---

<div align="center">

**[⬆ Back to Top](#vista)**

</div>
