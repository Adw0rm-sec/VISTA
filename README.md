<div align="center">

# 🎯 VISTA - Vulnerability Insight & Strategic Test Assistant

### AI-Powered Security Testing Assistant for Burp Suite

[![CI Build](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/Adw0rm-sec/VISTA)](https://github.com/Adw0rm-sec/VISTA/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange)](https://openjdk.org/)

**Real-time AI traffic analysis, intelligent vulnerability detection, and organized testing workflows — all inside Burp Suite.**

[Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](https://Adw0rm-sec.github.io/VISTA/)

</div>

---

## 📖 Overview

**VISTA** (Vulnerability Insight & Strategic Test Assistant) is a professional Burp Suite extension that enhances your security testing workflow with AI-powered intelligence. It combines real-time traffic analysis, interactive AI guidance, and practical pentesting tools to help you test faster, smarter, and more systematically.

**Version:** 2.10.27 | **Status:** Production Ready | **Size:** ~511KB

### Why VISTA?

- 🤖 **AI-Powered Traffic Analysis** — Real-time HTTP traffic monitoring with AI-driven vulnerability detection
- 💡 **Interactive AI Advisor** — Context-aware testing suggestions from GPT-4, Azure, or OpenRouter
- 🆓 **FREE AI Option** — Use OpenRouter with no credit card required
- 📝 **Custom Templates** — 12 built-in expert templates covering the most common bug bounty vulnerabilities
- 🎯 **Payload Library** — 80+ pre-built payloads across 8 categories with AI integration
- 🛡️ **WAF Detection** — Automatically detect and bypass 8 major WAFs
- 🎯 **Scope-Aware** — Define target scope, only analyze what matters
- � **Data Persistence** — Auto-save traffic, findings, and sessions across Burp restarts
- 📦 **Backup & Restore** — Export/import all VISTA data to any location
- �🚀 **Zero Dependencies** — Pure Java, no external libraries required

---

## ✨ Key Features

### 🌐 Intelligent Traffic Monitor *(Flagship Feature)*

Real-time HTTP traffic analysis powered by AI:

- **Automatic Vulnerability Detection** — AI analyzes intercepted traffic and flags security issues with severity ratings
- **Scope-Aware Analysis** — Define target domains; VISTA only burns AI tokens on in-scope traffic
- **Hierarchical Findings Tree** — Findings grouped by category with expandable detail view
- **Live Findings Counter** — Tab badge shows `Findings (5)` so you know when new issues are detected
- **Customizable Analysis Template** — Edit the AI prompt that drives analysis with a professional split-pane editor
- **Traffic Tab** — Browse all captured HTTP transactions with request/response viewer
- **Export & Clear** — Manage findings lifecycle during engagements

### 🤖 AI-Powered Testing Assistant

Get intelligent, context-aware testing guidance powered by leading AI models:

- **Interactive AI Advisor** — Analyzes HTTP requests and suggests targeted testing approaches
- **Multi-Request Analysis** — Handle complex workflows across multiple requests
- **Context-Aware Suggestions** — AI adapts based on response patterns and findings
- **Follow-Up Conversations** — Interactive chat mode for deeper analysis
- **Attach from Repeater** — Send requests to AI without losing conversation context

**Supported AI Providers:**
- **OpenAI** (GPT-4, GPT-4o, GPT-4o-mini)
- **Azure OpenAI Service** (Enterprise deployments)
- **OpenRouter** (500+ models, 2 FREE models available) ⭐

### 📝 Custom AI Prompt Templates

Accelerate your testing with pre-built and custom templates:

**12 Built-in Expert Templates:**
- XSS - DOM Based (comprehensive DOM XSS testing)
- XSS - Reflected Expert (advanced reflected XSS with WAF bypass)
- SQL Injection Expert (PortSwigger/OWASP-grade methodology)
- SSRF Expert (cloud metadata, IP obfuscation, blind SSRF)
- IDOR / BOLA Expert (object-level authorization, ID manipulation)
- SSTI Expert (engine fingerprinting, sandbox escape, RCE)
- Auth Bypass Expert (login flaws, 2FA bypass, privilege escalation)
- File Upload Expert (extension bypass, web shell, path traversal)
- Race Condition Expert (TOCTOU, Turbo Intruder, double-spend)
- JWT / OAuth Expert (algorithm confusion, token manipulation)
- API Security Expert (OWASP API Top 10, mass assignment, GraphQL)
- Traffic - Bug Bounty Hunter (AI-powered traffic analysis)

**Template Features:**
- 35 dynamic variables ({{URL}}, {{METHOD}}, {{REQUEST}}, {{RESPONSE}}, etc.)
- Create and save custom templates
- Search and filter functionality
- Import/Export for team collaboration
- Usage tracking and favorites

### 🎯 Payload Library Manager

Organize and manage your testing payloads efficiently:

**80+ Built-in Payloads across 8 Libraries:**
- XSS Reflected (Basic, Event Handlers, Encoding Bypasses)
- XSS Stored (Persistent payloads)
- SQL Injection - Error Based (MySQL, PostgreSQL, MSSQL, Oracle)
- SQL Injection - Blind (Boolean-based techniques)
- SSTI (Jinja2, Twig, Freemarker, Velocity)
- SSRF (Cloud Metadata, Internal Networks)
- Command Injection (Linux, Windows)
- XXE (XML External Entity payloads)

**Library Features:**
- Create custom payload collections
- Bulk import with auto-detection
- AI-powered payload suggestions
- Context-aware filtering
- Export/Import for sharing

### 🛡️ Advanced Security Features

**WAF Detection & Bypass:**
- Automatically detects 8 major WAFs (Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, Wordfence, Sucuri, F5 BIG-IP)
- 250+ real-world bypass techniques from PayloadsAllTheThings
- WAF-specific bypass suggestions

**Systematic Testing:**
- Step-by-step methodologies for 5 vulnerability types (XSS, SQLi, SSTI, Command Injection, SSRF)
- Headless browser verification for XSS
- Reflection analysis for input tracking
- Seamless Burp Repeater integration

### 🎨 Modern User Interface

VISTA features a clean, streamlined UI with a professional status bar:

**Always-Visible Status Bar:**
- VISTA branding with version
- Live AI status indicator (● Ready / ● Not Configured)
- Provider & model display
- One-click jump to Settings

**5 Focused Tabs:**

| Tab | Purpose |
|-----|---------|
| 💡 **AI Advisor** | Interactive AI testing assistant with conversation history |
| 🌐 **Traffic Monitor** | Real-time traffic analysis with AI-powered findings |
| 📝 **Prompt Templates** | Custom AI prompt management (12 expert built-in) |
| 🎯 **Payload Library** | Payload organization with AI integration (80+) |
| ⚙️ **Settings** | AI provider configuration, connection testing, data backup & restore |

**Context Menu Integration:**
- Right-click any request → **"💡 Send to VISTA AI Advisor"**
- Right-click any request → **"📎 Attach to Interactive Assistant"**

---

## 🚀 Installation

### Requirements

- **Java:** 17 or higher
- **Burp Suite:** Professional or Community Edition

### Quick Install (Recommended)

**Option 1: Download from Releases**

1. Visit [Latest Release](https://github.com/Adw0rm-sec/VISTA/releases/latest)
2. Download `vista-2.10.24.jar` from Assets
3. In Burp Suite: **Extensions → Add → Java → Select JAR**
4. VISTA tab appears in Burp with status bar

**Option 2: Command Line**

```bash
# Download latest release
curl -LO https://github.com/Adw0rm-sec/VISTA/releases/download/latest/vista-2.10.24.jar
```

### Build from Source

```bash
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA
mvn clean package -DskipTests
# JAR will be in target/vista-2.10.24.jar
```

---

## ⚡ Quick Start

### Step 1: Configure AI Provider

Go to **VISTA → Settings** tab (or click ⚙ in the status bar):

**For OpenAI:**
```
Provider: OpenAI
API Key: sk-...
Model: gpt-4o-mini (recommended for cost-effectiveness)
```

**For Azure AI:**
```
Provider: Azure AI
API Key: your-azure-key
Endpoint: https://your-resource.openai.azure.com
Deployment: your-deployment-name
```

**For OpenRouter (FREE Option):** ⭐
```
Provider: OpenRouter
API Key: sk-or-v1-... (Get free at openrouter.ai/keys)
Model: meta-llama/llama-3.3-70b-instruct:free (recommended)
       or tngtech/deepseek-r1t2-chimera:free (reasoning)
```

### Step 2: Start Testing

**Method 1: Traffic Monitor (Passive AI Analysis)**
1. Go to **Traffic Monitor** tab → Click **"▶ Start Monitoring"**
2. Configure scope (add your target domains)
3. Browse the target — VISTA automatically analyzes traffic
4. Check **Findings** tab for AI-detected vulnerabilities

**Method 2: AI Advisor (Interactive)**
1. Right-click any request in Burp → **"💡 Send to VISTA AI Advisor"**
2. AI automatically analyzes the request
3. Get testing suggestions and payloads
4. Ask follow-up questions for deeper analysis

**Method 3: Use Templates**
1. Go to **Prompt Templates** tab
2. Select a template (e.g., "XSS Testing - Reflected")
3. Click **"Use Template"**
4. AI provides targeted testing guidance

---

## 🆓 FREE AI with OpenRouter

VISTA supports **OpenRouter** — giving you access to powerful AI models **completely free**!

| Feature | OpenRouter | OpenAI | Azure AI |
|---------|:----------:|:------:|:--------:|
| **Cost** | 🆓 FREE | 💰 Paid | 💰 Paid |
| **Credit Card** | ❌ Not Required | ✅ Required | ✅ Required |
| **Setup Time** | ⚡ 5 minutes | ⏱️ 10 minutes | ⏱️ 30+ minutes |
| **Quality** | ⭐⭐⭐⭐⭐ GPT-4 Level | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Context Window** | 128K+ tokens | 128K tokens | 128K tokens |
| **Best For** | Students, Learning, Testing | Production, Enterprise | Enterprise Only |

### Quick Setup (5 Minutes)

1. Go to [openrouter.ai](https://openrouter.ai) → Sign up (no credit card)
2. Visit [openrouter.ai/keys](https://openrouter.ai/keys) → Create Key
3. In VISTA Settings: Select **OpenRouter**, paste key, save
4. Done — all VISTA features work for free!

### Available Free Models

| Model | ID | Best For |
|-------|-----|---------|
| **Llama 3.3 70B** (Recommended) | `meta-llama/llama-3.3-70b-instruct:free` | General testing, fast responses |
| **DeepSeek R1T2 Chimera** | `tngtech/deepseek-r1t2-chimera:free` | Complex analysis, WAF bypasses |

---

## 🎯 Supported Vulnerabilities

| Vulnerability | AI Guidance | Payloads | Bypass Techniques | Methodologies |
|--------------|:-----------:|:--------:|:-----------------:|:-------------:|
| Cross-Site Scripting (XSS) | ✅ | ✅ | ✅ | ✅ |
| SQL Injection | ✅ | ✅ | ✅ | ✅ |
| Server-Side Template Injection (SSTI) | ✅ | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ | ✅ |
| Server-Side Request Forgery (SSRF) | ✅ | ✅ | ✅ | ✅ |
| XML External Entity (XXE) | ✅ | ✅ | ✅ | — |
| Local File Inclusion (LFI) | ✅ | — | ✅ | — |
| Insecure Direct Object Reference (IDOR) | ✅ | — | ✅ | — |
| Authentication Bypass | ✅ | — | ✅ | — |
| NoSQL Injection | ✅ | — | ✅ | — |

---

## 💡 Use Cases

### For Penetration Testers
- AI-powered traffic analysis catches what manual review misses
- Interactive AI advisor for deep-dive testing guidance
- Proven payload libraries with WAF bypass techniques
- Scope-aware analysis — no wasted tokens on irrelevant traffic

### For Bug Bounty Hunters
- Passive AI monitoring while you browse targets
- Instant findings with severity ratings
- Customizable templates for focused testing
- Free AI option via OpenRouter — zero cost

### For Security Teams
- Standardize testing approaches with shared templates
- Build team payload libraries
- Consistent AI-driven analysis across engagements
- Enterprise AI support via Azure OpenAI

---

## 🔧 Configuration

### AI Provider Settings

**Cost Optimization:**
- Default temperature: 0.3 (focused, deterministic responses)
- Efficient prompts with truncated request/response data
- Scope filtering prevents unnecessary AI analysis
- Recommended model: `gpt-4o-mini` (~$0.001-0.003 per interaction)

**Data Privacy:**
- Requests are truncated before sending to AI
- Sensitive headers can be filtered
- No data stored by VISTA externally (only by your AI provider)
- All data stored locally in `~/.vista/`

### Local Data Storage

VISTA persists all data locally with auto-save (every 60s), shutdown hooks, and atomic writes:

```
~/.vista/
├── data/               # Auto-saved data
│   ├── traffic.json        # HTTP traffic transactions
│   ├── findings.json       # Exploit findings
│   └── traffic-findings.json # Traffic analysis findings
├── prompts/
│   ├── built-in/           # Built-in prompt templates
│   └── custom/             # User-created templates
├── payloads/
│   ├── built-in/           # Built-in payload libraries
│   └── custom/             # User-created payloads
├── sessions/           # Chat conversation history
~/.vista-ai-config.json # AI provider configuration
```

**Backup & Restore:** Use **Settings → Export Backup** to save all data to any folder. Restore anytime with **Import Backup**.

---

## 📊 Technical Details

### Architecture

- **Language:** Java 17+
- **Framework:** Swing UI
- **API:** Burp Suite Extension API
- **Dependencies:** Zero external dependencies (Pure Java + Burp API)
- **Build Tool:** Maven
- **JAR Size:** ~511KB
- **Total Files:** 87 Java source files
- **Lines of Code:** 28,000+

### Project Structure

```
src/main/java/
├── burp/
│   └── BurpExtender.java                 # Extension entry point + status bar
└── com/vista/security/
    ├── core/                             # Core functionality
    │   ├── AIConfigManager.java          # AI configuration management
    │   ├── IntelligentTrafficAnalyzer.java # AI traffic analysis engine
    │   ├── VistaPersistenceManager.java  # Data persistence (auto-save, backup/restore)
    │   ├── TrafficBufferManager.java     # Traffic capture & buffering
    │   ├── TrafficMonitorService.java    # Monitoring orchestration
    │   ├── ScopeManager.java            # Target scope management
    │   ├── FindingsManager.java         # AI findings management
    │   ├── PromptTemplateManager.java   # Template management
    │   ├── PayloadLibraryManager.java   # Payload management
    │   ├── WAFDetector.java             # WAF detection
    │   ├── BypassKnowledgeBase.java     # Bypass techniques
    │   └── SessionManager.java          # Session persistence
    ├── model/                            # Data models
    │   ├── TrafficFinding.java          # AI finding model
    │   ├── HttpTransaction.java         # HTTP transaction model
    │   ├── PromptTemplate.java          # Template model
    │   └── Payload.java                 # Payload model
    ├── service/                          # AI services
    │   ├── OpenAIService.java           # OpenAI integration
    │   ├── AzureAIService.java          # Azure OpenAI integration
    │   └── OpenRouterService.java       # OpenRouter integration
    └── ui/                               # User interface
        ├── VistaTheme.java              # Centralized theme & styling
        ├── TrafficMonitorPanel.java     # Traffic Monitor tab
        ├── TrafficFindingsTreePanel.java # Hierarchical findings view
        ├── FindingDetailsPanel.java     # Finding detail viewer
        ├── TestingSuggestionsPanel.java  # AI Advisor tab
        ├── PromptTemplatePanel.java     # Prompt Templates tab
        ├── PromptCustomizationDialog.java # Template editor dialog
        ├── PayloadLibraryPanel.java     # Payload Library tab
        ├── SettingsPanel.java           # Settings tab (config + backup/restore)
        └── HttpMessageViewer.java       # Request/Response viewer
```

---

## 📖 Documentation

- **📚 Full Documentation:** [Adw0rm-sec.github.io/VISTA](https://Adw0rm-sec.github.io/VISTA/)
- **Issues:** [GitHub Issues](https://github.com/Adw0rm-sec/VISTA/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Adw0rm-sec/VISTA/discussions)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security:** [SECURITY.md](SECURITY.md)

---

## 🤝 Contributing

We welcome contributions from the community! Whether it's:

- 🐛 Bug reports
- 💡 Feature requests
- 📝 Documentation improvements
- 🔧 Code contributions

Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA
mvn clean package -DskipTests
# JAR → target/vista-2.10.24.jar
```

---

## 🔒 Security & Responsible Use

### Disclaimer

VISTA is designed for **authorized security testing only**. Users are responsible for:

- ✅ Obtaining proper authorization before testing
- ✅ Complying with applicable laws and regulations
- ✅ Using the tool ethically and responsibly
- ✅ Respecting data privacy and confidentiality

For security issues, please see [SECURITY.md](SECURITY.md) or contact the maintainers privately.

---

## 📜 License

VISTA is released under the [MIT License](LICENSE).

```
MIT License
Copyright (c) 2026 Adw0rm-sec
```

---

## 🙏 Acknowledgments

- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** — Bypass techniques and payloads
- **[Burp Suite](https://portswigger.net/burp)** — Extensibility API and platform
- **[OpenAI](https://openai.com/)**, **[Azure](https://azure.microsoft.com/)**, **[OpenRouter](https://openrouter.ai/)** — AI capabilities
- **Security Community** — Testing methodologies, feedback, and inspiration

---

## 📞 Support & Community

- 💬 **Discussions:** [GitHub Discussions](https://github.com/Adw0rm-sec/VISTA/discussions)
- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/Adw0rm-sec/VISTA/issues)
- 📧 **Contact:** [@Adw0rm-sec](https://github.com/Adw0rm-sec)

⭐ **Star this repository** to stay updated • 👀 **Watch releases** for new versions

---

<div align="center">

### Made with ❤️ for the Security Community

**[⬆ Back to Top](#-vista---vulnerability-insight--strategic-test-assistant)**

---

**VISTA** — Vulnerability Insight & Strategic Test Assistant

*Empowering security professionals with AI-powered intelligence*

</div>

<!-- BUILD_INFO --> **Latest Build:** 20260222-105316 | **Version:** 2.10.27 | **Commit:** 2d366aa
