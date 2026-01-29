<div align="center">

# 🎯 VISTA - Vulnerability Insight & Strategic Test Assistant

### AI-Powered Security Testing Assistant for Burp Suite

[![CI Build](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/Adw0rm-sec/VISTA)](https://github.com/Adw0rm-sec/VISTA/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange)](https://openjdk.org/)

**Intelligent vulnerability testing with AI-powered guidance, custom templates, and organized workflows**

[Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation)

</div>

---

## 📖 Overview

**VISTA** (Vulnerability Insight & Strategic Test Assistant) is a professional Burp Suite extension that enhances your security testing workflow with AI-powered intelligence. It combines the power of OpenAI and Azure AI with practical pentesting tools to help you test faster, smarter, and more systematically.

**Version:** 2.8.0 | **Status:** Production Ready | **Size:** ~370KB

### Why VISTA?

- 🤖 **AI-Powered Guidance** - Get intelligent testing suggestions from GPT-4
- 📝 **Custom Templates** - 20+ built-in templates for common vulnerabilities
- 🎯 **Payload Library** - 100+ pre-built payloads with AI integration
- 📁 **Request Organization** - Group and track your testing systematically
- 🛡️ **WAF Detection** - Automatically detect and bypass 8 major WAFs
- 🚀 **Zero Dependencies** - Pure Java, no external libraries required

---

## ✨ Key Features

### 🤖 AI-Powered Testing Assistant

Get intelligent, context-aware testing guidance powered by leading AI models:

- **Unified AI Advisor** - Analyzes HTTP requests and suggests targeted testing approaches
- **Multi-Request Analysis** - Handle complex workflows across multiple requests
- **Context-Aware Suggestions** - AI adapts based on response patterns and findings
- **Follow-Up Questions** - Interactive conversation mode for deeper analysis

**Supported AI Providers:**
- OpenAI (GPT-4, GPT-4o, GPT-4o-mini)
- Azure OpenAI Service

### 📝 Custom AI Prompt Templates

Accelerate your testing with pre-built and custom templates:

**20+ Built-in Templates:**
- XSS Testing (Reflected, Stored, DOM-based)
- SQL Injection (Error-based, Blind, Time-based)
- SSRF, SSTI, Command Injection
- Authentication & Authorization Testing
- API Security Testing
- File Upload Vulnerabilities

**Template Features:**
- 24 dynamic variables ({{URL}}, {{METHOD}}, {{HEADERS}}, etc.)
- Create and save custom templates
- Search and filter functionality
- Import/Export for team collaboration
- Usage tracking and favorites

### 🎯 Payload Library Manager

Organize and manage your testing payloads efficiently:

**100+ Built-in Payloads:**
- XSS (Basic, Event Handlers, Encoding Bypasses)
- SQL Injection (MySQL, PostgreSQL, MSSQL, Oracle)
- SSTI (Jinja2, Twig, Freemarker, Velocity)
- SSRF (Cloud Metadata, Internal Networks)
- Command Injection (Linux, Windows)
- XXE, LFI, NoSQL Injection

**Library Features:**
- Create custom payload collections
- Bulk import with auto-detection
- AI-powered payload suggestions
- Success rate tracking
- Context-aware filtering
- Export/Import for sharing

### 📁 Request Collection Engine

Stay organized during complex testing engagements:

- **Group Similar Requests** - Organize endpoints into named collections
- **Track Progress** - Mark requests as tested/success
- **Add Notes** - Document observations and findings
- **Side-by-Side Comparison** - Compare requests and responses
- **Pattern Detection** - Automatically identify similar endpoints
- **Export/Import** - Share collections with your team

### 🛡️ Advanced Security Features

**WAF Detection & Bypass:**
- Automatically detects 8 major WAFs (Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, F5, Barracuda, Fortinet)
- 500+ real-world bypass techniques from PayloadsAllTheThings
- WAF-specific bypass suggestions

**Systematic Testing:**
- Step-by-step methodologies for 9 vulnerability types
- Headless browser verification for XSS
- Reflection analysis for input tracking
- Seamless Burp Repeater integration

### 🎨 Modern User Interface

**6 Intuitive Tabs:**

| Tab | Purpose |
|-----|---------|
| 🏠 **Dashboard** | Quick stats, system status, and actions |
| 💡 **AI Advisor** | Unified AI testing assistant |
| 📝 **Prompt Templates** | Custom AI prompt management |
| 🎯 **Payload Library** | Payload organization and AI integration |
| 📁 **Collections** | Request organization and comparison |
| ⚙️ **Settings** | AI provider configuration |

**Context Menu Integration:**
- Right-click any request → "💡 Send to VISTA AI Advisor"
- Right-click any request → "📁 Add to Collection"

---

## 🚀 Installation

### Requirements

- **Java:** 17 or higher
- **Burp Suite:** Professional or Community Edition

### Quick Install (Recommended)

**Option 1: Download from Releases**

1. Visit [Latest Release](https://github.com/Adw0rm-sec/VISTA/releases/latest)
2. Download `vista-2.8.0.jar` from Assets
3. In Burp Suite: **Extensions → Add → Java → Select JAR**
4. VISTA tab appears in Burp

**Option 2: Command Line**

```bash
# Download latest release
curl -LO https://github.com/Adw0rm-sec/VISTA/releases/download/v2.8.0/vista-2.8.0.jar

# Or download latest auto-build
curl -L https://github.com/Adw0rm-sec/VISTA/raw/main/builds/vista-latest.jar -o vista.jar
```

### Build from Source

```bash
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA
mvn clean package
# JAR will be in target/vista-2.8.0.jar
```

---

## ⚡ Quick Start

### Step 1: Configure AI Provider

Go to **VISTA → Settings** tab and configure your AI provider:

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

### Step 2: Start Testing

**Method 1: AI Advisor**
1. Right-click any request in Burp → **"💡 Send to VISTA AI Advisor"**
2. AI automatically analyzes the request
3. Get testing suggestions and payloads
4. Ask follow-up questions for deeper analysis

**Method 2: Use Templates**
1. Go to **Prompt Templates** tab
2. Select a template (e.g., "XSS Testing - Reflected")
3. Click **"Use Template"**
4. AI provides targeted testing guidance

**Method 3: Organize with Collections**
1. Right-click requests → **"📁 Add to Collection"**
2. Group similar endpoints together
3. Track testing progress
4. Compare responses side-by-side

---

## 🎯 Supported Vulnerabilities

| Vulnerability | AI Guidance | Payloads | Bypass Techniques | Methodologies |
|--------------|:-----------:|:--------:|:-----------------:|:-------------:|
| Cross-Site Scripting (XSS) | ✅ | ✅ | ✅ | ✅ |
| SQL Injection | ✅ | ✅ | ✅ | ✅ |
| Server-Side Template Injection (SSTI) | ✅ | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ | ✅ |
| Server-Side Request Forgery (SSRF) | ✅ | ✅ | ✅ | ✅ |
| XML External Entity (XXE) | ✅ | ✅ | ✅ | ✅ |
| Local File Inclusion (LFI) | ✅ | ✅ | ✅ | ✅ |
| Insecure Direct Object Reference (IDOR) | ✅ | ✅ | ✅ | ✅ |
| Authentication Bypass | ✅ | ✅ | ✅ | ✅ |
| NoSQL Injection | ✅ | ✅ | ✅ | ✅ |

---

## 💡 Use Cases

### For Penetration Testers
- Get AI-powered testing suggestions instantly
- Use proven payload libraries
- Organize testing workflows systematically
- Track progress across engagements
- Generate professional reports

### For Bug Bounty Hunters
- Test faster with AI guidance
- Reuse successful payloads
- Organize similar endpoints
- Document testing methodology
- Export findings for reports

### For Security Teams
- Standardize testing approaches
- Share custom templates across team
- Build team payload libraries
- Collaborate on collections
- Maintain testing consistency

---

## 🔧 Configuration

### AI Provider Settings

**Cost Optimization:**
- Default temperature: 0.3 (focused, deterministic responses)
- Efficient prompts with truncated request/response data
- Recommended model: `gpt-4o-mini` (~$0.001-0.003 per interaction)

**Data Privacy:**
- Requests are truncated before sending to AI
- Sensitive headers can be filtered
- No data stored by VISTA (only by AI provider)
- All data stored locally in `~/.vista/`

### Local Data Storage

VISTA stores configuration and data locally:

```
~/.vista/
├── templates/      # Custom prompt templates
├── payloads/       # Payload libraries
├── collections/    # Request collections
└── config.json     # AI configuration
```

---

## 📊 Technical Details

### Architecture

- **Language:** Java 17+
- **Framework:** Swing UI
- **API:** Burp Suite Extension API
- **Dependencies:** Zero external dependencies (Pure Java + Burp API)
- **Build Tool:** Maven
- **JAR Size:** ~370KB
- **Total Files:** 50+ Java files
- **Lines of Code:** 15,000+

### Project Structure

```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Extension entry point
└── com/vista/security/
    ├── core/                          # Core functionality
    │   ├── AIConfigManager.java       # AI configuration
    │   ├── PromptTemplateManager.java # Template management
    │   ├── PayloadLibraryManager.java # Payload management
    │   ├── RequestCollectionManager.java # Collection management
    │   ├── WAFDetector.java           # WAF detection
    │   └── BypassKnowledgeBase.java   # Bypass techniques
    ├── model/                         # Data models
    │   ├── PromptTemplate.java
    │   ├── Payload.java
    │   └── RequestCollection.java
    ├── service/                       # AI services
    │   ├── OpenAIService.java
    │   └── AzureAIService.java
    └── ui/                            # User interface
        ├── DashboardPanel.java
        ├── TestingSuggestionsPanel.java
        ├── PromptTemplatePanel.java
        ├── PayloadLibraryPanel.java
        ├── RequestCollectionPanel.java
        └── SettingsPanel.java
```

---

## 📖 Documentation

All documentation is included in the main README. For additional help:

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

Please see our [Contributing Guide](CONTRIBUTING.md) for details on how to get started.

### Development Setup

```bash
# Clone repository
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA

# Build
mvn clean package

# Run tests
mvn test

# Check code quality
mvn checkstyle:check
```

---

## 🔒 Security & Responsible Use

### Disclaimer

VISTA is designed for **authorized security testing only**. Users are responsible for:

- ✅ Obtaining proper authorization before testing
- ✅ Complying with applicable laws and regulations
- ✅ Using the tool ethically and responsibly
- ✅ Respecting data privacy and confidentiality

### Security Policy

For security issues, please see [SECURITY.md](SECURITY.md) or contact the maintainers privately.

---

## 📜 License

VISTA is released under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2026 Adw0rm-sec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

VISTA is built on the shoulders of giants:

- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** - Bypass techniques and payloads
- **[Burp Suite](https://portswigger.net/burp)** - Extensibility API and platform
- **[OpenAI](https://openai.com/)** & **[Azure](https://azure.microsoft.com/)** - AI capabilities
- **Security Community** - Testing methodologies, feedback, and inspiration

---

## 📞 Support & Community

### Get Help

- 💬 **Discussions:** [GitHub Discussions](https://github.com/Adw0rm-sec/VISTA/discussions)
- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/Adw0rm-sec/VISTA/issues)
- 📧 **Email:** [Contact Maintainers](https://github.com/Adw0rm-sec)

### Stay Updated

- ⭐ **Star this repository** to stay updated
- 👀 **Watch releases** for new versions
- 🔔 **Follow** [@Adw0rm-sec](https://github.com/Adw0rm-sec) on GitHub

---

## 🗺️ Roadmap

### v2.9.0 (Planned)
- 🤖 AI-powered collection analysis
- 📥 Bulk import from Proxy/Repeater
- 🔍 Advanced response comparison
- 🔎 Enhanced search and filtering

### v3.0.0 (Future)
- 🎯 Smart Findings Manager
- 🤖 Automated vulnerability detection
- 📊 Advanced report generation
- 🔌 Plugin system for extensibility

---

## 📈 Statistics

- **Total Java Files:** 50+
- **Lines of Code:** 15,000+
- **Built-in Templates:** 20+
- **Built-in Payloads:** 100+
- **Supported Vulnerabilities:** 10+
- **WAF Detection:** 8 major WAFs
- **Bypass Techniques:** 500+
- **External Dependencies:** 0 (Zero!)

---

<div align="center">

### Made with ❤️ for the Security Community

**[⬆ Back to Top](#-vista)**

---

**VISTA** - Vulnerability Insight & Strategic Test Assistant

*Empowering security professionals with AI-powered intelligence*

</div>

<!-- BUILD_INFO --> **Latest Build:** 20260129-100037 | **Version:** 2.8.0 | **Commit:** f2635f7
