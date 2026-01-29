<div align="center">

# VISTA

### AI-Powered Security Testing Assistant for Burp Suite

[![CI Build](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml)
[![Security Scan](https://github.com/Adw0rm-sec/VISTA/actions/workflows/security.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/Adw0rm-sec/VISTA?include_prereleases)](https://github.com/Adw0rm-sec/VISTA/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange)](https://openjdk.org/)

**Intelligent vulnerability testing with AI-powered guidance, custom templates, payload libraries, and request organization**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation)

</div>

---

## 🎯 Overview

VISTA (Vulnerability Insight & Strategic Test Assistant) is a comprehensive Burp Suite extension that combines AI-powered testing guidance with practical pentesting tools. It helps security professionals test faster and smarter through intelligent suggestions, organized workflows, and reusable testing components.

**Current Version**: 2.8.0 | **Build Status**: ✅ Production Ready | **JAR Size**: 353KB

---

## ✨ Features

### 🤖 AI-Powered Testing Assistant

**Unified AI Advisor** - Get intelligent testing guidance powered by OpenAI or Azure AI:
- Analyzes HTTP requests and suggests testing approaches
- Provides vulnerability-specific payloads and methodologies
- Adapts suggestions based on response patterns
- Supports multi-request analysis for complex workflows
- Context-aware follow-up questions

**Supported AI Providers:**
- OpenAI (GPT-4, GPT-4o, GPT-4o-mini)
- Azure OpenAI Service

### 📝 Custom AI Prompt Templates

**20+ Built-in Templates** covering common testing scenarios:
- XSS Testing (Reflected, Stored, DOM-based)
- SQL Injection (Error-based, Blind, Time-based)
- SSRF, SSTI, Command Injection
- Authentication & Authorization Testing
- API Security Testing
- File Upload Vulnerabilities

**Template Features:**
- 24 dynamic variables ({{URL}}, {{METHOD}}, {{HEADERS}}, etc.)
- Create custom templates for your workflows
- Search and filter templates
- Import/Export for team sharing
- Usage tracking and favorites

### 🎯 Payload Library Manager

**100+ Built-in Payloads** across 8 vulnerability categories:
- XSS (Basic, Event Handlers, Encoding Bypasses)
- SQL Injection (MySQL, PostgreSQL, MSSQL, Oracle)
- SSTI (Jinja2, Twig, Freemarker, Velocity)
- SSRF (Cloud Metadata, Internal Networks)
- Command Injection (Linux, Windows)
- XXE (File Disclosure, SSRF)
- LFI/Path Traversal
- NoSQL Injection

**Library Features:**
- Create custom payload libraries
- Bulk import with auto-detection
- AI-powered payload suggestions
- Success rate tracking
- Context-aware filtering
- Export/Import for sharing

### 📁 Request Collection Engine

**Organize and Track Your Testing:**
- Group similar requests into named collections
- Mark requests as tested/success
- Add notes and observations
- Side-by-side request comparison
- Pattern detection for similar endpoints
- Export/Import collections as JSON
- Statistics and progress tracking

**Use Cases:**
- Systematic endpoint testing
- Parameter fuzzing workflows
- Multi-step attack chains
- Team collaboration and handoffs

### 🛡️ Advanced Security Features

**WAF Detection** - Automatically detects 8 major WAFs:
- Cloudflare, AWS WAF, ModSecurity
- Akamai, Imperva, F5 BIG-IP
- Barracuda, Fortinet FortiWeb

**Bypass Knowledge Base** - 500+ real-world bypass techniques from PayloadsAllTheThings

**Systematic Testing Engine** - Step-by-step methodologies for 9 vulnerability types

**Headless Browser Verification** - Verify XSS payloads actually execute

**Reflection Analysis** - Detect where input is reflected in responses

**Repeater Integration** - Seamless integration with Burp Repeater

### 🎨 Modern User Interface

**6 Intuitive Tabs:**

1. **🏠 Dashboard** - Quick stats, system status, and actions
2. **💡 AI Advisor** - Unified AI testing assistant
3. **📝 Prompt Templates** - Custom AI prompt management
4. **🎯 Payload Library** - Payload organization and AI integration
5. **📁 Collections** - Request organization and comparison
6. **⚙️ Settings** - AI provider configuration

**Context Menu Integration:**
- Right-click any request → "💡 Send to VISTA AI Advisor"
- Right-click any request → "📁 Add to Collection"

---

## 🚀 Installation

### Requirements
- Java 17 or higher
- Burp Suite Professional or Community Edition

### Quick Install

1. **Download the latest JAR:**
   ```bash
   curl -L https://github.com/Adw0rm-sec/VISTA/raw/main/builds/vista-latest.jar -o vista.jar
   ```

2. **Or download from [Releases](https://github.com/Adw0rm-sec/VISTA/releases)**

3. **Load in Burp Suite:**
   - Extensions → Add → Java
   - Select the downloaded JAR file
   - VISTA tab appears in Burp

### Build from Source

```bash
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA
mvn clean package
# JAR will be in target/vista-1.0.0-MVP.jar
```

---

## ⚡ Quick Start

### 1. Configure AI Provider

Go to **VISTA → Settings** tab:

**For OpenAI:**
```
Provider: OpenAI
API Key: sk-...
Model: gpt-4o-mini (recommended for cost)
```

**For Azure AI:**
```
Provider: Azure AI
API Key: your-key
Endpoint: https://your-resource.openai.azure.com
Deployment: your-deployment-name
```

### 2. Start Testing

**Method 1: AI Advisor**
1. Right-click any request → "💡 Send to VISTA AI Advisor"
2. AI analyzes the request automatically
3. Get testing suggestions and payloads
4. Ask follow-up questions

**Method 2: Use Templates**
1. Go to **Prompt Templates** tab
2. Select a template (e.g., "XSS Testing - Reflected")
3. Click "Use Template"
4. AI provides targeted testing guidance

**Method 3: Organize with Collections**
1. Right-click requests → "📁 Add to Collection"
2. Group similar endpoints together
3. Track testing progress
4. Compare responses side-by-side

---

## 📖 Documentation

All documentation is available in the main README. For additional help:
- Check the [Issues](https://github.com/Adw0rm-sec/VISTA/issues) page
- Review the inline code comments
- Explore the UI tabs for feature descriptions

---

## 🎯 Supported Vulnerabilities

| Vulnerability | AI Guidance | Payloads | Bypass Techniques | Methodologies |
|--------------|-------------|----------|-------------------|---------------|
| XSS | ✅ | ✅ | ✅ | ✅ |
| SQL Injection | ✅ | ✅ | ✅ | ✅ |
| SSTI | ✅ | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ | ✅ |
| SSRF | ✅ | ✅ | ✅ | ✅ |
| XXE | ✅ | ✅ | ✅ | ✅ |
| LFI/Path Traversal | ✅ | ✅ | ✅ | ✅ |
| IDOR | ✅ | ✅ | ✅ | ✅ |
| Auth Bypass | ✅ | ✅ | ✅ | ✅ |
| NoSQL Injection | ✅ | ✅ | ✅ | ✅ |

---

## 💡 Use Cases

### For Penetration Testers
- Get AI-powered testing suggestions instantly
- Use proven payload libraries
- Organize testing workflows
- Track progress across engagements
- Share findings with team

### For Bug Bounty Hunters
- Test faster with AI guidance
- Reuse successful payloads
- Organize similar endpoints
- Document testing methodology
- Export findings for reports

### For Security Teams
- Standardize testing approaches
- Share custom templates
- Build team payload libraries
- Collaborate on collections
- Maintain testing consistency

---

## 🔧 Configuration

### AI Provider Settings

**Cost Optimization:**
- Default temperature: 0.3 (focused responses)
- Efficient prompts with truncated request/response
- Recommended model: gpt-4o-mini (~$0.001-0.003 per interaction)

**Data Privacy:**
- Requests are truncated before sending to AI
- Sensitive headers can be filtered
- No data stored by VISTA (only AI provider)

### Data Storage

VISTA stores data locally in `~/.vista/`:
- `templates/` - Custom prompt templates
- `payloads/` - Payload libraries
- `collections/` - Request collections
- `config.json` - AI configuration

---

## 🏗️ Project Structure

```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Extension entry point
└── com/vista/security/
    ├── core/
    │   ├── AIConfigManager.java       # AI configuration
    │   ├── PromptTemplateManager.java # Template management
    │   ├── PayloadLibraryManager.java # Payload management
    │   ├── RequestCollectionManager.java # Collection management
    │   ├── WAFDetector.java           # WAF detection
    │   ├── BypassKnowledgeBase.java   # Bypass techniques
    │   └── ...
    ├── model/
    │   ├── PromptTemplate.java        # Template model
    │   ├── Payload.java               # Payload model
    │   ├── RequestCollection.java     # Collection model
    │   └── ...
    ├── service/
    │   ├── OpenAIService.java         # OpenAI integration
    │   └── AzureAIService.java        # Azure AI integration
    └── ui/
        ├── DashboardPanel.java        # Dashboard tab
        ├── TestingSuggestionsPanel.java # AI Advisor tab
        ├── PromptTemplatePanel.java   # Templates tab
        ├── PayloadLibraryPanel.java   # Payloads tab
        ├── RequestCollectionPanel.java # Collections tab
        └── SettingsPanel.java         # Settings tab
```

---

## 🚀 CI/CD Pipeline

VISTA uses GitHub Actions for automated builds and testing:

- ✅ **Automated Builds** - JAR built on every push
- ✅ **Multi-Platform Testing** - Ubuntu, Windows, macOS
- ✅ **Security Scanning** - CodeQL, Trivy, OWASP, TruffleHog
- ✅ **Code Quality** - Checkstyle, SpotBugs, SonarCloud
- ✅ **Test Coverage** - JaCoCo with Codecov integration
- ✅ **Docker Support** - Multi-stage builds with caching

**Download Latest Build:**
```bash
curl -L https://github.com/Adw0rm-sec/VISTA/raw/main/builds/vista-latest.jar -o vista.jar
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

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
mvn checkstyle:check spotbugs:check
```

---

## 📊 Statistics

- **Total Java Files**: 50+
- **Lines of Code**: 15,000+
- **Built-in Templates**: 20+
- **Built-in Payloads**: 100+
- **Supported Vulnerabilities**: 10+
- **WAF Detection**: 8 major WAFs
- **Bypass Techniques**: 500+
- **Zero External Dependencies**: Pure Java + Burp API

---

## 🔒 Security

VISTA is designed for authorized security testing only. Users are responsible for:
- Obtaining proper authorization before testing
- Complying with applicable laws and regulations
- Using the tool ethically and responsibly

For security issues, please see [SECURITY.md](SECURITY.md).

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **PayloadsAllTheThings** - Bypass techniques and payloads
- **Burp Suite** - Extensibility API
- **OpenAI & Azure** - AI capabilities
- **Security Community** - Testing methodologies and feedback

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Adw0rm-sec/VISTA/issues)
- **Documentation**: [Full Documentation](https://github.com/Adw0rm-sec/VISTA)
- **Discussions**: [GitHub Discussions](https://github.com/Adw0rm-sec/VISTA/discussions)

---

## 🗺️ Roadmap

### v2.9.0 (Planned)
- AI-powered collection analysis
- Bulk import from Proxy/Repeater
- Advanced response comparison
- Search and filter enhancements

### v3.0.0 (Future)
- Smart Findings Manager
- Automated vulnerability detection
- Report generation
- Plugin system

---

<div align="center">

**[⬆ Back to Top](#vista)**

Made with ❤️ for the security community

</div>

<!-- BUILD_INFO --> **Latest Build:** 20260129-070310 | **Version:** 1.0.0-MVP | **Commit:** 53d4e4f
