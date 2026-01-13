<div align="center">

# VISTA

### Vulnerability Insight & Strategic Test Assistant

[![CI Build](https://github.com/rajrathod-code/VISTA/actions/workflows/build.yml/badge.svg)](https://github.com/rajrathod-code/VISTA/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/rajrathod-code/VISTA?include_prereleases)](https://github.com/rajrathod-code/VISTA/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange)](https://openjdk.org/)

**AI-powered Burp Suite extension for intelligent security testing**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Configuration](#configuration) • [Contributing](#contributing) 

</div>

---

## Overview

VISTA is a Burp Suite extension that integrates AI capabilities to accelerate penetration testing workflows. It provides contextual security recommendations, automated vulnerability detection, and intelligent payload suggestions tailored to each HTTP request.

## Features

### Core Capabilities
- **AI-Assisted Analysis** - Integrates with Azure OpenAI and OpenAI for intelligent security recommendations
- **Request Management** - Organize and analyze multiple requests with per-request chat history
- **Vulnerability Presets** - 11 built-in vulnerability templates (SQLi, XSS, CSRF, IDOR, SSRF, etc.)

### Security Analysis
- **Session Detection** - Auto-detect session cookies, JWT tokens, and authentication headers
- **Reflection Analysis** - Find parameter reflections with XSS risk assessment
- **Parameter Extraction** - Detailed parameter analysis with security test suggestions

### Productivity
- **Request Grouping** - Organize requests with custom names and color coding
- **Payload Library** - 70+ built-in security payloads across multiple categories
- **Findings Management** - Track vulnerabilities with severity levels per request
- **Report Export** - Generate Markdown reports with findings and analysis

## Installation

### Prerequisites
- Java 17 or higher
- Burp Suite Professional or Community Edition
- Maven 3.6+ (for building from source)

### Download Release
1. Download the latest JAR from [Releases](https://github.com/rajrathod-code/VISTA/releases)
2. In Burp Suite: **Extensions → Add → Java → Select JAR**

### Build from Source
```bash
git clone https://github.com/rajrathod-code/VISTA.git
cd VISTA
mvn package -DskipTests
```
The JAR will be in `target/vista-1.0.0-MVP.jar`

## Usage

### Quick Start
1. Load the extension in Burp Suite
2. Browse to target application through Burp Proxy
3. Right-click any request → **Send to VISTA**
4. Configure AI provider in Settings (optional)
5. Use quick actions or ask questions about the request

### Quick Actions
| Action | Description |
|--------|-------------|
| 🔍 Auto-Analyze | Comprehensive security analysis |
| 📋 Extract Parameters | Show all parameters with suggestions |
| 🔐 Analyze Session | Detect session cookies and auth headers |
| 🔄 Find Reflections | Detect parameter reflections in response |
| 📄 Export Report | Generate Markdown report |
| ⚠️ Add Finding | Record security finding |

### Keyboard Shortcuts
- `Ctrl+Enter` - Send question to AI
- `Enter` (empty field) - Auto-suggest tests
- `Delete` - Remove selected request
- `Escape` - Cancel processing
- `Double-click` - Send to Repeater

## Configuration

### AI Providers

#### Azure OpenAI
```
Endpoint: https://your-resource.openai.azure.com
Deployment: gpt-4o-mini
API Version: 2024-12-01-preview
API Key: <your-key>
```

#### OpenAI
```
Model: gpt-4o-mini
Base URL: https://api.openai.com/v1
API Key: <your-key>
```

### Settings
- **Temperature** - Control AI response creativity (0.0-1.0)
- **Strip Headers** - Remove sensitive headers before AI analysis
- **Max Characters** - Limit request/response size sent to AI

### Configuration File
Settings are persisted in `~/.vista-config.json`

## Project Structure

```
src/main/java/
├── burp/                           # Burp Suite API interfaces
│   └── BurpExtender.java           # Extension entry point
└── com/vista/security/
    ├── core/                       # Core utilities
    │   ├── HttpMessageParser.java
    │   ├── ParameterAnalyzer.java
    │   ├── PayloadLibrary.java
    │   ├── ReflectionAnalyzer.java
    │   ├── ReportGenerator.java
    │   ├── SessionAnalyzer.java
    │   └── VulnerabilityTemplates.java
    ├── model/                      # Data models
    │   └── RequestGroup.java
    ├── service/                    # AI integrations
    │   ├── AIService.java
    │   ├── AzureAIService.java
    │   └── OpenAIService.java
    └── ui/                         # User interface
        └── MainPanel.java
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

Please report security vulnerabilities responsibly. See [SECURITY.md](SECURITY.md) for details.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for misuse of this tool.

---

<div align="center">

**[⬆ Back to Top](#vista)**

</div>
