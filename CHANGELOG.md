# Changelog

All notable changes to VISTA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-MVP] - 2024-12-16

### Added
- **AI Integration**
  - Azure OpenAI support with configurable endpoint, deployment, and API version
  - OpenAI support with model selection and custom base URL
  - Temperature control for AI response creativity
  - Connection testing functionality

- **Security Analysis**
  - Session cookie detection (JSESSIONID, PHPSESSID, ASP.NET_SessionId, JWT, etc.)
  - Authentication header detection (Bearer, Basic, API keys)
  - Security flag analysis (Secure, HttpOnly, SameSite)
  - Parameter reflection detection with context analysis
  - XSS risk level assessment (Critical/High/Medium/Low)
  - 11 vulnerability presets (SQLi, XSS, CSRF, IDOR, SSRF, etc.)

- **Request Management**
  - Multi-request list with summaries
  - Request grouping with custom names and 10 color options
  - Color-coded request list by group
  - Send to Repeater/Intruder integration
  - Per-request analysis history

- **Payload Library**
  - 70+ built-in security payloads
  - Categories: XSS, SQLi, SSRF, Path Traversal, Command Injection
  - Custom payload support

- **Productivity Features**
  - Quick action buttons for common tasks
  - Keyboard shortcuts (Ctrl+Enter, Delete, Escape)
  - Findings management with severity levels
  - Markdown report export
  - Custom template support

- **UI/UX**
  - Tabbed interface (Request, Response, Parameters, Session, Reflections)
  - Collapsible settings panel
  - Status indicators and progress bar
  - Chat-style AI interaction

### Technical
- Refactored package structure to `com.vista.security`
- Industry-standard naming conventions
- Configuration persistence in `~/.vista-config.json`
- GitHub Actions CI/CD pipeline

## [0.2.1] - Previous Release

- Initial public release
- Basic AI integration
- Request/Response viewing
