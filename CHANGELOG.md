# Changelog

All notable changes to VISTA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.10.26] - 2026-02-19

### Added
- **Real-Time Activity Log** — New "📋 Activity Log" sub-tab under Traffic Monitor
  - Live-scrolling table showing every request's analysis lifecycle (Captured → Queued → Analyzing → Completed)
  - Color-coded log levels: CAPTURED (blue), QUEUED (yellow), ANALYZING (cyan), COMPLETED (green), FINDING (orange), SKIPPED (gray), ERROR (red)
  - Summary bar with live counters for total events, findings, errors, and analysis count
  - Filter dropdown (All Events, Findings Only, Errors Only, Analysis Only)
  - Clear log button; max 5,000 entries with automatic oldest-first trimming
  - Columns: Time, Level, #, Method, URL, Status, Result, Details, Duration

- **Burp-Style HTTP Request/Response Viewer** — Professional syntax highlighting in Traffic Monitor
  - **Request coloring**: HTTP method (blue bold), URL path (dark bold), query parameters (orange keys, green values), HTTP version (gray)
  - **Header coloring**: Purple bold header names, gray colon separator, dark values
  - **Status line coloring**: Green (2xx), yellow (3xx), orange (4xx), red (5xx) status codes
  - **JSON pretty-formatting**: Auto-detected JSON bodies rendered with 2-space indentation and syntax coloring (purple keys, green strings, blue numbers, orange booleans)
  - **HTML/XML pretty-formatting**: Auto-detected markup bodies with proper indentation and tag coloring (blue tags, orange attribute names, green attribute values)

### Changed
- Traffic Monitor now has 3 tabs: Traffic, Findings, Activity Log
- HttpMessageViewer completely rewritten for professional HTTP display

## [2.10.25] - 2026-02-19

### Fixed
- **OpenRouter Free Models Updated** — Replaced 5 rotated-out free models with current active ones
- **parseResponse() Bug Fix** — Fixed critical bug where API errors were returned as strings instead of throwing exceptions
- **HTTP Error Handling** — Added specific handling for HTTP 400, 401, 403, 429, 500, 502, 503 errors with descriptive messages
- **Timeout Increased** — Raised API timeout from 60s to 120s for reasoning models (DeepSeek R1, Qwen QwQ)

## [2.10.24] - 2026-02-19

### Added
- **Data Backup & Restore** — New UI in Settings to export/import all VISTA data to any folder
  - Timestamped backup folders (`vista-backup-YYYYMMDD-HHmmss/`)
  - Exports traffic, findings, templates, payloads, sessions, and AI config
  - Import with validation and overwrite confirmation
- **Data Persistence** — All data now survives Burp restarts
  - Auto-save every 60 seconds with dirty-flag optimization
  - JVM shutdown hook for unexpected termination
  - Atomic file writes (write-to-tmp then rename) to prevent corruption
  - Traffic, exploit findings, and traffic findings persisted to `~/.vista/data/`
- **Centralized Theme System** — `VistaTheme` utility class for consistent UI styling

### Changed
- **Professional UI Overhaul** — Complete visual redesign across all panels
- **Settings Button Flow** — Test Connection must pass before Save Configuration is enabled
- **Traffic Table** — Double-click `#` header toggles sort order; double-click `#` cell opens color picker for row highlighting
- **Test Connection Error Handling** — Fixed HTTP 401/error responses being reported as "Connection successful!"
- **Template/Payload Persistence** — Fixed JSON parser breaking on escaped quotes in payloads and templates

### Removed
- **11 unused source files** removed for production cleanup:
  - `BypassEngine.java`, `BypassAssistantPanel.java`, `BypassAttempt.java`, `BypassResult.java`
  - `DataDecoder.java`, `ReportGenerator.java`, `InteractiveExploitAdvisor.java`
  - `TrafficMonitorPanelEnhanced.java`, `MCPDiagnostics.java`, `RequestGroup.java`
  - `IntelligentTrafficAnalyzer.java.bak`
- **2 dead methods** from `PromptTemplateManager` (`cleanupAllOldTemplates`, `cleanupBuiltInDuplicates`)
- **~70 verbose debug print statements** cleaned across 5+ files (16 essential lifecycle logs retained)

## [2.8.1] - 2026-01-29

### Fixed
- **OpenAI API Key Field Not Visible** - Fixed issue where OpenAI API key field was not showing when OpenAI provider was selected
- **Separate API Keys Per Provider** - Each AI provider (OpenAI, Azure AI, OpenRouter) now has its own dedicated API key field
- **API Key Persistence** - API keys are now stored separately per provider and persist correctly when switching between providers
- **Backward Compatibility** - Added migration support for legacy config files with single API key field
- **OpenRouter Support in Bypass Assistant** - Added OpenRouter provider support to Bypass Assistant panel

### Changed
- Updated AIConfigManager to store separate API keys for each provider
- Updated SettingsPanel to use provider-specific API key fields
- Updated all AI engines to use provider-specific API keys
- Removed deprecated API warnings

## [2.8.0] - 2026-01-29

### Added
- **Request Collection Engine** - Organize and track HTTP requests
  - Create named collections with descriptions
  - Add requests via context menu
  - Mark requests as tested/success
  - Add notes to individual requests
  - Side-by-side request comparison
  - Export/Import collections as JSON
  - Pattern detection for similar requests
  - Statistics tracking

- **Custom AI Prompt Templates** (v2.6.0)
  - 20+ built-in templates for common testing scenarios
  - 24 dynamic variables ({{URL}}, {{METHOD}}, {{HEADERS}}, etc.)
  - Create custom templates
  - Search and filter functionality
  - Import/Export for team sharing
  - Usage tracking

- **Payload Library Manager** (v2.7.0)
  - 100+ built-in payloads across 8 vulnerability categories
  - Create custom payload libraries
  - Bulk import with auto-detection
  - AI-powered payload suggestions
  - Success rate tracking
  - Context-aware filtering
  - Export/Import for sharing

- **Automated Build Pipeline**
  - GitHub Actions CI/CD
  - Automatic JAR builds on push
  - Multi-platform testing (Ubuntu, Windows, macOS)
  - Code quality checks
  - Docker support

### Changed
- Updated UI with 6 tabs (Dashboard, AI Advisor, Templates, Payloads, Collections, Settings)
- Improved AI response handling
- Enhanced request/response parsing
- Optimized JAR size (~370KB)

### Fixed
- Various bug fixes and performance improvements
- Improved error handling
- Enhanced stability

## [2.0.0] - 2025

### Added
- Unified AI Advisor with multi-request support
- WAF Detection (8 major WAFs)
- Bypass Knowledge Base (500+ techniques)
- Systematic Testing Engine
- Headless Browser Verification
- Reflection Analysis
- Repeater Integration
- Deep Request/Response Analysis

### Changed
- Complete UI redesign
- Improved AI integration
- Enhanced testing methodologies

## [1.0.0] - 2024

### Added
- Initial release
- Basic AI-powered testing assistance
- OpenAI and Azure AI support
- Findings management
- Report generation
- Burp Suite integration

---

## Version Numbering

VISTA follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backward compatible manner
- **PATCH** version for backward compatible bug fixes

## Links

- [Releases](https://github.com/Adw0rm-sec/VISTA/releases)
- [Issues](https://github.com/Adw0rm-sec/VISTA/issues)
- [Contributing](CONTRIBUTING.md)
