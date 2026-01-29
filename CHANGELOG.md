# Changelog

All notable changes to VISTA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
