# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres loosely to Semantic Versioning.

## [0.2.0] - 2025-09-28
### Added
- Rebrand to VISTA (Vulnerability Insight & Strategic Test Assistant).
- OpenAI provider alongside Azure AI.
- Per-request chat isolation & response binding.
- Styled chat with colored speaker tags (VISTA, You, etc.).
- Template loading with size budget & truncation.
- Persistence migrated to `.vista.json` (auto-migrate from `.burpraj.json`).
- Preset vulnerability focus areas (CSRF, IDOR, SQLi, SSRF, XSS).

### Changed
- Artifact renamed to `vista` with version `0.2.0`.
- Removed unused presets (Authentication/JWT, Business Logic, Race Conditions, RCE).
- Simplified persistence: only global chat persisted.

### Removed
- Test suite (moved out for production packaging).

## [0.1.0] - Initial
- Original BurpRaj MVP (Azure only, basic chat, request list, header stripping).
