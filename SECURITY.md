# Security Policy

## Supported Versions
The latest released version receives security-related attention. Older versions may not be patched.

## Reporting a Vulnerability
Please open a private (security) advisory or email the maintainer rather than filing a public issue for:
- Potential RCE / injection in extension code
- Sensitive data leakage through logs or AI payload construction
- Dependency-based CVEs (if dependencies are later added)

Provide:
- Description & impact
- Steps to reproduce
- Suggested remediation (if any)

## Handling Sensitive Data
The extension attempts to strip Authorization/Cookie headers before sending data to AI if the option is enabled. Users must verify compliance with their testing authorization and data policies.
