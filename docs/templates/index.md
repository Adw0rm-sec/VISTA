---
layout: default
title: Templates
nav_order: 4
has_children: true
---

# Prompt Templates
{: .no_toc }

12 expert templates + custom template creation for focused vulnerability testing.
{: .fs-6 .fw-300 }

---

## Overview

Templates are structured AI prompts that shape how VISTA analyzes HTTP requests. Instead of generic analysis, templates provide deep, methodology-driven testing guidance for specific vulnerability classes.

### Why Use Templates?

| Without Template | With Expert Template |
|:----------------|:--------------------|
| "This parameter might be vulnerable to XSS" | "Based on reflection analysis, use these 5 payloads targeting the unquoted attribute context. If Cloudflare WAF is detected, apply double-encoding bypass..." |
| Generic vulnerability scan | PortSwigger-grade methodology with step-by-step exploitation |
| Basic payload suggestions | WAF-aware, context-specific payloads with bypass techniques |

---

## Template Types

### Standard Mode
Basic templates with simple system/user prompts. Good for general analysis.

### Expert Mode
Advanced templates with comprehensive methodology, exploitation techniques, and structured output requirements. **Recommended for bug bounty hunting.**

---

## Quick Reference

| Template | Vulnerability | Mode |
|:---------|:-------------|:-----|
| [XSS - DOM Based]({% link templates/built-in-templates.md %}#xss---dom-based) | DOM XSS | Standard |
| [Traffic - Bug Bounty]({% link templates/built-in-templates.md %}#traffic---bug-bounty-hunter) | Traffic Analysis | Standard |
| [SQL Injection Expert]({% link templates/built-in-templates.md %}#sql-injection-expert) | SQLi | Expert |
| [XSS - Reflected Expert]({% link templates/built-in-templates.md %}#xss---reflected-expert) | Reflected XSS | Expert |
| [SSRF Expert]({% link templates/built-in-templates.md %}#ssrf-expert) | SSRF | Expert |
| [IDOR / BOLA Expert]({% link templates/built-in-templates.md %}#idor--bola-expert) | IDOR/BOLA | Expert |
| [SSTI Expert]({% link templates/built-in-templates.md %}#ssti-expert) | SSTI | Expert |
| [Auth Bypass Expert]({% link templates/built-in-templates.md %}#auth-bypass-expert) | Auth Bypass | Expert |
| [File Upload Expert]({% link templates/built-in-templates.md %}#file-upload-expert) | File Upload | Expert |
| [Race Condition Expert]({% link templates/built-in-templates.md %}#race-condition-expert) | Race Conditions | Expert |
| [JWT / OAuth Expert]({% link templates/built-in-templates.md %}#jwt--oauth-expert) | JWT/OAuth | Expert |
| [API Security Expert]({% link templates/built-in-templates.md %}#api-security-expert) | API Top 10 | Expert |

→ See [Built-in Templates]({% link templates/built-in-templates.md %}) for detailed descriptions of each template.
→ See [Custom Templates]({% link templates/custom-templates.md %}) to create your own.
