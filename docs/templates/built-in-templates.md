---
layout: default
title: Built-in Templates
parent: Templates
nav_order: 1
---

# Built-in Expert Templates
{: .no_toc }

12 pre-built templates covering the most common bug bounty vulnerability classes.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Standard Templates

### XSS - DOM Based

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Standard |
| **Tags** | `xss`, `dom`, `javascript` |

Comprehensive DOM XSS testing template. Analyzes JavaScript sources and sinks, identifies DOM manipulation patterns, and suggests DOM-specific payloads.

**Best for:** Single-page applications, JavaScript-heavy pages, client-side routing.

---

### Traffic - Bug Bounty Hunter

| Property | Value |
|:---------|:------|
| **Category** | Analysis |
| **Mode** | Standard |
| **Tags** | `traffic`, `bug-bounty`, `reconnaissance` |

AI-powered traffic analysis template optimized for bug bounty hunting. Used by the Traffic Monitor for passive vulnerability detection.

**Best for:** Passive reconnaissance, broad vulnerability scanning, traffic monitoring.

---

## Expert Templates

### SQL Injection Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `sqli`, `expert`, `database`, `portswigger`, `bug-bounty` |

PortSwigger Academy-grade SQL injection methodology covering all major injection types and database engines.

**Covers:**
- Error-based, Union-based, Blind (boolean + time), Out-of-band SQLi
- MySQL, PostgreSQL, MSSQL, Oracle, SQLite specifics
- WAF bypass techniques (comments, encoding, HPP)
- Second-order injection detection
- Automated sqlmap integration guidance

**Best for:** Login forms, search functionality, API parameters, any database-backed input.

---

### XSS - Reflected Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `xss`, `reflected`, `expert`, `portswigger`, `bug-bounty` |

Advanced reflected XSS testing with context-aware payload generation and WAF bypass.

**Covers:**
- HTML context, attribute context, JavaScript context, URL context injection
- Event handler payloads (50+ handlers)
- Encoding bypass (HTML entities, URL encoding, Unicode, double encoding)
- CSP bypass techniques
- Mutation XSS (mXSS)
- Browser-specific vectors

**Best for:** Search pages, error messages, URL parameters reflected in page, form inputs.

---

### SSRF Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `ssrf`, `expert`, `cloud`, `bug-bounty` |

Server-Side Request Forgery with cloud metadata exploitation and filter bypass.

**Covers:**
- URL parameter identification (`url=`, `redirect=`, `src=`, `link=`, etc.)
- Cloud metadata endpoints (AWS IMDSv1/v2, GCP, Azure, DigitalOcean)
- IP obfuscation (decimal, hex, octal, IPv6, DNS rebinding)
- Blind SSRF detection via OOB callbacks
- Protocol smuggling (gopher://, file://, dict://)
- Redirect chain exploitation

**Best for:** URL fetchers, webhooks, PDF generators, image processors, import/export features.

---

### IDOR / BOLA Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `idor`, `bola`, `authorization`, `expert`, `bug-bounty`, `api` |

Insecure Direct Object Reference and Broken Object Level Authorization testing.

**Covers:**
- Sequential ID, UUID, Base64-encoded, and hashed ID manipulation
- Horizontal privilege escalation (accessing other users' data)
- Vertical privilege escalation (admin access)
- Nested resource testing (`/users/{id}/orders/{orderId}`)
- Mass enumeration risk assessment
- Write-based vs read-based IDOR impact analysis

**Best for:** REST APIs, user profiles, order systems, document access, any endpoint with resource IDs.

{: .tip }
> IDOR is the #1 most reported bug bounty finding. This template helps systematically identify every possible IDOR vector in an API.

---

### SSTI Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `ssti`, `expert`, `rce`, `bug-bounty`, `portswigger` |

Server-Side Template Injection with engine fingerprinting and RCE exploitation.

**Covers:**
- PortSwigger decision tree for engine fingerprinting
- Engine-specific exploitation: Jinja2, Twig, Freemarker, Velocity, ERB, Smarty, Thymeleaf, Pebble, Mako
- Sandbox escape techniques
- Filter bypass (encoding, concatenation, alternative functions)
- File read → command execution → reverse shell escalation path

**Best for:** Dynamic content generation, email templates, custom page builders, any user input rendered through a template engine.

---

### Auth Bypass Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `auth`, `bypass`, `expert`, `privilege-escalation`, `bug-bounty` |

Authentication and authorization bypass with comprehensive testing methodology.

**Covers:**
- Login bypass (SQLi, default credentials, response manipulation)
- Password reset flaws (token prediction, host header poisoning)
- 2FA bypass (response manipulation, brute-force, null code)
- OAuth misconfiguration (redirect_uri, state, PKCE)
- HTTP method tampering (GET vs POST)
- Path normalization bypass (`/admin` → `/Admin`, `/../admin`)
- Header tricks (X-Original-URL, X-Forwarded-For)
- Mass assignment (`role=user` → `role=admin`)

**Best for:** Login pages, admin panels, API authentication, password reset flows, OAuth implementations.

---

### File Upload Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `file-upload`, `expert`, `rce`, `web-shell`, `bug-bounty` |

File upload vulnerability testing with extension bypass and RCE paths.

**Covers:**
- Extension bypass (double extension, null byte, case tricks, alternate extensions)
- Content-Type manipulation
- Magic byte injection (GIF89a + PHP, PNG + PHP)
- Path traversal via filename (`../../../var/www/shell.php`)
- Web shell upload for PHP, ASP, JSP environments
- `.htaccess` upload for Apache
- ImageMagick/Ghostscript exploitation

**Best for:** Profile picture uploads, document uploads, import features, any file upload functionality.

---

### Race Condition Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `race-condition`, `expert`, `toctou`, `business-logic`, `bug-bounty` |

Race condition and TOCTOU testing for limit bypass and business logic abuse.

**Covers:**
- HTTP/2 single-packet attack (PortSwigger technique)
- Coupon/discount code double-redemption
- Financial double-spend attacks
- Vote/like manipulation
- Account registration race
- Ready-to-use Turbo Intruder Python scripts
- Verification methodology for confirming exploitation

**Best for:** E-commerce checkout, coupon systems, voting/rating, money transfers, any one-time operation.

{: .tip }
> This template includes a ready-to-use **Turbo Intruder script** — just copy and paste into Burp's Turbo Intruder for immediate race condition testing.

---

### JWT / OAuth Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `jwt`, `oauth`, `expert`, `authentication`, `bug-bounty`, `portswigger` |

JWT token manipulation and OAuth/OIDC flow exploitation.

**Covers:**
- Algorithm confusion (RS256 → HS256, RS256 → none)
- Key injection (jwk, jku, kid header attacks)
- Signature bypass (removal, weak keys, default secrets)
- Claim manipulation (sub, role, admin, exp)
- JWT cracking with hashcat
- OAuth redirect_uri manipulation
- State parameter CSRF
- Authorization code replay/theft
- PKCE bypass

**Best for:** Any application using JWT tokens or OAuth 2.0/OIDC for authentication.

---

### API Security Expert

| Property | Value |
|:---------|:------|
| **Category** | Exploitation |
| **Mode** | Expert |
| **Tags** | `api`, `expert`, `owasp`, `rest`, `graphql`, `bug-bounty` |

Comprehensive API security testing based on OWASP API Security Top 10 (2023).

**Covers:**
- All 10 OWASP API Security categories
- API enumeration (version discovery, Swagger/OpenAPI, GraphQL introspection)
- Mass assignment testing
- Rate limiting bypass
- CORS misconfiguration
- GraphQL-specific attacks (introspection, batching, nested queries)
- API versioning exploitation (deprecated endpoints)

**Best for:** REST APIs, GraphQL APIs, microservices, any API-first application.

---

## Using a Template

1. Go to the **Prompt Templates** tab in VISTA
2. Browse or search for the template you need
3. Click the template to preview its contents
4. Click **"Use Template"** to activate it
5. Send a request to the AI Advisor — the template shapes the analysis
6. The active template is shown in the AI Advisor UI

{: .note }
> You can switch templates at any time. The new template applies to the next AI interaction.
