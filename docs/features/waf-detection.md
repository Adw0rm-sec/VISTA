---
layout: default
title: WAF Detection
parent: Features
nav_order: 4
---

# WAF Detection & Bypass
{: .no_toc }

Automatically detect 8 major WAFs with 250+ bypass techniques.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Overview

VISTA automatically detects Web Application Firewalls (WAFs) from HTTP response headers and body patterns, then provides WAF-specific bypass techniques. This information is injected into AI analysis via the `{{WAF_DETECTION}}` variable, enabling the AI to suggest targeted bypass payloads.

---

## Supported WAFs

| WAF | Detection Method | Bypass Techniques |
|:----|:----------------|:-----------------|
| **Cloudflare** | `cf-ray` header, `__cfduid` cookie | 50+ |
| **AWS WAF** | `x-amzn-requestid` header, AWS error patterns | 30+ |
| **ModSecurity** | `mod_security` header, OWASP CRS patterns | 40+ |
| **Akamai** | `akamai` headers, ghost patterns | 30+ |
| **Imperva (Incapsula)** | `incap_ses` cookie, `visid_incap` | 25+ |
| **Wordfence** | Wordfence block page patterns | 25+ |
| **Sucuri** | `x-sucuri-id` header, Sucuri block page | 20+ |
| **F5 BIG-IP** | `BigIP` cookie, F5 error patterns | 30+ |

---

## How Detection Works

```
HTTP Response arrives
        │
        ▼
┌──────────────────┐
│  Header Analysis │ ← Check for WAF-specific headers
│  Cookie Analysis │ ← Check for WAF cookies
│  Body Analysis   │ ← Check for WAF block pages
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  WAF Identified  │ → Cloudflare, AWS WAF, etc.
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Bypass KB       │ ← Load WAF-specific bypass techniques
│  250+ techniques │    from BypassKnowledgeBase
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  AI Context      │ ← Inject WAF info + bypass suggestions
│  {{WAF_DETECTION}}│    into AI prompt
└──────────────────┘
```

1. **Response Analysis** — VISTA examines HTTP headers, cookies, and response bodies for WAF signatures
2. **WAF Identification** — Matches patterns against known WAF fingerprints
3. **Bypass Loading** — Loads relevant bypass techniques from the knowledge base
4. **AI Integration** — WAF info is automatically included in AI analysis

---

## Bypass Techniques

### Example: Cloudflare Bypass Techniques

| Category | Example |
|:---------|:--------|
| **Encoding** | Double URL encoding, Unicode normalization |
| **Case manipulation** | `<ScRiPt>`, mixed case keywords |
| **Comment injection** | `/**/UN/**/ION/**/SE/**/LECT` |
| **HTTP smuggling** | Transfer-Encoding chunked abuse |
| **IP rotation** | Origin IP discovery, CDN bypass |

### Example: ModSecurity CRS Bypass

| Category | Example |
|:---------|:--------|
| **Rule evasion** | Payload splitting across parameters |
| **Paranoia level** | Techniques for PL1-PL4 |
| **Content-Type** | `application/json` vs `application/x-www-form-urlencoded` |
| **Unicode** | UTF-8 overlong encoding |

---

## Using WAF Information

### In AI Advisor

When WAF is detected, the AI Advisor automatically:

1. Reports the detected WAF in its analysis
2. Suggests WAF-specific bypass payloads
3. Adjusts testing methodology to account for WAF rules
4. Recommends encoding and obfuscation techniques

### In Templates

Expert templates use the `{{WAF_DETECTION}}` variable:

```
WAF: {{WAF_DETECTION}}

If WAF is detected, provide bypass-specific payloads...
```

### In Payload Library

WAF detection influences payload suggestions — when a Cloudflare WAF is detected, VISTA prioritizes Cloudflare-specific bypass payloads.

---

## Bypass Knowledge Base

VISTA's bypass techniques are sourced from:

- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** — WAF bypass sections
- **Real-world bypass research** — Techniques from disclosed bypasses
- **PortSwigger Research** — Advanced bypass methodologies

{: .note }
> Bypass techniques are continuously matched against detected vulnerability types. For example, if testing for XSS behind Cloudflare, only XSS-relevant Cloudflare bypasses are suggested.
