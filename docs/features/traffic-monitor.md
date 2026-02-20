---
layout: default
title: Traffic Monitor
parent: Features
nav_order: 1
---

# Traffic Monitor
{: .no_toc }

Real-time AI-powered HTTP traffic analysis — VISTA's flagship feature.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Overview

The Traffic Monitor passively intercepts HTTP traffic flowing through Burp Suite's proxy and sends it to your configured AI provider for vulnerability analysis. It runs in the background while you browse the target application, automatically flagging security issues.

---

## How It Works

```
Browser → Burp Proxy → VISTA Traffic Monitor
                              │
                    ┌─────────▼──────────┐
                    │   Scope Filter     │
                    │   (in-scope only)  │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Traffic Buffer    │
                    │  (batch requests)  │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │   AI Analysis      │
                    │   (vulnerability   │
                    │    detection)      │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Findings Tree    │
                    │   (categorized)    │
                    └────────────────────┘
```

1. **Capture** — All HTTP traffic through Burp's proxy is intercepted
2. **Filter** — Only in-scope traffic is forwarded (saves AI tokens)
3. **Buffer** — Requests are batched for efficient analysis
4. **Analyze** — AI evaluates each request/response for vulnerabilities
5. **Report** — Findings appear in a hierarchical tree with severity ratings

---

## Using Traffic Monitor

### Starting Monitoring

1. Go to the **Traffic Monitor** tab
2. Click **"▶ Start Monitoring"**
3. The status indicator changes to show monitoring is active
4. Browse your target application through Burp's proxy

### Configuring Scope

Only in-scope traffic is analyzed (prevents wasting AI tokens on irrelevant requests):

1. In Traffic Monitor, click **"Scope"** or go to Settings
2. Add target domains: `example.com`, `api.example.com`
3. VISTA only sends matching traffic to the AI

### Viewing Findings

Findings appear in a **hierarchical tree view**:

```
📂 Cross-Site Scripting (3)
  ├── 🔴 Reflected XSS in search parameter — /search?q=...
  ├── 🟡 Potential DOM XSS via hash — /app#callback=...
  └── 🟡 Unencoded output in response — /profile
📂 SQL Injection (1)
  └── 🔴 Error-based SQLi in login — /api/login
📂 Security Misconfiguration (2)
  ├── 🟢 Missing X-Frame-Options — /dashboard
  └── 🟢 Verbose error messages — /api/users
```

- **Tab badge** shows `Findings (6)` so you know when new issues are detected
- Click any finding to see full details, affected request/response, and remediation advice
- Findings are color-coded by severity (🔴 High, 🟡 Medium, 🟢 Low)

### Managing Findings

- **Export** — Save findings for reporting
- **Clear** — Remove all findings to start fresh
- **Auto-save** — Findings persist across Burp restarts

---

## Customizing Analysis

### Analysis Template

The AI prompt used for traffic analysis can be customized:

1. Go to **Prompt Templates** tab
2. Find the "Traffic - Bug Bounty Hunter" template
3. Click **"Edit"** to modify the analysis prompt
4. Or create a custom template and set it as the traffic analysis template

### Token Optimization

VISTA minimizes AI costs by:

- **Scope filtering** — Only analyze in-scope traffic
- **Request truncation** — Large requests/responses are trimmed before sending to AI
- **Batching** — Multiple requests are analyzed efficiently
- **Deduplication** — Similar requests aren't analyzed repeatedly

---

## Tips

{: .tip }
> Set a tight scope before starting monitoring. Analyzing every request wastes tokens and clutters findings.

{: .tip }
> Use the Traffic Monitor for reconnaissance — let it run while you manually explore the application, then review findings for deeper testing with the AI Advisor.
