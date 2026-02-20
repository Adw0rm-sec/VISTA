---
layout: default
title: Scope Management
parent: Configuration
nav_order: 2
---

# Scope Management
{: .no_toc }

Define target scope to focus AI analysis on relevant traffic.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Why Scope Matters

Without scope management, VISTA would analyze **every** HTTP request passing through Burp's proxy — including CDN requests, tracking pixels, third-party scripts, and other irrelevant traffic. This wastes AI tokens and clutters findings.

Scope ensures VISTA only analyzes traffic from your **target application**.

---

## Configuring Scope

### Adding Scope

1. Go to **Traffic Monitor** tab → click **"Scope"**
2. Or go to **Settings** tab → Scope section
3. Add target domains:

```
example.com
api.example.com
*.example.com
```

### Scope Patterns

| Pattern | Matches |
|:--------|:--------|
| `example.com` | Exact domain match |
| `*.example.com` | All subdomains |
| `api.example.com` | Specific subdomain |

### Removing Scope

Click the ✕ next to any scope entry to remove it.

---

## How Scope Affects Features

| Feature | With Scope | Without Scope |
|:--------|:-----------|:-------------|
| **Traffic Monitor** | Only analyzes in-scope traffic | Analyzes ALL traffic (expensive) |
| **AI Advisor** | No restriction (always works) | No restriction |
| **Findings** | Only in-scope findings | All findings |
| **Token Usage** | Efficient | Wasteful |

---

## Best Practices

{: .tip }
> **Always set scope before starting Traffic Monitor.** This prevents unnecessary AI token consumption.

{: .tip }
> **Include API subdomains.** Many applications use separate API domains (api.example.com) — include these in scope.

{: .tip }
> **Use wildcards sparingly.** `*.example.com` catches everything, but `app.example.com` + `api.example.com` is more precise.
