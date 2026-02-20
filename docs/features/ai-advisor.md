---
layout: default
title: AI Advisor
parent: Features
nav_order: 2
---

# AI Advisor
{: .no_toc }

Interactive AI-powered testing assistant with conversation history.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Overview

The AI Advisor is your interactive security testing companion. Send any HTTP request to the AI Advisor, and it provides targeted vulnerability analysis, testing payloads, and step-by-step exploitation guidance. It maintains full conversation history so you can ask follow-up questions.

---

## How to Use

### Sending a Request

**From anywhere in Burp Suite:**

1. Right-click any HTTP request (Proxy, Target, Repeater, etc.)
2. Select **"💡 Send to VISTA AI Advisor"**
3. VISTA switches to the AI Advisor tab
4. AI automatically analyzes the request and provides:
   - Vulnerability assessment
   - Testing payloads
   - Step-by-step methodology
   - Risk rating

### Asking Follow-Up Questions

After the initial analysis, type follow-up questions in the chat input:

- *"Can you provide more XSS payloads for this parameter?"*
- *"How would I bypass the WAF for this endpoint?"*
- *"What about blind SQL injection?"*
- *"Show me the Turbo Intruder script for this race condition"*

The AI remembers the full conversation context and the attached request.

### Attaching Additional Requests

For multi-request analysis (e.g., testing a workflow):

1. Right-click another request in Burp
2. Select **"📎 Attach to Interactive Assistant"**
3. The request is added to the current conversation context
4. AI can now analyze the relationship between multiple requests

---

## Conversation Flow

```
┌──────────────────────────────────────────────┐
│  1. User sends request via right-click       │
│     → "💡 Send to VISTA AI Advisor"          │
└──────────────────┬───────────────────────────┘
                   │
┌──────────────────▼───────────────────────────┐
│  2. VISTA builds analysis context:           │
│     • HTTP request/response data             │
│     • Parameter analysis                     │
│     • WAF detection results                  │
│     • Selected template (if any)             │
│     • Variable context (35 variables)        │
└──────────────────┬───────────────────────────┘
                   │
┌──────────────────▼───────────────────────────┐
│  3. AI Provider processes prompt             │
│     (OpenAI / Azure / OpenRouter)            │
└──────────────────┬───────────────────────────┘
                   │
┌──────────────────▼───────────────────────────┐
│  4. Response displayed in chat UI            │
│     • Markdown rendering                     │
│     • Code blocks with copy button           │
│     • Structured analysis                    │
└──────────────────┬───────────────────────────┘
                   │
┌──────────────────▼───────────────────────────┐
│  5. User asks follow-up (conversation mode)  │
│     • Full history maintained                │
│     • Context-aware responses                │
│     • Attach more requests if needed         │
└──────────────────────────────────────────────┘
```

---

## Using Templates with AI Advisor

Templates dramatically improve AI response quality by providing structured, expert-level prompts:

1. Go to **Prompt Templates** tab
2. Select a template (e.g., "SSRF (Expert)")
3. Click **"Use Template"**
4. Now send a request to AI Advisor — the template shapes the analysis
5. AI provides deep, methodology-driven guidance specific to that vulnerability class

{: .tip }
> Always use an expert template when you know what vulnerability class you're testing. The difference in response quality is significant.

---

## Session Management

- **Conversations persist** across interactions within the same session
- **New request** starts a fresh session (previous session is properly closed)
- **Sessions are saved** to `~/.vista/sessions/` for persistence across Burp restarts
- **Thread-safe** — conversation history is synchronized for safe concurrent access

---

## Context Variables

The AI Advisor automatically extracts and injects 35 context variables from the HTTP request:

| Variable | Description |
|:---------|:------------|
| `{{REQUEST}}` | Full raw HTTP request |
| `{{RESPONSE}}` | Full raw HTTP response |
| `{{URL}}` | Request URL |
| `{{METHOD}}` | HTTP method (GET, POST, etc.) |
| `{{PARAMETERS_LIST}}` | All parameters with values |
| `{{HEADERS}}` | Request headers |
| `{{BODY}}` | Request body |
| `{{ENDPOINT_TYPE}}` | Detected endpoint type (API, form, etc.) |
| `{{WAF_DETECTION}}` | Detected WAF information |
| `{{RISK_SCORE}}` | Calculated risk score |
| `{{DEEP_REQUEST_ANALYSIS}}` | Deep analysis of request patterns |
| `{{DEEP_RESPONSE_ANALYSIS}}` | Deep analysis of response patterns |
| `{{SENSITIVE_DATA}}` | Detected sensitive data in traffic |
| `{{ERROR_MESSAGES}}` | Error messages found in response |
| `{{USER_QUERY}}` | User's question text |

These variables are automatically populated and used by templates to provide rich, context-aware analysis.

---

## Tips for Best Results

{: .tip }
> **Be specific** — Instead of "find vulnerabilities," ask "test the `search` parameter for reflected XSS with WAF bypass."

{: .tip }
> **Use follow-ups** — After initial analysis, drill down: "show me payloads for the second vulnerability you identified."

{: .tip }
> **Attach related requests** — When testing multi-step flows (login → token → API call), attach all related requests for holistic analysis.
