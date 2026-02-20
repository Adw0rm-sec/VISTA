---
layout: default
title: Custom Templates
parent: Templates
nav_order: 2
---

# Custom Templates
{: .no_toc }

Create your own AI prompt templates for specialized testing scenarios.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Overview

While VISTA includes 12 expert built-in templates, you can create custom templates for:

- **Specialized vulnerability types** not covered by built-in templates
- **Client-specific testing** with custom methodology requirements
- **Team standardization** — share consistent testing approaches
- **Technology-specific analysis** (e.g., GraphQL-specific, gRPC, WebSocket)

---

## Creating a Custom Template

### Using the UI

1. Go to **Prompt Templates** tab
2. Click **"New Template"**
3. Fill in the template fields:

| Field | Required | Description |
|:------|:---------|:------------|
| **Name** | ✅ | Template display name |
| **Category** | ✅ | Grouping category (e.g., "Exploitation", "Analysis") |
| **Description** | ✅ | Brief description of what the template does |
| **System Prompt** | ✅ | The AI's role and expertise (see below) |
| **User Prompt** | ✅ | The analysis request with variables (see below) |
| **Mode** | ✅ | Standard or Expert |
| **Tags** | Optional | Searchable tags for filtering |
| **Model Override** | Optional | Use a specific AI model for this template |
| **Temperature Override** | Optional | Custom temperature (0.0–1.0) |
| **Max Tokens Override** | Optional | Custom response length limit |

4. Click **"Save"**

---

## Writing Effective Prompts

### System Prompt (AI's Role)

The system prompt defines the AI's expertise and methodology. A good system prompt includes:

```
You are an ELITE [vulnerability type] expert with deep knowledge from
[sources: PortSwigger, OWASP, real-world bounties].

CORE EXPERTISE:
- [Technique 1]
- [Technique 2]
- [Technique 3]

METHODOLOGY:
1. [Step 1 — what to check first]
2. [Step 2 — how to test]
3. [Step 3 — how to bypass filters]
4. [Step 4 — how to escalate]

REAL-WORLD: [Context about bounty values and impact]
```

{: .tip }
> Be specific and comprehensive in the system prompt. The more expert knowledge you provide, the better the AI's analysis will be.

### User Prompt (Analysis Request)

The user prompt is where you use variables and define the output format:

```
Analyze this HTTP request/response for [vulnerability type].

RAW REQUEST: {{REQUEST}}
RAW RESPONSE: {{RESPONSE}}
PARAMS: {{PARAMETERS_LIST}}
WAF: {{WAF_DETECTION}}

USER QUESTION: {{USER_QUERY}}

PROVIDE:
1. [Analysis section 1]
2. [Analysis section 2]
3. [Testing payloads]
4. [Impact assessment]
```

---

## Available Variables

Use these variables in your user prompt — they are automatically populated from the HTTP request context:

### Request Variables

| Variable | Content |
|:---------|:--------|
| `{{REQUEST}}` | Full raw HTTP request |
| `{{RESPONSE}}` | Full raw HTTP response |
| `{{URL}}` | Request URL |
| `{{METHOD}}` | HTTP method |
| `{{HEADERS}}` | Request headers |
| `{{BODY}}` | Request body |
| `{{PARAMETERS_LIST}}` | All parameters with values |
| `{{COOKIES}}` | Cookie values |

### Analysis Variables

| Variable | Content |
|:---------|:--------|
| `{{ENDPOINT_TYPE}}` | Detected endpoint type |
| `{{WAF_DETECTION}}` | Detected WAF information |
| `{{RISK_SCORE}}` | Calculated risk score |
| `{{DEEP_REQUEST_ANALYSIS}}` | Deep request pattern analysis |
| `{{DEEP_RESPONSE_ANALYSIS}}` | Deep response analysis |
| `{{REFLECTION_ANALYSIS}}` | Input reflection tracking |
| `{{ERROR_MESSAGES}}` | Error messages in response |
| `{{SENSITIVE_DATA}}` | Detected sensitive data |
| `{{TECHNOLOGY_STACK}}` | Detected technologies |

### User Context

| Variable | Content |
|:---------|:--------|
| `{{USER_QUERY}}` | User's question text |
| `{{CONVERSATION_HISTORY}}` | Previous conversation context |

---

## Template Examples

### WebSocket Security Template

```yaml
Name: WebSocket Security Expert
Category: Exploitation
Mode: Expert

System Prompt: |
  You are an expert in WebSocket security testing.
  
  EXPERTISE:
  - Cross-Site WebSocket Hijacking (CSWSH)
  - WebSocket message injection
  - Origin validation bypass
  - Message format manipulation
  
  METHODOLOGY:
  1. Check Origin header validation
  2. Test for CSWSH (missing CSRF protection on handshake)
  3. Inject payloads in WebSocket messages
  4. Test for authorization on message types

User Prompt: |
  Analyze this WebSocket connection for vulnerabilities.
  
  REQUEST: {{REQUEST}}
  RESPONSE: {{RESPONSE}}
  
  PROVIDE:
  1. Handshake analysis (Origin, Sec-WebSocket-Key)
  2. CSWSH testing approach
  3. Message injection payloads
  4. Authorization bypass tests
```

### GraphQL-Specific Template

```yaml
Name: GraphQL Security Expert
Category: Exploitation
Mode: Expert

System Prompt: |
  You are a GraphQL security expert.
  
  EXPERTISE:
  - Introspection exploitation
  - Query batching attacks
  - Nested query DoS (query depth)
  - Authorization bypass via field-level access control
  - Injection through GraphQL variables
  
User Prompt: |
  Analyze this GraphQL request for vulnerabilities.
  
  REQUEST: {{REQUEST}}
  RESPONSE: {{RESPONSE}}
  DEEP ANALYSIS: {{DEEP_REQUEST_ANALYSIS}}
  
  PROVIDE:
  1. Introspection query results
  2. Query batching test
  3. Depth/complexity abuse payloads
  4. Field-level authorization tests
```

---

## Import & Export

### Exporting Templates

Share your custom templates with teammates:

1. Select a template in the Prompt Templates tab
2. Click **"Export"**
3. Template is saved as a JSON file

### Importing Templates

1. Click **"Import"** in the Prompt Templates tab
2. Select a template JSON file
3. Template is added to your custom templates

### Template File Format

Templates are stored as JSON in `~/.vista/prompts/custom/`:

```json
{
  "id": "custom-websocket-expert",
  "name": "WebSocket Security Expert",
  "category": "Exploitation",
  "author": "your-name",
  "description": "WebSocket security testing template",
  "systemPrompt": "You are a WebSocket security expert...",
  "userPrompt": "Analyze this WebSocket connection...",
  "isBuiltIn": false,
  "isActive": true,
  "mode": "EXPERT",
  "tags": ["websocket", "expert"],
  "modelOverride": null,
  "temperatureOverride": null,
  "maxTokensOverride": null
}
```

---

## Best Practices

{: .tip }
> **Be comprehensive in system prompts** — Include specific techniques, tool names, payload examples, and methodology steps. The AI performs much better with detailed context.

{: .tip }
> **Structure your output requirements** — Use numbered sections in the user prompt (PROVIDE: 1. Analysis, 2. Payloads, 3. Impact) to get organized responses.

{: .tip }
> **Use relevant variables** — Don't include all 35 variables. Only use variables relevant to your vulnerability type.

{: .tip }
> **Test with different models** — Use the model override to test which AI model works best for your template's use case.
