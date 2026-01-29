# VISTA Features - Complete Backstory & How They Work

## 📖 Table of Contents

1. [Bypass Engine (NEW)](#1-bypass-engine-new)
2. [Dual-Mode AI Assistant](#2-dual-mode-ai-assistant)
3. [WAF Detection](#3-waf-detection)
4. [Bypass Knowledge Base](#4-bypass-knowledge-base)
5. [Systematic Testing Engine](#5-systematic-testing-engine)
6. [Headless Browser Verification](#6-headless-browser-verification)
7. [Findings Management](#7-findings-management)
8. [AI Service Integration](#8-ai-service-integration)
9. [HTTP Message Parsing](#9-http-message-parsing)
10. [Report Generation](#10-report-generation)

---

## 1. Bypass Engine (NEW)

### 🎯 What It Does
The Bypass Engine is VISTA's newest feature that automatically generates and tests payload variations to bypass WAFs, input validation, and output encoding.

### 🔧 How It Works

#### Phase 1: Analysis
```java
BlockingAnalysis analysis = analyzeBlocking(baseRequest, originalPayload);
```

**What happens:**
1. Examines the HTTP response
2. Detects WAF from headers (Cloudflare, AWS WAF, ModSecurity, etc.)
3. Identifies protection type:
   - WAF_BLOCK (403 Forbidden)
   - INPUT_VALIDATION (400 Bad Request)
   - OUTPUT_ENCODING (HTML entities like &lt;)
   - CONTENT_TYPE_FILTER (406 Not Acceptable)
4. Extracts blocked keywords from payload

**Example:**
```
Input: <script>alert(1)</script>
Response: 403 Forbidden, cf-ray header present
Analysis: WAF=Cloudflare, Protection=WAF_BLOCK, Keywords=[script, alert]
```

#### Phase 2: Generation
```java
List<String> candidates = generateBypassCandidates(payload, attackType, analysis);
```

**What happens:**
1. **AI Generation**: Sends context to AI
   - Original payload
   - Attack type (XSS, SQLi, etc.)
   - Protection detected
   - WAF type
   - Blocked keywords
   
2. **AI Response**: Gets 10+ creative bypasses
   - Case variations
   - Encoding techniques
   - Alternative syntax
   - Context breaking

3. **Knowledge Base**: Adds proven techniques
   - 500+ bypasses from PayloadsAllTheThings
   - Filtered by attack type

4. **Encoding Variations**: Generates automatically
   - URL encoding
   - Double URL encoding
   - HTML entity encoding
   - Unicode encoding
   - Mixed encoding

5. **Obfuscation**: Attack-specific tricks
   - XSS: Comment injection, null bytes, alternative tags
   - SQLi: Comment variations, case manipulation
   - Command Injection: Variable expansion, IFS tricks

**Example Output:**
```
Generated 25 bypass candidates:
1. <ScRiPt>alert(1)</sCriPt>           (case variation)
2. <svg/onload=alert(1)>                (alternative tag)
3. %3Cscript%3Ealert(1)%3C/script%3E   (URL encoding)
4. &#x3c;script&#x3e;alert(1)           (HTML entities)
5. </title><script>alert(1)</script>   (context breaking)
...
```


#### Phase 3: Testing
```java
BypassResult result = testBypassCandidates(baseRequest, candidates, analysis, callback);
```

**What happens:**
1. Tests each candidate sequentially
2. Injects payload into request
3. Analyzes response for success indicators:
   - Status code (200 OK vs 403 Forbidden)
   - Response body (no encoding, no blocking message)
   - Payload reflection (unencoded)

4. **Early Stopping**: Stops immediately when bypass found
5. **Rate Limiting**: 100ms delay between tests
6. **Progress Callback**: Updates UI in real-time

**Example:**
```
[1/25] Testing: <ScRiPt>alert(1)</sCriPt>
       ✗ Still blocked (403)

[2/25] Testing: <svg/onload=alert(1)>
       ✗ Still blocked (403)

[3/25] Testing: </title><script>alert(1)</script>
       ✓ SUCCESS! (200 OK, payload reflected unencoded)
```

#### Phase 4: Learning
```java
learnFromSuccess(attackType, protectionType, successfulPayload);
```

**What happens:**
1. Stores successful bypass pattern
2. Key: "XSS_WAF_BLOCK"
3. Value: "</title><script>alert(1)</script>"
4. Next time: Applies this pattern to similar scenarios

**Learning Database:**
```
XSS_WAF_BLOCK → [</title><script>, <svg/onload=, ...]
SQLI_INPUT_VALIDATION → [' OR '1'='1, UNION/**/SELECT, ...]
```

### 💡 Real-World Example

**Scenario:** Testing XSS on a Cloudflare-protected site

```
1. User sends request with: <script>alert(1)</script>
2. Response: 403 Forbidden, cf-ray header

VISTA Analysis:
- WAF: Cloudflare
- Protection: WAF_BLOCK
- Blocked: script, alert

VISTA Generates:
- 10 AI-powered bypasses
- 5 encoding variations
- 8 XSS-specific obfuscations
- 2 historical successful patterns
Total: 25 candidates

VISTA Tests:
[1/25] <ScRiPt> → ✗ Blocked
[2/25] <svg/onload> → ✗ Blocked
[3/25] </title><script> → ✓ SUCCESS!

Result: Bypass found in 3 attempts (300ms)
Payload: </title><script>alert(document.domain)</script>
```

### 🎨 UI Integration

**New Tab: 🔓 Bypass Assistant**

```
┌─────────────────────────────────────────────────────┐
│ 🔓 Bypass Assistant                                 │
│ AI-powered WAF and validation bypass engine         │
├─────────────────────────────────────────────────────┤
│ Original Payload: [<script>alert(1)</script>]      │
│ Attack Type: [XSS ▼]  [🚀 Find Bypass]             │
├─────────────────────────────────────────────────────┤
│ Request/Response │ Bypass Results                   │
│                  │                                   │
│ GET /search?q=   │ [Analysis] WAF: Cloudflare       │
│ ...              │ [Generation] Generated 25        │
│                  │ [Testing] Testing 3/25...        │
│                  │ ✓ Bypass found!                  │
│                  │                                   │
│                  │ Payload: </title><script>...     │
│                  │ [Copy] [Test in Browser]         │
└─────────────────────────────────────────────────────┘
```

**Context Menu:**
- Right-click any request → "🔓 Send to VISTA Bypass Assistant"
- Automatically loads request
- Switches to Bypass Assistant tab

---

## 2. Dual-Mode AI Assistant

### 🎯 What It Does
Provides two distinct AI interaction modes for different testing workflows.

### 🔧 How It Works

#### Mode A: Quick Suggestions

**Purpose:** Get everything at once

**Flow:**
```
User: "How to test for XSS?"
  ↓
VISTA builds prompt:
  - User question
  - Request/Response (truncated)
  - WAF detection results
  - Systematic methodology
  - Bypass knowledge
  - Instruction: "Provide COMPLETE response"
  ↓
AI generates:
  - Testing approach (5 steps)
  - 10-20 payloads
  - Expected results
  - Pro tips
  ↓
User: Gets everything in one response
```

**Prompt Structure:**
```
SYSTEM: You are a penetration testing expert...

USER:
Request: GET /search?q=test
Response: 200 OK, <div>test</div>
WAF: None detected

Systematic Methodology:
1. Test reflection
2. Analyze context
3. Test basic payload
...

Bypass Knowledge:
- Case variation: <ScRiPt>
- Alternative tags: <svg/onload>
...

User Question: How to test for XSS?

Instructions: Provide a COMPLETE testing approach with:
- 5-step methodology
- 10-20 suggested payloads
- Expected results for each
- Pro tips
```

**AI Response:**
```
TESTING APPROACH:

Step 1: Test Reflection
Try: VISTATEST123
Look for: Exact reflection in response

Step 2: Analyze Context
Check: Is it in HTML body, attribute, or script?

Step 3: Test Basic Payload
Try: <script>alert(1)</script>
Look for: Execution or blocking

...

SUGGESTED PAYLOADS:
1. <script>alert(1)</script>
2. <svg/onload=alert(1)>
3. <img src=x onerror=alert(1)>
...

PRO TIPS:
- Check for CSP headers
- Try DOM-based XSS
...
```

