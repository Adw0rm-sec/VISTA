# 🎯 Payload Library - User Guide

## Overview

The **Payload Library** is a comprehensive collection of pre-built and custom payloads for security testing. It includes 100+ built-in payloads across 8 vulnerability categories, with success rate tracking and intelligent filtering.

**Version**: 2.6.0  
**Feature Status**: ✅ Complete

---

## 📚 What's Included

### Built-in Payload Libraries (100+ Payloads)

1. **XSS - Reflected** (25 payloads)
   - Basic script tags, event handlers, SVG/iframe vectors
   - Attribute context breakouts
   - JavaScript context escapes
   - WAF bypass techniques (case variation, encoding, polyglots)

2. **XSS - Stored** (5 payloads)
   - Persistent XSS vectors
   - Cookie exfiltration payloads
   - Domain/origin disclosure

3. **SQLi - Error Based** (14 payloads)
   - MySQL, PostgreSQL, MSSQL, Oracle
   - ExtractValue, UpdateXML, CAST errors
   - Version and database name extraction

4. **SQLi - Blind** (9 payloads)
   - Boolean-based (true/false conditions)
   - Time-based (SLEEP, WAITFOR, pg_sleep)
   - Substring and ASCII comparison

5. **SSTI - Template Injection** (10 payloads)
   - Jinja2 (Python)
   - Twig (PHP)
   - Freemarker (Java)
   - Velocity (Java)
   - Detection and RCE payloads

6. **SSRF** (9 payloads)
   - Localhost/loopback access
   - AWS/GCP metadata endpoints
   - Private network ranges
   - File and Gopher protocols

7. **Command Injection** (11 payloads)
   - Basic separators (;, |, &, &&, ||)
   - Backtick and $() execution
   - Bypass techniques (backslash, quotes, IFS)

8. **XXE - XML External Entity** (3 payloads)
   - File read
   - External HTTP requests
   - Parameter entities

---

## 🚀 Getting Started

### First Launch

1. Open Burp Suite and load the VISTA extension
2. Navigate to the **🎯 Payload Library** tab
3. Built-in libraries are automatically installed on first launch
4. You'll see: `Libraries: 8 | Payloads: 100+ | Used: 0 | Tests: 0`

### Interface Overview

```
┌─────────────────────────────────────────────────────────┐
│ 🎯 Payload Library                                      │
├─────────────────────────────────────────────────────────┤
│ Category: [All ▼] Context: [All ▼] Search: [____] 🔍   │
│ Libraries: 8 | Payloads: 100+ | Used: 0 | Tests: 0     │
├─────────────────────────────────────────────────────────┤
│ Payload                    │ Category │ Context │ Rate │
│ <script>alert(1)</script>  │ XSS      │ html... │ N/A  │
│ ' OR 1=1--                 │ SQLi     │ any     │ N/A  │
│ {{7*7}}                    │ SSTI     │ any     │ N/A  │
├─────────────────────────────────────────────────────────┤
│ Payload Details:                                        │
│ Value: <script>alert(1)</script>                        │
│ Description: Basic script tag                           │
│ Context: html-body                                      │
│ Tags: basic, xss                                        │
└─────────────────────────────────────────────────────────┘
```

---

## 💡 How to Use

### 1. Browse Payloads

**Filter by Category**:
- Select from dropdown: XSS, SQLi, SSTI, SSRF, Command Injection, XXE
- Shows all payloads in that category

**Filter by Context**:
- `any` - Works in any context
- `html-body` - HTML body context
- `html-attribute` - Inside HTML attributes
- `javascript` - JavaScript context

**Search**:
- Type keywords to search payload values, descriptions, and tags
- Example: "alert", "sleep", "template", "file"

### 2. Copy Payloads

**Method 1: Right-click Menu**
1. Select a payload from the table
2. Right-click → **📋 Copy Payload**
3. Payload is copied to clipboard

**Method 2: Keyboard Shortcut**
1. Select payload
2. Press Ctrl+C (or Cmd+C on Mac)

### 3. Use in Testing

**Manual Testing**:
1. Copy payload to clipboard
2. Go to Burp Repeater
3. Paste into request parameter
4. Send request
5. Analyze response

**With Repeater Integration**:
1. Select payload
2. Right-click → **🔄 Send to Repeater**
3. Follow instructions to paste and test

### 4. Track Success Rates

**Mark Results**:
1. After testing a payload, select it in the table
2. Right-click → **✓ Mark as Success** or **✗ Mark as Failure**
3. Enter target URL and parameter name
4. Result is recorded

**View Statistics**:
- Success Rate column shows: `75.0% (3/4)` = 3 successes out of 4 attempts
- "Not used" = Payload hasn't been tested yet
- Sort by success rate to find best-performing payloads

**Benefits**:
- Identify which payloads work best for your targets
- Build a knowledge base of effective techniques
- Prioritize high-success payloads in future tests

---

## 🔧 Advanced Features

### Create Custom Libraries

1. Click **➕ New Library** button
2. Enter library name (e.g., "My Custom XSS")
3. Enter category (e.g., "XSS")
4. Enter subcategory (e.g., "Custom")
5. Library is created (empty)

**Note**: Adding payloads to custom libraries requires manual JSON editing (future feature).

### Import Libraries

1. Click **📥 Import Library**
2. Select a JSON file containing payload library
3. Library is imported and appears in the list

**JSON Format**:
```json
{
  "name": "My Payloads",
  "category": "XSS",
  "subcategory": "Custom",
  "payloads": [
    {
      "value": "<script>alert(1)</script>",
      "description": "Basic XSS",
      "context": "html-body",
      "encoding": "none",
      "tags": ["xss", "basic"]
    }
  ]
}
```

### Export Libraries

1. Click **📤 Export Library**
2. Select library from dropdown
3. Choose destination file
4. Library is exported as JSON

**Use Cases**:
- Share payloads with team members
- Backup custom libraries
- Transfer between Burp instances

---

## 📊 Understanding Success Rates

### How It Works

1. **Initial State**: All payloads show "Not used"
2. **After Testing**: Mark results as success/failure
3. **Calculation**: Success Rate = (Successes / Total Attempts) × 100%

### Example Workflow

```
Test 1: ' OR 1=1-- → Success ✓
  Success Rate: 100.0% (1/1)

Test 2: ' OR 1=1-- → Success ✓
  Success Rate: 100.0% (2/2)

Test 3: ' OR 1=1-- → Failure ✗
  Success Rate: 66.7% (2/3)

Test 4: ' OR 1=1-- → Success ✓
  Success Rate: 75.0% (3/4)
```

### Best Practices

- **Always mark results** after testing
- **Be consistent** with success criteria
- **Use context** - same payload may work differently in different contexts
- **Review top performers** - sort by success rate to find winners

---

## 🎯 Payload Categories Explained

### XSS (Cross-Site Scripting)

**Reflected**: Payloads for immediate execution
- Use in: Search boxes, URL parameters, form inputs
- Test for: Script execution, event handlers, DOM manipulation

**Stored**: Payloads for persistent storage
- Use in: Comments, profiles, messages
- Test for: Cookie theft, session hijacking, persistent attacks

### SQLi (SQL Injection)

**Error-Based**: Triggers database errors to extract data
- Use in: Login forms, search queries, filters
- Test for: Version info, database names, table enumeration

**Blind**: No direct output, use boolean/time-based inference
- Use in: Same as error-based, but when errors are suppressed
- Test for: Data extraction via true/false or timing delays

### SSTI (Server-Side Template Injection)

**Detection**: Math expressions to confirm vulnerability
- Use in: Template engines, email templates, dynamic pages
- Test for: Template syntax execution ({{7*7}} = 49)

**Exploitation**: RCE payloads for command execution
- Use in: Confirmed SSTI vulnerabilities
- Test for: Remote code execution, file read, system access

### SSRF (Server-Side Request Forgery)

**Internal Access**: Reach internal services
- Use in: URL parameters, webhooks, image fetchers
- Test for: Localhost access, internal network scanning

**Cloud Metadata**: Access cloud provider metadata
- Use in: Cloud-hosted applications
- Test for: AWS/GCP credentials, instance info

### Command Injection

**Basic**: Simple command separators
- Use in: System commands, file operations, ping utilities
- Test for: Command execution via ;, |, &, etc.

**Bypass**: Evade filters and WAFs
- Use in: Filtered inputs
- Test for: Escaping restrictions with quotes, backslashes, IFS

### XXE (XML External Entity)

**File Read**: Read local files
- Use in: XML parsers, SOAP APIs, file uploads
- Test for: /etc/passwd, config files, source code

**SSRF**: Make external requests
- Use in: Same as file read
- Test for: External HTTP requests, data exfiltration

---

## 🔍 Search Tips

### Effective Searches

- **By vulnerability**: "xss", "sqli", "ssti"
- **By technique**: "alert", "sleep", "template"
- **By target**: "mysql", "jinja2", "aws"
- **By bypass**: "waf", "bypass", "encoding"

### Tag-Based Filtering

Common tags:
- `basic` - Simple, straightforward payloads
- `waf-bypass` - Techniques to evade WAFs
- `rce` - Remote code execution
- `exfiltration` - Data theft
- `detection` - Vulnerability detection

---

## 📈 Statistics Dashboard

### Metrics Explained

- **Libraries**: Total number of payload libraries (built-in + custom)
- **Payloads**: Total number of individual payloads
- **Used**: Number of payloads that have been tested at least once
- **Tests**: Total number of test results recorded

### Example

```
Libraries: 10 | Payloads: 150 | Used: 45 | Tests: 120
```

This means:
- 10 libraries installed (8 built-in + 2 custom)
- 150 total payloads available
- 45 payloads have been tested
- 120 total test attempts recorded (some payloads tested multiple times)

---

## 🛠️ Troubleshooting

### No Payloads Showing

**Problem**: Table is empty after launch

**Solution**:
1. Check if built-in libraries were installed
2. Look for log message: "Built-in libraries installed: 8 libraries"
3. If missing, click **🔄 Refresh** button
4. Check `~/.vista/payloads/built-in/` directory exists

### Import Fails

**Problem**: "Failed to import library" error

**Solution**:
1. Verify JSON file is valid (use JSON validator)
2. Check file format matches expected structure
3. Ensure file is readable (permissions)

### Success Rates Not Updating

**Problem**: Marked result but success rate unchanged

**Solution**:
1. Ensure you selected the correct payload
2. Check if payload ID matches (internal tracking)
3. Click **🔄 Refresh** to reload data
4. Check `~/.vista/payloads/test-history.json` file

---

## 💾 File Storage

### Directory Structure

```
~/.vista/payloads/
├── built-in/
│   ├── xss_-_reflected.json
│   ├── xss_-_stored.json
│   ├── sqli_-_error_based.json
│   ├── sqli_-_blind.json
│   ├── ssti_-_template_injection.json
│   ├── ssrf_-_server_side_request_forgery.json
│   ├── command_injection.json
│   └── xxe_-_xml_external_entity.json
├── custom/
│   └── (your custom libraries)
└── test-history.json
```

### Backup Recommendations

**What to backup**:
- `~/.vista/payloads/custom/` - Your custom libraries
- `~/.vista/payloads/test-history.json` - Your test results

**What NOT to backup**:
- `~/.vista/payloads/built-in/` - Regenerated on install

---

## 🎓 Best Practices

### 1. Organize Your Testing

- Use categories to focus on specific vulnerability types
- Filter by context to match your testing scenario
- Search for specific techniques when you know what you're looking for

### 2. Track Everything

- Always mark results after testing
- Be consistent with success criteria
- Review statistics regularly to identify patterns

### 3. Build Your Arsenal

- Create custom libraries for target-specific payloads
- Import community payloads
- Export and share successful payloads with your team

### 4. Stay Efficient

- Use right-click menu for quick actions
- Copy payloads directly to clipboard
- Sort by success rate to prioritize effective payloads

---

## 🚀 Future Enhancements

Planned features for future releases:

- ✨ AI-powered payload generation
- ✨ Automatic payload encoding (URL, Base64, etc.)
- ✨ Bulk testing with multiple payloads
- ✨ Integration with AI Advisor for context-aware suggestions
- ✨ Payload mutation and fuzzing
- ✨ Visual success rate charts
- ✨ Collaborative payload sharing

---

## 📞 Support

For issues or questions:
- Check the main VISTA documentation
- Review Burp Suite extension logs
- Report bugs via GitHub issues

---

**Happy Testing! 🎯**
