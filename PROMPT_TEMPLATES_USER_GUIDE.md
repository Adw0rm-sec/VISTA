# VISTA Custom AI Prompt Templates - User Guide

## Overview

VISTA v2.5.0 introduces **Custom AI Prompt Templates**, a powerful feature that allows you to create, manage, and use specialized AI prompts for different testing scenarios. This gives you complete control over how the AI analyzes requests and provides testing guidance.

## What Are Prompt Templates?

Prompt templates are pre-configured AI instructions that:
- Define the AI's role and expertise level
- Structure how requests/responses are analyzed
- Include dynamic variables that get replaced with actual data
- Can be specialized for specific vulnerability types (XSS, SQLi, SSTI, etc.)
- Can be customized for different testing methodologies

## Key Features

### 1. Built-in Templates (20 Pre-configured)
VISTA comes with 20 professional templates covering:
- **XSS Testing**: Reflected (Basic & Aggressive), Stored, DOM-based
- **SQL Injection**: Error-based, Blind Boolean, Time-based
- **SSTI**: Detection & Exploitation
- **Command Injection**: OS command injection testing
- **SSRF**: Basic & Cloud Metadata targeting
- **Authentication Bypass**: Auth/authz testing
- **API Security**: Comprehensive API audits
- **WAF Bypass**: Generic & Cloudflare-specific
- **Reconnaissance**: Parameter discovery, endpoint analysis, error analysis
- **Quick Scan**: Fast general vulnerability assessment

### 2. Custom Templates
- Create your own templates from scratch
- Copy and modify built-in templates
- Import/export templates as JSON files
- Share templates with your team

### 3. Dynamic Variables
Templates support 23+ variables that get replaced with actual data:
- `{{REQUEST}}` - Full HTTP request
- `{{RESPONSE}}` - Full HTTP response
- `{{REFLECTION_ANALYSIS}}` - Where parameters are reflected
- `{{WAF_DETECTION}}` - Detected WAF and bypass suggestions
- `{{RISK_SCORE}}` - Calculated risk score (0-10)
- `{{PREDICTED_VULNS}}` - AI-predicted vulnerabilities
- `{{DEEP_REQUEST_ANALYSIS}}` - Comprehensive request analysis
- `{{DEEP_RESPONSE_ANALYSIS}}` - Comprehensive response analysis
- And many more...

## How to Use Prompt Templates

### Step 1: Access the Prompt Templates Tab
1. Open VISTA in Burp Suite
2. Click on the **"📝 Prompt Templates"** tab
3. You'll see a list of all available templates

### Step 2: Browse Built-in Templates
- The left panel shows all templates
- Built-in templates are marked with 🔒 (read-only)
- Click any template to view its details
- Templates are organized by category: Exploitation, Reconnaissance, Bypass, General

### Step 3: Use a Template in AI Advisor
1. Go to the **"💡 AI Advisor"** tab
2. Send a request to VISTA (right-click in Burp → "Send to VISTA AI Advisor")
3. At the top, you'll see a **"📝 Template:"** dropdown
4. Select a template (e.g., "XSS - Reflected (Basic)")
5. Type your question or observation
6. Click **Send**

The AI will now use your selected template instead of the default prompt!

### Step 4: Create Your Own Template
1. Go to **"📝 Prompt Templates"** tab
2. Click **"➕ New"** button
3. Fill in the template details:
   - **Name**: Give it a descriptive name
   - **Description**: Explain what it's for
   - **Category**: Choose Exploitation, Reconnaissance, Bypass, or General
   - **Tags**: Add searchable tags (comma-separated)
   - **Active**: Check to make it available in AI Advisor
4. Write the **System Prompt** (defines AI's role)
5. Write the **User Prompt** (the actual instructions)
6. Use the variable buttons to insert dynamic data
7. Click **"💾 Save Template"**

### Step 5: Copy and Modify Built-in Templates
1. Select a built-in template (🔒)
2. Click **"📋 Copy"** button
3. The template is duplicated as editable
4. Modify it to your needs
5. Save with a new name

### Step 6: Import/Export Templates
**Export:**
1. Select a template
2. Click **"📤 Export"**
3. Choose save location
4. Template is saved as JSON file

**Import:**
1. Click **"📥 Import"**
2. Select a JSON template file
3. Template is added to your collection

## Template Structure

### System Prompt
Defines the AI's role and expertise:
```
You are an expert XSS penetration tester specializing in WAF bypass techniques.
```

### User Prompt (with Variables)
The actual testing instructions with dynamic variables:
```
USER'S QUESTION: {{USER_QUERY}}

Perform aggressive reflected XSS testing with bypass techniques.

REQUEST: {{REQUEST}}
RESPONSE: {{RESPONSE}}
REFLECTION: {{REFLECTION_ANALYSIS}}
WAF: {{WAF_DETECTION}}
RISK SCORE: {{RISK_SCORE}}/10

Provide advanced XSS payloads including:
1. Encoding variations (URL, HTML entity, Unicode)
2. Obfuscation techniques
3. WAF-specific bypasses
4. Polyglot payloads
5. Event handler variations
6. Protocol smuggling

Be creative and thorough. Include 10+ payload variations.
Address the user's specific question above.
```

**Important**: Always include `{{USER_QUERY}}` in your templates so the AI knows what the user actually asked!

## Available Variables Reference

### User Query Variable
- `{{USER_QUERY}}` - **Your actual question or prompt** - This is what you type in the chat field

### Request Variables
- `{{REQUEST}}` - Full HTTP request
- `{{REQUEST_METHOD}}` - GET, POST, etc.
- `{{REQUEST_URL}}` - Full URL
- `{{REQUEST_PATH}}` - URL path only
- `{{REQUEST_HEADERS}}` - All headers
- `{{REQUEST_PARAMETERS}}` - All parameters
- `{{REQUEST_BODY}}` - Request body
- `{{REQUEST_COOKIES}}` - Cookies

### Response Variables
- `{{RESPONSE}}` - Full HTTP response
- `{{RESPONSE_STATUS}}` - Status code
- `{{RESPONSE_HEADERS}}` - All headers
- `{{RESPONSE_BODY}}` - Response body
- `{{RESPONSE_SIZE}}` - Size in bytes

### Analysis Variables
- `{{REFLECTION_ANALYSIS}}` - Where/how parameters are reflected
- `{{DEEP_REQUEST_ANALYSIS}}` - Comprehensive request analysis
- `{{DEEP_RESPONSE_ANALYSIS}}` - Comprehensive response analysis
- `{{WAF_DETECTION}}` - Detected WAF and bypass suggestions
- `{{RISK_SCORE}}` - Risk score 0-10
- `{{PREDICTED_VULNS}}` - Predicted vulnerabilities
- `{{ENDPOINT_TYPE}}` - Type of endpoint (API, form, search, etc.)
- `{{PARAMETERS_LIST}}` - List of all parameters
- `{{ERROR_MESSAGES}}` - Detected error messages
- `{{SENSITIVE_DATA}}` - Detected sensitive data leaks

### Context Variables
- `{{TESTING_HISTORY}}` - Previous testing steps
- `{{CONVERSATION_CONTEXT}}` - Previous conversation
- `{{ATTACHED_REQUESTS_COUNT}}` - Number of attached requests

## Example Use Cases

### Use Case 1: Specialized XSS Testing
**Scenario**: You're testing a search feature and want aggressive XSS testing with WAF bypass.

**Steps**:
1. Send search request to AI Advisor
2. Select template: **"XSS - Reflected (Aggressive)"**
3. Ask: "Test for XSS"
4. AI provides 10+ WAF bypass payloads tailored to the reflection context

### Use Case 2: Blind SQLi Testing
**Scenario**: You suspect blind SQL injection but need systematic testing approach.

**Steps**:
1. Send request to AI Advisor
2. Select template: **"SQLi - Blind Boolean"** or **"SQLi - Time Based"**
3. Ask: "Test for blind SQLi"
4. AI provides boolean/time-based payloads with clear success indicators

### Use Case 3: Cloud Metadata SSRF
**Scenario**: Testing for SSRF on a cloud-hosted application.

**Steps**:
1. Send request to AI Advisor
2. Select template: **"SSRF - Cloud Metadata"**
3. Ask: "Test for SSRF"
4. AI provides AWS/GCP/Azure metadata endpoints with required headers

### Use Case 4: Custom Template for Your Workflow
**Scenario**: Your team has a specific testing methodology you want AI to follow.

**Steps**:
1. Create new template
2. Name: "Company XSS Methodology"
3. System Prompt: "You are a pentester following [Company] security testing standards."
4. User Prompt: Include your company's specific testing steps and requirements
5. Use variables to inject request/response data
6. Save and share with team via export

## Tips and Best Practices

### 1. Start with Built-in Templates
- Explore the 20 built-in templates first
- Understand how they structure prompts
- Copy and modify them for your needs

### 2. Use Specific Templates for Specific Tests
- Don't use "Quick Vulnerability Scan" for everything
- Select the template that matches your current testing goal
- Switch templates as you move through different vulnerability types

### 3. Leverage Variables Effectively
- Always include `{{REQUEST}}` and `{{RESPONSE}}`
- Use `{{REFLECTION_ANALYSIS}}` for XSS/injection testing
- Use `{{WAF_DETECTION}}` when dealing with filters
- Use `{{DEEP_REQUEST_ANALYSIS}}` for comprehensive context

### 4. Create Templates for Recurring Scenarios
- If you test the same type of application repeatedly, create a template
- Example: "WordPress Plugin Testing", "API Gateway Testing", "GraphQL Testing"

### 5. Organize with Categories and Tags
- Use categories to group similar templates
- Add descriptive tags for easy searching
- Example tags: "waf-bypass", "cloud", "api", "aggressive", "stealth"

### 6. Share Templates with Your Team
- Export your best templates
- Share via Git, Slack, or team drive
- Build a team library of proven templates

### 7. Iterate and Improve
- Track template usage count (shown in UI)
- Refine templates based on AI output quality
- Remove or deactivate templates that don't work well

## Template Management

### Searching Templates
- Use the search box to filter by name, description, or tags
- Use category dropdown to filter by category
- Combine search and category for precise filtering

### Activating/Deactivating Templates
- Uncheck "Active" to hide a template from AI Advisor dropdown
- Useful for templates you're still developing
- Built-in templates are always active

### Deleting Templates
- Only custom templates can be deleted
- Built-in templates are protected
- Select template → Click "🗑️ Delete"

### Usage Tracking
- Each template tracks how many times it's been used
- Helps identify your most valuable templates
- Shown in template list and editor

## Advanced Features

### Template Variables in System Prompts
You can use variables in both system and user prompts:
```
System Prompt: You are an expert in {{ENDPOINT_TYPE}} security testing.
```

### Multi-Request Context
When multiple requests are attached in Interactive Assistant:
- `{{ATTACHED_REQUESTS_COUNT}}` shows the count
- `{{TESTING_HISTORY}}` includes all attached requests
- Templates can reference previous tests

### Conversation-Aware Templates
Templates have access to conversation history:
- `{{CONVERSATION_CONTEXT}}` includes previous messages
- Useful for follow-up questions and iterative testing
- AI maintains context across multiple interactions

## Troubleshooting

### Template Not Showing in Dropdown
- Check if template is marked as "Active"
- Refresh by switching tabs or reloading extension
- Verify template was saved successfully

### Variables Not Being Replaced
- Ensure variable names are exact (case-sensitive)
- Use double curly braces: `{{VARIABLE}}`
- Check if the data source is available (e.g., no response = empty `{{RESPONSE}}`)

### AI Output Not Following Template
- Review your prompt structure
- Be more specific in instructions
- Use clear formatting (numbered lists, sections)
- Test with simpler prompts first

### Template Import Fails
- Verify JSON file is valid
- Check if file was exported from VISTA
- Try creating a new template manually

## Example Templates

### Example 1: Custom XSS Template
```
Name: XSS - My Company Standard
Category: Exploitation
Tags: xss, company-standard, reflected

System Prompt:
You are a senior penetration tester following [Company] XSS testing methodology.

User Prompt:
Test for XSS vulnerabilities following our standard approach.

REQUEST: {{REQUEST}}
RESPONSE: {{RESPONSE}}
REFLECTION: {{REFLECTION_ANALYSIS}}
WAF: {{WAF_DETECTION}}

Follow these steps:
1. Identify all reflection points
2. Determine reflection context (HTML, JS, attribute)
3. Test with company-approved payloads only
4. Document findings in company format
5. Provide remediation aligned with company standards

Use only these payload categories:
- Basic: <script>alert(1)</script>
- Event handlers: <img src=x onerror=alert(1)>
- Polyglots: jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

Provide clear pass/fail for each test.
```

### Example 2: API Security Template
```
Name: REST API Security Audit
Category: Reconnaissance
Tags: api, rest, security-audit

System Prompt:
You are an API security expert specializing in REST API vulnerabilities.

User Prompt:
Perform comprehensive REST API security audit.

REQUEST: {{REQUEST}}
RESPONSE: {{RESPONSE}}
ENDPOINT: {{ENDPOINT_TYPE}}
RISK: {{RISK_SCORE}}/10

Audit checklist:
1. Authentication & Authorization
   - Missing/weak tokens
   - Token expiration
   - Privilege escalation

2. Input Validation
   - Injection flaws (SQLi, NoSQLi, XXE)
   - Mass assignment
   - Type confusion

3. Data Exposure
   - Excessive data in responses
   - Sensitive data in URLs
   - PII leakage

4. Rate Limiting
   - Brute force protection
   - DoS prevention

5. IDOR Testing
   - Object reference manipulation
   - UUID predictability

Provide specific test cases for each finding.
```

## Conclusion

Custom AI Prompt Templates give you unprecedented control over VISTA's AI analysis. By creating specialized templates for different scenarios, you can:
- Get more relevant and actionable testing guidance
- Enforce your team's testing methodologies
- Adapt to different application types and security requirements
- Build a library of proven testing approaches

Start with the built-in templates, experiment with modifications, and gradually build your own collection of templates that match your testing style and requirements.

Happy testing! 🎯
