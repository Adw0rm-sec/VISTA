# VISTA Customization System - Detailed Implementation Guide

## Overview

This document explains how VISTA's customization system works, including detailed implementation plans for the top 5 recommended features.

## Architecture: Centralized Customization Manager

All customizations are managed through a unified system with these components:

```
┌─────────────────────────────────────────────────────────────┐
│                  CustomizationManager                        │
│  (Singleton - manages all user customizations)              │
├─────────────────────────────────────────────────────────────┤
│  - PromptTemplateManager                                     │
│  - PayloadLibraryManager                                     │
│  - WorkflowPresetManager                                     │
│  - FindingTemplateManager                                    │
│  - RequestCollectionManager                                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Storage Layer (JSON Files)                      │
├─────────────────────────────────────────────────────────────┤
│  ~/.vista/prompts/          - Prompt templates              │
│  ~/.vista/payloads/         - Payload libraries              │
│  ~/.vista/workflows/        - Testing workflows              │
│  ~/.vista/findings/         - Finding templates              │
│  ~/.vista/collections/      - Request collections            │
│  ~/.vista/config.json       - Global settings                │
└─────────────────────────────────────────────────────────────┘
```

### Storage Location
- **User Home**: `~/.vista/` (cross-platform)
- **Format**: JSON (human-readable, easy to share)
- **Backup**: Auto-backup before modifications
- **Import/Export**: ZIP files for sharing

---

## Feature 1: Custom AI Prompt Templates System

### What It Does

Allows users to create, save, and reuse custom AI prompts with dynamic variable substitution. Instead of hardcoded prompts, users can:
- Create templates for specific vulnerability types
- Use variables that auto-populate with request/response data
- Share templates with team members
- Override AI behavior per-template (temperature, model, etc.)

### User Experience

**Before (Current)**:
```
User: "Test for XSS"
AI: [Uses hardcoded prompt in TestingSuggestionsPanel.java]
```

**After (With Templates)**:
```
User: Selects "XSS - Reflected (Aggressive)" template from dropdown
AI: [Uses custom template with user's preferred style and variables]
```

### Implementation Details

#### 1. Data Model

**PromptTemplate.java**:
```java
public class PromptTemplate {
    private String id;              // UUID
    private String name;            // "XSS - Reflected (Aggressive)"
    private String category;        // "Exploitation", "Reconnaissance", "Bypass"
    private String author;          // "@username"
    private String description;     // "Aggressive XSS testing with WAF bypass"
    private String systemPrompt;    // AI role definition
    private String userPrompt;      // Main prompt with variables
    private boolean isBuiltIn;      // true for default templates
    private boolean isActive;       // false = disabled
    
    // AI Configuration Overrides (optional)
    private String modelOverride;   // null = use global, or "gpt-4o"
    private Double temperatureOverride;
    private Integer maxTokensOverride;
    
    // Metadata
    private long createdAt;
    private long modifiedAt;
    private int usageCount;         // Track popularity
    private List<String> tags;      // ["waf-bypass", "reflected-xss"]
}
```

#### 2. Variable System

**Supported Variables** (50+ total):

**Request Variables**:
- `{{REQUEST}}` - Full HTTP request
- `{{REQUEST_METHOD}}` - GET, POST, etc.
- `{{REQUEST_URL}}` - Full URL
- `{{REQUEST_PATH}}` - /api/search
- `{{REQUEST_HEADERS}}` - All headers
- `{{REQUEST_PARAMETERS}}` - All parameters with values
- `{{REQUEST_BODY}}` - POST body
- `{{REQUEST_COOKIES}}` - All cookies

**Response Variables**:
- `{{RESPONSE}}` - Full HTTP response
- `{{RESPONSE_STATUS}}` - 200, 404, etc.
- `{{RESPONSE_HEADERS}}` - All headers
- `{{RESPONSE_BODY}}` - Response body
- `{{RESPONSE_SIZE}}` - Content length

**Analysis Variables** (from existing analyzers):
- `{{REFLECTION_ANALYSIS}}` - ReflectionAnalyzer output
- `{{DEEP_REQUEST_ANALYSIS}}` - DeepRequestAnalyzer output
- `{{DEEP_RESPONSE_ANALYSIS}}` - ResponseAnalyzer output
- `{{WAF_DETECTION}}` - WAFDetector output
- `{{RISK_SCORE}}` - 0-10 risk score
- `{{PREDICTED_VULNS}}` - List of predicted vulnerabilities
- `{{ENDPOINT_TYPE}}` - Login, API, Search, etc.
- `{{PARAMETERS_LIST}}` - Comma-separated parameter names
- `{{ERROR_MESSAGES}}` - Detected errors
- `{{SENSITIVE_DATA}}` - Detected sensitive info

**Context Variables**:
- `{{TESTING_HISTORY}}` - Previous test steps
- `{{CONVERSATION_CONTEXT}}` - Chat history
- `{{ATTACHED_REQUESTS_COUNT}}` - Number of attached requests
- `{{CURRENT_STEP}}` - Step number in workflow

**User Variables** (custom):
- `{{USER_NOTE}}` - User can add custom note
- `{{TARGET_NAME}}` - Target application name
- `{{CUSTOM_1}}` to `{{CUSTOM_5}}` - User-defined

#### 3. Core Classes

**PromptTemplateManager.java**:
```java
public class PromptTemplateManager {
    private static PromptTemplateManager instance;
    private Map<String, PromptTemplate> templates;
    private String templatesDir = System.getProperty("user.home") + "/.vista/prompts/";
    
    // Core Methods
    public List<PromptTemplate> getAllTemplates();
    public List<PromptTemplate> getTemplatesByCategory(String category);
    public PromptTemplate getTemplate(String id);
    public void saveTemplate(PromptTemplate template);
    public void deleteTemplate(String id);
    public void importTemplate(File jsonFile);
    public void exportTemplate(String id, File destination);
    
    // Variable Substitution
    public String processTemplate(PromptTemplate template, VariableContext context);
    
    // Built-in Templates
    private void loadBuiltInTemplates();
}
```

**VariableContext.java**:
```java
public class VariableContext {
    private IHttpRequestResponse request;
    private RequestAnalysis deepRequestAnalysis;
    private ResponseAnalysis deepResponseAnalysis;
    private ReflectionAnalyzer.ReflectionAnalysis reflectionAnalysis;
    private List<WAFDetector.WAFInfo> wafDetection;
    private List<TestingStep> testingHistory;
    private List<ConversationMessage> conversationHistory;
    private Map<String, String> customVariables;
    
    // Build context from current state
    public static VariableContext fromCurrentState(
        IHttpRequestResponse request,
        List<TestingStep> history,
        List<ConversationMessage> conversation
    );
    
    // Get variable value
    public String getVariable(String varName);
}
```

**VariableProcessor.java**:
```java
public class VariableProcessor {
    // Process template and replace all variables
    public static String process(String template, VariableContext context) {
        String result = template;
        
        // Find all {{VARIABLE}} patterns
        Pattern pattern = Pattern.compile("\\{\\{([A-Z_0-9]+)\\}\\}");
        Matcher matcher = pattern.matcher(template);
        
        while (matcher.find()) {
            String varName = matcher.group(1);
            String value = context.getVariable(varName);
            result = result.replace("{{" + varName + "}}", value);
        }
        
        return result;
    }
}
```

#### 4. UI Components

**PromptTemplatePanel.java** (new tab in Settings):
```
┌─────────────────────────────────────────────────────────────┐
│  Prompt Templates                                            │
├─────────────────────────────────────────────────────────────┤
│  Category: [All ▼] [Exploitation] [Reconnaissance] [Bypass] │
│  Search: [________________]  [+ New] [Import] [Export All]  │
├─────────────────────────────────────────────────────────────┤
│  ┌─ Template List ──────────────────────────────────────┐   │
│  │ ✓ XSS - Reflected (Aggressive)        [Built-in]    │   │
│  │ ✓ SQLi - Error Based                  [Built-in]    │   │
│  │ ✓ SSTI - Jinja2 Detection             [Built-in]    │   │
│  │ ✓ My Custom API Test                  [Custom]      │   │
│  │   Disabled Template                    [Custom]      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─ Template Editor ────────────────────────────────────┐   │
│  │ Name: [XSS - Reflected (Aggressive)              ]   │   │
│  │ Category: [Exploitation ▼]                            │   │
│  │ Description: [Aggressive XSS testing with WAF...]    │   │
│  │                                                       │   │
│  │ System Prompt:                                        │   │
│  │ ┌─────────────────────────────────────────────────┐ │   │
│  │ │You are an expert XSS pentester...              │ │   │
│  │ └─────────────────────────────────────────────────┘ │   │
│  │                                                       │   │
│  │ User Prompt:                                          │   │
│  │ ┌─────────────────────────────────────────────────┐ │   │
│  │ │Analyze this request for XSS:                   │ │   │
│  │ │{{REQUEST}}                                      │ │   │
│  │ │                                                 │ │   │
│  │ │Reflection Analysis:                            │ │   │
│  │ │{{REFLECTION_ANALYSIS}}                         │ │   │
│  │ │                                                 │ │   │
│  │ │WAF Detection:                                   │ │   │
│  │ │{{WAF_DETECTION}}                               │ │   │
│  │ └─────────────────────────────────────────────────┘ │   │
│  │                                                       │   │
│  │ [Insert Variable ▼] [Test Template] [Save] [Delete]  │   │
│  └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Integration in AI Advisor** (TestingSuggestionsPanel.java):
```
┌─────────────────────────────────────────────────────────────┐
│  AI Security Advisor                                         │
├─────────────────────────────────────────────────────────────┤
│  Template: [XSS - Reflected (Aggressive) ▼]  [⚙️ Manage]   │
│  Query: [How to test for XSS?                            ]  │
│  [Send]                                                      │
└─────────────────────────────────────────────────────────────┘
```

#### 5. Built-in Templates

**Pre-loaded templates** (20+ included):

1. **XSS - Reflected (Basic)** - Standard XSS testing
2. **XSS - Reflected (Aggressive)** - With WAF bypass
3. **XSS - Stored** - Persistent XSS testing
4. **XSS - DOM Based** - Client-side XSS
5. **SQLi - Error Based** - SQL injection with errors
6. **SQLi - Blind Boolean** - Boolean-based blind SQLi
7. **SQLi - Time Based** - Time-based blind SQLi
8. **SSTI - Detection** - Template injection detection
9. **SSTI - Exploitation** - Template injection exploitation
10. **Command Injection** - OS command injection
11. **SSRF - Basic** - Server-side request forgery
12. **SSRF - Cloud Metadata** - AWS/GCP metadata access
13. **Auth Bypass - Logic Flaws** - Authentication bypass
14. **API Security Audit** - REST/GraphQL testing
15. **WAF Bypass - Generic** - Generic WAF evasion
16. **WAF Bypass - Cloudflare** - Cloudflare-specific
17. **Parameter Discovery** - Hidden parameter finding
18. **Endpoint Analysis** - Endpoint reconnaissance
19. **Error Message Analysis** - Error-based info disclosure
20. **Quick Vulnerability Scan** - Fast general scan

#### 6. Implementation Steps

**Step 1**: Create data models (1 day)
- PromptTemplate.java
- VariableContext.java
- VariableProcessor.java

**Step 2**: Create manager (1 day)
- PromptTemplateManager.java
- JSON serialization/deserialization
- File I/O operations
- Built-in template loading

**Step 3**: Create UI (1 day)
- PromptTemplatePanel.java (Settings tab)
- Template list view
- Template editor
- Variable insertion helper

**Step 4**: Integration (0.5 days)
- Modify TestingSuggestionsPanel.java
- Add template dropdown
- Replace hardcoded prompts with template system
- Add "Manage Templates" button

**Step 5**: Testing (0.5 days)
- Test variable substitution
- Test import/export
- Test built-in templates
- Test custom templates

**Total**: 3 days

---

## Feature 2: Payload Library Manager

### What It Does

Centralized payload management system that:
- Stores payloads organized by vulnerability type
- Imports from PayloadsAllTheThings, SecLists, custom files
- Provides context-aware payload suggestions
- Tracks which payloads worked/failed
- Integrates with AI for payload generation

### User Experience

**Scenario**: Testing for XSS
```
1. User right-clicks parameter in Repeater
2. Selects "VISTA → Insert Payload → XSS → Reflected"
3. Dropdown shows:
   - <script>alert(1)</script>
   - <img src=x onerror=alert(1)>
   - "><script>alert(1)</script>
   - [20 more payloads...]
   - [AI Generate Custom Payload...]
4. User selects payload, it's inserted
5. After testing, user marks as "Worked" or "Failed"
6. AI learns from successful payloads
```

### Implementation Details

#### 1. Data Model

**PayloadLibrary.java**:
```java
public class PayloadLibrary {
    private String id;
    private String name;              // "XSS - Reflected"
    private String category;          // "XSS", "SQLi", "SSTI", etc.
    private String subcategory;       // "Reflected", "Stored", "DOM"
    private List<Payload> payloads;
    private boolean isBuiltIn;
    private String source;            // "PayloadsAllTheThings", "Custom"
}

public class Payload {
    private String id;
    private String value;             // Actual payload
    private String description;       // "Basic alert payload"
    private List<String> tags;        // ["basic", "unencoded"]
    private String encoding;          // "none", "url", "base64", "double-url"
    private String context;           // "html-body", "html-attribute", "javascript"
    private int successCount;         // How many times it worked
    private int failureCount;         // How many times it failed
    private double successRate;       // Calculated
    private long lastUsed;
}
```

**PayloadTestResult.java**:
```java
public class PayloadTestResult {
    private String payloadId;
    private String targetUrl;
    private String parameter;
    private boolean success;
    private String response;
    private long timestamp;
    private String notes;
}
```

#### 2. Core Classes

**PayloadLibraryManager.java**:
```java
public class PayloadLibraryManager {
    private static PayloadLibraryManager instance;
    private Map<String, PayloadLibrary> libraries;
    private List<PayloadTestResult> testHistory;
    private String payloadsDir = System.getProperty("user.home") + "/.vista/payloads/";
    
    // Library Management
    public List<PayloadLibrary> getAllLibraries();
    public PayloadLibrary getLibrary(String id);
    public void saveLibrary(PayloadLibrary library);
    public void deleteLibrary(String id);
    
    // Payload Operations
    public List<Payload> getPayloadsByCategory(String category);
    public List<Payload> getPayloadsByContext(String context);
    public List<Payload> searchPayloads(String query);
    public Payload getTopPayload(String category); // Highest success rate
    
    // Import/Export
    public void importFromFile(File file, String format); // JSON, TXT, CSV
    public void importFromPayloadsAllTheThings();
    public void importFromSecLists();
    public void exportLibrary(String id, File destination);
    
    // Testing History
    public void recordTestResult(PayloadTestResult result);
    public List<PayloadTestResult> getTestHistory(String payloadId);
    public void updatePayloadStats(String payloadId, boolean success);
    
    // AI Integration
    public String generatePayload(String category, String context, 
                                  String wafType, String observations);
}
```

#### 3. UI Components

**PayloadLibraryPanel.java** (new tab in Settings):

```
┌─────────────────────────────────────────────────────────────┐
│  Payload Library Manager                                     │
├─────────────────────────────────────────────────────────────┤
│  Category: [XSS ▼]  Context: [All ▼]  Tags: [waf-bypass]   │
│  Search: [alert]  [+ Add] [Import] [Export] [AI Generate]  │
├─────────────────────────────────────────────────────────────┤
│  ┌─ Payload List ───────────────────────────────────────┐   │
│  │ ✓ <script>alert(1)</script>                          │   │
│  │   Success: 45/50 (90%)  Last used: 2 days ago        │   │
│  │   Tags: basic, unencoded  Context: html-body          │   │
│  │                                                       │   │
│  │ ✓ <img src=x onerror=alert(1)>                       │   │
│  │   Success: 38/42 (90%)  Last used: 1 week ago        │   │
│  │   Tags: event-handler  Context: html-body             │   │
│  │                                                       │   │
│  │ ✓ "><script>alert(1)</script>                        │   │
│  │   Success: 12/20 (60%)  Last used: 3 days ago        │   │
│  │   Tags: attribute-break  Context: html-attribute      │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─ Payload Details ────────────────────────────────────┐   │
│  │ Payload: <script>alert(1)</script>                   │   │
│  │ Description: Basic XSS alert payload                  │   │
│  │ Category: XSS → Reflected                             │   │
│  │ Context: HTML Body                                    │   │
│  │ Encoding: None                                        │   │
│  │ Tags: [basic] [unencoded] [+ Add Tag]                │   │
│  │                                                       │   │
│  │ Statistics:                                           │   │
│  │   Success: 45 times (90%)                             │   │
│  │   Failed: 5 times (10%)                               │   │
│  │   Last used: 2 days ago                               │   │
│  │                                                       │   │
│  │ Recent Tests:                                         │   │
│  │   ✓ example.com/search?q=... (200 OK)                │   │
│  │   ✓ test.com/api/search (200 OK)                     │   │
│  │   ✗ secure.com/search (403 Forbidden - WAF)          │   │
│  │                                                       │   │
│  │ [Edit] [Duplicate] [Delete] [View Test History]      │   │
│  └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Context Menu Integration** (in Repeater):
```
Right-click on parameter value → VISTA →
  ├─ Insert Payload →
  │   ├─ XSS →
  │   │   ├─ Reflected (20 payloads)
  │   │   ├─ Stored (15 payloads)
  │   │   └─ DOM Based (10 payloads)
  │   ├─ SQLi →
  │   │   ├─ Error Based (25 payloads)
  │   │   ├─ Blind Boolean (20 payloads)
  │   │   └─ Time Based (15 payloads)
  │   └─ [More categories...]
  ├─ AI Generate Payload...
  └─ Mark Last Payload As →
      ├─ ✓ Worked
      └─ ✗ Failed
```

#### 4. Built-in Payload Libraries

**Pre-loaded libraries** (1000+ payloads):

1. **XSS - Reflected** (100 payloads)
   - Basic alerts
   - Event handlers
   - Attribute breaks
   - Tag breaks
   - Encoded variants

2. **XSS - WAF Bypass** (50 payloads)
   - Cloudflare bypasses
   - AWS WAF bypasses
   - Generic obfuscation

3. **SQLi - Error Based** (80 payloads)
   - MySQL errors
   - PostgreSQL errors
   - MSSQL errors
   - Oracle errors

4. **SQLi - Blind** (60 payloads)
   - Boolean-based
   - Time-based
   - Out-of-band

5. **SSTI - Detection** (40 payloads)
   - Jinja2
   - Twig
   - Freemarker
   - Velocity

6. **Command Injection** (50 payloads)
   - Linux commands
   - Windows commands
   - Command chaining
   - Encoded variants

7. **SSRF** (30 payloads)
   - Internal IPs
   - Cloud metadata
   - Protocol smuggling

8. **Path Traversal** (40 payloads)
   - Basic traversal
   - Encoded variants
   - Null byte injection

#### 5. AI Payload Generation

**Integration with AI**:
```java
public String generatePayload(String category, String context, 
                              String wafType, String observations) {
    String prompt = """
        Generate a %s payload for the following context:
        
        Context: %s
        WAF Detected: %s
        Previous Observations: %s
        
        Requirements:
        - Must work in the specified context
        - Must bypass the detected WAF
        - Should be based on successful patterns
        - Provide 3 variations
        
        Format: One payload per line
        """.formatted(category, context, wafType, observations);
    
    String response = callAI(prompt);
    
    // Parse response and add to library
    List<String> payloads = parsePayloads(response);
    for (String payload : payloads) {
        addPayload(new Payload(payload, "AI Generated", category));
    }
    
    return response;
}
```

#### 6. Import from PayloadsAllTheThings

**Automated import**:
```java
public void importFromPayloadsAllTheThings() {
    // Download from GitHub
    String baseUrl = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/";
    
    Map<String, String> categories = Map.of(
        "XSS Injection", "XSS injection/README.md",
        "SQL Injection", "SQL Injection/README.md",
        "SSTI", "Server Side Template Injection/README.md",
        "Command Injection", "Command Injection/README.md"
    );
    
    for (Map.Entry<String, String> entry : categories.entrySet()) {
        String content = downloadFile(baseUrl + entry.getValue());
        List<Payload> payloads = parseMarkdown(content);
        saveLibrary(new PayloadLibrary(entry.getKey(), payloads));
    }
}
```

#### 7. Implementation Steps

**Step 1**: Create data models (1 day)
- PayloadLibrary.java
- Payload.java
- PayloadTestResult.java

**Step 2**: Create manager (1.5 days)
- PayloadLibraryManager.java
- Import/export functionality
- Statistics tracking
- AI integration

**Step 3**: Create UI (1.5 days)
- PayloadLibraryPanel.java
- Context menu integration
- Payload insertion logic

**Step 4**: Built-in libraries (1 day)
- Create 1000+ payloads
- Organize by category
- Add metadata

**Total**: 5 days

---

## Feature 3: Testing Workflow Presets

### What It Does

Automated testing sequences that guide users through systematic vulnerability testing. Instead of manual ad-hoc testing, users follow proven workflows.

### User Experience

**Scenario**: Testing for SQLi
```
1. User selects "SQLi - Complete Audit" workflow
2. Workflow starts:
   Step 1/5: Error-based detection
   → AI suggests: ' OR '1'='1
   → User tests in Repeater
   → User reports: "Got SQL error"
   
3. Workflow auto-advances:
   Step 2/5: Determine database type
   → AI suggests: ' AND 1=1-- (MySQL test)
   → User tests
   → User reports: "Works"
   
4. Workflow continues through all steps
5. At end, generates summary report
```

### Implementation Details

#### 1. Data Model

**WorkflowPreset.java**:
```java
public class WorkflowPreset {
    private String id;
    private String name;              // "SQLi - Complete Audit"
    private String category;          // "Exploitation", "Reconnaissance"
    private String description;
    private List<WorkflowStep> steps;
    private boolean isBuiltIn;
    private String author;
    
    // Execution settings
    private boolean autoAdvance;      // Auto-advance on success
    private boolean requireConfirmation;
    private int estimatedTime;        // Minutes
}

public class WorkflowStep {
    private int stepNumber;
    private String name;              // "Error-based detection"
    private String description;
    private String promptTemplate;    // Template ID to use
    private List<String> payloads;    // Suggested payloads
    private SuccessCriteria successCriteria;
    private String nextStepOnSuccess; // Step ID or "auto"
    private String nextStepOnFailure;
    private boolean optional;
}

public class SuccessCriteria {
    private List<String> responseContains;    // ["error", "SQL"]
    private List<Integer> statusCodes;        // [200, 500]
    private String responseSizeChange;        // "increase", "decrease"
    private String customPattern;             // Regex
}
```

**WorkflowExecution.java**:
```java
public class WorkflowExecution {
    private String id;
    private String workflowId;
    private IHttpRequestResponse targetRequest;
    private int currentStep;
    private List<WorkflowStepResult> results;
    private long startTime;
    private long endTime;
    private String status;            // "running", "completed", "paused"
}

public class WorkflowStepResult {
    private int stepNumber;
    private String payload;
    private IHttpRequestResponse request;
    private boolean success;
    private String observation;
    private long timestamp;
}
```

#### 2. Core Classes

**WorkflowPresetManager.java**:
```java
public class WorkflowPresetManager {
    private static WorkflowPresetManager instance;
    private Map<String, WorkflowPreset> presets;
    private Map<String, WorkflowExecution> activeExecutions;
    
    // Preset Management
    public List<WorkflowPreset> getAllPresets();
    public WorkflowPreset getPreset(String id);
    public void savePreset(WorkflowPreset preset);
    public void deletePreset(String id);
    
    // Execution
    public WorkflowExecution startWorkflow(String presetId, IHttpRequestResponse request);
    public void advanceStep(String executionId, WorkflowStepResult result);
    public void pauseWorkflow(String executionId);
    public void resumeWorkflow(String executionId);
    public void cancelWorkflow(String executionId);
    
    // Analysis
    public boolean evaluateSuccessCriteria(SuccessCriteria criteria, 
                                          IHttpRequestResponse response);
    public String generateWorkflowReport(String executionId);
}
```

#### 3. UI Components

**WorkflowExecutionPanel.java** (new panel in AI Advisor):
```
┌─────────────────────────────────────────────────────────────┐
│  Workflow: SQLi - Complete Audit                    [Pause] │
├─────────────────────────────────────────────────────────────┤
│  Progress: ████████░░░░░░░░░░  Step 3/5 (60%)              │
│                                                               │
│  ✓ Step 1: Error-based detection (Success)                  │
│  ✓ Step 2: Determine database type (Success - MySQL)        │
│  ▶ Step 3: Extract database version                         │
│  ○ Step 4: Enumerate tables                                 │
│  ○ Step 5: Extract data                                     │
├─────────────────────────────────────────────────────────────┤
│  Current Step: Extract database version                     │
│                                                               │
│  🤖 AI Suggestion:                                           │
│  Based on MySQL detection, try:                              │
│  ' UNION SELECT @@version--                                  │
│                                                               │
│  📋 Instructions:                                            │
│  1. Copy the payload above                                   │
│  2. Insert into the 'id' parameter in Repeater              │
│  3. Send the request                                         │
│  4. Report what you observe below                            │
│                                                               │
│  Your observation: [I see version 5.7.33 in response    ]   │
│  [Mark as Success] [Mark as Failed] [Skip Step]             │
└─────────────────────────────────────────────────────────────┘
```

**Workflow Selector** (in AI Advisor):
```
┌─────────────────────────────────────────────────────────────┐
│  Start Testing Workflow                                      │
├─────────────────────────────────────────────────────────────┤
│  Category: [Exploitation ▼]                                  │
│                                                               │
│  Available Workflows:                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ▶ XSS - Quick Scan (5 steps, ~10 min)              │   │
│  │   Test for reflected XSS with common payloads       │   │
│  │                                                      │   │
│  │ ▶ SQLi - Complete Audit (5 steps, ~20 min)         │   │
│  │   Systematic SQL injection testing                  │   │
│  │                                                      │   │
│  │ ▶ SSTI - Detection & Exploitation (4 steps, ~15min)│   │
│  │   Detect and exploit template injection            │   │
│  │                                                      │   │
│  │ ▶ Auth Bypass - Logic Flaws (6 steps, ~25 min)     │   │
│  │   Test authentication mechanisms                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
│  [Start Workflow] [Preview Steps] [Cancel]                  │
└─────────────────────────────────────────────────────────────┘
```

#### 4. Built-in Workflows

**Pre-loaded workflows** (15+ included):

1. **XSS - Quick Scan** (5 steps)
   - Reflection detection
   - Basic payload test
   - Encoded payload test
   - Event handler test
   - Verification

2. **XSS - WAF Bypass** (7 steps)
   - WAF detection
   - Basic payload (baseline)
   - Encoding bypass
   - Obfuscation bypass
   - Case variation
   - Protocol smuggling
   - Verification

3. **SQLi - Complete Audit** (5 steps)
   - Error-based detection
   - Database type identification
   - Version extraction
   - Table enumeration
   - Data extraction

4. **SQLi - Blind Testing** (6 steps)
   - Boolean-based detection
   - True/false baseline
   - Character extraction setup
   - Database name extraction
   - Table enumeration
   - Verification

5. **SSTI - Detection & Exploitation** (4 steps)
   - Template engine detection
   - Basic injection test
   - Code execution test
   - Privilege escalation

6. **Command Injection** (5 steps)
   - Basic injection test
   - Command chaining
   - Output extraction
   - Blind detection
   - Reverse shell

7. **SSRF - Internal Access** (4 steps)
   - Basic SSRF test
   - Internal IP scanning
   - Cloud metadata access
   - Port scanning

8. **Auth Bypass - Logic Flaws** (6 steps)
   - Direct object reference
   - Parameter manipulation
   - HTTP method tampering
   - Header manipulation
   - Session fixation
   - Verification

#### 5. Implementation Steps

**Step 1**: Create data models (1 day)
- WorkflowPreset.java
- WorkflowStep.java
- WorkflowExecution.java
- SuccessCriteria.java

**Step 2**: Create manager (1.5 days)
- WorkflowPresetManager.java
- Execution engine
- Success criteria evaluation

**Step 3**: Create UI (2 days)
- WorkflowExecutionPanel.java
- Workflow selector dialog
- Progress tracking
- Step navigation

**Step 4**: Built-in workflows (1.5 days)
- Create 15+ workflows
- Define steps and criteria
- Test execution flow

**Total**: 6 days

---

## Feature 4: Smart Finding Manager

### What It Does

Automated vulnerability documentation system that captures evidence, generates reports, and manages findings throughout the testing process.

### User Experience

**Scenario**: Found XSS vulnerability
```
1. User tests payload in Repeater
2. Payload works!
3. User clicks "Add to Findings" button
4. Dialog appears:
   - Auto-filled: Vulnerability type (XSS)
   - Auto-filled: Severity (High)
   - Auto-filled: Request/Response
   - Auto-filled: AI-generated description
5. User adds screenshot, notes
6. Finding saved
7. At end of test, export all findings as report
```

### Implementation Details

#### 1. Data Model

**Finding.java**:
```java
public class Finding {
    private String id;
    private String title;             // "Reflected XSS in search parameter"
    private String vulnerabilityType; // "XSS", "SQLi", etc.
    private Severity severity;        // CRITICAL, HIGH, MEDIUM, LOW, INFO
    private Confidence confidence;    // CERTAIN, FIRM, TENTATIVE
    
    // Evidence
    private IHttpRequestResponse originalRequest;
    private IHttpRequestResponse pocRequest;
    private String payload;
    private List<byte[]> screenshots;
    private String description;       // AI-generated
    private String impact;
    private String remediation;
    
    // Metadata
    private String targetUrl;
    private String parameter;
    private long discoveredAt;
    private String discoveredBy;
    private List<String> tags;
    private String status;            // "new", "verified", "false-positive"
    
    // Timeline
    private List<FindingEvent> timeline;
}

public class FindingEvent {
    private long timestamp;
    private String eventType;         // "created", "verified", "updated"
    private String description;
    private IHttpRequestResponse request;
}

public enum Severity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO
}

public enum Confidence {
    CERTAIN, FIRM, TENTATIVE
}
```

**FindingTemplate.java**:
```java
public class FindingTemplate {
    private String id;
    private String name;              // "HackerOne Format"
    private String platform;          // "HackerOne", "Bugcrowd", "Custom"
    private String titleFormat;
    private String descriptionFormat;
    private String impactFormat;
    private String stepsFormat;
    private String remediationFormat;
    private boolean includeScreenshots;
    private boolean includeCurl;
}
```

#### 2. Core Classes

**FindingManager.java** (enhance existing):
```java
public class FindingManager {
    private static FindingManager instance;
    private List<Finding> findings;
    private Map<String, FindingTemplate> templates;
    
    // Finding Management
    public void addFinding(Finding finding);
    public void updateFinding(String id, Finding finding);
    public void deleteFinding(String id);
    public List<Finding> getAllFindings();
    public List<Finding> getFindingsBySeverity(Severity severity);
    public Finding getFinding(String id);
    
    // AI Integration
    public String generateDescription(Finding finding);
    public String generateImpact(Finding finding);
    public String generateRemediation(Finding finding);
    public Severity suggestSeverity(Finding finding);
    
    // Evidence Collection
    public void addScreenshot(String findingId, byte[] screenshot);
    public void addTimelineEvent(String findingId, FindingEvent event);
    
    // Duplicate Detection
    public List<Finding> findSimilar(Finding finding);
    public boolean isDuplicate(Finding finding);
    
    // Export
    public String exportAsMarkdown(List<Finding> findings, FindingTemplate template);
    public String exportAsHTML(List<Finding> findings, FindingTemplate template);
    public byte[] exportAsPDF(List<Finding> findings, FindingTemplate template);
    public String exportAsJSON(List<Finding> findings);
    
    // Bulk Operations
    public void markAsFalsePositive(List<String> findingIds);
    public void changeSeverity(List<String> findingIds, Severity newSeverity);
    public void addTagToFindings(List<String> findingIds, String tag);
}
```

#### 3. UI Components

**Enhanced FindingsPanel.java**:

```
┌─────────────────────────────────────────────────────────────┐
│  Findings Manager                                            │
├─────────────────────────────────────────────────────────────┤
│  Filter: [All ▼] [Critical] [High] [Medium] [Low]          │
│  Status: [All ▼] [New] [Verified] [False Positive]         │
│  Search: [XSS]  [+ Add Finding] [Export] [Bulk Actions ▼]  │
├─────────────────────────────────────────────────────────────┤
│  ┌─ Findings List ──────────────────────────────────────┐   │
│  │ 🔴 CRITICAL: SQL Injection in login                  │   │
│  │    example.com/login  Discovered: 2 hours ago        │   │
│  │                                                       │   │
│  │ 🟠 HIGH: Reflected XSS in search                     │   │
│  │    example.com/search  Discovered: 3 hours ago       │   │
│  │                                                       │   │
│  │ 🟡 MEDIUM: Missing security headers                  │   │
│  │    example.com/*  Discovered: 1 day ago              │   │
│  │                                                       │   │
│  │ 🟢 LOW: Information disclosure                       │   │
│  │    example.com/api/info  Discovered: 2 days ago      │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─ Finding Details ────────────────────────────────────┐   │
│  │ Title: Reflected XSS in search parameter             │   │
│  │ Type: Cross-Site Scripting (XSS)                     │   │
│  │ Severity: HIGH  Confidence: CERTAIN                  │   │
│  │ Target: https://example.com/search?q=test            │   │
│  │ Parameter: q                                          │   │
│  │ Discovered: 3 hours ago by @pentester                │   │
│  │ Tags: [reflected-xss] [unfiltered] [+ Add]           │   │
│  │                                                       │   │
│  │ Description: (AI-Generated)                           │   │
│  │ ┌─────────────────────────────────────────────────┐ │   │
│  │ │The application reflects user input from the 'q'│ │   │
│  │ │parameter without proper sanitization. This     │ │   │
│  │ │allows an attacker to inject arbitrary          │ │   │
│  │ │JavaScript code that executes in the victim's   │ │   │
│  │ │browser context...                              │ │   │
│  │ └─────────────────────────────────────────────────┘ │   │
│  │                                                       │   │
│  │ Proof of Concept:                                     │   │
│  │ Payload: <script>alert(document.domain)</script>     │   │
│  │ [View Request] [View Response] [Copy cURL]           │   │
│  │                                                       │   │
│  │ Screenshots: (2)                                      │   │
│  │ [📷 Payload in URL] [📷 Alert popup]                 │   │
│  │                                                       │   │
│  │ Timeline: (3 events)                                  │   │
│  │ • Created 3 hours ago                                 │   │
│  │ • Verified 2 hours ago                                │   │
│  │ • Updated severity 1 hour ago                         │   │
│  │                                                       │   │
│  │ [Edit] [Verify] [Mark False Positive] [Delete]       │   │
│  └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Quick Add Finding Dialog**:
```
┌─────────────────────────────────────────────────────────────┐
│  Add Finding                                                 │
├─────────────────────────────────────────────────────────────┤
│  Title: [Reflected XSS in search parameter              ]   │
│  Type: [XSS ▼]  Severity: [High ▼]  Confidence: [Certain ▼]│
│                                                               │
│  Target URL: [https://example.com/search?q=test         ]   │
│  Parameter: [q                                          ]   │
│  Payload: [<script>alert(1)</script>                    ]   │
│                                                               │
│  Description: (AI-Generated - Click to edit)                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │The application reflects user input from the 'q'     │   │
│  │parameter without proper sanitization...             │   │
│  └─────────────────────────────────────────────────────┘   │
│  [🤖 Regenerate with AI]                                    │
│                                                               │
│  Evidence:                                                    │
│  ✓ Request/Response attached                                 │
│  [📷 Add Screenshot] [📎 Attach Additional Request]         │
│                                                               │
│  Tags: [reflected-xss] [unfiltered] [+ Add]                 │
│                                                               │
│  [Save Finding] [Save & Continue Testing] [Cancel]          │
└─────────────────────────────────────────────────────────────┘
```

**Export Dialog**:
```
┌─────────────────────────────────────────────────────────────┐
│  Export Findings                                             │
├─────────────────────────────────────────────────────────────┤
│  Select Findings:                                            │
│  ☑ All findings (4)                                          │
│  ☐ Only selected (2)                                         │
│  ☐ By severity: [High ▼]                                     │
│                                                               │
│  Template: [HackerOne Format ▼]                              │
│  ├─ HackerOne Format                                         │
│  ├─ Bugcrowd Format                                          │
│  ├─ Intigriti Format                                         │
│  ├─ OWASP Format                                             │
│  └─ Custom Template...                                       │
│                                                               │
│  Format: [Markdown ▼]                                        │
│  ├─ Markdown (.md)                                           │
│  ├─ HTML (.html)                                             │
│  ├─ PDF (.pdf)                                               │
│  └─ JSON (.json)                                             │
│                                                               │
│  Options:                                                     │
│  ☑ Include screenshots                                       │
│  ☑ Include full requests/responses                           │
│  ☑ Include cURL commands                                     │
│  ☑ Include timeline                                          │
│  ☐ Redact sensitive data                                     │
│                                                               │
│  [Preview] [Export] [Cancel]                                 │
└─────────────────────────────────────────────────────────────┘
```

#### 4. AI-Generated Content

**Description Generation**:
```java
public String generateDescription(Finding finding) {
    String prompt = """
        Generate a professional vulnerability description for a bug bounty report.
        
        Vulnerability Type: %s
        Target URL: %s
        Parameter: %s
        Payload: %s
        
        Request:
        %s
        
        Response:
        %s
        
        Requirements:
        - Professional tone
        - Clear explanation of the vulnerability
        - Technical details
        - 2-3 paragraphs
        - No recommendations (separate section)
        
        Format: Plain text, no markdown
        """.formatted(
            finding.getVulnerabilityType(),
            finding.getTargetUrl(),
            finding.getParameter(),
            finding.getPayload(),
            truncate(requestToString(finding.getPocRequest()), 1000),
            truncate(responseToString(finding.getPocRequest()), 1000)
        );
    
    return callAI(prompt);
}
```

**Impact Generation**:
```java
public String generateImpact(Finding finding) {
    String prompt = """
        Generate the security impact section for this vulnerability.
        
        Vulnerability Type: %s
        Severity: %s
        Context: %s
        
        Requirements:
        - Explain what an attacker can do
        - Real-world attack scenarios
        - Business impact
        - 2-3 paragraphs
        
        Format: Plain text
        """.formatted(
            finding.getVulnerabilityType(),
            finding.getSeverity(),
            finding.getDescription()
        );
    
    return callAI(prompt);
}
```

#### 5. Finding Templates

**HackerOne Template**:
```markdown
# {{TITLE}}

## Summary
{{DESCRIPTION}}

## Steps to Reproduce
1. Navigate to {{TARGET_URL}}
2. Enter the following payload in the {{PARAMETER}} parameter:
   ```
   {{PAYLOAD}}
   ```
3. Observe that {{OBSERVATION}}

## Proof of Concept
**Request:**
```http
{{REQUEST}}
```

**Response:**
```http
{{RESPONSE}}
```

**cURL Command:**
```bash
{{CURL}}
```

## Impact
{{IMPACT}}

## Remediation
{{REMEDIATION}}

## Supporting Material/References
{{SCREENSHOTS}}

## Severity Assessment
- **Severity:** {{SEVERITY}}
- **Difficulty:** {{DIFFICULTY}}
- **CVSS Score:** {{CVSS}}
```

#### 6. Implementation Steps

**Step 1**: Enhance data models (1 day)
- Finding.java (enhance existing)
- FindingTemplate.java
- FindingEvent.java

**Step 2**: Enhance manager (1.5 days)
- FindingManager.java (enhance existing)
- AI content generation
- Duplicate detection
- Export functionality

**Step 3**: Enhance UI (2 days)
- FindingsPanel.java (enhance existing)
- Quick add dialog
- Export dialog
- Timeline view

**Step 4**: Templates (1 day)
- Create 5+ report templates
- Test export formats
- PDF generation

**Total**: 5.5 days

---

## Feature 5: Request Collection & Comparison Engine

### What It Does

Organize requests into named collections and perform intelligent comparison and pattern analysis across multiple requests.

### User Experience

**Scenario**: Testing multiple search endpoints
```
1. User creates collection "Search Endpoints"
2. Adds 10 search requests from different pages
3. Clicks "Analyze Collection"
4. AI identifies:
   - Common parameters: q, query, search
   - Different filtering: Some have XSS protection, some don't
   - Pattern: Admin search has no filtering!
5. User focuses on vulnerable endpoint
```

### Implementation Details

#### 1. Data Model

**RequestCollection.java**:
```java
public class RequestCollection {
    private String id;
    private String name;              // "Search Endpoints"
    private String description;
    private List<CollectionItem> items;
    private List<String> tags;
    private long createdAt;
    private long modifiedAt;
    private String color;             // For visual organization
}

public class CollectionItem {
    private String id;
    private IHttpRequestResponse request;
    private String label;             // User-defined label
    private String notes;
    private long addedAt;
    private Map<String, String> metadata;
}

public class CollectionAnalysis {
    private String collectionId;
    private List<String> commonParameters;
    private List<String> uniqueParameters;
    private Map<String, List<String>> parameterValues;
    private List<PatternMatch> patterns;
    private List<Difference> differences;
    private String aiSummary;
}

public class PatternMatch {
    private String pattern;           // "All use 'q' parameter"
    private List<String> matchingItems;
    private String significance;      // AI explanation
}

public class Difference {
    private String aspect;            // "Security headers"
    private Map<String, String> values; // item_id -> value
    private String significance;
}
```

#### 2. Core Classes

**RequestCollectionManager.java**:
```java
public class RequestCollectionManager {
    private static RequestCollectionManager instance;
    private Map<String, RequestCollection> collections;
    
    // Collection Management
    public RequestCollection createCollection(String name);
    public void deleteCollection(String id);
    public List<RequestCollection> getAllCollections();
    public RequestCollection getCollection(String id);
    
    // Item Management
    public void addItem(String collectionId, IHttpRequestResponse request, String label);
    public void removeItem(String collectionId, String itemId);
    public void updateItemLabel(String collectionId, String itemId, String label);
    public void updateItemNotes(String collectionId, String itemId, String notes);
    
    // Bulk Operations
    public void addFromProxyHistory(String collectionId, String urlPattern);
    public void addFromRepeater(String collectionId);
    public void addFromSitemap(String collectionId, String scope);
    
    // Analysis
    public CollectionAnalysis analyzeCollection(String collectionId);
    public String compareRequests(List<String> itemIds);
    public List<String> findCommonParameters(String collectionId);
    public Map<String, List<String>> groupByPattern(String collectionId, String pattern);
    
    // AI Integration
    public String generateCollectionSummary(String collectionId);
    public List<String> suggestTestingPriority(String collectionId);
    public String findVulnerabilityPatterns(String collectionId);
    
    // Export/Import
    public void exportCollection(String collectionId, File destination);
    public void importCollection(File source);
}
```

#### 3. UI Components

**RequestCollectionPanel.java** (new tab):
```
┌─────────────────────────────────────────────────────────────┐
│  Request Collections                                         │
├─────────────────────────────────────────────────────────────┤
│  [+ New Collection] [Import] [Export Selected]              │
│                                                               │
│  ┌─ Collections ────────────────────────────────────────┐   │
│  │ 🔵 Search Endpoints (10 requests)                    │   │
│  │ 🟢 Login Flows (5 requests)                          │   │
│  │ 🟡 Admin Panel (8 requests)                          │   │
│  │ 🔴 API Endpoints (15 requests)                       │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─ Collection: Search Endpoints ──────────────────────┐   │
│  │ Description: All search functionality endpoints      │   │
│  │ Created: 2 days ago  Modified: 1 hour ago            │   │
│  │ Tags: [search] [user-input] [+ Add]                  │   │
│  │                                                       │   │
│  │ Requests: (10)                                        │   │
│  │ ┌─────────────────────────────────────────────────┐ │   │
│  │ │ ☑ GET /search?q=test                            │ │   │
│  │ │   Label: Main search  Notes: No filtering       │ │   │
│  │ │                                                 │ │   │
│  │ │ ☑ GET /api/search?query=test                   │ │   │
│  │ │   Label: API search  Notes: JSON response      │ │   │
│  │ │                                                 │ │   │
│  │ │ ☑ POST /search/advanced                        │ │   │
│  │ │   Label: Advanced search  Notes: Multiple params│ │   │
│  │ │                                                 │ │   │
│  │ │ [+ Add from Repeater] [+ Add from Proxy]       │ │   │
│  │ └─────────────────────────────────────────────────┘ │   │
│  │                                                       │   │
│  │ [Analyze Collection] [Compare Selected] [Bulk Test]  │   │
│  └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Collection Analysis View**:
```
┌─────────────────────────────────────────────────────────────┐
│  Collection Analysis: Search Endpoints                       │
├─────────────────────────────────────────────────────────────┤
│  🤖 AI Summary:                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │This collection contains 10 search endpoints. Key    │   │
│  │findings:                                             │   │
│  │                                                      │   │
│  │1. All endpoints accept user input via 'q' or       │   │
│  │   'query' parameters                                │   │
│  │2. 7/10 endpoints reflect input in HTML response    │   │
│  │3. Admin search (/admin/search) has NO XSS          │   │
│  │   protection - HIGH PRIORITY TARGET                 │   │
│  │4. API endpoints return JSON (lower XSS risk)       │   │
│  │5. Advanced search uses POST with multiple params   │   │
│  │                                                      │   │
│  │Recommended testing order:                           │   │
│  │1. /admin/search (highest risk)                     │   │
│  │2. /search (main endpoint)                          │   │
│  │3. /search/advanced (complex logic)                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
│  📊 Common Parameters:                                       │
│  • q (6 endpoints)                                           │
│  • query (3 endpoints)                                       │
│  • filter (4 endpoints)                                      │
│  • page (8 endpoints)                                        │
│                                                               │
│  🔍 Unique Parameters:                                       │
│  • /admin/search: admin_token                                │
│  • /search/advanced: category, date_from, date_to            │
│                                                               │
│  ⚠️ Security Differences:                                    │
│  • XSS Protection:                                           │
│    - Present: 7 endpoints                                    │
│    - MISSING: /admin/search, /legacy/search, /debug/search  │
│  • Rate Limiting:                                            │
│    - Present: 5 endpoints                                    │
│    - Missing: 5 endpoints                                    │
│                                                               │
│  [Export Report] [Start Testing Workflow] [Close]           │
└─────────────────────────────────────────────────────────────┘
```

**Side-by-Side Comparison**:
```
┌─────────────────────────────────────────────────────────────┐
│  Compare Requests (2 selected)                               │
├─────────────────────────────────────────────────────────────┤
│  Request 1: /search?q=test    │  Request 2: /admin/search   │
├───────────────────────────────┼─────────────────────────────┤
│  GET /search?q=test HTTP/1.1  │  GET /admin/search?q=test   │
│  Host: example.com            │  Host: example.com          │
│  Cookie: session=abc123       │  Cookie: session=abc123     │
│                               │  Cookie: admin_token=xyz    │ ◄─ DIFFERENCE
│  ─────────────────────────────┼─────────────────────────────┤
│  HTTP/1.1 200 OK              │  HTTP/1.1 200 OK            │
│  Content-Type: text/html      │  Content-Type: text/html    │
│  X-XSS-Protection: 1          │  (missing)                  │ ◄─ DIFFERENCE
│                               │                             │
│  <div>Results for: test</div> │  <div>Results for: test</div>│
│  (HTML encoded)               │  (NOT encoded)              │ ◄─ CRITICAL
│                               │                             │
│  🤖 AI Analysis:                                             │
│  The admin search endpoint is missing XSS protection and    │
│  does not encode user input. This is a HIGH SEVERITY        │
│  reflected XSS vulnerability. Test with:                    │
│  <script>alert(document.domain)</script>                    │
└─────────────────────────────────────────────────────────────┘
```

#### 4. Bulk Import

**Import from Proxy History**:
```java
public void addFromProxyHistory(String collectionId, String urlPattern) {
    // Get all proxy history
    IHttpRequestResponse[] history = callbacks.getProxyHistory();
    
    Pattern pattern = Pattern.compile(urlPattern);
    int added = 0;
    
    for (IHttpRequestResponse item : history) {
        String url = helpers.analyzeRequest(item).getUrl().toString();
        if (pattern.matcher(url).find()) {
            addItem(collectionId, item, extractLabel(url));
            added++;
        }
    }
    
    callbacks.printOutput("Added " + added + " requests to collection");
}
```

#### 5. AI-Powered Analysis

**Pattern Detection**:
```java
public String findVulnerabilityPatterns(String collectionId) {
    RequestCollection collection = getCollection(collectionId);
    
    // Build analysis context
    StringBuilder context = new StringBuilder();
    for (CollectionItem item : collection.getItems()) {
        context.append("Request: ").append(requestToString(item.getRequest())).append("\n");
        context.append("Response: ").append(responseToString(item.getRequest())).append("\n\n");
    }
    
    String prompt = """
        Analyze these %d related requests and identify vulnerability patterns.
        
        %s
        
        Focus on:
        1. Inconsistent security controls
        2. Missing protections in some endpoints
        3. Different input validation
        4. Privilege escalation opportunities
        5. Logic flaws
        
        Provide:
        - List of identified patterns
        - Security implications
        - Testing priority order
        - Specific payloads to try
        
        Format as structured analysis.
        """.formatted(collection.getItems().size(), truncate(context.toString(), 8000));
    
    return callAI(prompt);
}
```

#### 6. Implementation Steps

**Step 1**: Create data models (1 day)
- RequestCollection.java
- CollectionItem.java
- CollectionAnalysis.java

**Step 2**: Create manager (1.5 days)
- RequestCollectionManager.java
- Bulk import functionality
- Analysis engine

**Step 3**: Create UI (2 days)
- RequestCollectionPanel.java
- Analysis view
- Comparison view

**Step 4**: AI integration (1 day)
- Pattern detection
- Summary generation
- Priority suggestions

**Total**: 5.5 days

---

## Customization Management Architecture

### Centralized Storage

All customizations stored in `~/.vista/`:
```
~/.vista/
├── config.json              # Global settings
├── prompts/
│   ├── built-in/
│   │   ├── xss-reflected.json
│   │   ├── sqli-error.json
│   │   └── ...
│   └── custom/
│       ├── my-api-test.json
│       └── ...
├── payloads/
│   ├── built-in/
│   │   ├── xss-reflected.json
│   │   ├── sqli-mysql.json
│   │   └── ...
│   └── custom/
│       └── my-payloads.json
├── workflows/
│   ├── built-in/
│   │   ├── xss-quick-scan.json
│   │   └── ...
│   └── custom/
│       └── my-workflow.json
├── findings/
│   ├── templates/
│   │   ├── hackerone.json
│   │   └── ...
│   └── findings.json
├── collections/
│   ├── search-endpoints.json
│   └── ...
└── backups/
    └── [automatic backups]
```

### JSON Format Examples

**Prompt Template**:
```json
{
  "id": "xss-reflected-aggressive",
  "name": "XSS - Reflected (Aggressive)",
  "category": "Exploitation",
  "author": "@vista",
  "description": "Aggressive XSS testing with WAF bypass",
  "systemPrompt": "You are an expert XSS pentester...",
  "userPrompt": "Analyze for XSS:\n{{REQUEST}}\n\nReflection:\n{{REFLECTION_ANALYSIS}}\n\nWAF:\n{{WAF_DETECTION}}",
  "isBuiltIn": true,
  "isActive": true,
  "modelOverride": null,
  "temperatureOverride": null,
  "maxTokensOverride": null,
  "createdAt": 1706745600000,
  "modifiedAt": 1706745600000,
  "usageCount": 0,
  "tags": ["xss", "reflected", "waf-bypass"]
}
```

**Payload Library**:
```json
{
  "id": "xss-reflected",
  "name": "XSS - Reflected",
  "category": "XSS",
  "subcategory": "Reflected",
  "payloads": [
    {
      "id": "xss-001",
      "value": "<script>alert(1)</script>",
      "description": "Basic alert payload",
      "tags": ["basic", "unencoded"],
      "encoding": "none",
      "context": "html-body",
      "successCount": 45,
      "failureCount": 5,
      "successRate": 0.9,
      "lastUsed": 1706745600000
    }
  ],
  "isBuiltIn": true,
  "source": "PayloadsAllTheThings"
}
```

### Import/Export System

**Export Format** (ZIP file):
```
vista-export-2025-01-28.zip
├── manifest.json            # What's included
├── prompts/
│   └── *.json
├── payloads/
│   └── *.json
├── workflows/
│   └── *.json
└── collections/
    └── *.json
```

**Manifest**:
```json
{
  "exportedAt": 1706745600000,
  "exportedBy": "@pentester",
  "vistaVersion": "2.5.0",
  "includes": {
    "prompts": 5,
    "payloads": 2,
    "workflows": 3,
    "collections": 1
  }
}
```

---

## Summary

### Total Implementation Time

| Feature | Time | Priority |
|---------|------|----------|
| 1. Custom AI Prompt Templates | 3 days | ⭐⭐⭐⭐⭐ |
| 2. Payload Library Manager | 5 days | ⭐⭐⭐⭐⭐ |
| 3. Testing Workflow Presets | 6 days | ⭐⭐⭐⭐⭐ |
| 4. Smart Finding Manager | 5.5 days | ⭐⭐⭐⭐⭐ |
| 5. Request Collection Engine | 5.5 days | ⭐⭐⭐⭐⭐ |
| **TOTAL** | **25 days** | **Phase 1 & 2** |

### Key Benefits

1. **Flexibility**: Users can customize every aspect of VISTA
2. **Efficiency**: Automated workflows save hours per test
3. **Documentation**: Automatic finding generation and reporting
4. **Organization**: Collections and libraries keep everything organized
5. **Collaboration**: Easy import/export for team sharing
6. **Learning**: System learns from successful tests

### Next Steps

**Recommendation**: Implement in order (1 → 2 → 3 → 4 → 5) as each builds on previous features.

**Start with Feature #1** (Custom AI Prompt Templates) - it's the foundation for everything else.

Would you like me to begin implementation of Feature #1?
