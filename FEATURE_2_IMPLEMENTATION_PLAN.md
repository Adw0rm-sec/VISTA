# Feature 2: Payload Library Manager - Implementation Plan

## Overview

**Goal**: Create a centralized payload management system with 1000+ organized payloads, success tracking, and one-click insertion.

**Version**: VISTA v2.6.0  
**Estimated Time**: 4 days  
**Priority**: High (⭐⭐ PRACTICAL)  
**Dependencies**: None (standalone feature)

## What We're Building

### Core Functionality
1. **Payload Storage**: Organized by vulnerability type (XSS, SQLi, SSTI, etc.)
2. **Success Tracking**: Track which payloads work/fail
3. **Context-Aware**: Suggest payloads based on reflection context
4. **One-Click Insertion**: Right-click → Insert payload
5. **Import/Export**: Load from PayloadsAllTheThings, SecLists, custom files
6. **AI Integration**: Generate custom payloads on demand

### User Benefits
- ✅ 1000+ ready-to-use payloads
- ✅ No more hunting for payloads
- ✅ Learn which payloads work best
- ✅ Context-aware suggestions
- ✅ One-click insertion in Repeater
- ✅ AI-generated custom payloads

## Implementation Phases

### Phase 1: Data Models (Day 1 - 4 hours)

**Files to Create**:
1. `src/main/java/com/vista/security/model/PayloadLibrary.java`
2. `src/main/java/com/vista/security/model/Payload.java`
3. `src/main/java/com/vista/security/model/PayloadTestResult.java`

**PayloadLibrary.java**:
```java
- id: String
- name: String (e.g., "XSS - Reflected")
- category: String (e.g., "XSS", "SQLi")
- subcategory: String (e.g., "Reflected", "Stored")
- payloads: List<Payload>
- isBuiltIn: boolean
- source: String (e.g., "PayloadsAllTheThings")
- description: String
- tags: List<String>
```

**Payload.java**:
```java
- id: String
- value: String (actual payload)
- description: String
- tags: List<String>
- encoding: String (none, url, base64, etc.)
- context: String (html-body, html-attribute, javascript, etc.)
- successCount: int
- failureCount: int
- successRate: double (calculated)
- lastUsed: long (timestamp)
- notes: String
```

**PayloadTestResult.java**:
```java
- payloadId: String
- targetUrl: String
- parameter: String
- success: boolean
- response: String
- timestamp: long
- notes: String
```

### Phase 2: Core Manager (Day 1-2 - 6 hours)

**File to Create**:
- `src/main/java/com/vista/security/core/PayloadLibraryManager.java`

**Key Methods**:
```java
// Singleton
public static PayloadLibraryManager getInstance()

// Library Management
public List<PayloadLibrary> getAllLibraries()
public PayloadLibrary getLibrary(String id)
public void saveLibrary(PayloadLibrary library)
public void deleteLibrary(String id)

// Payload Operations
public List<Payload> getPayloadsByCategory(String category)
public List<Payload> getPayloadsByContext(String context)
public List<Payload> searchPayloads(String query)
public Payload getTopPayload(String category) // Highest success rate
public List<Payload> getRecentPayloads(int limit)

// Import/Export
public void importFromFile(File file, String format)
public void exportLibrary(String id, File destination)

// Testing History
public void recordTestResult(PayloadTestResult result)
public List<PayloadTestResult> getTestHistory(String payloadId)
public void updatePayloadStats(String payloadId, boolean success)

// AI Integration (optional for v1)
public String generatePayload(String category, String context, String wafType)
```

**File Storage**:
- Location: `~/.vista/payloads/`
- Structure:
  ```
  ~/.vista/payloads/
  ├── built-in/
  │   ├── xss-reflected.json
  │   ├── xss-stored.json
  │   ├── sqli-error-based.json
  │   └── ...
  ├── custom/
  │   ├── my-custom-payloads.json
  │   └── ...
  └── test-history.json
  ```

### Phase 3: Built-in Payloads (Day 2 - 8 hours)

**Categories to Include** (1000+ total payloads):

1. **XSS** (300 payloads)
   - Reflected (100)
   - Stored (50)
   - DOM-based (50)
   - WAF bypass (100)

2. **SQL Injection** (250 payloads)
   - Error-based (80)
   - Blind Boolean (70)
   - Time-based (50)
   - Union-based (50)

3. **SSTI** (100 payloads)
   - Jinja2 (30)
   - Twig (20)
   - Freemarker (20)
   - Velocity (15)
   - ERB (15)

4. **Command Injection** (100 payloads)
   - Linux (50)
   - Windows (50)

5. **SSRF** (80 payloads)
   - Basic (40)
   - Cloud metadata (40)

6. **XXE** (50 payloads)

7. **Path Traversal** (50 payloads)

8. **LDAP Injection** (30 payloads)

9. **NoSQL Injection** (40 payloads)

**Payload Sources**:
- PayloadsAllTheThings (primary)
- SecLists
- PortSwigger Web Security Academy
- Custom curated payloads

**Implementation Approach**:
- Create JSON files with payloads
- Load on startup
- Organize by category/subcategory/context

### Phase 4: UI Panel (Day 3 - 8 hours)

**File to Create**:
- `src/main/java/com/vista/security/ui/PayloadLibraryPanel.java`

**UI Components**:

1. **Header**:
   - Category dropdown (XSS, SQLi, SSTI, etc.)
   - Context filter (html-body, html-attribute, etc.)
   - Search field
   - Action buttons (Add, Import, Export, AI Generate)

2. **Payload List** (left panel):
   - Table with columns: Payload, Success Rate, Last Used
   - Sortable by success rate, usage, name
   - Color-coded by success rate (green > 80%, yellow 50-80%, red < 50%)
   - Click to select

3. **Payload Details** (right panel):
   - Full payload value (with copy button)
   - Description
   - Category/subcategory
   - Context
   - Encoding
   - Tags
   - Statistics (success/failure counts, rate)
   - Recent test history
   - Action buttons (Edit, Duplicate, Delete, View History)

4. **Add/Edit Dialog**:
   - Payload value (text area)
   - Description
   - Category/subcategory dropdowns
   - Context dropdown
   - Encoding dropdown
   - Tags (comma-separated)
   - Save/Cancel buttons

### Phase 5: Context Menu Integration (Day 3-4 - 4 hours)

**File to Modify**:
- `src/main/java/burp/BurpExtender.java`

**Context Menu Structure**:
```
Right-click in Repeater → VISTA →
  ├─ Insert Payload →
  │   ├─ XSS →
  │   │   ├─ Reflected
  │   │   ├─ Stored
  │   │   └─ DOM Based
  │   ├─ SQLi →
  │   │   ├─ Error Based
  │   │   ├─ Blind Boolean
  │   │   └─ Time Based
  │   ├─ SSTI
  │   ├─ Command Injection
  │   ├─ SSRF
  │   └─ More...
  ├─ Mark Payload Result →
  │   ├─ ✓ Worked
  │   └─ ✗ Failed
  └─ Manage Payloads (opens Payload Library tab)
```

**Implementation**:
1. Detect selected text in Repeater
2. Show hierarchical menu with payload categories
3. On selection, replace selected text with payload
4. Track which payload was used
5. Allow marking success/failure

### Phase 6: Success Tracking (Day 4 - 4 hours)

**Features**:
1. **Automatic Tracking**:
   - When payload inserted, create pending test
   - User marks as worked/failed
   - Update payload statistics

2. **Statistics Display**:
   - Success count / Total uses
   - Success rate percentage
   - Last used timestamp
   - Recent test history

3. **Smart Suggestions**:
   - Sort payloads by success rate
   - Highlight top performers
   - Show "Recommended" badge for high success rate

4. **Test History**:
   - View all tests for a payload
   - Filter by success/failure
   - Export test history

## Simplified Implementation (MVP)

For faster delivery, we can simplify:

### What to Include in MVP:
✅ Core data models
✅ PayloadLibraryManager with file storage
✅ 500+ built-in payloads (instead of 1000+)
✅ Basic UI panel (list + details)
✅ Context menu integration (insert payload)
✅ Basic success tracking (manual marking)
✅ Import/export (JSON only)

### What to Defer to v2:
⏳ AI payload generation
⏳ Advanced filtering (by context, encoding)
⏳ Automatic success detection
⏳ PayloadsAllTheThings auto-sync
⏳ Payload variations generator

## Implementation Order

### Day 1 (8 hours)
- ✅ Create data models (4 hours)
- ✅ Create PayloadLibraryManager skeleton (4 hours)

### Day 2 (8 hours)
- ✅ Implement PayloadLibraryManager methods (4 hours)
- ✅ Create 500+ built-in payloads (4 hours)

### Day 3 (8 hours)
- ✅ Create PayloadLibraryPanel UI (8 hours)

### Day 4 (8 hours)
- ✅ Context menu integration (4 hours)
- ✅ Success tracking (2 hours)
- ✅ Testing and bug fixes (2 hours)

**Total**: 32 hours (4 days)

## Success Criteria

✅ 500+ payloads organized by category
✅ Payload Library tab in VISTA
✅ Context menu "Insert Payload" works
✅ Success/failure tracking works
✅ Import/export functionality
✅ Search and filter payloads
✅ Statistics display (success rate, usage)
✅ Clean, intuitive UI
✅ No performance issues
✅ JAR size < 500KB

## User Workflow Example

**Scenario**: Testing for XSS in search parameter

1. User sends request to Repeater
2. User selects parameter value
3. Right-click → VISTA → Insert Payload → XSS → Reflected
4. Dropdown shows top 10 payloads sorted by success rate
5. User selects `<script>alert(1)</script>`
6. Payload inserted, request sent
7. XSS works! User right-clicks → VISTA → Mark Payload Result → ✓ Worked
8. Payload success count increments
9. Next time, this payload appears higher in the list

## Technical Considerations

### Performance
- Lazy load payloads (don't load all 500+ at startup)
- Cache frequently used payloads
- Index payloads by category for fast lookup

### Storage
- JSON format for easy editing
- Separate files per category
- Test history in separate file

### UI
- Use JTable for payload list (sortable, filterable)
- Use JSplitPane for list + details
- Color-code by success rate for quick identification

### Integration
- Use Burp's IContextMenuFactory for context menu
- Use ITextEditor for payload insertion
- Track current request for context-aware suggestions

## Next Steps

1. Create data models
2. Implement PayloadLibraryManager
3. Generate built-in payloads
4. Build UI panel
5. Integrate context menu
6. Add success tracking
7. Test end-to-end
8. Create user guide

Let's start with Phase 1: Data Models! 🚀
