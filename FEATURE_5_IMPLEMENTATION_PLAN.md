# Feature 5: Request Collection Engine - Implementation Plan

## Overview

The **Request Collection Engine** allows users to organize and analyze similar requests together. This is perfect for:
- Comparing similar endpoints (e.g., all `/api/user/*` requests)
- Testing parameter variations systematically
- Finding patterns across multiple requests
- Bulk analysis with AI

**Version**: 2.7.0  
**Estimated Time**: 3-4 days  
**Status**: 🚀 Starting Implementation

---

## 🎯 User Stories

### Story 1: Organize Similar Requests
**As a** pentester  
**I want to** group similar requests into collections  
**So that** I can test them systematically

### Story 2: AI Pattern Detection
**As a** pentester  
**I want** AI to detect patterns across requests  
**So that** I can find vulnerabilities faster

### Story 3: Bulk Testing
**As a** pentester  
**I want to** test all requests in a collection at once  
**So that** I save time

### Story 4: Compare Responses
**As a** pentester  
**I want to** compare responses side-by-side  
**So that** I can spot differences

---

## 📋 Features

### Core Features
1. **Named Collections** - Create collections like "User API", "Admin Endpoints"
2. **Bulk Import** - Import from Proxy, Repeater, Sitemap
3. **AI Pattern Detection** - Automatically detect similar requests
4. **Comparison View** - Side-by-side request/response comparison
5. **Bulk AI Analysis** - Send all requests to AI at once
6. **Export/Import** - Share collections with team

### Advanced Features (Optional)
7. **Smart Grouping** - Auto-group by endpoint pattern
8. **Diff View** - Highlight differences between responses
9. **Success Criteria** - Mark which requests succeeded
10. **Timeline View** - See testing history

---

## 🏗️ Architecture

### Data Models

**RequestCollection.java**:
```java
- id: String
- name: String
- description: String
- items: List<CollectionItem>
- created: long
- modified: long
- tags: List<String>
```

**CollectionItem.java**:
```java
- id: String
- request: IHttpRequestResponse
- name: String (optional)
- notes: String
- tested: boolean
- success: boolean
- timestamp: long
```

### Core Classes

**RequestCollectionManager.java**:
- Singleton manager
- CRUD operations for collections
- Import/export functionality
- Pattern detection
- File storage in `~/.vista/collections/`

**RequestCollectionPanel.java**:
- Main UI panel
- Collection list
- Request table
- Comparison view
- Bulk actions

---

## 🎨 UI Design

```
┌─────────────────────────────────────────────────────────────┐
│ 📁 Request Collections                                      │
├─────────────────────────────────────────────────────────────┤
│ Collections:                    Actions:                    │
│ ┌─────────────────────┐        [➕ New] [📥 Import]        │
│ │ User API (15)       │        [🔄 Refresh]                │
│ │ Admin Endpoints (8) │                                     │
│ │ Payment Flow (12)   │                                     │
│ └─────────────────────┘                                     │
├─────────────────────────────────────────────────────────────┤
│ Requests in "User API":                                     │
│ ┌───────────────────────────────────────────────────────┐  │
│ │ Method │ URL                    │ Status │ Tested     │  │
│ │ GET    │ /api/user/profile      │ 200    │ ✓         │  │
│ │ POST   │ /api/user/update       │ 200    │ ✓         │  │
│ │ DELETE │ /api/user/delete       │ 403    │ ✗         │  │
│ └───────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│ Actions: [📋 Copy] [🤖 AI Analysis] [🔍 Compare] [🗑️ Delete]│
└─────────────────────────────────────────────────────────────┘
```

---

## 📅 Implementation Plan

### Phase 1: Data Models (Day 1 - 4 hours)

**Files to Create**:
1. `src/main/java/com/vista/security/model/RequestCollection.java`
2. `src/main/java/com/vista/security/model/CollectionItem.java`

**Features**:
- Basic data structures
- JSON serialization (manual, no Gson)
- Validation

### Phase 2: Core Manager (Day 1-2 - 6 hours)

**File to Create**:
- `src/main/java/com/vista/security/core/RequestCollectionManager.java`

**Methods**:
```java
// Collection Management
getAllCollections()
getCollection(id)
createCollection(name, description)
saveCollection(collection)
deleteCollection(id)

// Item Management
addItem(collectionId, request)
removeItem(collectionId, itemId)
updateItem(collectionId, itemId, notes, tested, success)

// Bulk Operations
importFromProxy(collectionId, filter)
importFromRepeater(collectionId)
importFromSitemap(collectionId, filter)

// Pattern Detection
detectSimilarRequests(request) // Returns matching collections
suggestCollectionName(requests) // AI suggests name

// Export/Import
exportCollection(id, file)
importCollection(file)
```

### Phase 3: UI Panel (Day 2-3 - 8 hours)

**File to Create**:
- `src/main/java/com/vista/security/ui/RequestCollectionPanel.java`

**Components**:
1. Collection list (left side)
2. Request table (center)
3. Request details (bottom)
4. Action buttons (top)

**Features**:
- Create/delete collections
- Add/remove requests
- Mark tested/success
- Bulk import
- Export/import

### Phase 4: AI Integration (Day 3 - 4 hours)

**Features**:
1. **Bulk AI Analysis** - Send all requests to AI
2. **Pattern Detection** - AI finds similar patterns
3. **Vulnerability Suggestions** - AI suggests what to test
4. **Auto-Naming** - AI suggests collection names

**Integration Points**:
- Use existing `TestingSuggestionsPanel` for AI
- Add "Analyze Collection" button
- Show AI suggestions in panel

### Phase 5: Comparison View (Day 3-4 - 6 hours)

**Features**:
1. Side-by-side request comparison
2. Response diff highlighting
3. Parameter comparison
4. Header comparison

**UI**:
```
┌─────────────────────────────────────────────────────────────┐
│ Compare Requests                                            │
├──────────────────────────────┬──────────────────────────────┤
│ Request 1                    │ Request 2                    │
│ GET /api/user/1              │ GET /api/user/2              │
│                              │                              │
│ Response: 200 OK             │ Response: 200 OK             │
│ {"id":1,"name":"Alice"}      │ {"id":2,"name":"Bob"}        │
│                              │                              │
│ Differences:                                                │
│ - ID: 1 → 2                                                 │
│ - Name: Alice → Bob                                         │
└─────────────────────────────────────────────────────────────┘
```

### Phase 6: Integration (Day 4 - 2 hours)

**Changes to Existing Files**:
1. `BurpExtender.java` - Add new tab
2. Add context menu: "Add to Collection"
3. Add keyboard shortcuts

---

## 🎯 Simplified MVP (Day 1-2)

To get something working quickly, start with:

### MVP Features:
1. ✅ Create named collections
2. ✅ Add requests manually (right-click → Add to Collection)
3. ✅ View requests in collection
4. ✅ Delete requests from collection
5. ✅ Basic AI analysis (send all to AI)

### Skip for MVP:
- ❌ Bulk import (add later)
- ❌ Comparison view (add later)
- ❌ Pattern detection (add later)
- ❌ Export/import (add later)

**MVP Time**: 1-2 days instead of 4 days

---

## 🚀 Quick Start Implementation

### Step 1: Create Models (2 hours)
```java
// RequestCollection.java - Simple version
public class RequestCollection {
    private String id;
    private String name;
    private String description;
    private List<CollectionItem> items;
    
    // Basic getters/setters
    // Manual JSON serialization
}

// CollectionItem.java - Simple version
public class CollectionItem {
    private String id;
    private byte[] request;  // Serialized IHttpRequestResponse
    private byte[] response;
    private String url;
    private String method;
    private String notes;
    
    // Basic getters/setters
}
```

### Step 2: Create Manager (3 hours)
```java
// RequestCollectionManager.java - MVP version
public class RequestCollectionManager {
    private static RequestCollectionManager instance;
    private Map<String, RequestCollection> collections;
    
    // Basic CRUD
    public RequestCollection createCollection(String name)
    public void addRequest(String collectionId, IHttpRequestResponse request)
    public void deleteRequest(String collectionId, String itemId)
    
    // File storage
    private void saveToFile()
    private void loadFromFile()
}
```

### Step 3: Create UI (4 hours)
```java
// RequestCollectionPanel.java - MVP version
public class RequestCollectionPanel extends JPanel {
    private JList<String> collectionList;
    private JTable requestsTable;
    private JButton newCollectionBtn;
    private JButton deleteBtn;
    
    // Simple UI with basic operations
}
```

### Step 4: Integration (1 hour)
```java
// BurpExtender.java
// Add new tab
tabbedPane.addTab("📁 Collections", requestCollectionPanel);

// Add context menu
menuItems.add(new JMenuItem("Add to Collection"));
```

**Total MVP Time**: 10 hours (1.5 days)

---

## 💡 Key Decisions

### 1. Storage Format
**Decision**: JSON files in `~/.vista/collections/`  
**Why**: Simple, portable, no database needed

### 2. Request Storage
**Decision**: Store serialized bytes + metadata  
**Why**: Preserve exact request/response

### 3. AI Integration
**Decision**: Reuse existing AI infrastructure  
**Why**: No need to duplicate code

### 4. UI Complexity
**Decision**: Start simple, add features incrementally  
**Why**: Get MVP working fast

---

## 🎓 Success Criteria

### MVP Success:
- ✅ User can create collections
- ✅ User can add requests to collections
- ✅ User can view requests in collections
- ✅ User can send collection to AI for analysis
- ✅ Collections persist across Burp restarts

### Full Success:
- ✅ All MVP features
- ✅ Bulk import from Proxy/Repeater
- ✅ Comparison view
- ✅ Pattern detection
- ✅ Export/import

---

## 🚀 Let's Start!

**Recommendation**: Implement MVP first (1-2 days), then add advanced features based on user feedback.

**Next Steps**:
1. Create data models
2. Create manager
3. Create simple UI
4. Integrate with BurpExtender
5. Test and iterate

Ready to start implementing? 🎯
