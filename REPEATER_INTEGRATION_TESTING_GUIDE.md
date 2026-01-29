# Repeater Integration - Testing Guide

## ✅ BUILD STATUS: SUCCESS

**JAR Location:** `target/vista-1.0.0-MVP.jar` (189KB)  
**Build Date:** January 26, 2026, 18:51  
**Version:** 2.2.0  

**Recent Fixes:**
- ✅ Race condition in context menu registration (FIXED)
- ✅ NoSuchMethodError with isHttps() method (FIXED)

---

## 🔧 WHAT WAS FIXED

### Critical Race Condition Fix

**Problem:** `registerContextMenuFactory()` was called BEFORE panels were initialized, causing `testingSuggestionsPanel` to be NULL when context menu tried to use it.

**Solution:** Moved `registerContextMenuFactory()` INSIDE `SwingUtilities.invokeLater()` AFTER all panels are initialized.

**Code Change in BurpExtender.java:**
```java
SwingUtilities.invokeLater(() -> {
    // Initialize all panels first
    this.settingsPanel = new SettingsPanel(callbacks);
    this.dashboardPanel = new DashboardPanel(callbacks);
    this.testingSuggestionsPanel = new TestingSuggestionsPanel(callbacks);
    this.bypassAssistantPanel = new BypassAssistantPanel(callbacks);
    this.findingsPanel = new FindingsPanel(callbacks);
    
    // Create tabbed interface
    this.tabbedPane = new JTabbedPane();
    // ... add tabs ...
    
    callbacks.addSuiteTab(this);
    
    // NOW register context menu factory AFTER panels are initialized
    callbacks.registerContextMenuFactory(BurpExtender.this);
    callbacks.printOutput("[VISTA] Context menu factory registered");
});
```

---

## 🎯 TESTING INSTRUCTIONS

### Step 1: Load Extension in Burp Suite

1. Open Burp Suite
2. Go to **Extender → Extensions**
3. Click **Add**
4. Select extension type: **Java**
5. Browse to: `target/vista-1.0.0-MVP.jar`
6. Click **Next**

### Step 2: Verify Initialization

Check **Burp → Extender → Extensions → VISTA → Output** tab for:

```
[VISTA] Starting panel initialization
[VISTA] SettingsPanel initialized
[VISTA] DashboardPanel initialized
[VISTA] TestingSuggestionsPanel initialized  ← MUST appear BEFORE context menu
[VISTA] BypassAssistantPanel initialized
[VISTA] FindingsPanel initialized
[VISTA] All panels initialized successfully
[VISTA] Context menu factory registered  ← MUST appear AFTER panels
```

**✅ PASS:** If you see this order  
**❌ FAIL:** If context menu registered before TestingSuggestionsPanel

### Step 3: Test Context Menu

1. Go to **Burp → Proxy → HTTP History** or **Repeater**
2. Right-click on any request
3. Verify you see these menu items:
   - 💡 Send to VISTA AI Advisor
   - 🔄 Send to Interactive Assistant (Auto-Attach)
   - 🔓 Send to VISTA Bypass Assistant

**✅ PASS:** All 3 menu items appear  
**❌ FAIL:** Menu items missing or error in Output tab

### Step 4: Test Auto-Attach Feature

1. In **Burp Repeater**, send a request (e.g., `GET /search?q=test`)
2. Right-click the request
3. Click **"🔄 Send to Interactive Assistant (Auto-Attach)"**

**Expected Behavior:**
- VISTA tab opens
- AI Advisor sub-tab is selected
- Interactive Assistant mode is active
- You see bold green text: **"✓ REQUEST ATTACHED: GET /search?q=test"**
- Chat input field has light green background
- History button shows: **"📋 History (0)"**

**Debug Output (check Burp Output tab):**
```
[VISTA] Context menu: Send to Interactive Assistant clicked
[VISTA] Tracking request: https://example.com/search?q=test
[VISTA] Setting request in panel
[VISTA] Calling attachRepeaterRequest
[VISTA] attachRepeaterRequest called
[VISTA] Switched to Interactive Assistant mode
[VISTA] Interactive chat panel set to visible
[VISTA] Request attached
[VISTA] Extracted: GET /search?q=test
[VISTA] Attachment label updated: ✓ REQUEST ATTACHED: GET /search?q=test
[VISTA] Chat field background changed to indicate attachment
[VISTA] Context menu action completed
```

**✅ PASS:** All visual indicators and debug output appear  
**❌ FAIL:** No attachment label or error in Output tab

### Step 5: Test Sending Message with Attachment

1. With request attached (from Step 4)
2. Type an observation: `"I see HTML encoding in the response"`
3. Click **Send**

**Expected Behavior:**
- System message appears:
  ```
  📎 Request/Response attached and sent to AI for analysis
     Request: GET /search?q=test HTTP/1.1
     Response: 1234 bytes
  ```
- Attachment label resets to: "No request attached"
- Chat field background returns to white
- History button updates to: **"📋 History (1)"**
- AI processes and responds

**Debug Output:**
```
[VISTA] sendInteractiveMessage called with: I see HTML encoding in the response
[VISTA] attachedTestRequest is: NOT NULL
[VISTA] Processing attached request...
[VISTA] Request length: 156
[VISTA] Response length: 2341
[VISTA] Added to testingSteps. Total steps: 1
[VISTA] Attachment reset
[VISTA] Starting AI processing thread
```

**✅ PASS:** All feedback appears and AI responds  
**❌ FAIL:** No system message or AI doesn't receive request

### Step 6: Test History Viewer

1. After sending at least one request (from Step 5)
2. Click **"📋 History (1)"** button

**Expected Behavior:**
- Dialog opens with title: "Testing History (1 tests)"
- Shows:
  ```
  TESTING HISTORY
  ================================================================================
  
  TEST #1
  --------------------------------------------------------------------------------
  Observation: I see HTML encoding in the response
  
  Request:
  GET /search?q=test HTTP/1.1
  Host: example.com
  ...
  
  Response:
  HTTP/1.1 200 OK
  Content-Type: text/html
  ...
  ```

**✅ PASS:** History dialog shows all sent requests  
**❌ FAIL:** Dialog empty or doesn't open

### Step 7: Test Multiple Requests

1. Attach and send request #1
2. Attach and send request #2
3. Attach and send request #3
4. Click **"📋 History (3)"**

**Expected Behavior:**
- History shows all 3 tests in order
- AI responses reference previous tests
- Each test shows observation, request, and response

**✅ PASS:** All tests tracked correctly  
**❌ FAIL:** Tests missing or out of order

### Step 8: Test Dropdown Selector

1. Send multiple requests in Repeater (at least 3)
2. Right-click each and select "Send to Interactive Assistant"
3. In VISTA, look at the dropdown: **"Quick attach from Repeater:"**
4. Click the dropdown

**Expected Behavior:**
- Shows recent requests in format:
  ```
  [18:38:45] GET https://example.com/search?q=test [200]
  [18:39:12] POST https://example.com/login [302]
  [18:39:45] GET https://example.com/profile [200]
  ```
- Select one from dropdown
- Request is attached automatically
- Attachment label updates

**✅ PASS:** Dropdown shows recent requests and selection works  
**❌ FAIL:** Dropdown empty or selection doesn't attach

---

## 🐛 TROUBLESHOOTING

### Issue: NoSuchMethodError - isHttps()

**Symptoms:**
- Error in Burp error logs: `java.lang.NoSuchMethodError: 'boolean burp.IHttpRequestResponse.isHttps()'`
- Clicking "Send to Interactive Assistant" causes crash
- Extension loads but context menu action fails

**Diagnosis:**
```
Check Burp → Extender → Extensions → VISTA → Errors tab
Look for: NoSuchMethodError at BurpExtender.getUrlFromRequest
```

**Solution:**
- ✅ FIXED in latest build (January 26, 2026, 18:51)
- Ensure you're using the latest JAR: `target/vista-1.0.0-MVP.jar`
- Rebuild if needed: `mvn clean package -q -DskipTests`
- Reload extension in Burp Suite

**Details:** See **BURP_API_COMPATIBILITY_FIX.md**

---

### Issue: Context Menu Not Appearing

**Symptoms:**
- Right-click doesn't show VISTA menu items
- No error in Output tab

**Diagnosis:**
```bash
# Check Output tab for:
[VISTA] Context menu factory registered
```

**Solution:**
- If missing, race condition still exists
- Verify `registerContextMenuFactory()` is AFTER panel initialization
- Rebuild: `mvn clean package -q -DskipTests`

### Issue: testingSuggestionsPanel is NULL

**Symptoms:**
- Error in Output tab: `[VISTA] testingSuggestionsPanel is null!`
- Context menu appears but clicking does nothing

**Diagnosis:**
```bash
# Check initialization order in Output tab:
[VISTA] TestingSuggestionsPanel initialized  ← Must be BEFORE
[VISTA] Context menu factory registered      ← This
```

**Solution:**
- Race condition - panels not initialized before context menu
- Verify code in `BurpExtender.java` line 95-105
- Ensure `registerContextMenuFactory()` is inside `SwingUtilities.invokeLater()`

### Issue: Request Not Attaching

**Symptoms:**
- Click "Send to Interactive Assistant" but no attachment label
- Chat field background stays white

**Diagnosis:**
```bash
# Check Output tab for:
[VISTA] attachRepeaterRequest called
[VISTA] Request attached
[VISTA] Attachment label updated
```

**Solution:**
- If logs appear but UI doesn't update, check `TestingSuggestionsPanel.attachRepeaterRequest()`
- Verify `attachmentLabel` and `interactiveChatField` are not null
- Check if `interactiveChatPanel.setVisible(true)` is called

### Issue: Request Not Sent to AI

**Symptoms:**
- Attachment label shows request
- Click Send but AI doesn't receive request
- No system message about attachment

**Diagnosis:**
```bash
# Check Output tab for:
[VISTA] sendInteractiveMessage called
[VISTA] attachedTestRequest is: NOT NULL  ← Should be NOT NULL
[VISTA] Processing attached request...
[VISTA] Added to testingSteps
```

**Solution:**
- If `attachedTestRequest is: NULL`, request wasn't attached properly
- Check `attachRepeaterRequest()` sets `attachedTestRequest = requestResponse`
- Verify `sendInteractiveMessage()` checks `if (attachedTestRequest != null)`

### Issue: History Button Not Updating

**Symptoms:**
- Send requests but History button stays at (0)
- History dialog is empty

**Diagnosis:**
```bash
# Check Output tab for:
[VISTA] Added to testingSteps. Total steps: 1
[VISTA] Added to testingSteps. Total steps: 2
```

**Solution:**
- If logs show steps added but button doesn't update, UI refresh issue
- Check `testingSteps.add()` is called in `sendInteractiveMessage()`
- Verify History button text is updated after adding step

---

## 📊 FEATURE VERIFICATION CHECKLIST

### Core Functionality
- [ ] Extension loads without errors
- [ ] All panels initialize in correct order
- [ ] Context menu factory registers after panels
- [ ] Context menu appears on right-click
- [ ] All 3 menu items are visible

### Auto-Attach Feature
- [ ] "Send to Interactive Assistant" switches to correct tab
- [ ] Request is tracked in RepeaterRequestTracker
- [ ] Attachment label shows bold green text
- [ ] Chat field background turns light green
- [ ] Interactive chat panel becomes visible

### Send with Attachment
- [ ] Typing observation and clicking Send works
- [ ] System message confirms request was sent
- [ ] Shows request first line and response size
- [ ] Attachment resets after sending
- [ ] Background returns to white
- [ ] History button increments

### History Viewer
- [ ] History button shows correct count
- [ ] Clicking opens dialog with all tests
- [ ] Each test shows observation, request, response
- [ ] Tests are in chronological order
- [ ] Dialog is scrollable and readable

### Dropdown Selector
- [ ] Dropdown shows recent Repeater requests
- [ ] Format includes timestamp, method, URL, status
- [ ] Selecting from dropdown attaches request
- [ ] Refresh button updates the list
- [ ] Maximum 50 requests tracked

### AI Integration
- [ ] AI receives attached request in prompt
- [ ] AI references actual tested request in response
- [ ] Testing history is included in follow-up prompts
- [ ] AI adapts suggestions based on history
- [ ] Conversation context is maintained

---

## 🎉 SUCCESS CRITERIA

Your Repeater Integration is working correctly if:

1. ✅ Context menu appears with all 3 options
2. ✅ "Send to Interactive Assistant" shows bold green attachment label
3. ✅ Chat field has light green background when request attached
4. ✅ Sending message shows detailed system confirmation
5. ✅ History button tracks all sent requests
6. ✅ History dialog shows complete testing history
7. ✅ AI receives and references actual tested requests
8. ✅ Dropdown shows recent Repeater requests
9. ✅ All debug logs appear in correct order
10. ✅ No null pointer exceptions in Output tab

---

## 📝 NEXT STEPS

### If All Tests Pass:
1. Start using the feature in real pentesting
2. Test with various request types (GET, POST, JSON, etc.)
3. Verify AI suggestions improve with testing history
4. Report any edge cases or improvements

### If Tests Fail:
1. Check the specific troubleshooting section above
2. Review debug output in Burp Output tab
3. Verify initialization order
4. Check for null pointer exceptions
5. Rebuild and retry: `mvn clean package -q -DskipTests`

---

## 🔍 DETAILED DEBUG GUIDE

### Enable Verbose Logging

All critical operations are already logged. Check **Burp → Extender → Extensions → VISTA → Output** tab.

### Key Log Messages to Look For

**Initialization:**
```
[VISTA] Starting panel initialization
[VISTA] TestingSuggestionsPanel initialized
[VISTA] Context menu factory registered
```

**Context Menu:**
```
[VISTA] Context menu: Send to Interactive Assistant clicked
[VISTA] Tracking request: https://...
[VISTA] Calling attachRepeaterRequest
```

**Attachment:**
```
[VISTA] attachRepeaterRequest called
[VISTA] Request attached
[VISTA] Extracted: GET /path
[VISTA] Attachment label updated
[VISTA] Chat field background changed
```

**Sending:**
```
[VISTA] sendInteractiveMessage called with: ...
[VISTA] attachedTestRequest is: NOT NULL
[VISTA] Processing attached request...
[VISTA] Request length: 156
[VISTA] Response length: 2341
[VISTA] Added to testingSteps. Total steps: 1
[VISTA] Attachment reset
```

### Common Error Messages

**Error:** `testingSuggestionsPanel is null!`  
**Cause:** Race condition - context menu registered before panel initialized  
**Fix:** Verify initialization order in code

**Error:** `NullPointerException in createMenuItems`  
**Cause:** Panel not initialized when context menu created  
**Fix:** Move `registerContextMenuFactory()` after panel initialization

**Error:** `attachedTestRequest is: NULL`  
**Cause:** Request not attached properly  
**Fix:** Check `attachRepeaterRequest()` implementation

---

## 📚 RELATED DOCUMENTATION

- **RCA_REPEATER_ATTACHMENT_ISSUE.md** - Detailed root cause analysis
- **TROUBLESHOOTING_REPEATER_INTEGRATION.md** - Comprehensive troubleshooting
- **REPEATER_INTEGRATION_FEATURE.md** - Feature specification
- **ENHANCED_INTERACTIVE_SUMMARY.md** - Interactive Assistant overview

---

**Version:** 2.2.0  
**Build:** SUCCESS  
**JAR:** target/vista-1.0.0-MVP.jar (189KB)  
**Status:** ✅ READY FOR TESTING
