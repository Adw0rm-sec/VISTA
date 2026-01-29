# Troubleshooting: Repeater Integration

## Issue: "Send to Interactive Assistant" not working

### What was fixed:

1. **Added automatic mode switching** - Now automatically switches to "Interactive Assistant" mode
2. **Added chat panel visibility** - Ensures the chat panel is visible when attaching
3. **Added helpful welcome message** - Shows instructions when first attaching from Repeater
4. **Added debug logging** - Logs every step to Burp's output for troubleshooting

### How to test if it's working:

**Step 1: Check Burp Output**
```
1. Open Burp Suite
2. Go to "Extender" → "Extensions" → Select "VISTA"
3. Go to "Output" tab at the bottom
4. You should see:
   ✓ Extension loaded successfully
   → Right-click any request → 'Send to VISTA AI Advisor'
   → Right-click any request → 'Send to VISTA Bypass Assistant'
```

**Step 2: Test the Context Menu**
```
1. Go to any tab (Proxy, Repeater, etc.)
2. Right-click on a request
3. You should see:
   💡 Send to VISTA AI Advisor
   🔄 Send to Interactive Assistant (Auto-Attach)  ← This one!
   🔓 Send to VISTA Bypass Assistant
```

**Step 3: Click and Watch Output**
```
1. Click "🔄 Send to Interactive Assistant (Auto-Attach)"
2. Watch Burp Output tab, you should see:
   [VISTA] Context menu: Send to Interactive Assistant clicked
   [VISTA] Tracking request: http://example.com/path
   [VISTA] Setting request in panel
   [VISTA] Calling attachRepeaterRequest
   [VISTA] attachRepeaterRequest called
   [VISTA] Switched to Interactive Assistant mode
   [VISTA] Interactive chat panel set to visible
   [VISTA] Request attached
   [VISTA] Extracted: GET /path
   [VISTA] Attachment label updated
   [VISTA] Dropdown updated
   [VISTA] Help message added to conversation
   [VISTA] Focus set to chat input field
   [VISTA] attachRepeaterRequest completed successfully
   [VISTA] Switching to AI Advisor tab
   [VISTA] Context menu action completed
```

**Step 4: Check VISTA UI**
```
1. VISTA tab should open automatically
2. Mode selector should show "Interactive Assistant"
3. You should see a welcome message:
   📎 Request attached from Repeater!
   
   💡 Quick Start:
   1. Type what you observed...
   2. Click Send
   3. AI will analyze...
   
4. At the bottom, you should see:
   ✓ Request attached from Repeater: GET /path
   Quick attach from Repeater: [dropdown]
   [Type your observation...] [📎 Attach] [Send]
```

### If it's still not working:

**Check 1: Is the extension loaded?**
```
Burp → Extender → Extensions
Look for "VISTA" with status "Loaded"
If not loaded, check "Errors" tab
```

**Check 2: Is the JAR up to date?**
```
1. Unload old extension
2. Load new JAR: target/vista-1.0.0-MVP.jar (187KB)
3. Check "Output" tab for startup messages
```

**Check 3: Are there any errors?**
```
Burp → Extender → Extensions → VISTA → Errors tab
Look for any red error messages
```

**Check 4: Is the panel initialized?**
```
Look in Output for:
[VISTA] testingSuggestionsPanel is null!

If you see this, the panel wasn't initialized properly.
Try reloading the extension.
```

### Common Issues:

**Issue 1: Context menu doesn't appear**
```
Cause: Extension not loaded or crashed
Fix: Reload extension, check Errors tab
```

**Issue 2: Menu appears but nothing happens**
```
Cause: Panel not initialized
Fix: Check Output tab for "testingSuggestionsPanel is null!"
      Reload extension
```

**Issue 3: Tab switches but no attachment**
```
Cause: attachRepeaterRequest not being called
Fix: Check Output tab for debug messages
      Verify method is being called
```

**Issue 4: Chat panel not visible**
```
Cause: Mode not switched or panel not shown
Fix: Check Output for "Interactive chat panel set to visible"
      Manually switch to Interactive Assistant mode
```

### Manual Workaround:

If auto-attach still doesn't work, you can manually attach:

```
1. Right-click → "Send to VISTA AI Advisor" (regular option)
2. In VISTA, select "Interactive Assistant" mode
3. Click "📎 Attach Request" button
4. Paste request/response manually
5. Click OK
```

### Debug Mode:

The new version includes extensive logging. Every action is logged to Burp Output:

```
[VISTA] Context menu: Send to Interactive Assistant clicked
[VISTA] Tracking request: ...
[VISTA] Setting request in panel
[VISTA] Calling attachRepeaterRequest
[VISTA] attachRepeaterRequest called
[VISTA] Switched to Interactive Assistant mode
[VISTA] Interactive chat panel set to visible
[VISTA] Request attached
[VISTA] Extracted: GET /path
[VISTA] Attachment label updated
[VISTA] Dropdown updated
[VISTA] Help message added to conversation
[VISTA] Focus set to chat input field
[VISTA] attachRepeaterRequest completed successfully
[VISTA] Switching to AI Advisor tab
[VISTA] Context menu action completed
```

If you don't see these messages, the method isn't being called.

### Report Issues:

If it's still not working after trying all the above:

1. Check Burp Output tab
2. Copy all [VISTA] messages
3. Check Errors tab
4. Copy any error messages
5. Report with:
   - Burp version
   - Java version
   - Operating system
   - Steps to reproduce
   - Output/Error messages

---

**Version:** 2.3.0  
**Feature:** Repeater Integration with Debug Logging  
**Status:** ✅ Enhanced with Troubleshooting
