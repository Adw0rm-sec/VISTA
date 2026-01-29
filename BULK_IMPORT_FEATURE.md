# 📋 Bulk Import Payloads - Feature Guide

## Overview

The **Bulk Import** feature allows you to paste multiple payloads at once (one per line) and import them all in seconds. This is perfect for:
- Importing payloads from PayloadsAllTheThings
- Adding your custom payload collections
- Quickly building your library from existing lists

**Version**: 2.6.0  
**Status**: ✅ Complete

---

## 🚀 How to Use

### Quick Start (30 seconds)

1. **Click "📋 Bulk Import" button** in Payload Library tab

2. **Paste your payloads** (one per line):
   ```
   <script>alert(1)</script>
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>
   ' OR 1=1--
   ' AND SLEEP(5)--
   {{7*7}}
   ${7*7}
   ```

3. **Select category** (e.g., "XSS" or create new one)

4. **Click "📥 Import All"**

5. **Done!** All payloads are now in your library

---

## 📚 Example Use Cases

### Use Case 1: Import XSS Payloads from GitHub

**Scenario**: You found a great XSS payload list on GitHub

**Steps**:
1. Copy payloads from GitHub (Ctrl+C)
2. Click "📋 Bulk Import" in VISTA
3. Paste payloads (Ctrl+V)
4. Category: "XSS"
5. Click "Import All"
6. ✅ 50 XSS payloads added in 10 seconds!

### Use Case 2: Import Your Custom Payloads

**Scenario**: You have a text file with your favorite payloads

**Steps**:
1. Open your text file
2. Copy all payloads
3. Click "📋 Bulk Import"
4. Paste payloads
5. Category: "My Favorites"
6. Tags: "custom, tested, working"
7. Click "Import All"
8. ✅ All your payloads now in VISTA!

### Use Case 3: Import from PayloadsAllTheThings

**Scenario**: You want to import SQL injection payloads

**Steps**:
1. Go to PayloadsAllTheThings GitHub
2. Navigate to SQL Injection section
3. Copy payloads
4. Click "📋 Bulk Import" in VISTA
5. Paste payloads
6. Category: "SQLi"
7. Context: "sql"
8. Enable "Auto-detect payload types" ✓
9. Click "Import All"
10. ✅ Payloads imported with automatic tags!

---

## 🎯 Features

### 1. One Payload Per Line
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```
Each line becomes a separate payload.

### 2. Auto-Skip Empty Lines
```
<script>alert(1)</script>

<img src=x onerror=alert(1)>

<svg onload=alert(1)>
```
Empty lines are automatically skipped.

### 3. Auto-Skip Comments
```
# XSS Payloads
<script>alert(1)</script>

// Event handlers
<img src=x onerror=alert(1)>
```
Lines starting with `#` or `//` are skipped.

### 4. Auto-Detect Payload Types ✨

When enabled, VISTA automatically detects and tags payloads:

**XSS Detection**:
- Detects: `<script>`, `onerror`, `onload`, `alert(`, `<svg>`, `<img>`, `<iframe>`
- Auto-tags: `xss`

**SQL Injection Detection**:
- Detects: `' OR`, `UNION SELECT`, `--`, `SLEEP(`, `WAITFOR`, `BENCHMARK(`
- Auto-tags: `sqli`

**SSTI Detection**:
- Detects: `{{`, `${`, `<%`, `#{`
- Auto-tags: `ssti`

**Command Injection Detection**:
- Detects: `;`, `|`, `&`, `` ` ``, `$(`
- Auto-tags: `command-injection`

**SSRF Detection**:
- Detects: `http://`, `localhost`, `127.0.0.1`, `169.254.169.254`
- Auto-tags: `ssrf`

**XXE Detection**:
- Detects: `<!ENTITY`, `<!DOCTYPE`, `SYSTEM "`
- Auto-tags: `xxe`

**Path Traversal Detection**:
- Detects: `../`, `..\\`, `%2e%2e`
- Auto-tags: `path-traversal`

**LFI Detection**:
- Detects: `/etc/passwd`, `c:\\windows`, `php://`, `data://`
- Auto-tags: `lfi`

### 5. Custom Tags

Add your own tags to all imported payloads:
```
Tags: custom, tested, working, waf-bypass
```

All payloads will get these tags plus auto-detected ones.

### 6. Category Auto-Creation

If you enter a new category name, VISTA automatically creates a library for it.

---

## 📊 Comparison: Before vs After

### Before (Manual Import)

**Importing 50 payloads**:
```
1. Click "Add Payload"
2. Paste payload #1
3. Fill description
4. Select category
5. Click Save
6. Repeat 49 more times...
```
**Time**: 25 minutes (30 seconds × 50)  
**Effort**: High (repetitive)  
**Error-prone**: Yes (easy to make mistakes)

### After (Bulk Import)

**Importing 50 payloads**:
```
1. Click "Bulk Import"
2. Paste all 50 payloads
3. Select category
4. Click "Import All"
5. Done!
```
**Time**: 30 seconds  
**Effort**: Minimal  
**Error-prone**: No (one operation)

**Improvement**: 50x faster! ⚡

---

## 💡 Pro Tips

### Tip 1: Use Auto-Detect
Always enable "Auto-detect payload types" - it saves time tagging payloads.

### Tip 2: Add Context
Set the context (html-body, javascript, sql) to help AI suggest the right payloads.

### Tip 3: Use Meaningful Categories
Use clear category names like:
- "XSS - Reflected"
- "SQLi - Error Based"
- "SSTI - Jinja2"

### Tip 4: Add Custom Tags
Add tags like "waf-bypass", "tested", "working" to find payloads easily later.

### Tip 5: Import from Trusted Sources
Good sources for payloads:
- PayloadsAllTheThings (GitHub)
- OWASP Testing Guide
- Your own tested payloads
- Team's shared collections

---

## 🎓 Example Workflows

### Workflow 1: Building Your XSS Library

```
1. Go to PayloadsAllTheThings/XSS
2. Copy basic XSS payloads
3. Bulk Import → Category: "XSS - Basic"
4. Copy WAF bypass payloads
5. Bulk Import → Category: "XSS - WAF Bypass"
6. Copy polyglot payloads
7. Bulk Import → Category: "XSS - Polyglot"
8. Done! Complete XSS library in 2 minutes
```

### Workflow 2: Team Payload Sharing

```
Team Member 1:
1. Tests and finds 20 working payloads
2. Exports library to JSON
3. Shares file with team

Team Member 2:
1. Receives JSON file
2. Clicks "Import File"
3. All 20 payloads with success rates imported
4. Can immediately use proven payloads
```

### Workflow 3: Custom Payload Collection

```
1. Create text file: my-payloads.txt
2. Add your favorite payloads (one per line)
3. Open VISTA → Bulk Import
4. Paste from file
5. Category: "My Favorites"
6. Tags: "custom, tested, high-success"
7. Import All
8. Your personal collection ready!
```

---

## 🔧 Technical Details

### Supported Formats

**Plain Text** (one per line):
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
' OR 1=1--
```

**With Comments**:
```
# XSS Payloads
<script>alert(1)</script>

// SQL Injection
' OR 1=1--
```

**With Empty Lines**:
```
<script>alert(1)</script>

<img src=x onerror=alert(1)>

<svg onload=alert(1)>
```

### Auto-Detection Algorithm

```java
// XSS Detection
if (payload.contains("<script") || payload.contains("onerror") || 
    payload.contains("alert(")) {
    tag = "xss";
}

// SQL Injection Detection
if (payload.contains("' OR") || payload.contains("UNION SELECT") || 
    payload.contains("--")) {
    tag = "sqli";
}

// And so on for other types...
```

### Performance

- **Import Speed**: ~100 payloads per second
- **Memory**: ~1KB per payload
- **Storage**: JSON files in `~/.vista/payloads/custom/`

---

## ❓ FAQ

**Q: Can I import from a file?**  
A: Yes! Use "📥 Import File" for JSON files, or copy-paste from text files using "📋 Bulk Import".

**Q: What if I paste 1000 payloads?**  
A: No problem! Bulk import handles large lists efficiently.

**Q: Can I edit payloads after importing?**  
A: Not yet in UI, but you can delete and re-add, or edit the JSON file directly.

**Q: Will auto-detect work for all payloads?**  
A: It works for common patterns. You can always add custom tags manually.

**Q: Can I import to multiple categories at once?**  
A: Not yet. Import to one category at a time, or use multiple import operations.

**Q: What happens to duplicate payloads?**  
A: They're added as separate entries. You can delete duplicates manually.

---

## 🎯 Summary

**Bulk Import** makes building your payload library **50x faster**:

- ✅ Paste multiple payloads at once
- ✅ Auto-detect payload types
- ✅ Auto-skip empty lines and comments
- ✅ Auto-create categories
- ✅ Add custom tags to all payloads
- ✅ Import 50+ payloads in 30 seconds

**Perfect for**:
- Importing from PayloadsAllTheThings
- Building custom collections
- Team payload sharing
- Quick library setup

---

**Version**: 2.6.0  
**Build**: Successful  
**JAR Size**: 324KB  
**Status**: ✅ Ready to Use!
