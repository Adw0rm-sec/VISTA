# Request Collection Engine - User Guide

## Overview

The **Request Collection Engine** helps you organize and analyze similar HTTP requests together. Perfect for testing related endpoints, comparing responses, and tracking your testing progress.

---

## Quick Start

### 1. Add Your First Request

**Right-click any request** in Burp (Proxy, Repeater, Sitemap):
1. Select **"📁 Add to Collection"**
2. If no collections exist, you'll be prompted to create one
3. Enter a name (e.g., "User API")
4. Request is added instantly!

### 2. View Your Collection

1. Go to **"📁 Collections"** tab in VISTA
2. Select your collection from the left panel
3. See all requests in the center table
4. Click a request to view full details below

### 3. Track Your Testing

- **Mark Tested**: Click "✓ Mark Tested" when you've tested a request
- **Mark Success**: Click "✓ Success" if it was successful
- **Add Notes**: Click "📝 Add Notes" to record observations

---

## Common Workflows

### Testing Similar Endpoints

**Scenario**: You want to test all `/api/user/*` endpoints

1. Create collection "User API Endpoints"
2. Right-click each user endpoint → "Add to Collection"
3. Go to Collections tab
4. Test each request systematically
5. Mark tested/success as you go
6. Add notes for findings

**Benefits**:
- See all related endpoints in one place
- Track which ones you've tested
- Compare responses easily
- Never lose track of progress

### Parameter Fuzzing

**Scenario**: Testing different parameter values for SQLi

1. Create collection "Login SQLi Tests"
2. Send request to Repeater
3. Modify parameter with different payloads
4. Right-click each variation → "Add to Collection"
5. Mark which ones succeeded
6. Compare successful vs failed requests

**Benefits**:
- Keep all test variations organized
- Identify patterns in successful bypasses
- Document your methodology

### Multi-Step Workflows

**Scenario**: Testing a complete registration flow

1. Create collection "Registration Flow"
2. Add requests in order:
   - POST /api/register
   - GET /api/verify?token=...
   - POST /api/login
   - GET /api/profile
3. Test each step
4. Mark which steps work
5. Add notes about dependencies

**Benefits**:
- Visualize the complete flow
- Track which steps are vulnerable
- Document the attack chain

---

## Features

### Collection Management

**Create Collection**:
- Click "➕ New Collection"
- Enter name and description
- Or auto-create when adding first request

**Rename Collection**:
- Select collection
- Click "✏️ Rename"
- Enter new name

**Delete Collection**:
- Select collection
- Click "🗑️ Delete"
- Confirm deletion

### Request Management

**Add Request**:
- Right-click any request in Burp
- Select "📁 Add to Collection"
- Choose collection

**View Request**:
- Select collection
- Click request in table
- View full request/response below

**Delete Request**:
- Select request
- Click "🗑️ Delete"
- Confirm deletion

**Mark Tested**:
- Select request
- Click "✓ Mark Tested"
- Shows ✓ in Tested column

**Mark Success**:
- Select request
- Click "✓ Success"
- Shows ✓ in Success column

**Add Notes**:
- Select request
- Click "📝 Add Notes"
- Enter observations

### Comparison View

**Compare Two Requests**:
1. Select collection with 2+ requests
2. Click "🔍 Compare"
3. Select two requests from dropdowns
4. Click "Compare"
5. View side-by-side comparison

**Use Cases**:
- Compare successful vs failed requests
- Spot differences in responses
- Identify patterns

### Export/Import

**Export Collection**:
1. Select collection
2. Click "📤 Export"
3. Choose location
4. Save as JSON

**Import Collection**:
1. Click "📥 Import"
2. Select JSON file
3. Collection is imported

**Use Cases**:
- Share findings with team
- Backup your work
- Transfer between Burp instances

---

## Tips & Tricks

### Organizing Collections

**By Feature**:
- "User Management API"
- "Payment Processing"
- "Admin Panel"

**By Vulnerability Type**:
- "SQLi Test Cases"
- "XSS Attempts"
- "IDOR Tests"

**By Testing Phase**:
- "Initial Recon"
- "Active Testing"
- "Exploitation"

### Naming Conventions

**Good Names**:
- "User API - SQLi Tests"
- "Admin Panel - Auth Bypass"
- "Payment Flow - IDOR"

**Bad Names**:
- "Test 1"
- "Requests"
- "Stuff"

### Using Notes Effectively

**What to Record**:
- Payload that worked
- Error messages observed
- Interesting behavior
- Next steps to try

**Example Notes**:
```
✓ SQLi confirmed with ' OR '1'='1
Response time: 5 seconds (possible time-based)
TODO: Try UNION injection
```

### Keyboard Shortcuts

- **Double-click** request → View details
- **Ctrl+C** → Copy selected request (future)
- **Delete** → Delete selected request (future)

---

## Statistics

The stats bar shows:
- **Collections**: Total number of collections
- **Requests**: Total requests across all collections
- **Tested**: Number of requests marked as tested

Example: `Collections: 5 | Requests: 87 | Tested: 62`

---

## Data Storage

**Location**: `~/.vista/collections/`

**Format**: JSON files (one per collection)

**Backup**: Simply copy the `~/.vista/collections/` folder

**Portability**: JSON files can be shared across systems

---

## Troubleshooting

### Collection Not Showing

**Problem**: Created collection but don't see it

**Solution**:
1. Click "🔄 Refresh"
2. Check `~/.vista/collections/` folder exists
3. Restart Burp Suite

### Request Not Added

**Problem**: Right-click → Add to Collection doesn't work

**Solution**:
1. Make sure you selected a request
2. Check VISTA is loaded (see VISTA tab)
3. Try creating collection first

### Can't Compare Requests

**Problem**: Compare button disabled

**Solution**:
- Need at least 2 requests in collection
- Add more requests first

### Export Failed

**Problem**: Export shows error

**Solution**:
1. Check write permissions
2. Choose different location
3. Check disk space

---

## Best Practices

### 1. Create Collections Early
Don't wait until you have 100 requests. Create collections as you start testing.

### 2. Use Descriptive Names
Future you will thank you for clear collection names.

### 3. Add Notes Immediately
Record observations while they're fresh in your mind.

### 4. Mark Progress
Use tested/success flags to track what you've done.

### 5. Export Regularly
Backup your collections, especially before major changes.

### 6. Compare Often
Use comparison view to spot patterns and differences.

### 7. Clean Up
Delete old/irrelevant collections to keep things organized.

---

## Advanced Usage

### Pattern Detection

VISTA can detect similar requests:
- Same host
- Same base path
- Different IDs/parameters

Example:
- `/api/user/123` and `/api/user/456` are similar
- Both would be suggested for "User API" collection

### Auto-Naming

When creating collections, VISTA suggests names based on:
- Common URL prefix
- Host name
- Request patterns

Example:
- Requests to `/api/user/*` → Suggests "User Endpoints"

### Bulk Operations (Future)

Coming soon:
- Bulk import from Proxy history
- Bulk mark as tested
- Bulk delete
- Bulk export

---

## Integration with Other Features

### With AI Advisor

**Future Enhancement**:
- Send entire collection to AI for analysis
- AI suggests which requests to test first
- AI detects patterns across requests

### With Payload Library

**Future Enhancement**:
- Apply payload library to all requests in collection
- Track which payloads work for which requests
- Build custom payload library from successful tests

### With Prompt Templates

**Future Enhancement**:
- Apply template to all requests in collection
- Batch testing with templates
- Template-based comparison

---

## FAQ

**Q: How many requests can a collection hold?**  
A: Tested with 100+ requests. No hard limit.

**Q: Can I have multiple collections?**  
A: Yes! Create as many as you need.

**Q: Are collections shared between Burp instances?**  
A: No, but you can export/import to share.

**Q: Can I edit a request in a collection?**  
A: Not yet. Add a new version instead.

**Q: What happens if I delete a collection?**  
A: All requests in it are deleted. Export first if unsure.

**Q: Can I merge collections?**  
A: Not yet. Future enhancement.

**Q: Does this work with Burp Pro features?**  
A: Yes! Works with all Burp editions.

---

## Keyboard Shortcuts (Future)

Coming soon:
- `Ctrl+N` - New collection
- `Ctrl+E` - Export collection
- `Ctrl+I` - Import collection
- `Ctrl+F` - Search in collection
- `Delete` - Delete selected item

---

## Video Tutorials (Future)

Coming soon:
- Creating your first collection
- Comparing requests
- Export/import workflow
- Advanced organization tips

---

## Support

**Issues**: [GitHub Issues](https://github.com/rajrathod-code/VISTA/issues)  
**Docs**: [Full Documentation](README.md)  
**Guide**: [Feature Complete](FEATURE_5_COMPLETE.md)

---

**Happy Testing!** 🚀
