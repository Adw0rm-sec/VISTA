# VISTA Dual-Mode Quick Start Guide

## 🚀 Get Started in 2 Minutes

### Step 1: Load VISTA Extension
1. Open Burp Suite
2. Go to **Extensions** → **Add**
3. Select `target/vista-1.0.0-MVP.jar`
4. See VISTA tab appear

### Step 2: Configure AI
1. Click **VISTA** tab
2. Go to **⚙️ Settings** tab
3. Choose provider: **OpenAI** or **Azure AI**
4. Enter your **API Key**
5. Click **Save**

### Step 3: Choose Your Mode

---

## 🎯 Mode 1: Quick Suggestions

**Use when:** You need payloads fast

### Workflow
```
1. Right-click any request in Burp
   ↓
2. Select "Send to VISTA AI Advisor"
   ↓
3. Select "Quick Suggestions" from dropdown
   ↓
4. Type: "How to test for XSS?"
   ↓
5. Click "Send"
   ↓
6. Get 20+ payloads instantly!
```

### Example Output
```
📋 TESTING APPROACH:
1. Check reflection
2. Test output encoding
3. Try context-specific payloads
4. Bypass filters
5. Verify execution

🎯 SUGGESTED PAYLOADS:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
[+15 more...]

🛡️ WAF BYPASS:
[If Cloudflare detected]
<sCrIpT>alert(1)</sCrIpT>
<script>alert(String.fromCharCode(88,83,83))</script>

✅ EXPECTED RESULTS:
Look for <script> tag in response...

💡 PRO TIPS:
Try event handlers if tags are filtered...
```

### What You Do Next
- Copy payloads to Burp Repeater
- Test them one by one
- Find what works!

**Time:** 2-5 minutes total

---

## 🎓 Mode 2: Interactive Assistant

**Use when:** You want step-by-step guidance

### Workflow
```
1. Right-click any request in Burp
   ↓
2. Select "Send to VISTA AI Advisor"
   ↓
3. Select "Interactive Assistant" from dropdown
   ↓
4. Type: "Test for XSS"
   ↓
5. Click "Send"
   ↓
6. AI gives you STEP 1
   ↓
7. You test it in Burp Repeater
   ↓
8. You report what you saw
   ↓
9. AI gives you STEP 2 (adapted to your results)
   ↓
10. Repeat until success!
```

### Example Conversation

**You:** "Test for XSS"

**AI:**
```
🎯 TESTING PLAN:
1. Check reflection ← START HERE
2. Test output encoding
3. Try context-specific payloads
4. Bypass filters
5. Verify execution

📍 STEP 1: Check for Reflection

🔬 WHAT TO TEST:
?search=VISTATEST123

📋 HOW TO TEST:
1. Go to Burp Repeater
2. Change 'search' parameter to: VISTATEST123
3. Send request

❓ WHAT TO LOOK FOR:
• Does "VISTATEST123" appear in response?
• Where? (HTML body, attribute, JavaScript?)
• Is it encoded?

💬 REPORT BACK:
Tell me what you observed.
```

**You:** "Yes, VISTATEST123 appears in a `<div>` tag, not encoded"

**AI:**
```
✅ ANALYSIS:
Perfect! Input reflected in HTML without encoding.
Strong XSS indicator.

📍 STEP 2: Test Basic XSS

🔬 WHAT TO TEST:
?search=<script>alert(1)</script>

📋 HOW TO TEST:
1. In Burp Repeater, change parameter
2. Send request
3. Check response

❓ WHAT TO LOOK FOR:
• Does <script> appear intact?
• Is it encoded (&lt;script&gt;)?
• Any errors?

💬 REPORT BACK:
What happened?
```

**You:** "The `<` and `>` are encoded"

**AI:**
```
✅ ANALYSIS:
HTML encoding detected. Need alternative vectors.

📍 STEP 3: Try Event Handler

🔬 WHAT TO TEST:
" onmouseover="alert(1)

📋 HOW TO TEST:
1. Use: ?search=" onmouseover="alert(1)
2. Send request
3. Check if it breaks out of attribute

❓ WHAT TO LOOK FOR:
• Does payload appear in attribute?
• Is quote filtered?
• Can you see onmouseover?

💬 REPORT BACK:
What do you see?
```

**[Continue until exploitation succeeds]**

**Time:** 10-30 minutes (includes testing time)

---

## 🔄 Switch Modes Anytime

You can switch between modes during testing:

```
Start with Quick Suggestions
         ↓
    Get payloads
         ↓
    Try them all
         ↓
    Nothing works? 😕
         ↓
Switch to Interactive Assistant
         ↓
    Get step-by-step help
         ↓
    Find the issue!
         ↓
    Success! 🎉
```

---

## 📊 Quick Comparison

| Question | Quick Suggestions | Interactive Assistant |
|----------|------------------|----------------------|
| How fast? | ⚡ Very fast (1 response) | 🐢 Slower (5-10 responses) |
| How many payloads? | 📦 10-20+ at once | 🎯 1-2 per step |
| Do I need experience? | ✅ Yes, helpful | ❌ No, teaches you |
| Does AI adapt? | ❌ Static suggestions | ✅ Adapts to your results |
| Best for? | 🏃 Speed testing | 🎓 Learning |

---

## 💡 Pro Tips

### For Quick Suggestions:
1. ✅ Use quick action buttons: `[XSS Testing]` `[SQLi Testing]`
2. ✅ Ask specific questions: "XSS payloads for attribute context"
3. ✅ Copy-paste payloads to Repeater
4. ✅ Test systematically through the list

### For Interactive Assistant:
1. ✅ Follow steps in order (don't skip!)
2. ✅ Report results specifically: "I see X in the response"
3. ✅ Include error messages and status codes
4. ✅ Ask "why" if you don't understand
5. ✅ Be patient - learning takes time

### For Both:
1. ✅ Load request first (right-click → Send to VISTA)
2. ✅ Check Dashboard for AI status
3. ✅ Use Clear button to start fresh
4. ✅ Switch modes if stuck

---

## 🎯 Common Use Cases

### Use Case 1: Bug Bounty Hunting
**Goal:** Test 50 parameters quickly  
**Mode:** Quick Suggestions  
**Why:** Fast, efficient, you know what to do

```
For each parameter:
1. Send to VISTA (10 sec)
2. Get payloads (30 sec)
3. Test in Repeater (2 min)
4. Move to next
Total: ~3 min per parameter
```

### Use Case 2: Learning Penetration Testing
**Goal:** Understand XSS testing properly  
**Mode:** Interactive Assistant  
**Why:** Step-by-step with explanations

```
1. Send request to VISTA
2. Ask: "Teach me XSS testing"
3. Follow each step
4. Learn WHY each test matters
5. Understand the methodology
Total: 20 min, deep learning
```

### Use Case 3: Stuck on Complex Filter
**Goal:** Bypass weird input filter  
**Mode:** Start Quick, switch to Interactive  
**Why:** Try common bypasses first, then get help

```
1. Quick mode: Get 20 bypass payloads
2. Test them all
3. Still stuck?
4. Switch to Interactive
5. AI helps you debug step-by-step
6. Success!
```

---

## 🚨 Troubleshooting

### "No request loaded"
→ Right-click a request in Burp first  
→ Select "Send to VISTA AI Advisor"

### "AI not configured"
→ Go to Settings tab  
→ Enter your API key  
→ Click Save

### "AI gives too much in Interactive mode"
→ This shouldn't happen  
→ Report as bug if it does

### "AI doesn't adapt to my results"
→ Be more specific in your reports  
→ Include: status codes, error messages, what you see

### "Which mode should I use?"
→ Experienced? Use Quick  
→ Learning? Use Interactive  
→ Stuck? Switch to Interactive  
→ Not sure? Try both!

---

## 📚 More Resources

- [📖 Complete Dual-Mode Guide](DUAL_MODE_GUIDE.md) - Detailed guide
- [📊 Mode Comparison](MODE_COMPARISON.md) - Visual comparison
- [🔧 Implementation Details](IMPLEMENTATION_SUMMARY.md) - Technical info
- [🚀 Advanced Features](ADVANCED_FEATURES.md) - WAF detection, etc.

---

## ✅ Checklist

Before you start:
- [ ] VISTA extension loaded in Burp
- [ ] AI configured in Settings tab
- [ ] Request loaded (right-click → Send to VISTA)
- [ ] Mode selected (Quick or Interactive)
- [ ] Ready to test!

---

## 🎉 You're Ready!

**Quick Suggestions:** Fast payloads for experienced testers  
**Interactive Assistant:** Step-by-step guidance for learning

**Try both and find what works for you!**

---

**Need help?** Check the [Dual-Mode Guide](DUAL_MODE_GUIDE.md) for detailed examples.

**Found a bug?** Report it on [GitHub Issues](https://github.com/rajrathod-code/VISTA/issues).

**Happy Testing! 🚀**
