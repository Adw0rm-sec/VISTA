# VISTA Dual-Mode AI Assistant Guide

## Overview
VISTA now offers **two distinct AI modes** to match your testing workflow:

1. **Quick Suggestions Mode** - Get immediate methodology and payload suggestions
2. **Interactive Assistant Mode** - AI guides you step-by-step through testing

## Mode Selection

Located at the top of the AI Advisor tab, simply select your preferred mode from the dropdown.

---

## Mode 1: Quick Suggestions

### What It Does
Provides comprehensive testing methodology and payload suggestions in a single response.

### Best For
- Experienced testers who know what to do
- Quick reference for payloads and techniques
- Learning systematic methodologies
- Getting multiple options at once

### How It Works

**You Ask:**
```
"How to test for XSS?"
```

**AI Provides:**
```
📋 TESTING APPROACH:
1. Check for reflection
2. Test output encoding
3. Try context-specific payloads
4. Test WAF bypass if needed
5. Verify execution

🎯 SUGGESTED PAYLOADS:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
[10+ more payloads with explanations]

🛡️ WAF BYPASS:
[If WAF detected, specific bypass techniques]

✅ EXPECTED RESULTS:
[What to look for in responses]

💡 PRO TIPS:
[Additional insights]
```

### Example Workflow
1. Right-click request → "Send to VISTA AI Advisor"
2. Select "Quick Suggestions" mode
3. Ask: "How to test for SQLi?"
4. Get complete methodology + 20+ payloads
5. Test manually in Burp Repeater
6. Ask follow-up if needed

---

## Mode 2: Interactive Assistant

### What It Does
AI acts as a mentor, guiding you through testing **one step at a time**, adapting based on your reported results.

### Best For
- Learning penetration testing
- Complex exploitation scenarios
- When stuck on a specific issue
- Methodical, thorough testing
- Real-time guidance and adaptation

### How It Works

**Initial Request:**

**You Ask:**
```
"Test for XSS"
```

**AI Responds:**
```
🎯 TESTING PLAN OVERVIEW:
1. Check for reflection
2. Test output encoding
3. Try context-specific payloads
4. Bypass filters if needed
5. Verify execution

📍 STEP 1: Check for Reflection

🔬 WHAT TO TEST:
Add a unique marker to the parameter:
?search=VISTATEST123

📋 HOW TO TEST:
1. Go to Burp Repeater
2. Modify the 'search' parameter to: VISTATEST123
3. Send the request

❓ WHAT TO LOOK FOR:
- Does "VISTATEST123" appear in the response?
- Where does it appear? (HTML body, attribute, JavaScript?)
- Is it modified or encoded?

💬 REPORT BACK:
Tell me what you observed in the response.
```

**You Test & Report:**
```
"Yes, VISTATEST123 appears in the HTML body inside a <div> tag, 
not encoded"
```

**AI Adapts & Continues:**
```
✅ ANALYSIS OF YOUR RESULTS:
Great! The input is reflected in HTML context without encoding.
This is a strong indicator of XSS vulnerability.

📍 NEXT STEP: Test Basic XSS Payload

🔬 WHAT TO TEST:
Replace VISTATEST123 with:
<script>alert(1)</script>

📋 HOW TO TEST:
1. In Burp Repeater, change the parameter to:
   ?search=<script>alert(1)</script>
2. Send the request
3. Check the response

❓ WHAT TO LOOK FOR:
- Does the <script> tag appear intact?
- Is it encoded (e.g., &lt;script&gt;)?
- Any error messages or filtering?

💬 REPORT BACK:
Tell me what happened.
```

**You Continue:**
```
"The < and > are encoded to &lt; and &gt;"
```

**AI Adapts Again:**
```
✅ ANALYSIS OF YOUR RESULTS:
HTML encoding is being applied. We need to try alternative vectors.

📍 NEXT STEP: Try Event Handler Payload

🔬 WHAT TO TEST:
Try this payload:
" onmouseover="alert(1)

📋 HOW TO TEST:
1. In Burp Repeater, use:
   ?search=" onmouseover="alert(1)
2. Send the request
3. Check if it breaks out of the attribute

❓ WHAT TO LOOK FOR:
- Does the payload appear in an attribute?
- Is the quote character filtered?
- Can you see onmouseover in the HTML?

💬 REPORT BACK:
What do you see?
```

### Example Workflow
1. Right-click request → "Send to VISTA AI Advisor"
2. Select "Interactive Assistant" mode
3. Ask: "Test for XSS"
4. AI provides STEP 1
5. You test in Burp Repeater
6. You report results: "I see X in the response"
7. AI analyzes and provides STEP 2
8. Repeat until exploitation succeeds or alternative approach needed

---

## Key Differences

| Feature | Quick Suggestions | Interactive Assistant |
|---------|------------------|----------------------|
| **Response Style** | Complete methodology at once | One step at a time |
| **Interaction** | Optional follow-ups | Required back-and-forth |
| **Payloads** | 10-20+ payloads provided | 1-2 payloads per step |
| **Adaptation** | Static suggestions | Adapts based on your results |
| **Best For** | Experienced testers | Learning & complex cases |
| **Speed** | Fast - one response | Slower - multiple exchanges |
| **Depth** | Broad coverage | Deep, focused guidance |

---

## When to Use Each Mode

### Use Quick Suggestions When:
- ✅ You know what you're doing
- ✅ You want multiple options quickly
- ✅ You're looking for specific payloads
- ✅ You want to learn methodologies
- ✅ Time is limited

### Use Interactive Assistant When:
- ✅ You're learning penetration testing
- ✅ You're stuck on a specific issue
- ✅ The vulnerability is complex
- ✅ You want real-time guidance
- ✅ You need help adapting to responses
- ✅ You want to understand WHY each step matters

---

## Advanced Interactive Assistant Features

### 1. Context Awareness
AI remembers the entire conversation and adapts suggestions based on:
- What worked and what didn't
- Filters/WAF detected
- Your skill level (inferred from questions)
- Complexity of the target

### 2. Adaptive Payloads
If a payload doesn't work, AI suggests:
- Alternative encoding
- Different attack vectors
- WAF bypass techniques
- Context-specific variations

### 3. Clarifying Questions
AI may ask you questions to provide better guidance:
- "What HTTP status code did you get?"
- "Is there a WAF error message?"
- "What context is the reflection in?"

### 4. Success Recognition
When exploitation succeeds, AI:
- Congratulates you
- Suggests verification steps
- Recommends documentation
- Proposes next testing areas

---

## Example: Complete Interactive Session

**User:** "Test for SQL injection"

**AI:** 
```
🎯 TESTING PLAN:
1. Test for error-based SQLi
2. Try boolean-based blind
3. Test time-based blind
4. Extract data if vulnerable

📍 STEP 1: Error-Based Detection
🔬 Test: Add a single quote to the id parameter
   ?id=1'
💬 Report back what error you see (if any)
```

**User:** "I get: 'You have an error in your SQL syntax'"

**AI:**
```
✅ Excellent! SQL error confirms injection.

📍 STEP 2: Confirm Injection
🔬 Test: ?id=1' AND '1'='1
❓ Does the page load normally?
💬 Report back
```

**User:** "Yes, page loads normally"

**AI:**
```
✅ Perfect! Now let's confirm the negative case.

📍 STEP 3: Negative Test
🔬 Test: ?id=1' AND '1'='2
❓ Does the page show different content or error?
💬 Report back
```

**User:** "Page shows no results"

**AI:**
```
✅ CONFIRMED: Boolean-based SQL Injection!

📍 STEP 4: Enumerate Database
🔬 Test: ?id=1' UNION SELECT NULL,NULL,NULL--
❓ Any errors about column count?
💬 Report back
```

*[Session continues until full exploitation]*

---

## Tips for Interactive Mode

### 1. Be Specific in Reports
❌ Bad: "It didn't work"
✅ Good: "The payload was HTML encoded, I see &lt;script&gt; in the response"

### 2. Include Relevant Details
- HTTP status codes
- Error messages
- Where reflection appears
- Any filtering observed

### 3. Ask Questions
If you don't understand a step, ask:
- "Why are we testing this?"
- "What does this payload do?"
- "What if I see X instead?"

### 4. Switch Modes Anytime
You can switch between modes during a session:
- Start with Interactive for guidance
- Switch to Quick for payload list
- Switch back to Interactive if stuck

---

## Technical Details

### Conversation History
Both modes maintain conversation history, allowing:
- Follow-up questions
- Context-aware responses
- Adaptive suggestions

### WAF Detection
Both modes automatically:
- Detect WAF presence
- Suggest WAF-specific bypasses
- Adapt payloads for detected WAF

### Knowledge Base Integration
Both modes leverage:
- PayloadsAllTheThings (500+ techniques)
- Systematic testing methodologies
- Real-world bypass knowledge

---

## Keyboard Shortcuts

- **Enter** in query field → Send message
- **Clear button** → Reset conversation
- **Mode dropdown** → Switch modes anytime

---

## Best Practices

### For Quick Suggestions:
1. Ask specific questions
2. Provide context in your query
3. Use follow-ups for clarification
4. Test systematically through suggestions

### For Interactive Assistant:
1. Follow the steps in order
2. Report results accurately
3. Don't skip steps (AI builds on previous results)
4. Ask questions if confused
5. Be patient - thorough testing takes time

---

## Troubleshooting

**Q: AI gives too much information in Interactive mode**
A: This shouldn't happen - report as bug. Interactive mode should give ONE step at a time.

**Q: AI doesn't adapt to my results**
A: Make sure you're reporting specific observations. AI needs details to adapt.

**Q: Can I switch modes mid-conversation?**
A: Yes! Just select the other mode. Conversation history is preserved.

**Q: Which mode is better?**
A: Depends on your needs. Try both and see what fits your workflow.

---

## Examples by Vulnerability Type

### XSS Testing
- **Quick**: Get 20+ XSS payloads instantly
- **Interactive**: Step-by-step from reflection check to exploitation

### SQL Injection
- **Quick**: Get error-based, boolean, time-based payloads
- **Interactive**: Guided from detection to data extraction

### SSTI
- **Quick**: Get template syntax for multiple engines
- **Interactive**: Identify engine, test injection, escalate to RCE

### Command Injection
- **Quick**: Get command separators and bypass techniques
- **Interactive**: Test injection points, bypass filters, achieve RCE

### SSRF
- **Quick**: Get URL schemes and bypass techniques
- **Interactive**: Test internal access, bypass filters, exploit cloud metadata

---

## Future Enhancements

Planned improvements:
- Save interactive sessions
- Export step-by-step reports
- Replay previous sessions
- Share testing workflows
- Custom testing templates

---

**Version**: 2.0.0  
**Last Updated**: January 18, 2026  
**Modes**: Quick Suggestions + Interactive Assistant
