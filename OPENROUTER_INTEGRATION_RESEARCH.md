# OpenRouter Integration - Research & Planning

## 🎯 What is OpenRouter?

**OpenRouter** is a unified AI gateway that provides access to 500+ AI models from 60+ providers through a single OpenAI-compatible API.

**Think of it as**: "One API key to rule them all" - access GPT-4, Claude, Gemini, Llama, Mistral, and hundreds more without managing multiple API keys.

---

## ✅ YES, We Can Integrate OpenRouter!

**How Easy**: VERY EASY - It's OpenAI-compatible!

**Implementation Effort**: 1-2 hours (similar to adding Azure AI)

---

## 🌟 Why OpenRouter is AMAZING for VISTA

### 1. **Access to 500+ Models**
- OpenAI: GPT-4, GPT-4o, GPT-3.5
- Anthropic: Claude 3.5 Sonnet, Claude 3 Opus
- Google: Gemini Pro, Gemini Ultra
- Meta: Llama 3.1 (8B, 70B, 405B)
- Mistral: Mistral Large, Mistral Medium
- Cohere: Command R+
- **And 500+ more!**

### 2. **Single API Key**
- No need to manage multiple API keys
- One billing dashboard
- Unified usage tracking

### 3. **Smart Routing & Fallbacks**
- Automatic fallback if primary model fails
- Load balancing across providers
- Cost optimization

### 4. **Competitive Pricing**
- Often cheaper than direct provider access
- Pay-as-you-go (no subscriptions)
- Free tier available (25+ free models)

### 5. **OpenAI-Compatible**
- Same API format as OpenAI
- Can reuse our existing OpenAIService code
- Just change the base URL!

---

## 💰 Pricing Comparison

### OpenRouter vs Direct Providers

| Model | Direct Provider | OpenRouter | Savings |
|-------|----------------|------------|---------|
| GPT-4o | $2.50/1M tokens | $2.50-4.50/1M | Similar |
| Claude 3.5 Sonnet | $3.00/1M tokens | $3.00-5.00/1M | Similar |
| Llama 3.1 70B | Free (self-host) | $0.60-0.85/1M | Paid but convenient |
| Gemini Pro | $0.50/1M tokens | $0.50-1.00/1M | Similar |

**Platform Fee**: 5.5% on credit purchases (very reasonable)

### Free Models Available

OpenRouter offers 25+ FREE models including:
- Meta Llama 3.1 8B
- Google Gemma 2 9B
- Mistral 7B
- Qwen 2.5 7B
- And more!

**This is HUGE**: Users can test VISTA with AI for FREE!

---

## 🏗️ How It Works

### Architecture

```
VISTA
  ↓
OpenRouterService.java (new)
  ↓
HTTP POST to https://openrouter.ai/api/v1/chat/completions
  ↓
OpenRouter Gateway
  ↓
Routes to: GPT-4 | Claude | Gemini | Llama | etc.
  ↓
Returns response (OpenAI format)
```

### API Endpoint

**Base URL**: `https://openrouter.ai/api/v1`

**Endpoints**:
- `/chat/completions` - Main chat endpoint (OpenAI compatible)
- `/models` - List available models
- `/generation` - Get generation details

### Authentication

**Header**: `Authorization: Bearer YOUR_OPENROUTER_API_KEY`

**Optional Headers**:
- `HTTP-Referer`: Your site URL (for rankings)
- `X-Title`: Your app name (for rankings)

---

## 🔧 Implementation Details

### 1. OpenRouterService.java

```java
package com.vista.security.service;

public class OpenRouterService implements AIService {
    
    public static class Configuration {
        private String apiKey;
        private String model = "anthropic/claude-3.5-sonnet"; // Default
        private double temperature = 0.3;
        private int maxTokens = 2000;
        
        // Getters and setters
    }
    
    private final Configuration config;
    private static final String BASE_URL = "https://openrouter.ai/api/v1";
    
    public OpenRouterService(Configuration config) {
        this.config = config;
    }
    
    @Override
    public String ask(String systemPrompt, String userPrompt) throws Exception {
        String url = BASE_URL + "/chat/completions";
        
        // Build request (same format as OpenAI!)
        String requestBody = buildChatRequest(systemPrompt, userPrompt);
        
        // Send HTTP POST with OpenRouter-specific headers
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + config.apiKey);
        headers.put("Content-Type", "application/json");
        headers.put("HTTP-Referer", "https://github.com/your-repo/VISTA");
        headers.put("X-Title", "VISTA Security Testing");
        
        String response = sendHttpPost(url, requestBody, headers);
        
        // Parse response (same format as OpenAI!)
        return parseResponse(response);
    }
    
    // Helper method to list available models
    public List<Model> listModels() throws Exception {
        String url = BASE_URL + "/models";
        String response = sendHttpGet(url);
        return parseModels(response);
    }
}
```

### 2. AIConfigManager Updates

```java
// Add OpenRouter fields
private String openRouterApiKey = "";
private String openRouterModel = "anthropic/claude-3.5-sonnet";

// Add getters/setters
public String getOpenRouterApiKey() { return openRouterApiKey; }
public void setOpenRouterApiKey(String key) { 
    this.openRouterApiKey = key; 
    save();
}

public String getOpenRouterModel() { return openRouterModel; }
public void setOpenRouterModel(String model) { 
    this.openRouterModel = model; 
    save();
}
```

### 3. SettingsPanel Updates

```java
// Add UI components
private final JPasswordField openRouterApiKeyField = new JPasswordField(35);
private final JComboBox<String> openRouterModelCombo = new JComboBox<>();
private final JButton refreshOpenRouterModelsBtn = new JButton("Refresh Models");

// Add OpenRouter section
JPanel openRouterPanel = createSection("OpenRouter Settings");
openRouterPanel.add(createRow("API Key:", openRouterApiKeyField));
openRouterPanel.add(createRow("Model:", openRouterModelCombo));
openRouterPanel.add(refreshOpenRouterModelsBtn);

// Populate with popular models
openRouterModelCombo.addItem("anthropic/claude-3.5-sonnet");
openRouterModelCombo.addItem("openai/gpt-4o");
openRouterModelCombo.addItem("google/gemini-pro-1.5");
openRouterModelCombo.addItem("meta-llama/llama-3.1-70b-instruct");
openRouterModelCombo.addItem("mistralai/mistral-large");
```

---

## 🎯 Benefits for VISTA Users

### 1. **Model Flexibility**
- Try different models without changing code
- Switch from GPT-4 to Claude with one click
- Test which model works best for security testing

### 2. **Cost Optimization**
- Use cheaper models for simple tasks
- Use premium models for complex analysis
- Automatic fallback to cheaper alternatives

### 3. **No Vendor Lock-in**
- Not tied to OpenAI or any single provider
- Can switch providers anytime
- Future-proof against API changes

### 4. **Free Tier**
- 25+ free models available
- Perfect for testing and learning
- No credit card required to start

### 5. **Unified Billing**
- One invoice for all models
- Easy cost tracking
- Consolidated usage analytics

---

## 📊 Model Recommendations for VISTA

### Best Models by Use Case

#### 1. **General Security Testing** ⭐
**Model**: `anthropic/claude-3.5-sonnet`
- **Cost**: $3.00/1M input, $15.00/1M output
- **Context**: 200K tokens
- **Why**: Excellent reasoning, great at security analysis

#### 2. **Cost-Effective** 💰
**Model**: `meta-llama/llama-3.1-8b-instruct:free`
- **Cost**: FREE
- **Context**: 128K tokens
- **Why**: Good quality, zero cost, perfect for testing

#### 3. **Best Quality** 🏆
**Model**: `openai/gpt-4o`
- **Cost**: $2.50/1M input, $10.00/1M output
- **Context**: 128K tokens
- **Why**: Top-tier reasoning, excellent for complex analysis

#### 4. **Fast & Cheap** ⚡
**Model**: `google/gemini-flash-1.5`
- **Cost**: $0.075/1M input, $0.30/1M output
- **Context**: 1M tokens (!)
- **Why**: Very fast, very cheap, huge context

#### 5. **Code Analysis** 💻
**Model**: `anthropic/claude-3-opus`
- **Cost**: $15.00/1M input, $75.00/1M output
- **Context**: 200K tokens
- **Why**: Best at code understanding and payload generation

---

## 🆚 Comparison: OpenRouter vs Local vs Direct

| Feature | OpenRouter | Local (Ollama) | Direct (OpenAI) |
|---------|------------|----------------|-----------------|
| **Setup** | Easy (API key) | Medium (install) | Easy (API key) |
| **Cost** | $$ (pay-per-use) | Free (hardware) | $$$ (expensive) |
| **Privacy** | ⚠️ Cloud | ✅ Local | ⚠️ Cloud |
| **Models** | 500+ models | 100+ models | OpenAI only |
| **Quality** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Speed** | Fast (cloud) | Medium (local) | Fast (cloud) |
| **Offline** | ❌ Needs internet | ✅ Works offline | ❌ Needs internet |
| **Free Tier** | ✅ 25+ models | ✅ All models | ❌ No free tier |

---

## 🎯 Recommended Provider Strategy

### Tier System for Users

**Tier 1: Free (Beginners)**
- Provider: OpenRouter
- Model: `meta-llama/llama-3.1-8b-instruct:free`
- Cost: $0
- Use Case: Learning, testing, light usage

**Tier 2: Budget (Regular Users)**
- Provider: OpenRouter
- Model: `google/gemini-flash-1.5`
- Cost: ~$5-20/month
- Use Case: Regular security testing

**Tier 3: Professional (Power Users)**
- Provider: OpenRouter
- Model: `anthropic/claude-3.5-sonnet`
- Cost: ~$50-200/month
- Use Case: Professional pentesting

**Tier 4: Privacy-Focused (Enterprise)**
- Provider: Local (Ollama)
- Model: `llama3.1:8b`
- Cost: Hardware only
- Use Case: Air-gapped, compliance, privacy

**Tier 5: Best Quality (Premium)**
- Provider: Direct OpenAI or OpenRouter
- Model: `gpt-4o` or `claude-3-opus`
- Cost: ~$100-500/month
- Use Case: Critical assessments, complex analysis

---

## 🚀 Implementation Plan

### Phase 1: Basic OpenRouter Support (1-2 hours)

**Tasks**:
1. Create `OpenRouterService.java` (copy OpenAIService, change URL)
2. Update `AIConfigManager` (add OpenRouter fields)
3. Update `SettingsPanel` (add OpenRouter section)
4. Add provider dropdown: OpenAI | Azure AI | OpenRouter | Local AI
5. Test with free model

**Result**: Users can use OpenRouter with any model

### Phase 2: Model Selection UI (1-2 hours)

**Tasks**:
1. Fetch models from `/models` endpoint
2. Categorize models (by provider, cost, capability)
3. Add model search/filter
4. Show model details (cost, context, speed)
5. Recommend models based on use case

**Result**: Easy model discovery and selection

### Phase 3: Smart Features (2-3 hours)

**Tasks**:
1. Automatic fallback (if primary model fails)
2. Cost tracking and warnings
3. Model performance comparison
4. Usage analytics
5. Model recommendations

**Result**: Intelligent model management

---

## 💡 User Experience

### Setup Flow

1. **Get API Key**:
   - Go to https://openrouter.ai
   - Sign up (free)
   - Get API key

2. **Configure VISTA**:
   - Settings → Provider: "OpenRouter"
   - Paste API key
   - Select model (or use default)
   - Test connection

3. **Start Testing**:
   - Use VISTA normally
   - OpenRouter handles routing
   - Pay only for what you use

### Settings Panel

```
┌─────────────────────────────────────────────────┐
│ OpenRouter Settings                             │
├─────────────────────────────────────────────────┤
│ API Key: [••••••••••••••••••••••••••]  [Show]  │
│                                                 │
│ Model: [anthropic/claude-3.5-sonnet      ▼]    │
│                                                 │
│ Model Info:                                     │
│   Provider: Anthropic                           │
│   Cost: $3.00/1M input, $15.00/1M output       │
│   Context: 200K tokens                          │
│   Speed: Fast                                   │
│                                                 │
│ [🔄 Refresh Models] [💰 View Pricing]          │
│                                                 │
│ Status: ✓ Connected (500+ models available)    │
└─────────────────────────────────────────────────┘
```

---

## 🎓 Advantages Over Other Options

### vs Direct OpenAI
- ✅ Access to more models (Claude, Gemini, etc.)
- ✅ Competitive pricing
- ✅ Automatic fallbacks
- ✅ Free tier available

### vs Local AI (Ollama)
- ✅ No installation required
- ✅ Access to premium models (GPT-4, Claude)
- ✅ No hardware requirements
- ✅ Always up-to-date models
- ⚠️ Requires internet
- ⚠️ Costs money (but has free tier)

### vs Azure AI
- ✅ Simpler setup (no deployment needed)
- ✅ More model choices
- ✅ Better pricing transparency
- ✅ Free tier available

---

## 🔒 Privacy Considerations

**Data Handling**:
- Data sent to OpenRouter servers
- OpenRouter routes to model provider
- Subject to provider's privacy policy

**For Privacy-Sensitive Work**:
- Use Local AI (Ollama) instead
- Or use OpenRouter with open-source models
- Check provider's data retention policy

**Recommendation**:
- OpenRouter: General testing, non-sensitive data
- Local AI: Sensitive data, compliance requirements

---

## 📋 Final Recommendation

### ✅ YES, Add OpenRouter Support!

**Why**:
1. ✅ Very easy to implement (OpenAI-compatible)
2. ✅ Gives users access to 500+ models
3. ✅ Free tier available (great for beginners)
4. ✅ Competitive pricing
5. ✅ No vendor lock-in
6. ✅ Smart routing and fallbacks

**Priority**: HIGH (implement alongside Local AI)

**Effort**: 1-2 hours for basic support

**User Benefit**: HUGE (flexibility, cost savings, free tier)

---

## 🎯 Recommended Provider Lineup

After all research, here's the ideal provider lineup for VISTA:

1. **OpenRouter** ⭐ - Best for most users
   - 500+ models
   - Free tier
   - Easy setup
   - Flexible

2. **Local AI (Ollama)** ⭐ - Best for privacy
   - Free
   - Private
   - Offline
   - Customizable

3. **OpenAI** - Best for simplicity
   - Easy setup
   - Reliable
   - Good quality
   - Expensive

4. **Azure AI** - Best for enterprise
   - Enterprise features
   - Compliance
   - SLAs
   - Complex setup

---

## 📊 Implementation Priority

**Recommended Order**:
1. ✅ OpenAI (already done)
2. ✅ Azure AI (already done)
3. 🔥 **OpenRouter** (implement next - HIGH PRIORITY)
4. 🔥 **Local AI** (implement next - HIGH PRIORITY)

**Why this order**:
- OpenRouter + Local AI together give users maximum flexibility
- OpenRouter is easy (1-2 hours)
- Local AI is slightly more complex (6-10 hours)
- Together they cover all use cases

---

**Next Step**: Create unified spec for both OpenRouter + Local AI support! 🚀
