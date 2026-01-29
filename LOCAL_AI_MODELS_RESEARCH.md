# Local AI Models Support - Research & Planning

## Executive Summary

**Goal**: Add support for locally-hosted AI models to VISTA, giving users privacy, cost savings, and offline capabilities.

**Current State**: VISTA supports OpenAI and Azure AI (cloud-based, requires API keys and internet)

**Proposed Solution**: Add support for local AI models via OpenAI-compatible APIs (Ollama, LM Studio, llama.cpp)

---

## 🔍 Research Findings

### 1. What Competitors Are Doing

Based on research, most AI-powered security tools are moving towards supporting local models because:

1. **Privacy**: Sensitive security data stays on-premises
2. **Cost**: No API fees for heavy usage
3. **Offline**: Works without internet connection
4. **Compliance**: Meets data residency requirements
5. **Customization**: Can fine-tune models for security-specific tasks

### 2. Popular Local AI Platforms

#### **Ollama** (Most Popular)
- **What**: Easy-to-use local AI platform
- **API**: OpenAI-compatible endpoints
- **Default Port**: `http://localhost:11434`
- **Endpoints**: 
  - `/v1/chat/completions` (OpenAI compatible)
  - `/v1/models` (list available models)
  - `/v1/embeddings` (for embeddings)
- **Pros**: 
  - Easiest to install and use
  - Huge model library (100+ models)
  - Active community
  - Cross-platform (Mac, Linux, Windows)
- **Cons**: 
  - Requires local installation
  - Needs decent hardware (8GB+ RAM)

#### **LM Studio** (User-Friendly GUI)
- **What**: Desktop app with GUI for running local models
- **API**: OpenAI-compatible endpoints
- **Default Port**: `http://localhost:1234`
- **Endpoints**: Same as OpenAI API
- **Pros**:
  - Beautiful GUI
  - Easy model management
  - Multi-model serving
  - Built-in benchmarking
- **Cons**:
  - Desktop app required
  - Less automation-friendly than Ollama

#### **llama.cpp Server** (Advanced)
- **What**: C++ implementation, very fast
- **API**: OpenAI-compatible endpoints
- **Pros**:
  - Fastest inference
  - Lowest memory usage
  - Most flexible
- **Cons**:
  - More technical to set up
  - Command-line focused

---

## 🤖 Recommended Models for Security Testing

### Top Models (2024-2025)

Based on research, here are the best models for VISTA's use case:

#### **1. Llama 3.1 (8B) - RECOMMENDED**
- **Size**: 8 billion parameters (~5GB)
- **RAM Required**: 8GB minimum
- **Strengths**: 
  - Excellent reasoning
  - Good at security analysis
  - Fast inference
  - 128K context window
- **Ollama**: `ollama pull llama3.1:8b`
- **Best For**: General security testing, vulnerability analysis

#### **2. DeepSeek-R1 (7B/14B)**
- **Size**: 7-14 billion parameters
- **RAM Required**: 8-16GB
- **Strengths**:
  - Advanced reasoning
  - Code analysis
  - Security-focused
- **Ollama**: `ollama pull deepseek-r1:7b`
- **Best For**: Complex vulnerability chains, exploit development

#### **3. Qwen 2.5 Coder (7B)**
- **Size**: 7 billion parameters
- **RAM Required**: 8GB
- **Strengths**:
  - Code understanding
  - Payload generation
  - API analysis
- **Ollama**: `ollama pull qwen2.5-coder:7b`
- **Best For**: Payload crafting, code review

#### **4. Mistral (7B)**
- **Size**: 7 billion parameters
- **RAM Required**: 8GB
- **Strengths**:
  - Fast
  - Efficient
  - Good general knowledge
- **Ollama**: `ollama pull mistral:7b`
- **Best For**: Quick analysis, general testing

#### **5. Gemma 2 (9B)**
- **Size**: 9 billion parameters
- **RAM Required**: 10GB
- **Strengths**:
  - Multimodal
  - Efficient
  - Good reasoning
- **Ollama**: `ollama pull gemma2:9b`
- **Best For**: Balanced performance

### Model Size Recommendations

| Hardware | Recommended Model | Performance |
|----------|------------------|-------------|
| 8GB RAM | Llama 3.1 8B, Mistral 7B | Good |
| 16GB RAM | Llama 3.1 8B, DeepSeek-R1 14B | Excellent |
| 32GB+ RAM | Llama 3.1 70B, DeepSeek-R1 70B | Outstanding |

---

## 🏗️ Implementation Logic

### Architecture Design

```
┌─────────────────────────────────────────────────┐
│                  VISTA                          │
│                                                 │
│  ┌──────────────────────────────────────────┐  │
│  │      AIConfigManager                     │  │
│  │  - provider: "OpenAI" | "Azure" | "Local"│  │
│  │  - endpoint: user-configurable           │  │
│  │  - model: user-selectable                │  │
│  └──────────────────────────────────────────┘  │
│                     │                           │
│                     ▼                           │
│  ┌──────────────────────────────────────────┐  │
│  │      AIService Factory                   │  │
│  │  - Creates appropriate service           │  │
│  └──────────────────────────────────────────┘  │
│         │              │              │         │
│         ▼              ▼              ▼         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ OpenAI   │  │  Azure   │  │  Local   │     │
│  │ Service  │  │ Service  │  │ Service  │     │
│  └──────────┘  └──────────┘  └──────────┘     │
│                                    │            │
└────────────────────────────────────┼────────────┘
                                     │
                                     ▼
                    ┌────────────────────────────┐
                    │   Local AI Platform        │
                    │  (Ollama / LM Studio)      │
                    │  http://localhost:11434    │
                    └────────────────────────────┘
```

### Key Implementation Points

#### 1. **OpenAI-Compatible API**
- All local platforms (Ollama, LM Studio, llama.cpp) support OpenAI-compatible endpoints
- We can reuse most of our OpenAI service code
- Just change the base URL from `https://api.openai.com` to `http://localhost:11434`

#### 2. **LocalAIService Class**
```java
public class LocalAIService implements AIService {
    private String endpoint = "http://localhost:11434";
    private String model = "llama3.1:8b";
    
    // Same interface as OpenAIService
    // Just different base URL
}
```

#### 3. **Configuration Changes**
Add to Settings Panel:
- **Provider**: OpenAI | Azure AI | **Local AI** (new)
- **Endpoint**: `http://localhost:11434` (default for Ollama)
- **Model**: Dropdown with common models + custom input
- **Test Connection**: Verify local server is running

#### 4. **Model Detection**
- Call `/v1/models` endpoint to list available models
- Auto-populate dropdown with installed models
- Show helpful message if no models found

#### 5. **Error Handling**
- Detect if local server is not running
- Provide helpful error messages:
  - "Ollama not running. Start with: ollama serve"
  - "No models installed. Install with: ollama pull llama3.1:8b"

---

## 💡 User Benefits

### Why Users Will Love This

1. **Privacy First**
   - Sensitive security data never leaves their machine
   - No API keys to manage
   - No data sent to cloud providers

2. **Cost Savings**
   - No API fees (OpenAI can be expensive for heavy use)
   - Unlimited usage
   - No rate limits

3. **Offline Capability**
   - Works without internet
   - Perfect for air-gapped environments
   - No dependency on external services

4. **Performance**
   - Local inference can be faster (no network latency)
   - Consistent response times
   - No API rate limiting

5. **Customization**
   - Can fine-tune models for specific security tasks
   - Can use specialized security models
   - Full control over model behavior

---

## 🎯 Recommended Implementation Approach

### Phase 1: Basic Support (MVP)

**Goal**: Get local AI working with minimal changes

**Tasks**:
1. Create `LocalAIService.java` (similar to OpenAIService)
2. Update `AIConfigManager` to support "Local AI" provider
3. Update `SettingsPanel` with Local AI configuration
4. Add endpoint and model fields
5. Test with Ollama

**Estimated Effort**: 2-3 hours

### Phase 2: Enhanced UX

**Goal**: Make it user-friendly

**Tasks**:
1. Auto-detect if Ollama/LM Studio is running
2. Fetch available models from `/v1/models`
3. Show helpful setup instructions
4. Add "Quick Setup" guide in UI
5. Model recommendations based on hardware

**Estimated Effort**: 2-3 hours

### Phase 3: Advanced Features

**Goal**: Power user features

**Tasks**:
1. Support multiple local endpoints
2. Model performance benchmarking
3. Custom model parameters (temperature, top_p, etc.)
4. Model switching per feature
5. Fallback to cloud if local fails

**Estimated Effort**: 3-4 hours

---

## 🔧 Technical Implementation Details

### 1. LocalAIService.java

```java
package com.vista.security.service;

public class LocalAIService implements AIService {
    
    public static class Configuration {
        private String endpoint = "http://localhost:11434";
        private String model = "llama3.1:8b";
        private double temperature = 0.3;
        private int maxTokens = 2000;
        
        // Getters and setters
    }
    
    private final Configuration config;
    
    public LocalAIService(Configuration config) {
        this.config = config;
    }
    
    @Override
    public String ask(String systemPrompt, String userPrompt) throws Exception {
        // Use OpenAI-compatible endpoint
        String url = config.endpoint + "/v1/chat/completions";
        
        // Build request (same format as OpenAI)
        String requestBody = buildChatRequest(systemPrompt, userPrompt);
        
        // Send HTTP POST
        String response = sendHttpPost(url, requestBody);
        
        // Parse response (same format as OpenAI)
        return parseResponse(response);
    }
    
    // Helper method to list available models
    public List<String> listModels() throws Exception {
        String url = config.endpoint + "/v1/models";
        String response = sendHttpGet(url);
        return parseModels(response);
    }
    
    // Helper method to check if server is running
    public boolean isServerRunning() {
        try {
            listModels();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
```

### 2. AIConfigManager Updates

```java
// Add new fields
private String localEndpoint = "http://localhost:11434";
private String localModel = "llama3.1:8b";

// Add getters/setters
public String getLocalEndpoint() { return localEndpoint; }
public void setLocalEndpoint(String endpoint) { 
    this.localEndpoint = endpoint; 
    save();
}

public String getLocalModel() { return localModel; }
public void setLocalModel(String model) { 
    this.localModel = model; 
    save();
}
```

### 3. SettingsPanel Updates

```java
// Add UI components
private final JTextField localEndpointField = new JTextField("http://localhost:11434", 35);
private final JComboBox<String> localModelCombo = new JComboBox<>();
private final JButton refreshModelsBtn = new JButton("Refresh Models");

// Add Local AI section
JPanel localPanel = createSection("Local AI Settings");
localPanel.add(createRow("Endpoint:", localEndpointField));
localPanel.add(createRow("Model:", localModelCombo));
localPanel.add(refreshModelsBtn);

// Add refresh button handler
refreshModelsBtn.addActionListener(e -> refreshLocalModels());

private void refreshLocalModels() {
    try {
        LocalAIService.Configuration config = new LocalAIService.Configuration();
        config.setEndpoint(localEndpointField.getText());
        LocalAIService service = new LocalAIService(config);
        
        List<String> models = service.listModels();
        localModelCombo.removeAllItems();
        for (String model : models) {
            localModelCombo.addItem(model);
        }
        
        if (models.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "No models found. Install with:\n\nollama pull llama3.1:8b",
                "No Models", JOptionPane.INFORMATION_MESSAGE);
        }
    } catch (Exception ex) {
        JOptionPane.showMessageDialog(this,
            "Cannot connect to local AI server.\n\n" +
            "Make sure Ollama is running:\n\nollama serve",
            "Connection Error", JOptionPane.ERROR_MESSAGE);
    }
}
```

---

## 📋 User Setup Guide (To Include in Docs)

### Quick Start: Using Local AI with VISTA

#### Step 1: Install Ollama

**Mac/Linux**:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows**:
Download from https://ollama.com/download

#### Step 2: Start Ollama

```bash
ollama serve
```

#### Step 3: Install a Model

```bash
# Recommended: Llama 3.1 8B (requires 8GB RAM)
ollama pull llama3.1:8b

# Alternative: Mistral 7B (faster, requires 8GB RAM)
ollama pull mistral:7b

# For more power: Llama 3.1 70B (requires 32GB+ RAM)
ollama pull llama3.1:70b
```

#### Step 4: Configure VISTA

1. Open VISTA Settings tab
2. Select "Local AI" as provider
3. Endpoint: `http://localhost:11434` (default)
4. Click "Refresh Models" to see installed models
5. Select your model
6. Click "Test Connection"
7. Start testing!

---

## 🎯 Recommended Default Configuration

### For Most Users (8-16GB RAM)

```
Provider: Local AI
Endpoint: http://localhost:11434
Model: llama3.1:8b
Temperature: 0.3
Max Tokens: 2000
```

### For Power Users (32GB+ RAM)

```
Provider: Local AI
Endpoint: http://localhost:11434
Model: llama3.1:70b
Temperature: 0.3
Max Tokens: 4000
```

### For Fast Testing (8GB RAM)

```
Provider: Local AI
Endpoint: http://localhost:11434
Model: mistral:7b
Temperature: 0.3
Max Tokens: 1500
```

---

## 🚀 Benefits Summary

### For Individual Pentesters
- ✅ No API costs
- ✅ Complete privacy
- ✅ Offline capability
- ✅ Unlimited usage

### For Security Teams
- ✅ Data stays on-premises
- ✅ Compliance-friendly
- ✅ Predictable costs
- ✅ Customizable models

### For Enterprise
- ✅ Air-gapped environments
- ✅ Data residency compliance
- ✅ No vendor lock-in
- ✅ Full control

---

## 📊 Comparison: Cloud vs Local

| Feature | OpenAI/Azure | Local AI |
|---------|--------------|----------|
| **Cost** | $$ per request | Free (hardware cost) |
| **Privacy** | Data sent to cloud | Data stays local |
| **Speed** | Network latency | Local (faster) |
| **Offline** | ❌ Requires internet | ✅ Works offline |
| **Setup** | Easy (API key) | Medium (install software) |
| **Model Quality** | Excellent (GPT-4) | Good (Llama 3.1) |
| **Customization** | Limited | Full control |
| **Compliance** | Depends on provider | Full control |

---

## 🎓 Conclusion

**Recommendation**: Implement local AI support as a high-priority feature.

**Why**:
1. **User Demand**: Privacy and cost are major concerns for security professionals
2. **Easy Implementation**: OpenAI-compatible APIs make it straightforward
3. **Competitive Advantage**: Not many Burp extensions support local AI
4. **Future-Proof**: Local AI is the future for sensitive workloads

**Best Approach**:
- Start with Ollama support (most popular)
- Use OpenAI-compatible endpoints (minimal code changes)
- Recommend Llama 3.1 8B as default model
- Provide clear setup instructions
- Add model auto-detection for better UX

**Estimated Total Effort**: 6-10 hours for full implementation

---

**Next Steps**: Create a spec document and implementation plan! 🚀
