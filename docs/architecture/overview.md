---
layout: default
title: Architecture
nav_order: 6
has_children: false
---

# Architecture Overview
{: .no_toc }

How VISTA works under the hood — code structure, data flow, and design decisions.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Design Principles

1. **Zero Dependencies** — Pure Java + Burp Suite API. No external libraries.
2. **Modular Architecture** — Clean separation between core engine, AI services, models, and UI.
3. **Provider Agnostic** — Same codebase works with OpenAI, Azure, and OpenRouter.
4. **Local-First** — All data stored locally with auto-save. No external data storage.
5. **Thread-Safe** — All shared state uses proper synchronization.

---

## High-Level Architecture

```
┌───────────────────────────────────────────────────────────┐
│                      Burp Suite                           │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              BurpExtender.java                       │ │
│  │         (Extension Entry Point + Status Bar)         │ │
│  └──────────────┬───────────────────────┬───────────────┘ │
│                 │                       │                  │
│  ┌──────────────▼───────────┐ ┌────────▼──────────────┐  │
│  │     UI Layer (Swing)     │ │    Core Engine         │  │
│  │                          │ │                        │  │
│  │ • TestingSuggestionsPanel│ │ • AIConfigManager      │  │
│  │ • TrafficMonitorPanel    │ │ • TrafficMonitorService│  │
│  │ • PromptTemplatePanel    │ │ • PromptTemplateManager│  │
│  │ • PayloadLibraryPanel    │ │ • PayloadLibraryManager│  │
│  │ • SettingsPanel          │ │ • ScopeManager         │  │
│  │ • VistaTheme             │ │ • WAFDetector          │  │
│  │                          │ │ • SessionManager       │  │
│  └──────────────┬───────────┘ │ • FindingsManager      │  │
│                 │             │ • VistaPersistenceManager│ │
│                 │             └────────┬───────────────┘  │
│                 │                      │                   │
│  ┌──────────────▼──────────────────────▼──────────────┐   │
│  │              AI Service Layer                      │   │
│  │                                                    │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐    │   │
│  │  │ OpenAI   │  │ Azure AI │  │ OpenRouter   │    │   │
│  │  │ Service  │  │ Service  │  │ Service      │    │   │
│  │  └──────────┘  └──────────┘  └──────────────┘    │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │              Model Layer                           │   │
│  │                                                    │   │
│  │  PromptTemplate  HttpTransaction  TrafficFinding   │   │
│  │  Payload          TemplateMode     VariableContext  │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
src/main/java/
├── burp/
│   └── BurpExtender.java                    # Entry point + status bar
└── com/vista/security/
    ├── core/                                # Core business logic
    │   ├── AIConfigManager.java             # AI config management
    │   ├── IntelligentTrafficAnalyzer.java  # AI traffic analysis engine
    │   ├── VistaPersistenceManager.java     # Data persistence
    │   ├── TrafficBufferManager.java        # Traffic buffering
    │   ├── TrafficMonitorService.java       # Monitoring orchestration
    │   ├── ScopeManager.java               # Target scope
    │   ├── FindingsManager.java            # Findings management
    │   ├── PromptTemplateManager.java      # Template engine (12 built-in)
    │   ├── PayloadLibraryManager.java      # Payload management
    │   ├── WAFDetector.java                # WAF detection
    │   ├── BypassKnowledgeBase.java        # 250+ bypass techniques
    │   ├── SystematicTestingEngine.java    # Testing methodologies
    │   └── SessionManager.java            # Session persistence
    ├── model/                               # Data models
    │   ├── PromptTemplate.java             # Template model
    │   ├── HttpTransaction.java            # HTTP transaction
    │   ├── TrafficFinding.java             # Finding model
    │   ├── Payload.java                    # Payload model
    │   ├── TemplateMode.java               # STANDARD / EXPERT enum
    │   └── VariableContext.java            # 35 template variables
    ├── service/                             # AI provider services
    │   ├── AIService.java                  # Base class + Configuration
    │   ├── OpenAIService.java              # OpenAI API integration
    │   ├── AzureAIService.java             # Azure OpenAI integration
    │   └── OpenRouterService.java          # OpenRouter integration
    └── ui/                                  # User interface (Swing)
        ├── VistaTheme.java                 # Centralized theme
        ├── TestingSuggestionsPanel.java    # AI Advisor tab
        ├── TrafficMonitorPanel.java        # Traffic Monitor tab
        ├── TrafficFindingsTreePanel.java   # Findings tree view
        ├── FindingDetailsPanel.java        # Finding details
        ├── PromptTemplatePanel.java        # Templates tab
        ├── PromptCustomizationDialog.java  # Template editor
        ├── PayloadLibraryPanel.java        # Payloads tab
        ├── SettingsPanel.java              # Settings tab
        └── HttpMessageViewer.java          # Request/response viewer
```

---

## Data Flow

### AI Advisor Flow

```
User right-clicks request → "Send to VISTA AI Advisor"
          │
          ▼
TestingSuggestionsPanel.setRequest(request)
          │
          ├── Extract HTTP data (URL, method, headers, body, params)
          ├── Run WAF detection
          ├── Build VariableContext (35 variables)
          ├── Apply active PromptTemplate (substitute {{VARIABLES}})
          │
          ▼
AIService.callAIWithPrompts(systemPrompt, userPrompt, config)
          │
          ├── OpenAIService  → POST https://api.openai.com/v1/chat/completions
          ├── AzureAIService → POST https://{endpoint}/openai/deployments/{name}/chat/completions
          └── OpenRouterService → POST https://openrouter.ai/api/v1/chat/completions
          │
          ▼
Response parsed → displayed in chat UI → saved to conversation history
```

### Traffic Monitor Flow

```
HTTP traffic through Burp Proxy
          │
          ▼
BurpExtender.processHttpMessage()
          │
          ▼
ScopeManager.isInScope(url) → filter out-of-scope
          │
          ▼
TrafficBufferManager.addTransaction()
          │
          ▼
IntelligentTrafficAnalyzer.analyze(transaction)
          │
          ▼
AIService.callAI() → AI response → parse findings
          │
          ▼
FindingsManager.addFinding() → UI tree updated → tab badge updated
```

---

## Key Design Decisions

### Why Zero Dependencies?

Burp Suite extensions run inside Burp's JVM. External dependencies can conflict with Burp's own libraries or other extensions. By using only the Java standard library and Burp's API, VISTA avoids all compatibility issues.

### Why Singleton Managers?

`PromptTemplateManager`, `PayloadLibraryManager`, `SessionManager`, etc. are singletons because they manage shared state (file-system-backed collections) that must be consistent across all UI components.

### Why Thread-Safe Collections?

The AI Advisor processes responses on background threads while the UI reads conversation history on the Swing EDT. `Collections.synchronizedList()` prevents concurrent modification exceptions.

### Why Auto-Save Every 60 Seconds?

Balances data safety with disk I/O overhead. Combined with shutdown hooks and atomic writes, this ensures data survives crashes and normal exits alike.

---

## Technical Specifications

| Metric | Value |
|:-------|:------|
| **Language** | Java 17+ |
| **UI Framework** | Swing |
| **Build Tool** | Maven |
| **Source Files** | 87 Java files |
| **Lines of Code** | 28,000+ |
| **JAR Size** | ~511KB |
| **Dependencies** | Zero (Pure Java + Burp API) |
| **Data Format** | JSON (manual parsing, no library) |
| **Auto-Save Interval** | 60 seconds |
| **Template Variables** | 35 |
| **Built-in Templates** | 12 |
| **Built-in Payloads** | 80+ |
| **WAFs Detected** | 8 |
| **Bypass Techniques** | 250+ |
