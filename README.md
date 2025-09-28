<div align="center">
    
# VISTA – Vulnerability Insight & Strategic Test Assistant

[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()  [![Release](https://img.shields.io/badge/release-0.2.1-blue)]()  [![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)  

<img width="1920" height="922" alt="image" src="https://github.com/user-attachments/assets/1570ed80-9664-44d9-8f53-b3a42ffd2c4a" />

</div>

## 🦉 VISTA Overview

VISTA is an AI-powered **Burp Suite extension** that gives **request-specific testing guidance** using Azure AI or OpenAI. It enhances your pentesting workflow with per-request chat histories, payload suggestions, and context-aware advice — helping you find and exploit vulnerabilities faster and more smartly.

---

## 🛠️ Features

- **Seamless Integration**: Right-click “Send to VISTA” in Burp Suite (Proxy/Repeater) to instantly get intelligent analysis.  
- **Contextual Guidance**: Receive advice, payloads, test strategies tailored to that specific request.  
- **Chat Memory**: Each request has its own mini-conversation history.  
- **Privacy-Focused**: Optionally strip sensitive headers (Authorization, Cookies) before sending to AI.  
- **Custom Templates**: Use and tweak templates for different types of vulnerabilities or tests.  

---

## 🚀 Quick Start

### 1. Build (Windows / cross-platform via Maven)

```bash
cd path/to/project
mvn -q clean package
```

The compiled JAR will be available for direct use.


### 2. Load in Burp

1. Open **Burp Suite → Extender → Extensions → Add**  
2. Select **Extension type: Java**  
3. Choose the JAR file (e.g. `vista-0.2.1.jar`)  

---

### 3. Configure Azure / OpenAI

You can enter these in the VISTA settings panel:

- **Endpoint**:  
  Example: `https://your-resource.openai.azure.com` or `https://your-resource.cognitiveservices.azure.com`  
- **Deployment**: Name of your model deployment (e.g. `gpt-5-mini` or `gpt-4o-mini`)  
- **API Version**: Default `2024-12-01-preview` (or as configured in Azure)  
- **API Key**: Your Azure key or OpenAI key  

Use “Test Connection” to verify connectivity without sending actual requests.

---

### 4. Using VISTA

1. In **Proxy** or **Repeater**, right-click a request → **Send to VISTA**  
2. In the VISTA tab:  
   - Leave the prompt blank to get automatic guidance for that request  
   - Or ask a specific question (e.g. “Check for SQLi or auth bypass”)  
3. Review suggested payloads, strategies, and notes  
4. Adjust settings or templates as needed  

---

## 🧠 Notes & Behavior

- Settings & global chat are saved in `~/.vista.json` (migrates from legacy `~/.burpraj.json` if it exists).  
- Per-request chat histories are in memory only (not saved to disk).  
- The extension includes stub Burp API interfaces for compilation — at runtime it uses the real Burp APIs.  
- The extension performs minimal JSON parsing; highly unusual or nested responses may cause parse failures.  
- Data sent to Azure / OpenAI **may include sensitive info**; by default we **strip Authorization / Cookie headers** when sending.  
- **Only test systems you have permission to test**. This tool assumes ethical use.
---

## 🎯 Roadmap / Future Ideas

- Streaming responses from AI (partial results)  
- Enhanced provider selection (Azure / OpenAI / local models)  
- Per-request chat persistence  
- More prompt templates & redaction rules  
- Domain-based policies and filters  
- UI improvements (settings, feedback, prompt tuning)  

---

## ⚖️ License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ❤️ Support the Project

If you like **VISTA**, feel free to ⭐ the repo, contribute with issues or pull requests, and share with the community.

---

## 🧾 About

**VISTA** (Vulnerability Insight & Strategic Test Assistant) — an AI extension for Burp Suite that helps pentesters with smart, per-request guidance.  
Built by **Adw0rm-sec** 

---
