# VISTA – Vulnerability Insight & Strategic Test Assistant

AI-assisted Burp Suite extension providing request-specific testing guidance (Azure AI / OpenAI) with per-request chat histories, templates, and payload suggestions.

License: MIT (see `LICENSE`)

Features:
- Context menu: "Send to VISTA" in Proxy/Repeater
- Tab with Request/Response viewers and a small chat
- Settings panel to enter Azure endpoint, deployment, api version, and key
- Optional stripping of sensitive headers before sending to AI

## Build (Windows)

```powershell
cd e:\BurpAIEx
mvn -q clean package
```

Output jar: `target/vista-0.2.0.jar`

Note: Tests have been removed for the production distribution to minimize footprint. Maintain a separate branch with tests for ongoing development if desired.

## Load in Burp
- Burp Suite -> Extender -> Extensions -> Add
- Extension type: Java
- Select the jar above

## Configure Azure

Enter values directly in the Settings panel:
- Endpoint: e.g., https://your-resource.openai.azure.com or https://your-resource.cognitiveservices.azure.com
- Deployment: your deployment name (not model ID), e.g., gpt-5-mini or gpt-4o-mini
- API Version: default 2024-12-01-preview (adjust per portal)
- API Key: paste your Azure resource key

## Use
1. Right-click a message in Proxy/Repeater -> "Send to VISTA"
2. In the tab, you can ask a question, or leave it blank to get automatic request-specific guidance with payloads. Configure settings if needed.
3. Use "Test connection" to validate Azure credentials without sending captured data.

## Notes
- Settings & global chat are persisted to `~/.vista.json` (automatic one-time migration from legacy `~/.burpraj.json` if it exists). Per-request chats are currently in-memory only.
- The extension includes stub Burp API interfaces for compilation - it will work with the actual Burp Suite APIs at runtime.
- We do minimal JSON parsing; responses with unusual shapes may show a parse error.
- Data sent to Azure may contain sensitive info; by default we strip Authorization/Cookie headers in AI payloads.
 - The assistant assumes you are authorized to test the application and focuses on practical, request-specific guidance with payloads.

## Publishing to GitHub
1. Initialize repo: `git init` then add & commit files.
2. Create remote repo on GitHub (e.g., `vista`), then: `git remote add origin git@github.com:<you>/vista.git`.
3. Commit & push: `git add . && git commit -m "feat: initial public release" && git push -u origin main`.
4. Tag a version: `git tag -a v0.2.0 -m "Release v0.2.0" && git push origin v0.2.0`.
5. Create a GitHub Release and attach `target/vista-0.2.0.jar`.
6. (Optional) Enable Discussions, set up branch protection, add CI workflow.

## CI (Suggested)
GitHub Actions example workflow (`.github/workflows/build.yml`):
```
name: CI
on: [push, pull_request]
jobs:
	build:
		runs-on: ubuntu-latest
		steps:
			- uses: actions/checkout@v4
			- name: Set up JDK 17
				uses: actions/setup-java@v4
				with:
					distribution: temurin
					java-version: '17'
					cache: maven
			- name: Build
				run: mvn -q -DskipTests package
```


## Next steps
- Streaming responses
- Completed: Provider selection (Azure AI / OpenAI), per-request chats, remove, Repeater send, settings collapse
- Request history and prompt templates
- Redaction rules editor and per-domain policies
