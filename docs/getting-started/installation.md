---
layout: default
title: Installation
parent: Getting Started
nav_order: 1
---

# Installation
{: .no_toc }

Download, build, and install VISTA in Burp Suite.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Requirements

| Requirement | Version |
|:------------|:--------|
| **Java** | 17 or higher |
| **Burp Suite** | Professional or Community Edition |
| **Maven** | 3.6+ (only for building from source) |

---

## Option 1: Download from Releases (Recommended)

The fastest way to get started:

1. Visit the [Latest Release](https://github.com/Adw0rm-sec/VISTA/releases/latest)
2. Download `vista-2.10.24.jar` from **Assets**
3. Open Burp Suite
4. Go to **Extensions → Installed → Add**
5. Set Extension type to **Java**
6. Click **Select file** and choose the downloaded JAR
7. Click **Next** — the VISTA tab appears with a status bar

{: .tip }
> After installation, the VISTA status bar shows at the bottom of every tab with AI connection status, provider info, and quick settings access.

---

## Option 2: Command Line Download

```bash
# Download latest release
curl -LO https://github.com/Adw0rm-sec/VISTA/releases/download/latest/vista-2.10.24.jar

# Then load in Burp Suite: Extensions → Add → Java → Select JAR
```

---

## Option 3: Build from Source

Build VISTA yourself for development or to use the latest code:

```bash
# Clone the repository
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA

# Build the JAR
mvn clean package -DskipTests

# Output: target/vista-2.10.24.jar
```

Then load `target/vista-2.10.24.jar` in Burp Suite as described in Option 1.

### Development Setup

```bash
# Clone and build
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA
mvn clean compile

# Run tests
mvn test

# Build JAR
mvn clean package -DskipTests
```

---

## Verifying Installation

After loading VISTA in Burp Suite:

1. **VISTA tab** appears in the main tab bar
2. **Status bar** shows at the bottom with:
   - VISTA version number
   - AI status indicator (🔴 Not Configured / 🟢 Ready)
   - Provider & model info (after configuration)
3. Five sub-tabs are available:
   - 💡 AI Advisor
   - 🌐 Traffic Monitor
   - 📝 Prompt Templates
   - 🎯 Payload Library
   - ⚙️ Settings

{: .note }
> If you see the VISTA tab and status bar, installation was successful. Proceed to [Quick Start]({% link getting-started/quick-start.md %}) to configure your AI provider.

---

## Troubleshooting

### Extension Won't Load

- **Check Java version:** VISTA requires Java 17+. Run `java -version` to verify.
- **Check Burp logs:** Go to Extensions → Errors tab to see any loading errors.
- **Verify JAR integrity:** Re-download the JAR if it may be corrupted.

### No VISTA Tab Appears

- Ensure the extension is listed under Extensions → Installed
- Check that the extension checkbox is enabled (checked)
- Restart Burp Suite if needed

---

## Next Steps

→ [Quick Start Guide]({% link getting-started/quick-start.md %}) — Configure your AI provider and start testing
