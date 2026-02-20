---
layout: default
title: Data & Backup
parent: Configuration
nav_order: 3
---

# Data Persistence & Backup
{: .no_toc }

Auto-saved data, backup, and restore across Burp Suite sessions.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Data Storage Location

All VISTA data is stored locally in your home directory:

```
~/.vista/
├── data/                       # Auto-saved data
│   ├── traffic.json               # HTTP traffic transactions
│   ├── findings.json              # Exploit findings
│   └── traffic-findings.json     # Traffic analysis findings
├── prompts/
│   ├── built-in/                  # Built-in prompt templates
│   └── custom/                    # User-created templates
├── payloads/
│   ├── built-in/                  # Built-in payload libraries
│   └── custom/                    # User-created payloads
├── sessions/                   # Chat conversation history
~/.vista-ai-config.json         # AI provider configuration
```

---

## Auto-Save

VISTA automatically saves data with multiple safety mechanisms:

| Mechanism | Timing |
|:----------|:-------|
| **Periodic auto-save** | Every 60 seconds |
| **Shutdown hook** | When Burp Suite closes |
| **Atomic writes** | Prevents data corruption during save |

No manual save required — your data is always persisted.

---

## Backup & Restore

### Exporting a Backup

Save all VISTA data to any location:

1. Go to **Settings** tab
2. Click **"Export Backup"**
3. Choose a destination folder
4. VISTA creates a complete backup including:
   - Traffic data and findings
   - Custom templates
   - Custom payloads
   - Conversation history
   - AI configuration

### Importing a Backup

Restore from a previous backup:

1. Go to **Settings** tab
2. Click **"Import Backup"**
3. Select the backup folder
4. VISTA restores all data
5. Restart recommended after import

---

## Data Lifecycle

### During a Testing Session

```
Start Testing → Auto-save every 60s → Close Burp → Shutdown hook saves
                                                            │
Restart Burp → VISTA loads → All data restored ◄────────────┘
```

### Managing Data

| Action | How |
|:-------|:----|
| **Clear traffic** | Traffic Monitor → Clear button |
| **Clear findings** | Traffic Monitor → Clear findings |
| **Delete templates** | Prompt Templates → Delete |
| **Delete payloads** | Payload Library → Delete |
| **Full reset** | Delete `~/.vista/` directory |

---

## Privacy & Security

- **All data stays local** — stored only in `~/.vista/` on your machine
- **No external storage** — VISTA never sends data to its own servers
- **AI provider data** — Request data sent to your configured AI provider (OpenAI/Azure/OpenRouter) per their data policies
- **API keys** — Stored in plaintext in `~/.vista-ai-config.json`

{: .warning }
> Protect `~/.vista-ai-config.json` with appropriate file permissions, especially on shared systems. It contains your AI provider API key.

{: .tip }
> Use **Export Backup** before upgrading VISTA to a new version, just in case.
