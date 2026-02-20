---
layout: default
title: Contributing
nav_order: 7
---

# Contributing to VISTA
{: .no_toc }

Help make VISTA better — bug reports, features, documentation, and code.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Ways to Contribute

| Type | Description | Difficulty |
|:-----|:------------|:-----------|
| 🐛 **Bug Reports** | Report issues you find | Easy |
| 💡 **Feature Requests** | Suggest new capabilities | Easy |
| 📝 **Documentation** | Improve docs, fix typos | Easy |
| 🎯 **Payload Contributions** | Add new payloads | Medium |
| 📝 **Template Contributions** | Create expert templates | Medium |
| 🔧 **Code Contributions** | Fix bugs, add features | Advanced |

---

## Development Setup

### Prerequisites

- **Java 17+** — [Download OpenJDK](https://openjdk.org/)
- **Maven 3.6+** — [Download Maven](https://maven.apache.org/)
- **Burp Suite** — [Download Burp](https://portswigger.net/burp/communitydownload)
- **Git** — [Download Git](https://git-scm.com/)

### Clone & Build

```bash
# Fork the repository on GitHub first, then:
git clone https://github.com/YOUR_USERNAME/VISTA.git
cd VISTA

# Build
mvn clean package -DskipTests

# Output JAR: target/vista-2.10.24.jar
```

### Testing Your Changes

1. Build the JAR: `mvn clean package -DskipTests`
2. Open Burp Suite
3. Go to Extensions → Add → Java → select `target/vista-2.10.24.jar`
4. Test your changes in VISTA

### Quick Compile Check

```bash
# Verify code compiles without full packaging
mvn compile -q
```

---

## Code Structure

See [Architecture Overview]({% link architecture/overview.md %}) for the full project structure.

Key directories:

| Directory | Contents |
|:----------|:---------|
| `src/main/java/burp/` | Extension entry point |
| `src/main/java/com/vista/security/core/` | Core business logic |
| `src/main/java/com/vista/security/model/` | Data models |
| `src/main/java/com/vista/security/service/` | AI provider integrations |
| `src/main/java/com/vista/security/ui/` | Swing UI components |
| `docs/` | GitHub Pages documentation |

---

## Contribution Guidelines

### Code Standards

- **Java 17+** features are welcome (records, text blocks, sealed classes)
- **No external dependencies** — VISTA must remain zero-dependency
- **Thread safety** — Use synchronized collections for shared state
- **Follow existing patterns** — Match the code style of surrounding code

### Adding a New Template

1. Open `src/main/java/com/vista/security/core/PromptTemplateManager.java`
2. Add a new creator method following the existing pattern:

```java
private PromptTemplate createMyNewExpert() {
    PromptTemplate template = new PromptTemplate(
        "My Vulnerability (Expert)",
        "Exploitation",
        "@vista",
        "Description of what this template covers",
        """
        System prompt with expertise, methodology, techniques...
        """,
        """
        User prompt with {{VARIABLES}}...
        """,
        TemplateMode.EXPERT
    );
    template.addTag("tag1");
    template.addTag("expert");
    template.addTag("bug-bounty");
    return template;
}
```

3. Register it in `loadBuiltInTemplates()`:

```java
PromptTemplate myTemplate = createMyNewExpert();
markAsBuiltIn(myTemplate);
templates.add(myTemplate);
```

### Adding New Payloads

1. Open `src/main/java/com/vista/security/core/PayloadLibraryManager.java`
2. Add payloads to the appropriate built-in library
3. Follow the existing payload format with description and tags

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** for your changes: `git checkout -b feature/my-improvement`
3. **Make your changes** and verify they compile: `mvn compile -q`
4. **Commit** with a clear message: `git commit -m "Add CORS misconfiguration expert template"`
5. **Push** to your fork: `git push origin feature/my-improvement`
6. **Open a Pull Request** on GitHub

---

## Reporting Issues

### Bug Reports

[Open an issue](https://github.com/Adw0rm-sec/VISTA/issues/new) with:

1. **VISTA version** (check status bar)
2. **Burp Suite version**
3. **Java version** (`java -version`)
4. **Steps to reproduce**
5. **Expected vs actual behavior**
6. **Error logs** (if any, from Burp Extensions → Errors tab)

### Feature Requests

[Open a discussion](https://github.com/Adw0rm-sec/VISTA/discussions) with:

1. **What** you want VISTA to do
2. **Why** it would be useful
3. **How** you envision it working

---

## Community

- 💬 [GitHub Discussions](https://github.com/Adw0rm-sec/VISTA/discussions) — Questions, ideas, show & tell
- 🐛 [GitHub Issues](https://github.com/Adw0rm-sec/VISTA/issues) — Bug reports
- 📧 [@Adw0rm-sec](https://github.com/Adw0rm-sec) — Maintainer

---

## License

VISTA is released under the [MIT License](https://github.com/Adw0rm-sec/VISTA/blob/main/LICENSE). By contributing, you agree that your contributions will be licensed under the same license.
