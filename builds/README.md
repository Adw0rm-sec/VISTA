# Pre-built JAR Files

This directory contains automatically built JAR files, updated on every push to the repository.

## Quick Download

### Latest Build
```bash
curl -L https://github.com/Adw0rm-sec/VISTA/raw/main/builds/vista-latest.jar -o vista.jar
```

### Direct Link
[Download vista-latest.jar](https://github.com/Adw0rm-sec/VISTA/raw/main/builds/vista-latest.jar)

## Installation

1. Download `vista-latest.jar` from this directory
2. Open Burp Suite
3. Go to **Extensions → Add → Java**
4. Select the downloaded JAR file
5. Configure your AI provider in **VISTA → Settings**

## Build Information

Check `BUILD_INFO.txt` for details about the latest build:
- Version
- Commit hash
- Build date
- Branch

## Versioned Builds

Versioned builds are named: `vista-{version}-{commit}.jar`

These allow you to:
- Track specific builds
- Roll back if needed
- Test different versions

## Automated Updates

This directory is automatically updated by GitHub Actions whenever:
- Code is pushed to `main` or `develop` branches
- Source files (`src/**`) or `pom.xml` are modified

The workflow:
1. Builds the JAR with Maven
2. Copies it to this directory as `vista-latest.jar`
3. Creates a versioned copy
4. Commits changes back to the repository

## Manual Build

If you prefer to build locally:

```bash
# Clone repository
git clone https://github.com/Adw0rm-sec/VISTA.git
cd VISTA

# Build with Maven
mvn clean package

# JAR will be in target/vista-2.10.24.jar
```

## Requirements

- Java 17 or higher
- Burp Suite Professional or Community Edition

## Support

For issues or questions:
- Check [BUILD_PIPELINE.md](../BUILD_PIPELINE.md)
- Open an issue on GitHub
- Read the [main README](../README.md)

---

**Note:** Always use the latest build for the newest features and bug fixes.
