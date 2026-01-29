# Quick Build Guide

Fast reference for building and deploying VISTA.

## Local Build

### Standard Build
```bash
mvn clean package
```

### Skip Tests
```bash
mvn clean package -DskipTests
```

### With Coverage
```bash
mvn clean test jacoco:report
open target/site/jacoco/index.html
```

## CI/CD

### Trigger Build
```bash
# Push to trigger CI
git push origin main

# Manual trigger
gh workflow run build.yml
```

### Create Release
```bash
# Version tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Manual release
gh workflow run release.yml -f version=1.0.0
```

### Check Status
```bash
# List recent runs
gh run list --limit 5

# Watch current run
gh run watch

# View specific run
gh run view <run-id> --log
```

## Docker

### Build Image
```bash
docker build -t vista:latest .
```

### Run Container
```bash
docker run -v $(pwd)/config:/vista/config vista:latest
```

### Pull from Registry
```bash
docker pull ghcr.io/adw0rm-sec/vista:latest
```

## Quality Checks

### All Checks
```bash
mvn clean verify checkstyle:check spotbugs:check
```

### Individual Checks
```bash
# Code style
mvn checkstyle:check

# Bug detection
mvn spotbugs:check

# Dependency updates
mvn versions:display-dependency-updates
```

## Testing

### Run All Tests
```bash
mvn test
```

### Run Specific Test
```bash
mvn test -Dtest=TestClassName
```

### Integration Tests
```bash
mvn verify
```

## Artifacts

### Download Latest Build
```bash
# Via GitHub CLI
gh run download --name vista-1.0.0-MVP-abc1234

# Via web
Actions → Latest run → Artifacts → Download
```

### Find JAR
```bash
# After local build
ls -lh target/vista-*.jar
```

## Common Issues

### Build Fails
```bash
# Clean and rebuild
mvn clean
rm -rf target/
mvn package
```

### Tests Fail
```bash
# Skip tests temporarily
mvn package -DskipTests

# Run tests with debug
mvn test -X
```

### Dependency Issues
```bash
# Clear Maven cache
rm -rf ~/.m2/repository
mvn clean install
```

## Quick Commands

```bash
# Full clean build with all checks
mvn clean verify

# Fast build (no tests, no checks)
mvn clean package -DskipTests -Dcheckstyle.skip -Dspotbugs.skip

# Release build
mvn clean package -Prelease

# Generate all reports
mvn clean verify site
```

## Environment Setup

### Java Version
```bash
# Check version
java -version

# Should be 17+
# If not, install: https://adoptium.net/
```

### Maven Version
```bash
# Check version
mvn -version

# Should be 3.6+
# If not, install: https://maven.apache.org/download.cgi
```

## IDE Integration

### IntelliJ IDEA
1. File → Open → Select pom.xml
2. Maven tool window → Lifecycle → package
3. Run → Edit Configurations → Add Maven → Command: `clean package`

### VS Code
1. Install "Extension Pack for Java"
2. Maven sidebar → vista → Lifecycle → package
3. Terminal → `mvn clean package`

### Eclipse
1. File → Import → Maven → Existing Maven Projects
2. Right-click pom.xml → Run As → Maven build
3. Goals: `clean package`

## Deployment

### Manual Deployment
1. Build: `mvn clean package`
2. Find JAR: `target/vista-1.0.0-MVP.jar`
3. Copy to Burp extensions folder
4. Load in Burp Suite

### Automated Deployment
1. Push tag: `git push origin v1.0.0`
2. Wait for release workflow
3. Download from GitHub Releases
4. Install in Burp Suite

## Monitoring

### Build Status
```bash
# Current status
gh run list --workflow=build.yml --limit 1

# Watch live
gh run watch
```

### View Logs
```bash
# Latest run logs
gh run view --log

# Specific workflow
gh run view --log --workflow=build.yml
```

## Resources

- Full docs: [BUILD_PIPELINE.md](BUILD_PIPELINE.md)
- Contributing: [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md)
- Workflows: [.github/workflows/README.md](.github/workflows/README.md)

---

**Need help?** Open an issue with the `build` label.
