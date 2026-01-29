# Release Checklist for VISTA

Use this checklist when creating a new release.

## Pre-Release Steps

### 1. Update Version Number
- [ ] Update version in `pom.xml`
  ```xml
  <version>X.Y.Z</version>
  ```
- [ ] Update version in `README.md` (Current Version section)
- [ ] Update JAR filename references in README if needed

### 2. Update CHANGELOG.md
- [ ] Add new version section with date
- [ ] List all Added features
- [ ] List all Changed items
- [ ] List all Fixed bugs
- [ ] List all Removed features (if any)

### 3. Test Build
```bash
mvn clean package
# Verify JAR builds successfully
# Test in Burp Suite
```

### 4. Commit Changes
```bash
git add pom.xml README.md CHANGELOG.md
git commit -m "release: version X.Y.Z

- Update version to X.Y.Z
- Update CHANGELOG with release notes
- Update documentation"
git push origin main
```

## Release Steps

### 5. Create Git Tag
```bash
git tag -a vX.Y.Z -m "VISTA vX.Y.Z - [Release Title]

Major Features:
- Feature 1
- Feature 2
- Feature 3

Full changelog: https://github.com/Adw0rm-sec/VISTA/blob/main/CHANGELOG.md"

git push origin vX.Y.Z
```

### 6. Verify Release
- [ ] Check GitHub Actions completed successfully
- [ ] Verify release appears on [Releases page](https://github.com/Adw0rm-sec/VISTA/releases)
- [ ] Download and test the JAR from release
- [ ] Verify release notes are correct

## Post-Release Steps

### 7. Update Documentation
- [ ] Update any external documentation
- [ ] Update BApp Store listing (if applicable)
- [ ] Announce on social media/forums (if applicable)

### 8. Prepare for Next Version
- [ ] Create milestone for next version
- [ ] Plan features for next release
- [ ] Update project board

---

## Version Numbering Guide

VISTA follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes, major rewrites
  - Example: 3.0.0 - Complete UI overhaul
  
- **MINOR** (X.Y.0): New features, backward compatible
  - Example: 2.9.0 - Add new AI provider support
  
- **PATCH** (X.Y.Z): Bug fixes, backward compatible
  - Example: 2.8.1 - Fix payload library bug

---

## Release Notes Template

```markdown
## What's New in vX.Y.Z

### 🎉 Major Features
- **Feature Name** - Description
  - Sub-feature 1
  - Sub-feature 2

### ✨ Improvements
- Improvement 1
- Improvement 2

### 🐛 Bug Fixes
- Fix 1
- Fix 2

### 📦 Technical Details
- JAR Size: ~XXX KB
- Java Version: 17+
- Build: Successful ✅

## Installation

1. Download `vista-X.Y.Z.jar` from assets below
2. In Burp Suite: Extensions → Add → Java → Select JAR
3. Configure AI provider in VISTA → Settings

## Requirements
- Java 17+
- Burp Suite Professional or Community

## Full Changelog
See [CHANGELOG.md](https://github.com/Adw0rm-sec/VISTA/blob/main/CHANGELOG.md)
```

---

## Quick Commands

### Check current version
```bash
grep "<version>" pom.xml | head -1
```

### List all tags
```bash
git tag -l
```

### View latest release
```bash
curl -s https://api.github.com/repos/Adw0rm-sec/VISTA/releases/latest | grep tag_name
```

### Delete tag (if needed)
```bash
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
```

---

**Last Updated**: January 29, 2026
