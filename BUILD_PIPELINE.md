# VISTA Build Pipeline Documentation

## Overview

VISTA uses GitHub Actions for continuous integration and deployment. The pipeline includes automated builds, testing, security scanning, code quality checks, and releases.

## Workflows

### 1. CI Build (`build.yml`)
**Triggers:** Push to `main`/`develop`, Pull Requests
**Purpose:** Main build and test workflow

**Steps:**
- Checkout code
- Set up Java 17
- Cache Maven dependencies
- Build JAR with Maven
- Run unit tests
- Generate build info
- Upload artifacts (JAR + build info)
- Upload test results

**Artifacts:**
- `vista-{version}-{commit}.jar` (30 days retention)
- `test-results` (7 days retention)

### 2. Multi-Platform Build (`multi-platform.yml`)
**Triggers:** Push to `main`, Pull Requests, Manual
**Purpose:** Verify builds across different OS and Java versions

**Matrix:**
- OS: Ubuntu, Windows, macOS
- Java: 17, 21

**Steps:**
- Build on each platform/Java combination
- Verify JAR creation
- Upload platform-specific artifacts
- Run integration tests

### 3. Release (`release.yml`)
**Triggers:** Git tags (`v*`), Manual dispatch
**Purpose:** Create GitHub releases with artifacts

**Steps:**
- Build release JAR
- Generate changelog from git history
- Verify JAR integrity
- Create GitHub release
- Upload release artifacts

**Release Notes Include:**
- Changes since last tag
- Installation instructions
- Requirements

### 4. Security Scan (`security.yml`)
**Triggers:** Push, Pull Requests, Weekly schedule, Manual
**Purpose:** Security vulnerability scanning

**Scans:**
- **OWASP Dependency Check** - Dependency vulnerabilities
- **CodeQL** - Static code analysis
- **Trivy** - Filesystem security scan
- **TruffleHog** - Secret detection

**Reports:** Uploaded to GitHub Security tab

### 5. Code Quality (`code-quality.yml`)
**Triggers:** Push to `main`/`develop`, Pull Requests
**Purpose:** Code quality and style checks

**Checks:**
- Checkstyle (Google style)
- SpotBugs (bug detection)
- Dependency tree analysis
- SonarCloud analysis (if configured)

### 6. Test Coverage (`test-coverage.yml`)
**Triggers:** Push, Pull Requests
**Purpose:** Track code coverage metrics

**Features:**
- JaCoCo coverage reports
- Codecov integration
- PR comments with coverage stats
- Coverage thresholds:
  - Overall: 40%
  - Changed files: 60%

### 7. PR Checks (`pr-checks.yml`)
**Triggers:** Pull Request events
**Purpose:** Validate pull requests

**Validations:**
- Semantic PR title (feat, fix, docs, etc.)
- Large file detection (>5MB warning)
- Line ending checks (LF only)
- Build verification
- JAR size check
- Automated PR comments

### 8. Nightly Build (`nightly.yml`)
**Triggers:** Daily at 2 AM UTC, Manual
**Purpose:** Regular health checks

**Tasks:**
- Full build and test suite
- Dependency update checks
- Plugin update checks
- Failure notifications (creates GitHub issue)

**Artifacts:**
- Nightly builds (7 days retention)
- Dependency update reports

### 9. Docker Build (`docker.yml`)
**Triggers:** Push to `main`, Tags, Manual
**Purpose:** Build and publish Docker images

**Features:**
- Multi-stage build
- GitHub Container Registry
- Automatic tagging (branch, version, SHA)
- Build cache optimization

## Setup Instructions

### Required Secrets

Add these to your GitHub repository settings (Settings → Secrets and variables → Actions):

#### Optional Secrets:
- `CODECOV_TOKEN` - For Codecov integration
- `SONAR_TOKEN` - For SonarCloud analysis

### Repository Settings

1. **Enable GitHub Actions:**
   - Settings → Actions → General
   - Allow all actions and reusable workflows

2. **Enable Security Features:**
   - Settings → Security → Code security and analysis
   - Enable Dependabot alerts
   - Enable Dependabot security updates
   - Enable CodeQL analysis

3. **Branch Protection (Recommended):**
   - Settings → Branches → Add rule for `main`
   - Require status checks before merging
   - Require branches to be up to date
   - Required checks:
     - `build`
     - `code-quality`
     - `pr-validation`

### Workflow Permissions

Ensure workflows have necessary permissions:
- Settings → Actions → General → Workflow permissions
- Select "Read and write permissions"
- Enable "Allow GitHub Actions to create and approve pull requests"

## Usage

### Manual Builds

Trigger workflows manually from GitHub Actions tab:
```
Actions → Select workflow → Run workflow
```

### Creating Releases

1. **Tag-based release:**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

2. **Manual release:**
   - Actions → Release → Run workflow
   - Enter version number

### Viewing Build Artifacts

1. Go to Actions tab
2. Select workflow run
3. Scroll to "Artifacts" section
4. Download desired artifact

## Local Development

### Build Locally
```bash
mvn clean package
```

### Run Tests
```bash
mvn test
```

### Generate Coverage Report
```bash
mvn clean test jacoco:report
# Report: target/site/jacoco/index.html
```

### Check Code Style
```bash
mvn checkstyle:check
```

### Run SpotBugs
```bash
mvn spotbugs:check
```

### Check for Updates
```bash
mvn versions:display-dependency-updates
mvn versions:display-plugin-updates
```

## Docker

### Build Docker Image
```bash
docker build -t vista:latest .
```

### Run Docker Container
```bash
docker run -v $(pwd)/config:/vista/config vista:latest
```

### Pull from GitHub Container Registry
```bash
docker pull ghcr.io/adw0rm-sec/vista:latest
```

## Troubleshooting

### Build Failures

1. **Check Java version:**
   ```bash
   java -version  # Should be 17+
   ```

2. **Clear Maven cache:**
   ```bash
   mvn clean
   rm -rf ~/.m2/repository
   ```

3. **Check workflow logs:**
   - Actions tab → Failed workflow → View logs

### Security Scan Issues

- **False positives:** Add to `.github/dependency-check-suppressions.xml`
- **High severity:** Address immediately or suppress with justification

### Coverage Failures

- Ensure tests are running: `mvn test`
- Check JaCoCo report: `target/site/jacoco/index.html`
- Adjust thresholds in `test-coverage.yml` if needed

## Badges

Add these to your README.md:

```markdown
[![CI Build](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml)
[![Security Scan](https://github.com/Adw0rm-sec/VISTA/actions/workflows/security.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/security.yml)
[![Code Quality](https://github.com/Adw0rm-sec/VISTA/actions/workflows/code-quality.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/code-quality.yml)
[![codecov](https://codecov.io/gh/Adw0rm-sec/VISTA/branch/main/graph/badge.svg)](https://codecov.io/gh/Adw0rm-sec/VISTA)
```

## Best Practices

1. **Commit Messages:** Use conventional commits (feat:, fix:, docs:, etc.)
2. **PR Titles:** Follow semantic format for automated changelog
3. **Testing:** Add tests for new features
4. **Security:** Never commit secrets or API keys
5. **Dependencies:** Keep dependencies up to date
6. **Documentation:** Update docs with code changes

## Maintenance

### Weekly Tasks
- Review nightly build failures
- Check dependency update reports
- Review security scan results

### Monthly Tasks
- Update dependencies
- Review and update workflows
- Check for GitHub Actions updates

### Release Checklist
- [ ] All tests passing
- [ ] Security scans clean
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in pom.xml
- [ ] Tag created and pushed

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Maven Documentation](https://maven.apache.org/guides/)
- [JaCoCo Documentation](https://www.jacoco.org/jacoco/trunk/doc/)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [CodeQL](https://codeql.github.com/)

## Support

For issues with the build pipeline:
1. Check workflow logs in Actions tab
2. Review this documentation
3. Open an issue with `build` label
4. Contact maintainers

---

**Last Updated:** January 2026
**Pipeline Version:** 1.0
