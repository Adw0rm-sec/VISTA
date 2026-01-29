# GitHub Actions Workflows

This directory contains all CI/CD workflows for VISTA.

## Workflow Overview

| Workflow | Trigger | Purpose | Duration |
|----------|---------|---------|----------|
| `build.yml` | Push, PR | Main build & test | ~3 min |
| `multi-platform.yml` | Push, PR, Manual | Cross-platform testing | ~8 min |
| `release.yml` | Tags, Manual | Create releases | ~4 min |
| `security.yml` | Push, PR, Weekly | Security scanning | ~10 min |
| `code-quality.yml` | Push, PR | Code quality checks | ~5 min |
| `test-coverage.yml` | Push, PR | Coverage reporting | ~4 min |
| `pr-checks.yml` | PR | PR validation | ~3 min |
| `nightly.yml` | Daily 2 AM UTC | Health checks | ~6 min |
| `docker.yml` | Push, Tags | Docker images | ~5 min |

## Quick Actions

### Run Manual Build
```bash
# Via GitHub CLI
gh workflow run build.yml

# Via web interface
Actions → CI Build → Run workflow
```

### Create Release
```bash
# Tag-based
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Manual
gh workflow run release.yml -f version=1.0.0
```

### View Workflow Status
```bash
gh run list --workflow=build.yml
gh run view <run-id>
```

## Workflow Dependencies

```
PR Created
    ↓
pr-checks.yml (validation)
    ↓
build.yml (build & test)
    ↓
code-quality.yml (quality checks)
    ↓
test-coverage.yml (coverage)
    ↓
security.yml (security scan)
    ↓
multi-platform.yml (cross-platform)
    ↓
Ready to Merge
```

## Artifacts

### Build Artifacts
- **Location:** Actions → Workflow run → Artifacts
- **Retention:** 7-30 days
- **Types:**
  - JAR files
  - Test reports
  - Coverage reports
  - Dependency reports

### Download Artifacts
```bash
# Via GitHub CLI
gh run download <run-id>

# Via web
Actions → Run → Artifacts section → Download
```

## Status Badges

Add to README.md:
```markdown
[![CI Build](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/build.yml)
[![Security](https://github.com/Adw0rm-sec/VISTA/actions/workflows/security.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/security.yml)
[![Quality](https://github.com/Adw0rm-sec/VISTA/actions/workflows/code-quality.yml/badge.svg)](https://github.com/Adw0rm-sec/VISTA/actions/workflows/code-quality.yml)
```

## Troubleshooting

### Workflow Failed
1. Check logs: Actions → Failed run → View logs
2. Re-run: Actions → Failed run → Re-run jobs
3. Debug: Add `ACTIONS_STEP_DEBUG=true` secret

### Slow Builds
- Check cache hit rate
- Review dependency downloads
- Consider matrix optimization

### Permission Errors
- Settings → Actions → Workflow permissions
- Enable "Read and write permissions"

## Maintenance

### Update Actions
```bash
# Check for updates
gh api repos/Adw0rm-sec/VISTA/actions/workflows | jq '.workflows[].path'

# Update action versions in workflow files
# Example: actions/checkout@v4 → actions/checkout@v5
```

### Disable Workflow
```yaml
# Add to workflow file
on:
  workflow_dispatch:  # Manual only
```

## Best Practices

1. **Cache Dependencies:** Use Maven cache for faster builds
2. **Fail Fast:** Use `fail-fast: false` in matrix for complete results
3. **Conditional Steps:** Use `if:` for optional steps
4. **Secrets Management:** Never hardcode secrets
5. **Artifact Cleanup:** Set appropriate retention periods

## Resources

- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
- [GitHub CLI](https://cli.github.com/)

---

For detailed documentation, see [BUILD_PIPELINE.md](../../BUILD_PIPELINE.md)
