# Contributing to VISTA

Thank you for your interest in contributing to VISTA! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/VISTA.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit with conventional commit format
7. Push and create a Pull Request

## Development Setup

### Prerequisites
- Java 17 or higher
- Maven 3.6+
- Git
- Burp Suite (for testing)

### Build
```bash
mvn clean package
```

### Run Tests
```bash
mvn test
```

## Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Other changes

### Examples
```
feat(ai-advisor): add support for Claude AI provider
fix(payload-library): resolve null pointer in bulk import
docs(readme): update installation instructions
```

## Pull Request Process

1. **Update Documentation:** Ensure README and relevant docs are updated
2. **Add Tests:** Include tests for new features
3. **Follow Code Style:** Use consistent formatting
4. **Pass CI Checks:** All workflows must pass
5. **Semantic PR Title:** Use conventional commit format
6. **Link Issues:** Reference related issues

### PR Title Format
```
feat: add new feature
fix: resolve bug in component
docs: update user guide
```

## Code Style

- Follow Google Java Style Guide
- Use meaningful variable names
- Add comments for complex logic
- Keep methods focused and small
- Use proper exception handling

### Formatting
```bash
mvn checkstyle:check
```

## Testing

- Write unit tests for new features
- Ensure existing tests pass
- Test with Burp Suite manually
- Include edge cases

### Coverage
- Maintain minimum 40% overall coverage
- New code should have 60%+ coverage

## Security

- Never commit API keys or secrets
- Report security issues privately
- Follow secure coding practices
- Run security scans locally

## Documentation

Update documentation for:
- New features
- API changes
- Configuration options
- User-facing changes

## Review Process

1. Automated checks run on PR
2. Maintainer reviews code
3. Address feedback
4. Approval and merge

## Questions?

- Open an issue for discussion
- Check existing issues and PRs
- Read the documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
