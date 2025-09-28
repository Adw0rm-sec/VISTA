# Contributing to VISTA

Thanks for your interest in contributing! To keep the project healthy and useful:

## Branching Model
- `main` (or `stable`): Production-ready code (what you ship inside Burp).
- `dev`: Active development (add tests, new features). Merge into `main` via PR once stable.

## Recommended Local Setup
1. Clone repo
2. (Optional) Restore tests if you keep them in a `tests` branch; re-add JUnit dependency.
3. Build: `mvn -q package`

## Pull Requests
- Keep PRs focused; prefer < 400 lines of diff excluding generated code.
- Describe motivation & testing steps.
- If touching AI prompt logic, note expected behavioral change.

## Coding Guidelines
- Java 17.
- Avoid external runtime deps unless strictly necessary.
- Keep UI responsive: long-running calls in background threads.
- Guard network calls and show status updates.

## Security / Privacy
- Never log sensitive header values (Authorization, Cookie). Mask if debugging.
- Strip or redact before sending to AI when possible.

## Release Process (suggested)
1. Update `CHANGELOG.md`.
2. Bump `<version>` in `pom.xml`.
3. Tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`.
4. Build: `mvn -q clean package`.
5. Attach `target/vista-X.Y.Z.jar` to GitHub release.

## Questions
Open a GitHub Discussion (if enabled) or issue.

Happy hacking!
