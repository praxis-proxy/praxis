# Copilot Instructions

## Code Review Protocol

Review the entire changeset on the first pass.
Report **Critical** and **Major** issues. If
none found, mention that with bold text. **Minor**
issues can be reported too, as long as they are
not pedantic, or nitpicks.

- **Critical**: security vulnerabilities, data loss,
  panics, silent failures, breaking API changes (unless in v0.x.x)
- **Major**: logic errors, race conditions, resource
  leaks, missing tests for core functionality,
  incorrect filter behavior, broken config validation
- **Minor**: Anything else that is low impact, but still
  has some substance.

## Project Overview

Praxis is a high-performance proxy server.

See the following before reviewing:

* `docs/architecture/overview.md`,
* `docs/developing/conventions.md`
* All other `docs/`
* `.claude/CLAUDE.md`

To make sure you understand the architecture, conventions, and preferences.

## Review Checklist

1. **Correctness**: edge cases, error paths, panics
2. **Testing**: coverage of new or changed behavior
3. **Security**: input validation, header leakage
4. **Performance**: hot-path allocations, unnecessary clones
5. **Conventions**: `docs/developing/conventions.md` compliance
