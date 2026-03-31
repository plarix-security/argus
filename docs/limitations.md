# Limitations

## Language Scope

- Python is the only supported finding language.
- TypeScript and JavaScript files are skipped explicitly and produce no findings.

## Call-Path Scope

- The shipped CLI and GitHub App scan flow analyzes Python files independently.
- Repository-wide cross-file call-path tracing is not part of the current shipped guarantee.
- Third-party package internals are not traced.

## Registration Scope

- Tool detection is pattern-based.
- Dynamic runtime registration may be missed.
- Framework labels indicate matched registration patterns, not complete framework coverage.

## Gate Detection Scope

- Structural authorization logic can be credited as a gate.
- Validation-helper names are heuristic only.
- Generic exceptions, logging, and `try/except` do not count as gates by themselves.

## Product Scope

- AFB04 only
- No TypeScript or JavaScript scanner implementation
- No AFB01, AFB02, or AFB03 detection
