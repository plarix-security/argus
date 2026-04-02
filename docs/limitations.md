# Limitations

## Language Scope

- Python is the only supported finding language.
- TypeScript and JavaScript files are skipped explicitly and produce no findings.

## Call-Path Scope

- Directory scans graph the analyzed Python file set together.
- Changed-file GitHub App scans do not guarantee full repository coverage.
- Third-party package internals are not traced.

## Registration Scope

- Tool detection is semantic-first for supported Python framework patterns, with pattern fallback when semantic resolution is incomplete.
- Dynamic runtime registration may be missed.
- Framework labels still do not imply complete runtime coverage.

## Gate Detection Scope

- Structural authorization logic can be credited as a gate.
- Imported decorators can be credited when their wrapper logic is resolvable and structural.
- Validation-helper names are heuristic only.
- Authorization-like decorator names are heuristic only unless structural gate behavior is proven.
- Generic exceptions, logging, and `try/except` do not count as gates by themselves.

## Product Scope (v1.2.2)

- Python-only static analysis
- AFB04 (Unauthorized Action) detection only
- No TypeScript or JavaScript support
