# Limitations

## Language Scope

- Python, TypeScript, and JavaScript are supported.
- Analysis is static only - no runtime execution.

## Call-Path Scope

- Directory scans graph the analyzed file set together (per language).
- Changed-file GitHub App scans do not guarantee full repository coverage.
- Third-party package internals are not traced.

## Registration Scope

- Tool detection is semantic-only.
- Dynamic runtime registration may be missed.
- Framework labels do not imply complete runtime coverage.

## Gate Detection Scope

- Structural authorization logic can be credited as a gate.
- Imported decorators can be credited when their wrapper logic is resolvable and structural.
- Decorator or function naming alone does not credit a gate without structural proof.
- Generic exceptions, logging, and `try/except` do not count as gates by themselves.

## Product Scope (v1.3.0)

- Python, TypeScript, and JavaScript static analysis
- AFB04 (Unauthorized Action) detection only
