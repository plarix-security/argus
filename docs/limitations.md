# Limitations

## Language Scope

- Python, TypeScript, and JavaScript are supported, but coverage is best-effort rather than guaranteed complete.
- Rust support is planned but not yet implemented.
- Analysis is static only - no runtime execution.

## Call-Path Scope

- Directory scans graph the analyzed file set together (per language).
- Changed-file GitHub App scans do not guarantee full repository coverage.
- Third-party package internals are not traced.
- Cross-language call tracing is not supported (e.g., Python calling a TypeScript service).

## Registration Scope

- Tool detection is semantic-only.
- Dynamic runtime registration may be missed.
- Framework labels do not imply complete runtime coverage.
- Regex is still used in helper paths (for example text cleanup and include/exclude pattern conversion), so the codebase is not regex-free.

## Gate Detection Scope

- Structural authorization logic can be credited as a gate.
- Imported decorators can be credited when their wrapper logic is resolvable and structural.
- Decorator or function naming alone does not credit a gate without structural proof.
- Generic exceptions (like bare `Error`), logging, and `try/except` do not count as gates by themselves.

## Product Scope (v1.4.0)

- Python, TypeScript, and JavaScript static analysis
- AFB04 (Unauthorized Action) detection only
