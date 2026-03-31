# WyScan

WyScan is a Python-first static scanner for AFB04-style unauthorized action exposure in agent code.

Current shipped behavior:

- Parses Python with tree-sitter.
- Detects Python tool registrations using framework and decorator patterns.
- Reports matched reachable operations when no credited policy gate is detected in the analyzed path.
- Skips TypeScript and JavaScript explicitly.

Use these pages for the current shipped behavior:

- [Installation](install.md)
- [Usage](usage.md)
- [Detection Model](detection.md)
- [GitHub App](github-app.md)
- [Limitations](limitations.md)
