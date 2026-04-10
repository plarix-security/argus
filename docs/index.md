# WyScan

WyScan is a static scanner for AFB04-style unauthorized action exposure in agent code. It supports Python, TypeScript, and JavaScript.

Current shipped behavior:

- Parses Python, TypeScript, and JavaScript with tree-sitter.
- Detects tool registrations using framework and decorator patterns across all supported languages.
- Reports matched reachable operations when no credited policy gate is detected in the analyzed path.

Use these pages for the current shipped behavior:

- [Installation](install.md)
- [Usage](usage.md)
- [Detection Model](detection.md)
- [GitHub App](github-app.md)
- [Limitations](limitations.md)
