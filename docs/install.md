# Installation

## Requirements

- Node.js 18 or higher

## Install from Source

```bash
git clone https://github.com/plarix-security/wyscan.git
cd wyscan
npm install
npm run build
npm link
```

After linking, the `wyscan` command is available globally.

## Verify Installation

```bash
wyscan check
```

Expected output:

```
wyscan  v0.7.0-beta  by Plarix

Checking dependencies...

  OK  Node.js                   v18.0.0
  OK  tree-sitter-python.wasm   found
  OK  Parser initialization     ok

All checks passed. Ready to scan.
```

## Development Setup

If you want to modify WyScan:

```bash
git clone https://github.com/plarix-security/wyscan.git
cd wyscan
npm install
npm run build
npm test
```

Run without global install:

```bash
npm run wyscan -- scan ./project
```
