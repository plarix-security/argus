# Installation

## Requirements

- Node.js 18 or newer

## Install From Source

```bash
git clone https://github.com/plarix-security/wyscan.git
cd wyscan
npm install
npm run build
npm link
```

## Verify

```bash
wyscan check
```

Example output shape:

```text
wyscan v<package-version>  ·  Plarix

Checking dependencies...

OK  Node.js
OK  tree-sitter-python.wasm
OK  Parser initialization
```

The printed version comes from `package.json`.

## Development

```bash
npm install
npm run build
npm test
npm run wyscan -- scan ./project
```
