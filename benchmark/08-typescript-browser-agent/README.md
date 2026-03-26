# 08-typescript-browser-agent

Browser automation agent using Playwright with OpenAI for control decisions.

## Vulnerabilities

| ID | Severity | Operation | Description |
|----|----------|-----------|-------------|
| BROWSER-001 | CRITICAL | page.evaluate | Arbitrary JS execution |
| BROWSER-002 | CRITICAL | page.goto | SSRF via navigation |
| BROWSER-003 | WARNING | page.fill | Form filling including auth |
| BROWSER-004 | WARNING | page.screenshot | Screenshot capture |
| BROWSER-005 | INFO | page.content | Page content extraction |

## Running

```bash
npm install
npx playwright install chromium
npx ts-node src/main.ts "Go to example.com and extract the main heading"
```
