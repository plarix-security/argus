# GitHub App

WyScan can run as a GitHub App for supported webhook events.

## Environment Variables

```bash
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=your-webhook-secret
PORT=3000
```

Current implementation expects `GITHUB_PRIVATE_KEY` to contain the PEM text in the environment.

## Start

```bash
npm run build
npm start
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/webhook` | POST | GitHub webhook events |

## Supported Events

- `push` on the default branch
- `pull_request` with actions `opened` and `synchronize`

## Current Scan Scope

- Push events scan the repository working tree.
- Pull request events scan changed analyzable files.
- Findings are written to a GitHub Check.
- Pull requests get an updated issue comment only when findings are present.

Failure and partial-coverage reporting are implementation areas that should be interpreted from the current check output rather than inferred from missing findings alone.
