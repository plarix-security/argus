# GitHub App Setup

WyScan can run as a GitHub App to scan pull requests and pushes automatically.

## Create a GitHub App

1. Go to GitHub Settings > Developer settings > GitHub Apps
2. Click "New GitHub App"
3. Configure:
   - **Name:** WyScan (or your preferred name)
   - **Homepage URL:** Your deployment URL
   - **Webhook URL:** `https://your-domain/webhook`
   - **Webhook secret:** Generate a secure random string
4. Permissions:
   - Repository contents: Read
   - Checks: Read and write
   - Pull requests: Read and write
5. Subscribe to events:
   - Push
   - Pull request
6. Save and note the App ID
7. Generate a private key and download it

## Environment Variables

Create a `.env` file or set these environment variables:

```bash
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=your-webhook-secret
PORT=3000
```

The private key must include the `\n` characters for newlines, or you can use a file path.

## Start the Service

```bash
npm run build
npm start
```

The server listens on the configured PORT (default 3000).

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check, returns 200 if running |
| `/webhook` | POST | GitHub webhook events |

## Supported Events

### Push Events

When code is pushed to the default branch:

1. WyScan clones the repository
2. Runs a full scan of all Python files
3. Creates a GitHub Check with results

### Pull Request Events

When a PR is opened or updated:

1. WyScan clones the repository
2. Checks out the PR head commit
3. Scans only the changed Python files
4. Creates a GitHub Check with results
5. Posts or updates a PR comment if findings exist

## Check Run Results

The Check conclusion is based on findings:

| Findings | Conclusion |
|----------|------------|
| Any critical | `failure` |
| Any warning (no critical) | `neutral` |
| No warnings or critical | `success` |

## PR Comment Format

When findings exist, WyScan posts a comment with:

- Scan scope and file count
- Findings grouped by severity
- Code locations and descriptions

The comment is updated on subsequent pushes rather than creating duplicates.

## Deployment Options

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install && npm run build
CMD ["npm", "start"]
```

### Cloud Run / App Engine

Set environment variables through the platform's configuration and deploy the Node.js application.

### Self-hosted

Run with a process manager like PM2:

```bash
npm run build
pm2 start dist/app.js --name wyscan
```
