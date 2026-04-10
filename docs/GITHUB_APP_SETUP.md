# GitHub App Manual Setup Guide

This document outlines the **manual steps required** after deploying the Wyscan GitHub App server. These steps must be completed by a human with appropriate GitHub permissions.

---

## Prerequisites

- GitHub organization or personal account with admin access
- Server/hosting environment with public HTTPS endpoint
- Docker installed (or Node.js 20+ for local development)

---

## Step 1: Register GitHub App

1. Navigate to GitHub Settings:
   - **For Organizations:** `https://github.com/organizations/YOUR_ORG/settings/apps`
   - **For Personal Account:** `https://github.com/settings/apps`

2. Click **"New GitHub App"**

3. Fill in the following fields:

   **Basic Information:**
   - **GitHub App name:** `Wyscan Security Scanner` (or your preferred name)
   - **Homepage URL:** `https://github.com/plarix-security/wyscan`
   - **Webhook URL:** `https://your-domain.com/webhook`
   - **Webhook secret:** Generate a secure random string (save this for env vars)
     ```bash
     openssl rand -hex 32
     ```

   **Permissions:**
   - **Repository permissions:**
     - **Issues:** Read & Write (to post scan results)
     - **Contents:** Read-only (to clone and scan repositories)
     - **Checks:** Read & Write (to create check runs)
     - **Pull requests:** Read & Write (to post PR comments)
     - **Metadata:** Read-only (required, auto-selected)

   **Subscribe to events:**
   - ✅ Installation
   - ✅ Push
   - ✅ Pull request

   **Where can this GitHub App be installed?**
   - Select based on your needs (only this account or any account)

4. Click **"Create GitHub App"**

5. **Note the App ID** displayed on the next page (needed for env vars)

---

## Step 2: Generate Private Key

1. On the GitHub App settings page, scroll to **"Private keys"** section

2. Click **"Generate a private key"**

3. Download the `.pem` file (e.g., `wyscan-app.2024-04-06.private-key.pem`)

4. **Store securely** - this is your authentication credential

---

## Step 3: Prepare Environment Variables

Create a `.env` file or configure your hosting environment with:

```bash
# GitHub App credentials
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
...your private key content here...
-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=your-webhook-secret-from-step-1

# Server configuration
PORT=3000
NODE_ENV=production
```

**Loading Private Key from File:**
```bash
export GITHUB_PRIVATE_KEY="$(cat wyscan-app.private-key.pem)"
```

**For Docker:**
```bash
docker run -d \
  --name wyscan-app \
  -p 3000:3000 \
  -e GITHUB_APP_ID=123456 \
  -e GITHUB_PRIVATE_KEY="$(cat wyscan-app.private-key.pem)" \
  -e GITHUB_WEBHOOK_SECRET=your-webhook-secret \
  wyscan-github-app
```

---

## Step 4: Deploy Application

### Option A: Docker (Recommended)

```bash
# Build image
docker build -t wyscan-github-app .

# Run container
docker run -d \
  --name wyscan-app \
  --restart unless-stopped \
  -p 3000:3000 \
  -e GITHUB_APP_ID=$GITHUB_APP_ID \
  -e GITHUB_PRIVATE_KEY="$GITHUB_PRIVATE_KEY" \
  -e GITHUB_WEBHOOK_SECRET=$GITHUB_WEBHOOK_SECRET \
  wyscan-github-app

# Verify health
curl http://localhost:3000/health
```

### Option B: Local Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Set environment variables
export GITHUB_APP_ID=123456
export GITHUB_PRIVATE_KEY="$(cat private-key.pem)"
export GITHUB_WEBHOOK_SECRET=your-secret

# Start server
npm start
```

---

## Step 5: Configure Public Webhook URL

Your webhook URL must be publicly accessible via HTTPS.

### Option A: Production Hosting

Deploy to a platform with HTTPS support:
- **AWS:** EC2 + ALB, ECS, or Lambda
- **Google Cloud:** Cloud Run, GKE, or Compute Engine
- **Azure:** App Service or Container Instances
- **DigitalOcean:** Droplet or App Platform
- **Heroku:** Container deployment

Set the webhook URL in GitHub App settings to your public endpoint:
```
https://wyscan.yourdomain.com/webhook
```

### Option B: Local Testing with ngrok

For development/testing:

```bash
# Start ngrok tunnel
ngrok http 3000

# Copy the HTTPS URL (e.g., https://abc123.ngrok.io)
# Update GitHub App webhook URL to: https://abc123.ngrok.io/webhook
```

**Note:** Free ngrok URLs change on restart. Upgrade to a paid plan for persistent URLs.

---

## Step 6: Install GitHub App on Repositories

1. Navigate to your GitHub App settings page

2. Click **"Install App"** in the left sidebar

3. Select the organization/account where you want to install

4. Choose repositories:
   - **All repositories** (scans everything)
   - **Only select repositories** (choose specific repos)

5. Click **"Install"**

6. **Verification:**
   - Check your server logs: `docker logs -f wyscan-app`
   - You should see: `Installation created for X repositories`
   - GitHub should post security issues to each installed repository

---

## Step 7: Verify Functionality

### Test Installation Event

After installing the app, verify:
- [ ] Server received `installation.created` webhook (check logs)
- [ ] Security issue was created in each repository
- [ ] Issue has proper title: `[Wyscan] Security Scan Report — abc1234`
- [ ] Issue has "security" label applied
- [ ] Issue content shows scan results or "No findings" message

### Test Push Event

1. Make a commit to the default branch of an installed repository
2. Verify:
   - [ ] GitHub Check run appears on the commit
   - [ ] New security issue is posted with scan results
   - [ ] Issue reflects the new commit SHA

### Test Pull Request Event

1. Open a PR in an installed repository
2. Verify:
   - [ ] GitHub Check run appears on the PR
   - [ ] PR comment is posted with scan results (if findings exist)
   - [ ] Check run shows pass/fail based on findings

---

## Troubleshooting

### Webhooks Not Received

1. Check GitHub App settings → **Advanced** → **Recent Deliveries**
2. Look for failed deliveries (red X icons)
3. Common issues:
   - Webhook URL not publicly accessible
   - SSL certificate errors (use valid HTTPS)
   - Firewall blocking GitHub webhook IPs
   - Server not running or crashed

### Authentication Errors

**Symptoms:** `401 Unauthorized` or `Bad credentials` in logs

**Solutions:**
- Verify `GITHUB_APP_ID` is correct (numeric ID, not app slug)
- Ensure `GITHUB_PRIVATE_KEY` includes full PEM content with `-----BEGIN/END-----` markers
- Check for newline character issues in private key (use `\n` or actual newlines, not literal `\n` strings)
- Regenerate private key if corrupted

### Permission Errors

**Symptoms:** `403 Forbidden` or `Resource not accessible by integration`

**Solutions:**
- Check GitHub App permissions (Issues: Read & Write, Contents: Read)
- Re-install the app to apply updated permissions
- Verify installation includes the repository being scanned

### Scan Failures

**Symptoms:** Error issues posted or failed check runs

**Solutions:**
- Check server logs for detailed error messages
- Verify repository is not empty
- Check for large repositories (may timeout during clone)
- Ensure sufficient disk space for temp clones (each scan creates temp directory)

### No Issues Created

**Symptoms:** Installation event received but no issues appear

**Solutions:**
- Check logs for `Failed to post issue` errors
- Verify GitHub App has Issues: Write permission
- Check if repositories have issues disabled (enable in repo settings)
- Look for rate limiting errors (GitHub API limits)

---

## Security Considerations

### Private Key Security

- **Never commit** the private key to version control
- Store in secure secrets management (AWS Secrets Manager, HashiCorp Vault, etc.)
- Rotate keys periodically (generate new key, update env vars, revoke old key)
- Use environment variables or mounted secrets in production

### Webhook Secret

- Use a strong random secret (minimum 32 characters)
- Store securely alongside private key
- Change secret if potentially compromised (update GitHub App settings + env vars)

### Network Security

- Use HTTPS for webhook endpoint (required by GitHub)
- Configure firewall to allow only GitHub webhook IPs (optional, see: https://api.github.com/meta)
- Implement rate limiting to prevent abuse
- Monitor webhook delivery logs for unusual activity

### Access Control

- Grant GitHub App minimal necessary permissions
- Install only on repositories that need scanning
- Review installation access periodically
- Revoke access from decommissioned repositories

---

## Maintenance

### Updating the App

```bash
# Pull latest code
git pull origin main

# Rebuild Docker image
docker build -t wyscan-github-app .

# Stop old container
docker stop wyscan-app
docker rm wyscan-app

# Start new container
docker run -d \
  --name wyscan-app \
  --restart unless-stopped \
  -p 3000:3000 \
  -e GITHUB_APP_ID=$GITHUB_APP_ID \
  -e GITHUB_PRIVATE_KEY="$GITHUB_PRIVATE_KEY" \
  -e GITHUB_WEBHOOK_SECRET=$GITHUB_WEBHOOK_SECRET \
  wyscan-github-app
```

### Monitoring

Monitor these metrics:
- **Webhook delivery success rate** (GitHub App → Advanced → Recent Deliveries)
- **Server uptime** (health endpoint: `/health`)
- **Scan success/failure rate** (check logs for errors)
- **Disk usage** (temp directories should be cleaned up after each scan)
- **Memory usage** (large repos may spike memory during analysis)

### Logs

```bash
# Docker logs
docker logs -f wyscan-app

# Save logs to file
docker logs wyscan-app > wyscan.log 2>&1
```

---

## Support

For issues, questions, or contributions:
- **GitHub Issues:** https://github.com/plarix-security/wyscan/issues
- **Documentation:** https://github.com/plarix-security/wyscan/tree/main/docs

---

## Summary Checklist

- [ ] Register GitHub App on GitHub.com
- [ ] Generate and download private key
- [ ] Configure environment variables (App ID, private key, webhook secret)
- [ ] Deploy application (Docker or Node.js)
- [ ] Configure public webhook URL
- [ ] Install app on repositories
- [ ] Verify installation event triggers scan
- [ ] Test push event creates check run + issue
- [ ] Test PR event creates check run + comment
- [ ] Set up monitoring and logging
- [ ] Document deployment details for your team

Once all steps are complete, Wyscan will automatically scan repositories on installation, push, and pull request events!
