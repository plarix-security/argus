import express from 'express';
import { Webhooks, createNodeMiddleware } from '@octokit/webhooks';
import * as dotenv from 'dotenv';
import { handlePushEvent, handlePullRequestEvent, handleInstallationEvent, GitHubAppConfig } from './github/webhook-handler';
import { NAME, VERSION } from './cli/version';

dotenv.config();

function validateEnv(): void {
  const required = ['GITHUB_APP_ID', 'GITHUB_PRIVATE_KEY', 'GITHUB_WEBHOOK_SECRET'];
  const missing = required.filter(v => !process.env[v]);
  if (missing.length > 0) {
    console.error('Missing:' + missing.join(', '));
    process.exit(1);
  }
}

function createApp(): express.Application {
  const app = express();
  app.get('/health', (_, res) => res.json({ status: 'ok' }));
  const config: GitHubAppConfig = { appId: process.env.GITHUB_APP_ID!, privateKey: process.env.GITHUB_PRIVATE_KEY!.replace(/\\n/g, '\n') };
  const webhooks = new Webhooks({ secret: process.env.GITHUB_WEBHOOK_SECRET! });
  webhooks.on('push', async ({ payload }) => { try { await handlePushEvent(payload as any, config); } catch (e) { console.error('Push error:', e); } });
  webhooks.on('pull_request', async ({ payload }) => { try { await handlePullRequestEvent(payload as any, config); } catch (e) { console.error('PR error:', e); } });
  webhooks.on('installation', async ({ payload }) => { try { await handleInstallationEvent(payload as any, config); } catch (e) { console.error('Installation event error:', e); } });
  app.use(createNodeMiddleware(webhooks, { path: '/webhook' }));
  return app;
}

let appInstance: express.Application | null = null;

function getApp(): express.Application {
  if (!appInstance) {
    appInstance = createApp();
  }
  return appInstance;
}

function startServer(): void {
  validateEnv();
  const app = getApp();
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`\n${NAME} ${VERSION}\nRunning on port ${port}\n`));
}

if (require.main === module) {
  startServer();
}

const app = getApp();

export { createApp, getApp, validateEnv, startServer };
export default app;
