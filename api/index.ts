type AppModule = typeof import('../src/app');
type App = ReturnType<AppModule['getApp']>;
type AppRequest = Parameters<App>[0];
type AppResponse = Parameters<App>[1];

let appInstance: App | undefined;

function getAppInstance(): App {
  if (!appInstance) {
    const appModule = require('../src/app') as AppModule;
    appInstance = appModule.getApp();
  }
  return appInstance;
}

function isHealthRequest(req: AppRequest): boolean {
  const request = req as { method?: string; url?: string };
  if (request.method !== 'GET') {
    return false;
  }

  const requestUrl = request.url ?? '';
  return requestUrl === '/' || requestUrl.startsWith('/health');
}

export default function handler(req: AppRequest, res: AppResponse): void {
  if (isHealthRequest(req)) {
    res.status(200).json({ status: 'ok' });
    return;
  }

  try {
    const app = getAppInstance();
    app(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
