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

export default function handler(req: AppRequest, res: AppResponse): void {
  try {
    const app = getAppInstance();
    app(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
