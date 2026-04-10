type AppModule = typeof import('../src/app');
type App = ReturnType<AppModule['getApp']>;
type AppRequest = Parameters<App>[0];
type AppResponse = Parameters<App>[1];

let appPromise: Promise<App> | undefined;

function getAppInstance(): Promise<App> {
  if (!appPromise) {
    appPromise = import('../src/app').then(({ getApp }) => getApp());
  }
  return appPromise;
}

export default function handler(req: AppRequest, res: AppResponse): void {
  getAppInstance()
    .then((app) => {
      app(req, res);
    })
    .catch((error) => {
      const message = error instanceof Error ? error.message : 'Server initialization failed';
      res.status(500).json({ error: message });
    });
}
