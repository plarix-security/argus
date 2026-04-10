type AppModule = typeof import('../src/app');
type App = ReturnType<AppModule['getApp']>;
type AppRequest = Parameters<App>[0];
type AppResponse = Parameters<App>[1];

export default async function handler(req: AppRequest, res: AppResponse): Promise<void> {
  try {
    const { getApp } = await import('../src/app');
    const app = getApp();
    app(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
