import { getApp } from '../src/app';

type App = ReturnType<typeof getApp>;
type AppRequest = Parameters<App>[0];
type AppResponse = Parameters<App>[1];

export default function handler(req: AppRequest, res: AppResponse): void {
  try {
    const app = getApp();
    app(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
