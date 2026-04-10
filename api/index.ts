import { getApp } from '../src/app';

interface MinimalResponse {
  status(code: number): MinimalResponse;
  json(payload: { error: string }): void;
}

type AppHandler = (req: unknown, res: unknown) => void;

export default function handler(req: unknown, res: MinimalResponse): void {
  try {
    const app = getApp() as unknown as AppHandler;
    app(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
