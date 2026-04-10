import { getApp } from '../src/app';

interface MinimalResponse {
  status(code: number): MinimalResponse;
  json(payload: { error: string }): void;
}

export default function handler(req: unknown, res: MinimalResponse): void {
  try {
    const app = getApp();
    app(req as never, res as never);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
