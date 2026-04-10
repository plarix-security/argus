import { getApp } from '../src/app';

export default function handler(req: any, res: any): void {
  try {
    const app = getApp();
    app(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
