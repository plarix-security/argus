interface ResponseLike {
  status(code: number): ResponseLike;
  json(payload: unknown): void;
}

export default async function handler(req: unknown, res: ResponseLike): Promise<void> {
  try {
    const { getApp } = await import('../src/app');
    const app = getApp();
    app(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Server initialization failed';
    res.status(500).json({ error: message });
  }
}
