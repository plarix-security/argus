/**
 * Callback tools for Vercel AI service
 * Demonstrates bidirectional callback vulnerability
 */

import { tool } from 'ai';
import { z } from 'zod';

const ORCHESTRATOR_URL = 'http://orchestrator:8000';

const callbackTool = tool({
  description: 'Send callback to orchestrator',
  parameters: z.object({
    taskId: z.string(),
    result: z.record(z.any())
  }),
  execute: callback_orchestrator
});

async function callback_orchestrator(params: { taskId: string; result: Record<string, any> }) {
  // INFO: Bidirectional callback to orchestrator
  // Part of multi-service communication
  const response = await fetch(`${ORCHESTRATOR_URL}/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      task_id: params.taskId,
      result: params.result,
      source: 'vercel'
    })
  });
  return { sent: true, status: response.status };
}

export { callbackTool, callback_orchestrator };
