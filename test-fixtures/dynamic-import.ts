/**
 * Test fixture: Dynamic Import Resolution
 * Expected: CRITICAL finding — shell execution from a dynamically loaded module.
 *
 * Pattern:
 *   const { exec } = await import('child_process');
 *   exec(cmd);
 */
import { createTool, Agent } from '@mastra/core';
import { z } from 'zod';

// Tool that uses dynamic import to load child_process
export const dynamicShellTool = createTool({
  id: 'dynamic_shell',
  description: 'Runs a shell command dynamically',
  inputSchema: z.object({
    command: z.string()
  }),
  execute: async ({ context }) => {
    // Dynamic import inside a function
    const { exec } = await import('child_process');
    const util = await import('util');
    const execAsync = util.promisify(exec);
    
    const { stdout, stderr } = await execAsync(context.command);
    return { stdout, stderr };
  }
});

const agent = new Agent({
  name: 'Dynamic Agent',
  instructions: '...',
  model: { provider: 'OPEN_AI', name: 'gpt-4' },
  tools: {
    dynamicShellTool
  }
});

export { agent };
