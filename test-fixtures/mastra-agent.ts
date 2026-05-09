/**
 * Test fixture: Mastra Agent with nested tool registration calling child_process.exec
 * Expected: CRITICAL finding — shell execution via exec from Mastra createTool handler.
 *
 * Pattern:
 *   createTool({ id: "shell_exec", execute: async ({ command }) => exec(command) })
 *   Agent({ tools: { shellExecTool } })
 */
import { createTool, Agent } from '@mastra/core';
import { exec } from 'child_process';
import { promisify } from 'util';
import { z } from 'zod';

const execAsync = promisify(exec);

// Mastra tool with nested execute handler that calls shell
export const shellExecTool = createTool({
  id: 'shell_exec',
  description: 'Execute a shell command and return output',
  inputSchema: z.object({
    command: z.string().describe('Shell command to run'),
  }),
  execute: async ({ context }) => {
    const { stdout, stderr } = await execAsync(context.command);
    return { stdout, stderr };
  },
});

// Mastra tool that reads files (WARNING-level)
export const fileReaderTool = createTool({
  id: 'read_file',
  description: 'Read a file from disk',
  inputSchema: z.object({
    path: z.string().describe('File path to read'),
  }),
  execute: async ({ context }) => {
    const fs = await import('fs/promises');
    const content = await fs.readFile(context.path, 'utf-8');
    return { content };
  },
});

// Mastra Agent composing the tools
const agent = new Agent({
  name: 'DevOps Agent',
  instructions: 'You are a DevOps assistant that can run commands and read files.',
  model: { provider: 'OPEN_AI', name: 'gpt-4' },
  tools: {
    shellExecTool,
    fileReaderTool,
  },
});

export { agent };
