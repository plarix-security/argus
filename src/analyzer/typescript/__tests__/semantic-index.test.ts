import { initParser, parseTypeScriptSource } from '../ast-parser';
import { extractSemanticInvocationRoots } from '../semantic-index';

describe('TypeScript semantic index', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('does not add generic exported-entry fallback roots', () => {
    const openAIFile = '/repo/openai-tool.ts';
    const scriptFile = '/repo/script.ts';

    const openAISource = `
      import OpenAI from 'openai';
      export function lookup() { return 'ok'; }
      const tools = [{ type: 'function', function: { name: 'lookup' } }];
    `;

    const scriptSource = `
      import * as fs from 'fs';
      export function processFiles() {
        fs.unlinkSync('/tmp/demo.txt');
      }
    `;

    const parsedOpenAI = parseTypeScriptSource(openAISource, false);
    const parsedScript = parseTypeScriptSource(scriptSource, false);
    expect(parsedOpenAI.success).toBe(true);
    expect(parsedScript.success).toBe(true);

    const files = new Map([
      [openAIFile, parsedOpenAI],
      [scriptFile, parsedScript],
    ]);

    const roots = extractSemanticInvocationRoots(files);

    expect(roots.has(`${openAIFile}:lookup`)).toBe(true);
    expect(roots.has(`${scriptFile}:processFiles`)).toBe(false);
  });

  it('extracts typed/as-asserted action-like callbacks from assignments', () => {
    const source = `
      import type { Action, Provider, Plugin } from '@elizaos/core';

      const actionA: Action = { name: 'a', handler: async () => {} };
      const actionB = { name: 'b', handler: async () => {} } as Action;
      const provider: Provider = { name: 'p', get: async () => {} };
      const plugin: Plugin = { name: 'plg', init: async () => {}, dispose: async () => {} };
    `;
    const parsed = parseTypeScriptSource(source);
    expect(parsed.success).toBe(true);

    const actionB = parsed.assignments.find(a => a.target === 'actionB');
    expect(actionB?.assertedType).toBe('Action');
    expect(actionB?.isObjectLiteral).toBe(true);

    const provider = parsed.assignments.find(a => a.target === 'provider');
    expect(provider?.typeAnnotation).toBe('Provider');

    expect(parsed.functions.some(f => f.name === 'actionA.handler')).toBe(true);
    expect(parsed.functions.some(f => f.name === 'actionB.handler')).toBe(true);
    expect(parsed.functions.some(f => f.name === 'provider.get')).toBe(true);
    expect(parsed.functions.some(f => f.name === 'plugin.init')).toBe(true);
    expect(parsed.functions.some(f => f.name === 'plugin.dispose')).toBe(true);
  });

  it('does not treat generic action objects as framework roots', () => {
    const filePath = '/tmp/action-object.ts';
    const source = `
      import type { Action } from '@elizaos/core';

      const myAction = {
        name: 'test',
        handler: async () => { doWork(); },
      };
    `;
    const parsed = parseTypeScriptSource(source);
    expect(parsed.success).toBe(true);

    const files = new Map([[filePath, parsed]]);
    const roots = extractSemanticInvocationRoots(files);
    expect(roots.size).toBe(0);
  });

  it('detects MCP server.tool registration roots', () => {
    const filePath = '/tmp/mcp.ts';
    const parsed = parseTypeScriptSource(`
      import { Server } from '@modelcontextprotocol/sdk/server/index.js';
      const server = new Server({ name: 'demo', version: '1.0.0' });

      async function readSecret() {
        return process.env.SECRET || '';
      }

      server.tool('read_secret', {}, readSecret);
    `);
    expect(parsed.success).toBe(true);
    const files = new Map([[filePath, parsed]]);

    const roots = extractSemanticInvocationRoots(files);
    expect(Array.from(roots.values()).some((root) => root.framework === 'mcp')).toBe(true);
  });
});
