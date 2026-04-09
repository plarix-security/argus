import { initParser, parseTypeScriptSource } from '../ast-parser';
import { extractSemanticInvocationRoots } from '../semantic-index';

describe('TypeScript semantic index Eliza patterns', () => {
  beforeAll(async () => {
    await initParser();
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

  it('detects service start, plugin events, and cross-file function references', () => {
    const runtimeFile = '/tmp/runtime.ts';
    const pluginFile = '/tmp/plugin.ts';

    const runtimeParsed = parseTypeScriptSource(`
      export async function runAction() {}
    `);
    const pluginParsed = parseTypeScriptSource(`
      import { Service, type PluginEvents, EventType } from '@elizaos/core';
      import { runAction } from './runtime';

      class AutonomyService extends Service {
        static async start() {
          return runAction();
        }
      }

      const events: PluginEvents = {
        [EventType.MESSAGE_RECEIVED]: [async () => runAction()],
      };

      const action = { name: 'x', handler: runAction };
    `);

    const files = new Map([
      [runtimeFile, runtimeParsed],
      [pluginFile, pluginParsed],
    ]);

    const roots = extractSemanticInvocationRoots(files);

    expect(roots.has(`${pluginFile}:AutonomyService.start`)).toBe(true);
    expect(
      Array.from(roots.keys()).some(key => key.startsWith(`${pluginFile}:events.[EventType.MESSAGE_RECEIVED][0]`))
    ).toBe(true);
    expect(roots.has(`${runtimeFile}:runAction`)).toBe(true);
  });
});

