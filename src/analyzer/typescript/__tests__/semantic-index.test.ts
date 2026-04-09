import { initParser, parseTypeScriptSource } from '../ast-parser';
import { extractSemanticInvocationRoots } from '../semantic-index';

describe('TypeScript semantic index', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('adds exported entry-point roots for dangerous files even when other roots exist', () => {
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
        fs.readFileSync('/tmp/demo.txt', 'utf8');
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

    expect(roots.has(`${scriptFile}:processFiles`)).toBe(true);
  });
});
