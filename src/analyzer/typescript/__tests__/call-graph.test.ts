import { initParser, parseTypeScriptSource } from '../ast-parser';
import { buildCallGraph } from '../call-graph';
import { SemanticInvocationRoot } from '../semantic-index';

describe('TypeScript call graph', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('traces same-file calls to functions declared later', () => {
    const filePath = '/repo/tool.ts';
    const source = `
      import { execSync } from 'child_process';

      export function runTool() {
        helper();
      }

      function helper() {
        execSync('echo test');
      }
    `;

    const parsed = parseTypeScriptSource(source, false);
    expect(parsed.success).toBe(true);

    const files = new Map([[filePath, parsed]]);
    const roots = new Map<string, SemanticInvocationRoot>([
      [
        `${filePath}:runTool`,
        {
          nodeId: `${filePath}:runTool`,
          toolName: 'runTool',
          framework: 'test',
          evidence: 'test root',
          sourceFile: filePath,
          line: 4,
        },
      ],
    ]);

    const graph = buildCallGraph(files, roots);
    expect(graph.exposedPaths.length).toBeGreaterThan(0);
    expect(graph.exposedPaths.some((path) => path.path.length > 1)).toBe(true);
  });

  it('traces calls into imported relative modules', () => {
    const toolFile = '/repo/tool.ts';
    const helperFile = '/repo/helpers.ts';
    const toolSource = `
      import { dangerousHelper } from './helpers';

      export function runTool() {
        dangerousHelper();
      }
    `;
    const helperSource = `
      import { exec } from 'child_process';

      export function dangerousHelper() {
        exec('echo test');
      }
    `;

    const parsedTool = parseTypeScriptSource(toolSource, false);
    const parsedHelper = parseTypeScriptSource(helperSource, false);
    expect(parsedTool.success).toBe(true);
    expect(parsedHelper.success).toBe(true);

    const files = new Map([
      [toolFile, parsedTool],
      [helperFile, parsedHelper],
    ]);
    const roots = new Map<string, SemanticInvocationRoot>([
      [
        `${toolFile}:runTool`,
        {
          nodeId: `${toolFile}:runTool`,
          toolName: 'runTool',
          framework: 'test',
          evidence: 'test root',
          sourceFile: toolFile,
          line: 4,
        },
      ],
    ]);

    const graph = buildCallGraph(files, roots);
    expect(graph.exposedPaths.length).toBeGreaterThan(0);
    expect(graph.exposedPaths.some((path) => path.operation.sourceFile === helperFile)).toBe(true);
  });

  it('resolves monorepo-style package imports to workspace files', () => {
    const toolFile = '/repo/packages/app/src/tool.ts';
    const helperFile = '/repo/packages/helpers/src/index.ts';
    const toolSource = `
      import { dangerousHelper } from '@scope/helpers';

      export function runTool() {
        dangerousHelper();
      }
    `;
    const helperSource = `
      import { execSync } from 'child_process';

      export function dangerousHelper() {
        execSync('echo test');
      }
    `;

    const parsedTool = parseTypeScriptSource(toolSource, false);
    const parsedHelper = parseTypeScriptSource(helperSource, false);
    expect(parsedTool.success).toBe(true);
    expect(parsedHelper.success).toBe(true);

    const files = new Map([
      [toolFile, parsedTool],
      [helperFile, parsedHelper],
    ]);
    const roots = new Map<string, SemanticInvocationRoot>([
      [
        `${toolFile}:runTool`,
        {
          nodeId: `${toolFile}:runTool`,
          toolName: 'runTool',
          framework: 'test',
          evidence: 'test root',
          sourceFile: toolFile,
          line: 4,
        },
      ],
    ]);

    const graph = buildCallGraph(files, roots);
    expect(graph.exposedPaths.some((path) => path.operation.sourceFile === helperFile)).toBe(true);
    expect(graph.diagnostics.crossFileResolvedEdges).toBeGreaterThan(0);
  });

  it('reports unresolved edges in diagnostics', () => {
    const filePath = '/repo/tool.ts';
    const source = `
      export function runTool() {
        unresolvedCall();
      }
    `;
    const parsed = parseTypeScriptSource(source, false);
    expect(parsed.success).toBe(true);
    const files = new Map([[filePath, parsed]]);
    const roots = new Map<string, SemanticInvocationRoot>([
      [
        `${filePath}:runTool`,
        {
          nodeId: `${filePath}:runTool`,
          toolName: 'runTool',
          framework: 'test',
          evidence: 'test root',
          sourceFile: filePath,
          line: 2,
        },
      ],
    ]);

    const graph = buildCallGraph(files, roots);
    expect(graph.diagnostics.unresolvedCallEdges).toBeGreaterThan(0);
  });
});
