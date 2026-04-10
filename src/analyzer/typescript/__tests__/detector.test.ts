import { analyzeTypeScriptFiles, ensureTypeScriptParserInitialized } from '../detector';

describe('TypeScript detector diagnostics', () => {
  beforeAll(async () => {
    await ensureTypeScriptParserInitialized();
  });

  it('attaches batch diagnostics to results', () => {
    const inputs = [
      {
        filePath: '/repo/tool.ts',
        sourceCode: `
          import { execSync } from 'child_process';
          export function runTool() { execSync('echo test'); }
        `,
      },
    ];

    const results = analyzeTypeScriptFiles(inputs);
    expect(results.length).toBe(1);
    expect(results[0].success).toBe(true);
    expect(results[0].analysisDiagnostics).toBeDefined();
    expect(results[0].analysisDiagnostics?.['totalRoots']).toBeGreaterThanOrEqual(0);
    expect(results[0].analysisDiagnostics?.['unresolvedCallEdges']).toBeGreaterThanOrEqual(0);
  });
});
