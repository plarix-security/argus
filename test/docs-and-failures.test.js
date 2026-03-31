const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { formatFinding } = require('../dist/cli/formatter');

const repoRoot = path.resolve(__dirname, '..');
const cliPath = path.join(repoRoot, 'dist', 'cli', 'index.js');
const appPath = path.join(repoRoot, 'dist', 'app.js');

function extractFirstJsonBlock(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const match = content.match(/```json\n([\s\S]*?)\n```/);

  if (!match) {
    throw new Error(`No JSON block found in ${filePath}`);
  }

  return JSON.parse(match[1]);
}

function makeTempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyscan-docs-'));

  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }

  return dir;
}

function runCli(args) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('docs and failure reporting', () => {
  test('README and usage JSON examples match the emitted schema shape', () => {
    const projectDir = makeTempProject({
      'agent.ts': 'export function tool() { return 1; }\n',
    });
    const actual = JSON.parse(runCli(['scan', projectDir, '--json']).stdout);
    const readmeExample = extractFirstJsonBlock(path.join(repoRoot, 'README.md'));
    const usageExample = extractFirstJsonBlock(path.join(repoRoot, 'docs', 'usage.md'));

    const expectedTopLevelKeys = Object.keys(actual).sort();
    const expectedFindingKeys = Object.keys(actual.findings[0] || {
      severity: '',
      file: '',
      line: 0,
      column: 0,
      operation: '',
      tool: '',
      framework: '',
      description: '',
      code_snippet: '',
      category: '',
    }).sort();
    const expectedCoverageKeys = Object.keys(actual.coverage).sort();

    expect(Object.keys(readmeExample).sort()).toEqual(expectedTopLevelKeys);
    expect(Object.keys(usageExample).sort()).toEqual(expectedTopLevelKeys);
    expect(Object.keys(readmeExample.findings[0]).sort()).toEqual(expectedFindingKeys);
    expect(Object.keys(usageExample.findings[0]).sort()).toEqual(expectedFindingKeys);
    expect(Object.keys(readmeExample.coverage).sort()).toEqual(expectedCoverageKeys);
    expect(Object.keys(usageExample.coverage).sort()).toEqual(expectedCoverageKeys);
  });

  test('app startup fails explicitly when required environment is missing', () => {
    const result = spawnSync(process.execPath, [appPath], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        SystemRoot: process.env.SystemRoot,
        COMSPEC: process.env.COMSPEC,
      },
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Missing:');
  });

  test('formatter preserves explicit depth-limit wording without escalation', () => {
    const text = formatFinding({
      type: 'AFB04',
      severity: 'info',
      category: 'tool_call',
      file: 'src/tool.py',
      line: 10,
      column: 1,
      codeSnippet: 'helper()',
      operation: 'Tool invocation: helper',
      explanation: 'Depth limit reached while tracing imported helper. Manual review recommended.',
      confidence: 0.95,
    });

    expect(text).toContain('Depth limit reached while tracing imported helper. Manual review recommended.');
    expect(text.toLowerCase()).not.toContain('attack');
    expect(text.toLowerCase()).not.toContain('ssrf');
  });
});
