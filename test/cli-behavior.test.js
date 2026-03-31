const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const cliPath = path.join(repoRoot, 'dist', 'cli', 'index.js');

function makeTempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyscan-cli-'));

  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }

  return dir;
}

function runCli(args) {
  return spawnSync('node', [cliPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('CLI behavior honesty', () => {
  test('removed recursive flag is rejected explicitly', () => {
    const projectDir = makeTempProject({
      'agent.py': 'print("hello")\n',
    });

    const result = runCli(['scan', projectDir, '--recursive']);

    expect(result.status).toBe(3);
    expect(result.stderr).toContain('Unknown flag "--recursive"');
  });

  test('level filtering affects summary output and exit code', () => {
    const projectDir = makeTempProject({
      'agent.py': [
        'from langchain.tools import tool',
        'import requests',
        '',
        '@tool',
        'def send_webhook(url: str):',
        '    requests.post(url, json={"ok": True})',
        '',
      ].join('\n'),
    });

    const result = runCli(['scan', projectDir, '--summary', '--level', 'critical']);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('0 findings');
    expect(result.stdout).not.toContain('1 warning');
  });

  test('summary output can be written to a file', () => {
    const projectDir = makeTempProject({
      'agent.py': [
        'from langchain.tools import tool',
        'import requests',
        '',
        '@tool',
        'def send_webhook(url: str):',
        '    requests.post(url, json={"ok": True})',
        '',
      ].join('\n'),
    });
    const outputPath = path.join(projectDir, 'summary.txt');

    const result = runCli(['scan', projectDir, '--summary', '--output', outputPath]);

    expect(result.status).toBe(1);
    expect(fs.readFileSync(outputPath, 'utf8')).toContain('1 warning');
  });

  test('JSON output reports skipped-language coverage explicitly', () => {
    const projectDir = makeTempProject({
      'agent.ts': 'export function tool() { return 1; }\n',
    });

    const result = runCli(['scan', projectDir, '--json']);
    const report = JSON.parse(result.stdout);

    expect(result.status).toBe(0);
    expect(report.findings).toEqual([]);
    expect(report.coverage.partial).toBe(true);
    expect(report.coverage.languages_skipped).toContain('typescript');
    expect(report.coverage.files_skipped).toBe(1);
    expect(report.coverage.skipped_files[0].reason).toContain('not implemented');
  });
});
