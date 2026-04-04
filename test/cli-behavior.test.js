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

  test('TypeScript files are analyzed in v1.3.0', () => {
    const projectDir = makeTempProject({
      'agent.ts': 'export function tool() { return 1; }\n',
    });

    const result = runCli(['scan', projectDir, '--json']);
    const report = JSON.parse(result.stdout);

    expect(result.status).toBe(0);
    expect(report.findings).toEqual([]);
    // TypeScript files are now analyzed, not skipped
    expect(report.coverage.files_analyzed).toBe(1);
    expect(report.total_cees).toBe(0);
    expect(report.cees).toEqual([]);
  });

  test('directory scan traces Python calls across files', () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from langchain.tools import tool',
        'from helpers import delete_workspace',
        '',
        '@tool',
        'def cleanup_agent(target: str):',
        '    delete_workspace(target)',
        '',
      ].join('\n'),
      'helpers.py': [
        'import shutil',
        '',
        'def delete_workspace(target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const result = runCli(['scan', projectDir, '--json']);
    const report = JSON.parse(result.stdout);

    expect(result.status).toBe(2);
    expect(report.total_cees).toBe(1);
    expect(report.cees).toHaveLength(1);
    expect(report.findings).toHaveLength(1);
    expect(report.cees[0].gate_status).toBe('absent');
    expect(report.cees[0].afb_type).toBe('AFB04');
    expect(report.findings[0].tool).toBe('cleanup_agent');
    expect(report.findings[0].operation).toContain('shutil.rmtree');
    expect(report.findings[0].involves_cross_file).toBe(true);
    expect(report.findings[0].tool_file).toContain('tools.py');
    expect(report.findings[0].call_path).toHaveLength(2);
  });

  test('non-structural decorators do not credit a gate (v1.2.2)', () => {
    // v1.2.2: Authorization-like decorator naming heuristic removed.
    // Gate credit requires structural proof only.
    const projectDir = makeTempProject({
      'auth.py': [
        'def login_required(fn):',
        '    return fn',
        '',
      ].join('\n'),
      'tools.py': [
        'import shutil',
        'from auth import login_required',
        'from langchain.tools import tool',
        '',
        '@login_required',
        '@tool',
        'def cleanup_agent(target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const result = runCli(['scan', projectDir, '--json']);
    const report = JSON.parse(result.stdout);

    expect(result.status).toBe(2);
    expect(report.total_cees).toBe(1);
    expect(report.cees).toHaveLength(1);
    expect(report.findings).toHaveLength(1);
    // Gate status is absent because login_required doesn't have structural gate behavior
    expect(report.cees[0].gate_status).toBe('absent');
    expect(report.cees[0].afb_type).toBe('AFB04');
    // v1.2.2: No authorization-like decorator naming mention - removed heuristic
    expect(report.findings[0].description).toContain('No policy gate detected');
  });

  test('terminal output for non-structural gate decorators (v1.2.2)', () => {
    // v1.2.2: Authorization-like decorator naming heuristic removed.
    const projectDir = makeTempProject({
      'auth.py': [
        'def login_required(fn):',
        '    return fn',
        '',
      ].join('\n'),
      'tools.py': [
        'import shutil',
        'from auth import login_required',
        'from langchain.tools import tool',
        '',
        '@login_required',
        '@tool',
        'def cleanup_agent(target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const result = runCli(['scan', projectDir]);

    expect(result.status).toBe(2);
    expect(result.stdout).toContain('1 critical');
    // v1.2.2: No authorization-like decorator naming mention - removed heuristic
    expect(result.stdout).toContain('No policy gate detected');
  });

  test('structural decorator gates keep CEEs but suppress AFB04 findings', () => {
    const projectDir = makeTempProject({
      'auth.py': [
        'def login_required(fn):',
        '    def wrapper(user, target):',
        '        if not user:',
        '            raise PermissionError("denied")',
        '        return fn(user, target)',
        '    return wrapper',
        '',
      ].join('\n'),
      'tools.py': [
        'import shutil',
        'from auth import login_required',
        'from langchain.tools import tool',
        '',
        '@login_required',
        '@tool',
        'def cleanup_agent(user, target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const result = runCli(['scan', projectDir, '--json']);
    const report = JSON.parse(result.stdout);

    expect(result.status).toBe(0);
    expect(report.total_cees).toBe(1);
    expect(report.findings).toEqual([]);
    expect(report.cees[0].gate_status).toBe('present');
    expect(report.cees[0].afb_type).toBeNull();
  });

  test('syntax-error Python files fail explicitly', () => {
    const projectDir = makeTempProject({
      'broken.py': [
        'from langchain.tools import tool',
        '',
        '@tool',
        'def broken_tool(:',
        '    return 1',
      ].join('\n'),
    });

    const result = runCli(['scan', projectDir]);

    expect(result.status).toBe(3);
    expect(result.stdout).toContain('Failed to analyze 1 file.');
  });
});
