const fs = require('fs');
const os = require('os');
const path = require('path');

const { AFBAnalyzer } = require('../dist/analyzer');

function makeTempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyscan-semantic-'));

  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }

  return dir;
}

describe('semantic-first python analysis', () => {
  test('langgraph create_react_agent roots tools semantically', async () => {
    const projectDir = makeTempProject({
      'graph.py': [
        'from langgraph.prebuilt import create_react_agent',
        'from tools import cleanup_workspace',
        '',
        'def build_agent(model):',
        '    return create_react_agent(model, [cleanup_workspace])',
        '',
      ].join('\n'),
      'tools.py': [
        'import shutil',
        '',
        'def cleanup_workspace(target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].tool).toBe('cleanup_workspace');
    expect(report.cees[0].framework).toBe('langgraph');
    expect(report.cees[0].evidenceKind).not.toBe('heuristic');
  });

  test('autogen function_map roots tools semantically', async () => {
    const projectDir = makeTempProject({
      'executor.py': [
        'from autogen import UserProxyAgent',
        'import shutil',
        '',
        'def cleanup_workspace(target: str):',
        '    shutil.rmtree(target)',
        '',
        'FUNCTION_MAP = {"cleanup": cleanup_workspace}',
        'user_proxy = UserProxyAgent(name="executor", function_map=FUNCTION_MAP)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].tool).toBe('cleanup_workspace');
    expect(report.cees[0].framework).toBe('autogen');
    expect(report.cees[0].evidenceKind).not.toBe('heuristic');
  });

  test('cee evidence records traced input flow into dangerous operations', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from langchain.tools import tool',
        '',
        '@tool',
        'def cleanup_agent(target: str):',
        '    path = target',
        '    shutil.rmtree(path)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].evidenceKind).toBe('structural');
    expect(report.cees[0].supportingEvidence.join(' ')).toContain('Traced tool input into shutil.rmtree arguments');
    expect(report.cees[0].classificationNote).toContain('Traced tool-controlled input into the matched operation arguments.');
    expect(report.findings[0].confidence).toBeGreaterThan(0.85);
  });

  test('pattern fallback remains available when semantic roots are absent', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'import shutil',
        '',
        'def action(fn):',
        '    return fn',
        '',
        '@action',
        'def cleanup_workspace(target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].framework).toBe('custom');
    expect(report.cees[0].evidenceKind).toBe('heuristic');
    expect(report.findings[0].confidence).toBeLessThan(0.8);
  });
});
