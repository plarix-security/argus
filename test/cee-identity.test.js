const fs = require('fs');
const os = require('os');
const path = require('path');

const { AFBAnalyzer } = require('../dist/analyzer');

function makeTempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyscan-cee-'));

  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }

  return dir;
}

describe('CEE identity', () => {
  test('same operation reached from two tools yields two CEEs', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from langchain.tools import tool',
        'from helpers import delete_workspace',
        '',
        '@tool',
        'def cleanup_alpha(target: str):',
        '    delete_workspace(target)',
        '',
        '@tool',
        'def cleanup_beta(target: str):',
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

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(2);
    expect(report.totalFindings).toBe(2);
    expect(report.cees.map((cee) => cee.tool).sort()).toEqual(['cleanup_alpha', 'cleanup_beta']);
  });
});
