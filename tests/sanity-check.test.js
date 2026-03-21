const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');
const { AFBAnalyzer } = require('../dist/analyzer');
const { AFBType, ExecutionCategory } = require('../dist/types');

describe('scanner sanity-check reporting', () => {
  test('directory analysis includes explicit non-guarantee sanity check metadata', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'afb-scanner-'));
    const sampleFile = path.join(tempDir, 'agent.py');
    fs.writeFileSync(sampleFile, 'import subprocess\nsubprocess.run("echo hi", shell=True)\n', 'utf8');

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(tempDir);

    expect(report.metadata.sanityCheck).toBeDefined();
    expect(report.metadata.sanityCheck.isComprehensiveCoverageScanner).toBe(false);
    expect(report.metadata.sanityCheck.supportedAFBs).toEqual([AFBType.UNAUTHORIZED_ACTION]);
    expect(report.metadata.sanityCheck.unsupportedAFBs).toEqual([
      AFBType.INSTRUCTION,
      AFBType.CONTEXT,
      AFBType.CONSTRAINT,
    ]);
    expect(report.metadata.sanityCheck.canonicalCEECategories).toEqual([
      ExecutionCategory.TOOL_CALL,
      ExecutionCategory.SHELL_EXECUTION,
      ExecutionCategory.FILE_OPERATION,
      ExecutionCategory.API_CALL,
      ExecutionCategory.DATABASE_OPERATION,
      ExecutionCategory.CODE_EXECUTION,
    ]);
  });

  test('CLI prints blunt sanity-check verdict for single-file scans', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'afb-scanner-cli-'));
    const sampleFile = path.join(tempDir, 'agent.py');
    fs.writeFileSync(sampleFile, 'print("hello")\n', 'utf8');

    const output = execSync(`node dist/cli.js "${sampleFile}"`, {
      cwd: path.resolve(__dirname, '..'),
      encoding: 'utf8',
    });

    expect(output).toContain('Sanity check verdict:');
    expect(output).toContain('cannot guarantee detection of all canonical execution events');
    expect(output).toContain('Supported AFBs: AFB04');
    expect(output).toContain('Unsupported AFBs: AFB01, AFB02, AFB03');
  });
});
