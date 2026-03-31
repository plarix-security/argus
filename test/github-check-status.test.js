const { summarizeReportForCheck, buildFailedCheckOutput } = require('../dist/github/webhook-handler');

function createReport(overrides = {}) {
  return {
    repository: 'repo',
    filesAnalyzed: ['src/tool.py'],
    totalFindings: 0,
    findingsBySeverity: {
      critical: 0,
      warning: 0,
      info: 0,
      suppressed: 0,
    },
    findings: [],
    metadata: {
      scannerVersion: '1.0.0',
      timestamp: '2026-03-31T00:00:00.000Z',
      totalTimeMs: 10,
      failedFiles: [],
      skippedFiles: [],
    },
    ...overrides,
  };
}

describe('GitHub check reporting', () => {
  test('clean full scan is reported as success', () => {
    const output = summarizeReportForCheck(createReport());

    expect(output.conclusion).toBe('success');
    expect(output.title).toBe('No findings reported');
    expect(output.summary).toContain('Coverage: full');
  });

  test('skipped-language partial scan is reported as neutral', () => {
    const output = summarizeReportForCheck(createReport({
      metadata: {
        scannerVersion: '1.0.0',
        timestamp: '2026-03-31T00:00:00.000Z',
        totalTimeMs: 10,
        failedFiles: [],
        skippedFiles: [{
          file: 'src/tool.ts',
          language: 'typescript',
          reason: 'TypeScript scanning is not implemented in this version. File skipped.',
        }],
      },
    }));

    expect(output.conclusion).toBe('neutral');
    expect(output.title).toBe('No findings reported; coverage partial');
    expect(output.summary).toContain('Coverage: partial');
    expect(output.summary).toContain('Skipped languages: typescript');
  });

  test('failed scan is reported explicitly', () => {
    const output = buildFailedCheckOutput(new Error('parser init failed'));

    expect(output.conclusion).toBe('failure');
    expect(output.title).toBe('Scan failed');
    expect(output.summary).toContain('The scan did not complete.');
    expect(output.text).toContain('No clean-scan conclusion can be drawn from this run.');
  });
});
