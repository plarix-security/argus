import { buildMethodologyDisclosure } from '../methodology-disclosure';
import { AnalysisReport } from '../../types';

function createReport(partial: boolean): AnalysisReport {
  return {
    repository: 'repo',
    filesAnalyzed: [],
    totalFindings: 0,
    totalCEEs: 0,
    findingsBySeverity: { critical: 0, warning: 0, info: 0, suppressed: 0 },
    findings: [],
    cees: [],
    metadata: {
      scannerVersion: '1.6.0',
      timestamp: new Date().toISOString(),
      totalTimeMs: 1,
      failedFiles: partial ? ['a.py'] : [],
      skippedFiles: partial ? [{ file: 'b.py', language: 'python', reason: 'skip' }] : [],
      fileLimitHit: false,
      fileLimit: Number.MAX_SAFE_INTEGER,
      totalFilesDiscovered: 2,
    },
  };
}

describe('methodology disclosure', () => {
  it('explicitly states regex is not the main method', () => {
    const disclosure = buildMethodologyDisclosure(createReport(false));

    expect(disclosure.regex_main_method).toBe(false);
    expect(disclosure.large_scale_agentic_readiness.ready).toBe(false);
    expect(disclosure.plan_for_large_scale_cee_coverage.length).toBeGreaterThanOrEqual(6);
  });

  it('marks partial scans as not ready with a direct short answer', () => {
    const disclosure = buildMethodologyDisclosure(createReport(true));

    expect(disclosure.short_answer).toMatch(/^No\./);
    expect(disclosure.short_answer).toContain('partial');
  });
});
