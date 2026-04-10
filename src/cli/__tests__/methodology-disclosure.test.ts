import { buildMethodologyDisclosure } from '../methodology-disclosure';
import { AnalysisReport } from '../../types';
import { VERSION } from '../version';

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
      scannerVersion: VERSION,
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

    expect(disclosure.runtime_surfaces).toContain('cli_only');
    expect(disclosure.runtime_surfaces).toContain('github_app_backend');
    expect(disclosure.regex_main_method).toBe(false);
    expect(disclosure.anti_overfit_policy.hardcoded_agent_schema_rules).toBe(false);
    expect(disclosure.anti_overfit_policy.memorized_framework_schema_rules).toBe(false);
    expect(disclosure.evidence_integrity_policy.length).toBeGreaterThanOrEqual(3);
  });

  it('marks partial scans with a coverage note', () => {
    const disclosure = buildMethodologyDisclosure(createReport(true));

    expect(disclosure.coverage_note).toContain('partial');
  });

  it('non-partial scans include a standard coverage note', () => {
    const disclosure = buildMethodologyDisclosure(createReport(false));

    expect(disclosure.coverage_note).toBeTruthy();
    expect(disclosure.coverage_note).not.toContain('partial');
  });
});
