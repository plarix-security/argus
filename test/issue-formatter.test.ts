import { generateIssueTitle, generateIssueBody, generateNoFindingsIssue } from '../src/reporter/issue-formatter';
import { AnalysisReport, Severity, AFBType, ExecutionCategory } from '../src/types';

describe('Issue Formatter', () => {
  describe('generateIssueTitle', () => {
    test('formats commit SHA correctly', () => {
      const title = generateIssueTitle('abc1234567890');
      expect(title).toBe('[Wyscan] Security Scan Report — abc1234');
    });

    test('handles short SHAs', () => {
      const title = generateIssueTitle('abc123');
      expect(title).toBe('[Wyscan] Security Scan Report — abc123');
    });

    test('extracts first 7 characters', () => {
      const title = generateIssueTitle('1234567890abcdef');
      expect(title).toBe('[Wyscan] Security Scan Report — 1234567');
    });
  });

  describe('generateIssueBody', () => {
    const mockReport: AnalysisReport = {
      repository: 'test-repo',
      commitSha: 'abc1234567',
      filesAnalyzed: ['file1.py', 'file2.py'],
      totalCEEs: 5,
      totalFindings: 2,
      findingsBySeverity: {
        critical: 1,
        warning: 1,
        info: 0,
        suppressed: 0
      },
      findings: [
        {
          type: AFBType.UNAUTHORIZED_ACTION,
          severity: Severity.CRITICAL,
          category: ExecutionCategory.FILE_OPERATION,
          file: 'test.py',
          line: 10,
          column: 5,
          codeSnippet: 'shutil.rmtree(dir)',
          operation: 'shutil.rmtree',
          explanation: 'Test critical finding',
          confidence: 0.95,
          context: {
            toolFile: 'tools.py',
            toolLine: 5,
            involvesCrossFile: true
          }
        },
        {
          type: AFBType.UNAUTHORIZED_ACTION,
          severity: Severity.WARNING,
          category: ExecutionCategory.FILE_OPERATION,
          file: 'test2.py',
          line: 20,
          column: 10,
          codeSnippet: 'file.write(data)',
          operation: 'file.write',
          explanation: 'Test warning finding',
          confidence: 0.85
        }
      ],
      cees: [],
      metadata: {
        scannerVersion: '1.3.5',
        timestamp: '2026-04-06T12:00:00Z',
        totalTimeMs: 1000,
        failedFiles: [],
        skippedFiles: []
      }
    };

    test('includes summary table', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('## 📊 Summary');
      expect(body).toContain('| Files Analyzed | 2 |');
      expect(body).toContain('| CEEs Detected | 5 |');
      expect(body).toContain('| **Critical** | **1** |');
      expect(body).toContain('| **Warning** | **1** |');
    });

    test('includes repository information', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('**Repository:** `owner/repo`');
      expect(body).toContain('**Commit:** `abc123`');
    });

    test('includes critical findings section', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('## 🔴 Critical Findings (1)');
      expect(body).toContain('test.py:10');
      expect(body).toContain('shutil.rmtree(dir)');
      expect(body).toContain('Test critical finding');
    });

    test('includes warning findings section', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('## ⚠️ Warning Findings (1)');
      expect(body).toContain('test2.py:20');
      expect(body).toContain('file.write(data)');
    });

    test('includes coverage notes section', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('## 📋 Coverage Notes');
      expect(body).toContain('The analyzed file set is graphed together per language');
    });

    test('includes footer with version', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('Powered by [WyScan]');
      expect(body).toContain('AFB04 Static Analyzer');
    });

    test('uses dividers for formatting', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('─'.repeat(60));
    });

    test('shows code blocks with syntax highlighting', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('```python');
      expect(body).toContain('shutil.rmtree(dir)');
      expect(body).toContain('```');
    });

    test('shows tool registration details when present', () => {
      const body = generateIssueBody(mockReport, 'owner/repo', 'abc123');
      expect(body).toContain('Tool registration: `tools.py:5`');
      expect(body).toContain('Path crosses file boundaries');
    });

    test('limits findings display', () => {
      const manyFindings: AnalysisReport = {
        ...mockReport,
        totalFindings: 10,
        findingsBySeverity: {
          critical: 10,
          warning: 0,
          info: 0,
          suppressed: 0
        },
        findings: Array(10).fill(null).map((_, i) => ({
          type: AFBType.UNAUTHORIZED_ACTION,
          severity: Severity.CRITICAL,
          category: ExecutionCategory.FILE_OPERATION,
          file: `test${i}.py`,
          line: 10,
          column: 5,
          codeSnippet: 'operation()',
          operation: 'operation',
          explanation: 'Test finding',
          confidence: 0.95
        }))
      };

      const body = generateIssueBody(manyFindings, 'owner/repo', 'abc123');
      expect(body).toContain('...and 5 more critical findings');
    });
  });

  describe('generateNoFindingsIssue', () => {
    const mockCleanReport: AnalysisReport = {
      repository: 'test-repo',
      commitSha: 'abc1234567',
      filesAnalyzed: ['file1.py', 'file2.py', 'file3.py'],
      totalCEEs: 10,
      totalFindings: 0,
      findingsBySeverity: {
        critical: 0,
        warning: 0,
        info: 0,
        suppressed: 0
      },
      findings: [],
      cees: [],
      metadata: {
        scannerVersion: '1.3.5',
        timestamp: '2026-04-06T12:00:00Z',
        totalTimeMs: 1000,
        failedFiles: [],
        skippedFiles: []
      }
    };

    test('shows clean scan message', () => {
      const body = generateNoFindingsIssue(mockCleanReport, 'owner/repo', 'abc123');
      expect(body).toContain('✅');
      expect(body).toContain('Clean Scan');
      expect(body).toContain('No AFB04 Vulnerabilities Detected');
    });

    test('includes CEE count', () => {
      const body = generateNoFindingsIssue(mockCleanReport, 'owner/repo', 'abc123');
      expect(body).toContain('10 canonical execution events');
    });

    test('includes summary table', () => {
      const body = generateNoFindingsIssue(mockCleanReport, 'owner/repo', 'abc123');
      expect(body).toContain('| Files Analyzed | 3 |');
      expect(body).toContain('| CEEs Detected | 10 |');
      expect(body).toContain('| Findings | **0** |');
    });

    test('shows positive security message', () => {
      const body = generateNoFindingsIssue(mockCleanReport, 'owner/repo', 'abc123');
      expect(body).toContain('proper authorization controls in place');
    });

    test('includes repository and commit info', () => {
      const body = generateNoFindingsIssue(mockCleanReport, 'owner/repo', 'abc123');
      expect(body).toContain('**Repository:** `owner/repo`');
      expect(body).toContain('**Commit:** `abc123`');
    });

    test('shows coverage as Full when no files skipped or failed', () => {
      const body = generateNoFindingsIssue(mockCleanReport, 'owner/repo', 'abc123');
      expect(body).toContain('| Coverage | Full |');
    });

    test('shows coverage as Partial when files skipped', () => {
      const reportWithSkipped: AnalysisReport = {
        ...mockCleanReport,
        metadata: {
          ...mockCleanReport.metadata,
          skippedFiles: [
            { file: 'test.ts', language: 'typescript', reason: 'Not supported' }
          ]
        }
      };

      const body = generateNoFindingsIssue(reportWithSkipped, 'owner/repo', 'abc123');
      expect(body).toContain('| Coverage | Partial |');
    });

    test('includes coverage notes when files skipped', () => {
      const reportWithSkipped: AnalysisReport = {
        ...mockCleanReport,
        metadata: {
          ...mockCleanReport.metadata,
          skippedFiles: [
            { file: 'test.ts', language: 'typescript', reason: 'Not supported' }
          ]
        }
      };

      const body = generateNoFindingsIssue(reportWithSkipped, 'owner/repo', 'abc123');
      expect(body).toContain('## 📋 Coverage Notes');
      expect(body).toContain('Files skipped: 1 typescript');
    });
  });
});
