/**
 * PR Comment Reporter
 *
 * Formats AFB04 findings into the specified PR comment format.
 * Posts as both a PR comment and GitHub Check output.
 */

import {
  AFBFinding,
  AnalysisReport,
  Severity,
} from '../types';

function getCoverageLines(report: AnalysisReport): string[] {
  const skippedFiles = report.metadata.skippedFiles;
  const failedFiles = report.metadata.failedFiles;
  const skippedLanguages = Array.from(new Set(skippedFiles.map((file) => file.language))).sort();
  const partialCoverage = skippedFiles.length > 0 || failedFiles.length > 0;
  const lines = [
    `**Coverage:** ${partialCoverage ? 'partial' : 'full'}`,
  ];

  if (failedFiles.length > 0) {
    lines.push(`**Files failed:** ${failedFiles.length}`);
  }

  if (skippedFiles.length > 0) {
    lines.push(`**Files skipped:** ${skippedFiles.length}`);
  }

  if (skippedLanguages.length > 0) {
    lines.push(`**Skipped languages:** ${skippedLanguages.join(', ')}`);
  }

  return lines;
}

function getCoverageNotes(report: AnalysisReport): string[] {
  const notes = [
    'Python files are analyzed independently in the shipped scan flow. Repository-wide cross-file tracing is not guaranteed.',
  ];

  if (report.metadata.failedFiles.length > 0) {
    notes.push(`Some files failed to analyze: ${report.metadata.failedFiles.slice(0, 5).join(', ')}`);
  }

  if (report.metadata.skippedFiles.length > 0) {
    const skippedExamples = report.metadata.skippedFiles.slice(0, 5).map((file) => `${file.file} (${file.language})`);
    notes.push(`Some files were skipped explicitly: ${skippedExamples.join(', ')}`);
  }

  return notes;
}

/**
 * Format a single finding as a markdown block per spec
 */
function formatFinding(finding: AFBFinding): string {
  return `**\`${finding.file}\` line ${finding.line}**
\`${finding.codeSnippet}\`
${finding.explanation}`;
}

/**
 * Generate the PR comment in the specified format
 */
export function generatePRComment(report: AnalysisReport): string {
  const { findings, totalFindings } = report;

  if (totalFindings === 0) {
    const coverageLines = getCoverageLines(report);
    const coverageNotes = getCoverageNotes(report);

    return `## WyScan Report

**Scan scope:** Python AFB04 scan
**Files analyzed:** ${report.filesAnalyzed.length}
**Findings reported:** 0
${coverageLines.join('\n')}

No findings were reported in the analyzed files.

---

${coverageNotes.join('\n')}`;
  }

  const criticalFindings = findings.filter((f) => f.severity === Severity.CRITICAL);
  const warningFindings = findings.filter((f) => f.severity === Severity.WARNING);
  const infoFindings = findings.filter((f) => f.severity === Severity.INFO);

  const sections: string[] = [];

  sections.push(`## WyScan Report

**Scan scope:** Python AFB04 scan
**Files analyzed:** ${report.filesAnalyzed.length}
**Findings reported:** ${totalFindings}
${getCoverageLines(report).join('\n')}`);

  if (criticalFindings.length > 0) {
    sections.push(`---

### Critical
`);
    const toShow = criticalFindings.slice(0, 5);
    for (const finding of toShow) {
      sections.push(formatFinding(finding));
      sections.push('');
    }
    if (criticalFindings.length > 5) {
      sections.push(`*...and ${criticalFindings.length - 5} more critical findings*`);
    }
  }

  if (warningFindings.length > 0) {
    sections.push(`---

### Warning
`);
    const toShow = warningFindings.slice(0, 5);
    for (const finding of toShow) {
      sections.push(formatFinding(finding));
      sections.push('');
    }
    if (warningFindings.length > 5) {
      sections.push(`*...and ${warningFindings.length - 5} more warning findings*`);
    }
  }

  if (infoFindings.length > 0) {
    sections.push(`---

### Info
`);
    const toShow = infoFindings.slice(0, 3);
    for (const finding of toShow) {
      sections.push(formatFinding(finding));
      sections.push('');
    }
    if (infoFindings.length > 3) {
      sections.push(`*...and ${infoFindings.length - 3} more info findings*`);
    }
  }

  sections.push(`---

${getCoverageNotes(report).join('\n')}

AFB01, AFB02, and AFB03 are out of scope for this scanner.`);

  return sections.join('\n');
}

/**
 * Generate a JSON report for programmatic consumption.
 */
export function generateJSONReport(report: AnalysisReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Generate terminal output with ANSI colors
 */
export function generateTerminalReport(report: AnalysisReport): string {
  const { findings, findingsBySeverity, totalFindings, metadata } = report;

  const RED = '\x1b[31m';
  const YELLOW = '\x1b[33m';
  const GREEN = '\x1b[32m';
  const CYAN = '\x1b[36m';
  const RESET = '\x1b[0m';
  const BOLD = '\x1b[1m';

  let output = `
${BOLD}${CYAN}WyScan Report${RESET}
${'='.repeat(50)}

${BOLD}Scan scope:${RESET} Python AFB04 scan
${BOLD}Files analyzed:${RESET} ${report.filesAnalyzed.length}
${BOLD}Findings reported:${RESET} ${totalFindings}
`;

  if (totalFindings === 0) {
    output += `
${GREEN}No findings were reported in the analyzed files.${RESET}
`;
    return output;
  }

  output += `
${BOLD}Summary:${RESET}
  ${RED}Critical:${RESET} ${findingsBySeverity.critical}
  ${YELLOW}Warning:${RESET}  ${findingsBySeverity.warning}
  Info:     ${findingsBySeverity.info}

${BOLD}Findings:${RESET}
`;

  // Show up to 10 findings
  const toShow = findings.slice(0, 10);
  for (const finding of toShow) {
    const severityColor = finding.severity === Severity.CRITICAL ? RED :
                          finding.severity === Severity.WARNING ? YELLOW : RESET;

    output += `
${severityColor}${BOLD}${finding.severity.toUpperCase()}${RESET} ${finding.file}:${finding.line}
  ${finding.codeSnippet.slice(0, 80)}
  ${finding.explanation}
`;
  }

  if (findings.length > 10) {
    output += `\n... and ${findings.length - 10} more findings\n`;
  }

  output += `
${'='.repeat(50)}
Analysis time: ${metadata.totalTimeMs}ms
`;

  return output;
}
