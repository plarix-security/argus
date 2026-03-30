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
  ExecutionCategory,
} from '../types';

/**
 * Category to action description mapping
 */
const CATEGORY_ACTION: Record<ExecutionCategory, string> = {
  [ExecutionCategory.TOOL_CALL]: 'tool registered',
  [ExecutionCategory.SHELL_EXECUTION]: 'shell command execution',
  [ExecutionCategory.FILE_OPERATION]: 'file operation',
  [ExecutionCategory.API_CALL]: 'external API call',
  [ExecutionCategory.DATABASE_OPERATION]: 'database operation',
  [ExecutionCategory.CODE_EXECUTION]: 'dynamic code execution',
};

/**
 * Get capability description for a finding
 */
function getCapabilityDescription(finding: AFBFinding): string {
  const category = finding.category;
  const snippet = finding.codeSnippet.toLowerCase();

  switch (category) {
    case ExecutionCategory.SHELL_EXECUTION:
      return 'shell/execute capability';
    case ExecutionCategory.FILE_OPERATION:
      if (snippet.includes('write') || snippet.includes('remove') || snippet.includes('delete') || snippet.includes('unlink') || snippet.includes('rmtree')) {
        return 'write/delete capability';
      }
      return 'file access capability';
    case ExecutionCategory.API_CALL:
      if (snippet.includes('post') || snippet.includes('put') || snippet.includes('delete')) {
        return 'write/send capability';
      }
      return 'external request capability';
    case ExecutionCategory.DATABASE_OPERATION:
      return 'database write capability';
    case ExecutionCategory.CODE_EXECUTION:
      return 'code execution capability';
    case ExecutionCategory.TOOL_CALL:
      return 'agent-callable capability';
    default:
      return 'external effect capability';
  }
}

/**
 * Format a single finding as a markdown block per spec
 */
function formatFinding(finding: AFBFinding): string {
  const funcName = finding.context?.enclosingFunction || finding.codeSnippet.split('(')[0].trim();
  const capability = getCapabilityDescription(finding);
  const policyStatus = finding.context?.isToolDefinition
    ? 'no policy gate in call path'
    : 'verify policy gates exist';

  return `**\`${finding.file}\` line ${finding.line}**
\`${funcName}(...)\` — ${CATEGORY_ACTION[finding.category]} with ${capability}, ${policyStatus}.
AFB04: agent can execute this without authorization basis.`;
}

/**
 * Generate the PR comment in the specified format
 */
export function generatePRComment(report: AnalysisReport): string {
  const { findings, findingsBySeverity, totalFindings } = report;

  // If no findings, return clean pass
  if (totalFindings === 0) {
    return `## AFB Security Analysis

**Scan scope:** AFB04 Unauthorized Action
**Files analyzed:** ${report.filesAnalyzed.length}
**Execution points found:** 0
**Exposures detected:** 0

---

No AFB04 exposures detected. All analyzed files passed.

---

### Not detected
AFB01, AFB02, AFB03 are out of scope for this version.

---

*AFB Scanner by Plarix — runtime enforcement: plarix.dev*`;
  }

  // Group findings by severity (exclude SUPPRESSED from PR reports)
  const criticalFindings = findings.filter((f) => f.severity === Severity.CRITICAL);
  const warningFindings = findings.filter((f) => f.severity === Severity.WARNING);
  const infoFindings = findings.filter((f) => f.severity === Severity.INFO);

  // Build sections
  const sections: string[] = [];

  sections.push(`## AFB Security Analysis

**Scan scope:** AFB04 Unauthorized Action
**Files analyzed:** ${report.filesAnalyzed.length}
**Execution points found:** ${totalFindings}
**Exposures detected:** ${totalFindings}`);

  // Critical section
  if (criticalFindings.length > 0) {
    sections.push(`---

### Critical
`);
    // Limit to 5 critical findings to avoid huge comments
    const toShow = criticalFindings.slice(0, 5);
    for (const finding of toShow) {
      sections.push(formatFinding(finding));
      sections.push('');
    }
    if (criticalFindings.length > 5) {
      sections.push(`*...and ${criticalFindings.length - 5} more critical findings*`);
    }
  }

  // Warning section
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

  // Info section
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

  // Not detected section
  sections.push(`---

### Not detected
AFB01, AFB02, AFB03 are out of scope for this version.`);

  // Footer
  sections.push(`---

*AFB Scanner by Plarix — runtime enforcement: plarix.dev*`);

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
${BOLD}${CYAN}AFB Security Analysis${RESET}
${'='.repeat(50)}

${BOLD}Scan scope:${RESET} AFB04 Unauthorized Action
${BOLD}Files analyzed:${RESET} ${report.filesAnalyzed.length}
${BOLD}Exposures detected:${RESET} ${totalFindings}
`;

  if (totalFindings === 0) {
    output += `
${GREEN}No AFB04 exposures detected.${RESET}
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
    const funcName = finding.context?.enclosingFunction || 'unknown';

    output += `
${severityColor}${BOLD}${finding.severity.toUpperCase()}${RESET} ${finding.file}:${finding.line}
  ${CYAN}${funcName}${RESET} — ${CATEGORY_ACTION[finding.category]}
  ${finding.codeSnippet.slice(0, 80)}
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
