/**
 * PR Comment Reporter
 *
 * Formats AFB04 analysis results as professional, developer-facing
 * GitHub PR comments. Output is structured like a security audit,
 * not a linter warning.
 */

import {
  AnalysisReport,
  AFBFinding,
  Severity,
  ExecutionCategory,
} from '../types';

/**
 * Emoji indicators for severity levels.
 */
const SEVERITY_EMOJI: Record<Severity, string> = {
  [Severity.CRITICAL]: '🔴',
  [Severity.HIGH]: '🟠',
  [Severity.MEDIUM]: '🟡',
};

/**
 * Category display names.
 */
const CATEGORY_NAMES: Record<ExecutionCategory, string> = {
  [ExecutionCategory.TOOL_CALL]: 'Tool Definition',
  [ExecutionCategory.SHELL_EXECUTION]: 'Shell Execution',
  [ExecutionCategory.FILE_OPERATION]: 'File Operation',
  [ExecutionCategory.API_CALL]: 'API Call',
  [ExecutionCategory.DATABASE_OPERATION]: 'Database Operation',
  [ExecutionCategory.CODE_EXECUTION]: 'Code Execution',
};

/**
 * Generate the PR comment markdown from an analysis report.
 */
export function generatePRComment(report: AnalysisReport): string {
  const lines: string[] = [];

  // Header
  lines.push('## 🛡️ AFB Scanner Report');
  lines.push('');
  lines.push('**Agent Failure Boundary Analysis** — Static analysis for unauthorized action execution points.');
  lines.push('');

  // Summary section
  lines.push('### Summary');
  lines.push('');
  
  if (report.totalFindings === 0) {
    lines.push('✅ **No AFB04 execution points detected** in the analyzed files.');
    lines.push('');
    lines.push(`- Files analyzed: ${report.filesAnalyzed.length}`);
    lines.push(`- Analysis time: ${report.metadata.totalTimeMs}ms`);
    lines.push('');
    lines.push(getFooter());
    return lines.join('\n');
  }

  // Severity breakdown
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| ${SEVERITY_EMOJI[Severity.CRITICAL]} Critical | ${report.findingsBySeverity.critical} |`);
  lines.push(`| ${SEVERITY_EMOJI[Severity.HIGH]} High | ${report.findingsBySeverity.high} |`);
  lines.push(`| ${SEVERITY_EMOJI[Severity.MEDIUM]} Medium | ${report.findingsBySeverity.medium} |`);
  lines.push('');

  // Stats
  lines.push(`**Total findings:** ${report.totalFindings} | **Files analyzed:** ${report.filesAnalyzed.length}`);
  lines.push('');

  // Findings section
  lines.push('---');
  lines.push('');
  lines.push('### Findings');
  lines.push('');

  // Group findings by file
  const findingsByFile = groupFindingsByFile(report.findings);
  
  for (const [file, findings] of findingsByFile) {
    lines.push(`#### 📄 \`${file}\``);
    lines.push('');
    
    for (const finding of findings) {
      lines.push(formatFinding(finding));
      lines.push('');
    }
  }

  // Explanation section
  lines.push('---');
  lines.push('');
  lines.push('<details>');
  lines.push('<summary><strong>What is AFB04?</strong></summary>');
  lines.push('');
  lines.push('**AFB04 (Unauthorized Action)** is an Agent Failure Boundary that identifies execution');
  lines.push('points where an AI agent can perform actions with real-world effects.');
  lines.push('');
  lines.push('These include:');
  lines.push('- **Tool Definitions**: Agent-callable functions that execute operations');
  lines.push('- **Shell Execution**: Commands that run on the host system');
  lines.push('- **File Operations**: Reading, writing, or deleting files');
  lines.push('- **API Calls**: External HTTP requests that may exfiltrate data');
  lines.push('- **Database Operations**: Queries that read or modify persistent state');
  lines.push('- **Code Execution**: Dynamic code evaluation (eval, exec)');
  lines.push('');
  lines.push('Each finding represents a point where agent reasoning could trigger');
  lines.push('an unauthorized action if upstream boundaries (AFB01-03) are compromised.');
  lines.push('');
  lines.push('</details>');
  lines.push('');

  // Failed files (if any)
  if (report.metadata.failedFiles.length > 0) {
    lines.push('<details>');
    lines.push('<summary><strong>Failed to analyze</strong></summary>');
    lines.push('');
    for (const file of report.metadata.failedFiles) {
      lines.push(`- \`${file}\``);
    }
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  lines.push(getFooter());

  return lines.join('\n');
}

/**
 * Format a single finding as markdown.
 */
function formatFinding(finding: AFBFinding): string {
  const lines: string[] = [];
  
  const severity = finding.severity.toUpperCase();
  const emoji = SEVERITY_EMOJI[finding.severity];
  const category = CATEGORY_NAMES[finding.category];
  
  // Finding header
  lines.push(`${emoji} **${severity}** — ${category}`);
  lines.push('');
  
  // Location
  lines.push(`📍 Line ${finding.line}, Column ${finding.column}`);
  lines.push('');
  
  // Code snippet
  lines.push('```');
  lines.push(finding.codeSnippet);
  lines.push('```');
  lines.push('');
  
  // Operation description
  lines.push(`**Operation:** ${finding.operation}`);
  lines.push('');
  
  // Explanation (why this is an AFB04)
  lines.push(`**Why:** ${finding.explanation}`);
  
  // Context if available
  if (finding.context) {
    const contextParts: string[] = [];
    
    if (finding.context.enclosingFunction) {
      contextParts.push(`function \`${finding.context.enclosingFunction}\``);
    }
    if (finding.context.enclosingClass) {
      contextParts.push(`class \`${finding.context.enclosingClass}\``);
    }
    if (finding.context.isToolDefinition) {
      contextParts.push('**inside tool definition**');
    }
    if (finding.context.framework) {
      contextParts.push(`framework: ${finding.context.framework}`);
    }
    
    if (contextParts.length > 0) {
      lines.push('');
      lines.push(`**Context:** ${contextParts.join(' | ')}`);
    }
  }
  
  // Confidence
  lines.push('');
  lines.push(`*Confidence: ${Math.round(finding.confidence * 100)}%*`);

  return lines.join('\n');
}

/**
 * Group findings by file path.
 */
function groupFindingsByFile(findings: AFBFinding[]): Map<string, AFBFinding[]> {
  const grouped = new Map<string, AFBFinding[]>();
  
  for (const finding of findings) {
    const existing = grouped.get(finding.file) || [];
    existing.push(finding);
    grouped.set(finding.file, existing);
  }
  
  return grouped;
}

/**
 * Generate the report footer.
 */
function getFooter(): string {
  return `---

*Generated by [AFB Scanner](https://github.com/plarix-security/afb-scanner) v0.1.0*

*AFB Scanner detects AFB04 (Unauthorized Action) boundaries through static analysis.*
*See the [AFB Specification](https://github.com/plarix-security/afb-spec) for the full taxonomy.*`;
}

/**
 * Generate a condensed summary for check run output.
 */
export function generateCheckSummary(report: AnalysisReport): string {
  if (report.totalFindings === 0) {
    return `✅ No AFB04 execution points detected (${report.filesAnalyzed.length} files analyzed)`;
  }

  const parts: string[] = [];
  
  if (report.findingsBySeverity.critical > 0) {
    parts.push(`${report.findingsBySeverity.critical} critical`);
  }
  if (report.findingsBySeverity.high > 0) {
    parts.push(`${report.findingsBySeverity.high} high`);
  }
  if (report.findingsBySeverity.medium > 0) {
    parts.push(`${report.findingsBySeverity.medium} medium`);
  }

  return `🛡️ Found ${report.totalFindings} AFB04 execution points (${parts.join(', ')})`;
}

/**
 * Generate JSON output for programmatic consumption.
 */
export function generateJSONReport(report: AnalysisReport): string {
  return JSON.stringify(report, null, 2);
}
