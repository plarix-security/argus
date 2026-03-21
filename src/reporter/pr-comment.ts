/**
 * PR Comment Reporter
 *
 * Formats AFB04 findings into professional, developer-facing PR comments.
 * Structured like a security audit report, not generic linter warnings.
 */

import {
  AFBFinding,
  AnalysisReport,
  Severity,
  ExecutionCategory,
} from "../types";
import { SCANNER_VERSION } from "../analyzer";

/**
 * Severity emoji mapping for visual clarity.
 */
const SEVERITY_EMOJI: Record<Severity, string> = {
  [Severity.CRITICAL]: "\u26A0\uFE0F", // Warning sign
  [Severity.HIGH]: "\uD83D\uDD34",     // Red circle
  [Severity.MEDIUM]: "\uD83D\uDFE1",   // Yellow circle
};

/**
 * Severity label mapping.
 */
const SEVERITY_LABEL: Record<Severity, string> = {
  [Severity.CRITICAL]: "CRITICAL",
  [Severity.HIGH]: "HIGH",
  [Severity.MEDIUM]: "MEDIUM",
};

/**
 * Category description mapping.
 */
const CATEGORY_DESCRIPTION: Record<ExecutionCategory, string> = {
  [ExecutionCategory.TOOL_CALL]: "Agent Tool Definition",
  [ExecutionCategory.SHELL_EXECUTION]: "Shell Command Execution",
  [ExecutionCategory.FILE_OPERATION]: "File System Operation",
  [ExecutionCategory.API_CALL]: "External API Call",
  [ExecutionCategory.DATABASE_OPERATION]: "Database Operation",
  [ExecutionCategory.CODE_EXECUTION]: "Dynamic Code Execution",
};

/**
 * Format a single finding as a markdown table row.
 */
function formatFindingRow(finding: AFBFinding, index: number): string {
  const emoji = SEVERITY_EMOJI[finding.severity];
  const severity = SEVERITY_LABEL[finding.severity];
  const fileLink = `\`${finding.file}:${finding.line}\``;
  const category = CATEGORY_DESCRIPTION[finding.category];

  return `| ${index} | ${emoji} ${severity} | ${fileLink} | ${category} | ${finding.operation} |`;
}

/**
 * Format a finding as a detailed markdown section.
 */
function formatFindingDetail(finding: AFBFinding, index: number): string {
  const emoji = SEVERITY_EMOJI[finding.severity];
  const severity = SEVERITY_LABEL[finding.severity];

  let detail = `
### ${emoji} Finding #${index}: ${severity}

- **File:** \`${finding.file}\`
- **Line:** ${finding.line}, Column: ${finding.column}
- **Category:** ${CATEGORY_DESCRIPTION[finding.category]}
- **Operation:** ${finding.operation}
${finding.context?.isToolDefinition ? "- **Context:** Inside agent tool definition" : ""}
${finding.context?.framework ? `- **Framework:** ${finding.context.framework}` : ""}

**Explanation:**
> ${finding.explanation}

**Code:**
\`\`\`
${finding.codeSnippet}
\`\`\`
`;

  return detail.trim();
}

/**
 * Generate the full PR comment report.
 */
export function generatePRComment(report: AnalysisReport): string {
  const { findings, findingsBySeverity, totalFindings, metadata } = report;

  // If no findings, return a clean pass message
  if (totalFindings === 0) {
    return `## AFB Scanner Report

\u2705 **No AFB04 (Unauthorized Action) boundaries detected.**

---
<details>
<summary>Scan Details</summary>

- **Files Analyzed:** ${report.filesAnalyzed.length}
- **Scanner Version:** ${metadata.scannerVersion}
- **Analysis Time:** ${metadata.totalTimeMs}ms
- **Timestamp:** ${metadata.timestamp}

</details>

---
*AFB Scanner v${SCANNER_VERSION} | [What is AFB?](https://github.com/plarix-security/afb-spec)*
`;
  }

  // Sort findings by severity (critical first)
  const sortedFindings = [...findings].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  // Generate summary section
  const criticalCount = findingsBySeverity.critical;
  const highCount = findingsBySeverity.high;
  const mediumCount = findingsBySeverity.medium;

  let summaryEmoji = "\u26A0\uFE0F"; // Warning by default
  if (criticalCount > 0) {
    summaryEmoji = "\u2757"; // Exclamation
  }

  // Build the summary table
  const summaryRows = sortedFindings.map((f, i) => formatFindingRow(f, i + 1));

  // Build detailed findings (only show first 10 to avoid comment size limits)
  const detailedFindings = sortedFindings
    .slice(0, 10)
    .map((f, i) => formatFindingDetail(f, i + 1));

  const truncatedNote =
    sortedFindings.length > 10
      ? `\n> **Note:** Showing 10 of ${sortedFindings.length} findings. Run locally for full report.\n`
      : "";

  return `## ${summaryEmoji} AFB Scanner Report

**${totalFindings} AFB04 (Unauthorized Action) ${totalFindings === 1 ? "boundary" : "boundaries"} detected.**

| Severity | Count |
|----------|-------|
| ${SEVERITY_EMOJI[Severity.CRITICAL]} Critical | ${criticalCount} |
| ${SEVERITY_EMOJI[Severity.HIGH]} High | ${highCount} |
| ${SEVERITY_EMOJI[Severity.MEDIUM]} Medium | ${mediumCount} |

---

### Summary

| # | Severity | Location | Category | Operation |
|---|----------|----------|----------|-----------|
${summaryRows.join("\n")}

---

### Detailed Findings
${truncatedNote}
${detailedFindings.join("\n\n---\n")}

---

<details>
<summary>About AFB04 (Unauthorized Action)</summary>

**AFB04** represents the **Agent \u2192 Act** boundary - the point where an AI agent 
attempts to perform an action that affects world state.

This includes:
- Tool invocations exposed to agent reasoning
- Shell command execution
- File system operations
- External API calls
- Database operations
- Dynamic code execution

These execution points require careful authorization and validation to prevent 
unintended actions driven by adversarial inputs or compromised reasoning.

[Learn more about the AFB Taxonomy](https://github.com/plarix-security/afb-spec)

</details>

<details>
<summary>Scan Details</summary>

- **Files Analyzed:** ${report.filesAnalyzed.length}
- **Scanner Version:** ${metadata.scannerVersion}
- **Analysis Time:** ${metadata.totalTimeMs}ms
- **Timestamp:** ${metadata.timestamp}
${metadata.failedFiles.length > 0 ? `- **Failed Files:** ${metadata.failedFiles.length}` : ""}

</details>

---
*AFB Scanner v${SCANNER_VERSION} | [AFB Spec](https://github.com/plarix-security/afb-spec)*
`;
}

/**
 * Generate a JSON report for programmatic consumption.
 */
export function generateJSONReport(report: AnalysisReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Generate a concise summary line for commit status.
 */
export function generateStatusSummary(report: AnalysisReport): string {
  const { totalFindings, findingsBySeverity } = report;

  if (totalFindings === 0) {
    return "AFB Scanner: No AFB04 boundaries detected";
  }

  const parts: string[] = [];
  if (findingsBySeverity.critical > 0) {
    parts.push(`${findingsBySeverity.critical} critical`);
  }
  if (findingsBySeverity.high > 0) {
    parts.push(`${findingsBySeverity.high} high`);
  }
  if (findingsBySeverity.medium > 0) {
    parts.push(`${findingsBySeverity.medium} medium`);
  }

  return `AFB Scanner: ${totalFindings} AFB04 boundaries (${parts.join(", ")})`;
}
