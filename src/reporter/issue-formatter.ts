/**
 * GitHub Issue Formatter
 *
 * Formats AFB04 scan results as GitHub Issues with terminal-style aesthetics
 * combined with markdown enhancements for readability.
 */

import * as path from 'path';
import { AFBFinding, AnalysisReport, Severity } from '../types';
import { VERSION } from '../cli/version';

const DIVIDER = '─'.repeat(60);

/**
 * Helper function to get coverage notes from report
 * Adapted from pr-comment.ts
 */
function getCoverageNotes(report: AnalysisReport): string[] {
  const notes = [
    'The analyzed Python file set is graphed together. Changed-file scans do not guarantee full repository coverage.',
  ];

  if (report.metadata.failedFiles.length > 0) {
    const failedExamples = report.metadata.failedFiles.slice(0, 5).join(', ');
    notes.push(`Some files failed to analyze: ${failedExamples}${report.metadata.failedFiles.length > 5 ? ', ...' : ''}`);
  }

  if (report.metadata.skippedFiles.length > 0) {
    const skippedByLanguage = report.metadata.skippedFiles.reduce((acc, file) => {
      acc[file.language] = (acc[file.language] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const skippedSummary = Object.entries(skippedByLanguage)
      .map(([lang, count]) => `${count} ${lang}`)
      .join(', ');
    notes.push(`Files skipped: ${skippedSummary}`);
  }

  return notes;
}

/**
 * Helper function to get coverage status string
 */
function getCoverageStatus(report: AnalysisReport): string {
  const partialCoverage = report.metadata.skippedFiles.length > 0 || report.metadata.failedFiles.length > 0;
  return partialCoverage ? 'Partial' : 'Full';
}

/**
 * Format a single finding for the issue body
 * Combines pattern from cli/formatter.ts with markdown from pr-comment.ts
 */
function formatFinding(finding: AFBFinding): string {
  const filename = path.basename(finding.file);
  const location = `${finding.file}:${finding.line}`;
  const detailLines: string[] = [];

  if (finding.context?.toolFile && finding.context?.toolLine) {
    detailLines.push(`- Tool registration: \`${finding.context.toolFile}:${finding.context.toolLine}\``);
  }

  if (finding.context?.involvesCrossFile) {
    detailLines.push('- Path crosses file boundaries');
  }

  if (finding.context?.depthLimitHit) {
    detailLines.push('- Tracing hit the configured depth limit');
  }

  if (finding.context?.unresolvedCalls && finding.context.unresolvedCalls.length > 0) {
    const unresolvedList = finding.context.unresolvedCalls.slice(0, 3).join('`, `');
    detailLines.push(`- Unresolved calls: \`${unresolvedList}\`${finding.context.unresolvedCalls.length > 3 ? ', ...' : ''}`);
  }

  // Detect language for code block syntax highlighting
  const extension = path.extname(finding.file);
  const language = extension === '.py' ? 'python' : extension === '.ts' ? 'typescript' : extension === '.js' ? 'javascript' : '';

  let output = `**\`${location}\`**\n`;
  output += '```' + language + '\n';
  output += finding.codeSnippet.trim() + '\n';
  output += '```\n';
  output += finding.explanation + '\n';

  if (detailLines.length > 0) {
    output += '\n**Details:**\n';
    output += detailLines.join('\n');
  }

  return output;
}

/**
 * Generate issue title from commit SHA
 * Format: [Wyscan] Security Scan Report — abc1234
 */
export function generateIssueTitle(commitSha: string): string {
  const shortSha = commitSha.slice(0, 7);
  return `[Wyscan] Security Scan Report — ${shortSha}`;
}

/**
 * Generate issue body with findings
 * Terminal-style formatting with markdown enhancements
 */
export function generateIssueBody(
  report: AnalysisReport,
  repoName: string,
  commitSha: string
): string {
  const shortSha = commitSha.slice(0, 7);
  const timestamp = new Date().toISOString();
  const coverage = getCoverageStatus(report);

  const criticalFindings = report.findings.filter((f) => f.severity === Severity.CRITICAL);
  const warningFindings = report.findings.filter((f) => f.severity === Severity.WARNING);
  const infoFindings = report.findings.filter((f) => f.severity === Severity.INFO);

  let body = `# 🔍 WyScan Security Report\n\n`;
  body += `**Repository:** \`${repoName}\`\n`;
  body += `**Commit:** \`${shortSha}\`\n`;
  body += `**Scan Date:** ${timestamp}\n`;
  body += `**Scan Type:** AFB04 (Unauthorized Action Boundary)\n\n`;
  body += DIVIDER + '\n\n';

  // Summary table
  body += `## 📊 Summary\n\n`;
  body += `| Metric | Count |\n`;
  body += `|--------|-------|\n`;
  body += `| Files Analyzed | ${report.filesAnalyzed.length} |\n`;
  body += `| CEEs Detected | ${report.totalCEEs} |\n`;
  body += `| **Critical** | **${criticalFindings.length}** |\n`;
  body += `| **Warning** | **${warningFindings.length}** |\n`;
  body += `| **Info** | **${infoFindings.length}** |\n`;
  body += `| Coverage | ${coverage} |\n\n`;
  body += DIVIDER + '\n\n';

  // Critical findings
  if (criticalFindings.length > 0) {
    body += `## 🔴 Critical Findings (${criticalFindings.length})\n\n`;
    const toShow = criticalFindings.slice(0, 5);
    for (const finding of toShow) {
      body += formatFinding(finding) + '\n\n---\n\n';
    }
    if (criticalFindings.length > 5) {
      body += `*...and ${criticalFindings.length - 5} more critical findings*\n\n`;
    }
    body += DIVIDER + '\n\n';
  }

  // Warning findings
  if (warningFindings.length > 0) {
    body += `## ⚠️ Warning Findings (${warningFindings.length})\n\n`;
    const toShow = warningFindings.slice(0, 5);
    for (const finding of toShow) {
      body += formatFinding(finding) + '\n\n---\n\n';
    }
    if (warningFindings.length > 5) {
      body += `*...and ${warningFindings.length - 5} more warning findings*\n\n`;
    }
    body += DIVIDER + '\n\n';
  }

  // Info findings
  if (infoFindings.length > 0) {
    body += `## ℹ️ Info Findings (${infoFindings.length})\n\n`;
    const toShow = infoFindings.slice(0, 3);
    for (const finding of toShow) {
      body += formatFinding(finding) + '\n\n---\n\n';
    }
    if (infoFindings.length > 3) {
      body += `*...and ${infoFindings.length - 3} more info findings*\n\n`;
    }
    body += DIVIDER + '\n\n';
  }

  // Coverage notes
  body += `## 📋 Coverage Notes\n\n`;
  const notes = getCoverageNotes(report);
  for (const note of notes) {
    body += `- ${note}\n`;
  }
  body += '\n' + DIVIDER + '\n\n';

  // Footer
  body += `<sub>🤖 Powered by [WyScan](https://github.com/plarix-security/wyscan) v${VERSION} | AFB04 Static Analyzer</sub>\n`;

  return body;
}

/**
 * Generate issue body for clean scan (no findings)
 */
export function generateNoFindingsIssue(
  report: AnalysisReport,
  repoName: string,
  commitSha: string
): string {
  const shortSha = commitSha.slice(0, 7);
  const timestamp = new Date().toISOString();
  const coverage = getCoverageStatus(report);

  let body = `# ✅ WyScan Security Report — Clean Scan\n\n`;
  body += `**Repository:** \`${repoName}\`\n`;
  body += `**Commit:** \`${shortSha}\`\n`;
  body += `**Scan Date:** ${timestamp}\n\n`;
  body += DIVIDER + '\n\n';

  body += `## No AFB04 Vulnerabilities Detected\n\n`;
  body += `WyScan analyzed **${report.filesAnalyzed.length} files** and detected **${report.totalCEEs} canonical execution events (CEEs)** `;
  body += `but determined none represent AFB04 (Unauthorized Action) boundaries without proper authorization gates.\n\n`;

  // Summary table
  body += `| Metric | Count |\n`;
  body += `|--------|-------|\n`;
  body += `| Files Analyzed | ${report.filesAnalyzed.length} |\n`;
  body += `| CEEs Detected | ${report.totalCEEs} |\n`;
  body += `| Findings | **0** |\n`;
  body += `| Coverage | ${coverage} |\n\n`;

  body += `This repository appears to have proper authorization controls in place for all detected execution events.\n\n`;
  body += DIVIDER + '\n\n';

  // Coverage notes if applicable
  const notes = getCoverageNotes(report);
  if (notes.length > 1 || report.metadata.skippedFiles.length > 0 || report.metadata.failedFiles.length > 0) {
    body += `## 📋 Coverage Notes\n\n`;
    for (const note of notes) {
      body += `- ${note}\n`;
    }
    body += '\n' + DIVIDER + '\n\n';
  }

  // Footer
  body += `<sub>🤖 Powered by [WyScan](https://github.com/plarix-security/wyscan) v${VERSION} | AFB04 Static Analyzer</sub>\n`;

  return body;
}
