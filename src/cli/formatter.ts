/**
 * Terminal Output Formatter
 *
 * Clean, professional security tool output.
 * Uses chalk for colors, strips when not TTY.
 */

import chalk from 'chalk';
import * as path from 'path';
import { AFBFinding, AnalysisReport, CEERecord, Severity } from '../types';
import { VERSION } from './version';

const DIVIDER = '─'.repeat(53);

/**
 * Check if stdout is a TTY (supports colors)
 */
export function isTTY(): boolean {
  return process.stdout.isTTY === true;
}

/**
 * Apply chalk styling only if TTY
 */
function styled(text: string, styleFn: (s: string) => string): string {
  return isTTY() ? styleFn(text) : text;
}

/**
 * Get finding description from explanation field
 */
function getDescription(finding: AFBFinding): string {
  return finding.explanation;
}

/**
 * Format code snippet - extract just the call, truncate at 60 chars
 */
function formatSnippet(snippet: string): string {
  // Clean up the snippet
  let clean = snippet.trim();

  // Remove common prefixes like "result = ", "response = ", etc.
  clean = clean.replace(/^[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*/, '');

  // Truncate at 60 chars
  if (clean.length > 60) {
    clean = clean.slice(0, 57) + '...';
  }

  return clean;
}

/**
 * Format severity with color and bullet
 */
function formatSeverityLabel(severity: Severity): string {
  const label = severity.toUpperCase().padEnd(8);
  switch (severity) {
    case Severity.CRITICAL:
      return styled(`● ${label}`, chalk.red.bold);
    case Severity.WARNING:
      return styled(`● ${label}`, chalk.yellow.bold);
    case Severity.INFO:
      return styled(`● ${label}`, chalk.cyan);
    default:
      return `● ${label}`;
  }
}

/**
 * Print header
 */
export function printHeader(): void {
  console.log(`  ${styled('wyscan', chalk.white)} v${VERSION}  ·  Plarix`);
  console.log(`  ${styled(DIVIDER, chalk.dim)}`);
}

/**
 * Print concise TUI-style quick panel
 */
export function printTuiQuickPanel(): void {
  const title = 'WYSCAN CLI QUICK PANEL';
  const rows = [
    'scan  : wyscan scan <path> [-l critical|warning]',
    'check : wyscan check',
    'json  : wyscan scan <path> --json',
    'quiet : wyscan scan <path> --summary',
  ];

  const contentWidth = Math.max(
    title.length,
    ...rows.map((row) => row.length),
  );

  const top = `  ┌${'─'.repeat(contentWidth + 2)}┐`;
  const header = `  │ ${styled(title.padEnd(contentWidth, ' '), chalk.white.bold)} │`;
  const divider = `  ├${'─'.repeat(contentWidth + 2)}┤`;
  const body = rows.map((row) => `  │ ${row.padEnd(contentWidth, ' ')} │`);
  const bottom = `  └${'─'.repeat(contentWidth + 2)}┘`;

  const lines = [top, header, divider, ...body, bottom];
  for (const line of lines) {
    console.log(isTTY() ? styled(line, chalk.dim) : line);
  }
}

/**
 * Print scan target
 */
export function printScanTarget(targetPath: string): void {
  // Show relative path or just filename
  const display = targetPath.startsWith('/') ? path.relative(process.cwd(), targetPath) : targetPath;
  console.log();
  console.log(`  Scanning  ${display}`);
}

/**
 * Print summary counts line
 */
export function printSummaryCounts(report: AnalysisReport): void {
  console.log();
  console.log(`  ${styled(DIVIDER, chalk.dim)}`);

  const { findingsBySeverity } = report;
  const parts: string[] = [];

  if (findingsBySeverity.critical > 0) {
    parts.push(styled(String(findingsBySeverity.critical), chalk.bold) + styled(' critical', chalk.dim));
  }
  if (findingsBySeverity.warning > 0) {
    parts.push(styled(String(findingsBySeverity.warning), chalk.bold) + styled(' warning', chalk.dim));
  }
  if (findingsBySeverity.info > 0) {
    parts.push(styled(String(findingsBySeverity.info), chalk.bold) + styled(' info', chalk.dim));
  }

  if (parts.length === 0) {
    console.log(`  ${styled('No findings reported.', chalk.green)}`);
  } else {
    console.log(`  ${parts.join(styled('  ·  ', chalk.dim))}`);
  }

  console.log(`  ${styled(`${report.totalCEEs} cees detected`, chalk.dim)}`);

  console.log(`  ${styled(DIVIDER, chalk.dim)}`);
}

/**
 * Format a single finding
 */
export function formatFinding(finding: AFBFinding): string {
  const filename = path.basename(finding.file);
  const col = finding.column || 0;
  const location = `${styled(filename, chalk.white.bold)}${styled(`:${finding.line}:${col}`, chalk.dim)}`;
  const snippet = formatSnippet(finding.codeSnippet);
  const description = getDescription(finding);
  const detailLines: string[] = [];

  if (finding.context?.toolFile && finding.context?.toolLine) {
    detailLines.push(`tool: ${finding.context.toolFile}:${finding.context.toolLine}`);
  }

  if (finding.context?.involvesCrossFile) {
    detailLines.push('path: cross-file');
  }

  if (finding.context?.depthLimitHit) {
    detailLines.push('trace: depth limit hit');
  }

  if (finding.context?.unresolvedCalls && finding.context.unresolvedCalls.length > 0) {
    detailLines.push(`unresolved: ${finding.context.unresolvedCalls.slice(0, 3).join(', ')}`);
  }

  const lines = [
    `  ${formatSeverityLabel(finding.severity)} ${location}`,
    `    ${styled(snippet, chalk.white)}`,
    `    ${styled(description, chalk.gray)}`,
  ];

  for (const detailLine of detailLines) {
    lines.push(`    ${styled(detailLine, chalk.dim)}`);
  }

  return lines.join('\n');
}

/**
 * Print all findings
 */
export function printFindings(findings: AFBFinding[], level: Severity = Severity.INFO): void {
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.WARNING]: 1,
    [Severity.INFO]: 2,
    [Severity.SUPPRESSED]: 3,
  };

  const filtered = findings.filter(f => severityOrder[f.severity] <= severityOrder[level]);

  if (filtered.length === 0) {
    return;
  }

  console.log();
  for (let i = 0; i < filtered.length; i++) {
    console.log(formatFinding(filtered[i]));
    if (i < filtered.length - 1) {
      console.log(); // Blank line between findings
    }
  }
}

function getCoverageNotes(report: AnalysisReport): string[] {
  const notes: string[] = [];
  const failedFiles = report.metadata.failedFiles;
  const skippedFiles = report.metadata.skippedFiles;

  if (failedFiles.length > 0) {
    const label = failedFiles.length === 1 ? 'file' : 'files';
    notes.push(`Failed to analyze ${failedFiles.length} ${label}. Exit code reflects scan failure.`);
  }

  if (skippedFiles.length > 0) {
    const skippedLanguages = Array.from(new Set(skippedFiles.map((file) => file.language))).sort();
    const label = skippedFiles.length === 1 ? 'file' : 'files';
    notes.push(`Skipped ${skippedFiles.length} unsupported ${label}: ${skippedLanguages.join(', ')}.`);
  }

  return notes;
}

/**
 * Print footer with file count and timing
 */
export function printFooter(report: AnalysisReport): void {
  const { filesAnalyzed, metadata } = report;
  const runtimeSec = (metadata.totalTimeMs / 1000).toFixed(1);
  const fileCount = filesAnalyzed.length;
  const fileLabel = fileCount === 1 ? 'file' : 'files';

  console.log();
  console.log(`  ${styled(DIVIDER, chalk.dim)}`);
  console.log(`  ${styled(`${fileCount} ${fileLabel}  ·  ${runtimeSec}s`, chalk.dim)}`);

  for (const note of getCoverageNotes(report)) {
    console.log(`  ${styled(note, chalk.dim)}`);
  }
}

function formatCEE(cee: CEERecord): string {
  const filename = path.basename(cee.file);
  const classification = cee.afbType || 'unclassified';
  const lines = [
    `  ${styled('○', chalk.dim)} ${styled(classification, chalk.dim)} ${styled(filename, chalk.white.bold)}${styled(`:${cee.line}:${cee.column || 0}`, chalk.dim)}`,
    `    ${styled(formatSnippet(cee.codeSnippet), chalk.white)}`,
    `    ${styled(cee.classificationNote, chalk.gray)}`,
  ];

  return lines.join('\n');
}

export function printUnclassifiedCEEs(report: AnalysisReport): void {
  const unclassified = report.cees.filter((cee) => cee.afbType === null);

  if (unclassified.length === 0) {
    return;
  }

  console.log();
  console.log(`  ${styled('Unclassified CEEs', chalk.white.bold)}`);
  console.log(`  ${styled(DIVIDER, chalk.dim)}`);

  for (let i = 0; i < unclassified.length; i++) {
    console.log(formatCEE(unclassified[i]));
    if (i < unclassified.length - 1) {
      console.log();
    }
  }
}

/**
 * Print one-line summary (for --summary flag)
 */
export function printOneLiner(report: AnalysisReport): void {
  const { findingsBySeverity, filesAnalyzed, metadata } = report;
  const runtimeSec = (metadata.totalTimeMs / 1000).toFixed(1);

  const parts: string[] = [];

  if (findingsBySeverity.critical > 0) {
    parts.push(`${findingsBySeverity.critical} critical`);
  }
  if (findingsBySeverity.warning > 0) {
    parts.push(`${findingsBySeverity.warning} warning`);
  }
  if (findingsBySeverity.info > 0) {
    parts.push(`${findingsBySeverity.info} info`);
  }

  const fileCount = filesAnalyzed.length;
  const fileLabel = fileCount === 1 ? 'file' : 'files';

  if (metadata.failedFiles.length > 0) {
    parts.push(`${metadata.failedFiles.length} failed`);
  }

  if (metadata.skippedFiles.length > 0) {
    parts.push(`${metadata.skippedFiles.length} skipped`);
  }

  parts.push(`${report.totalCEEs} cees`);

  const hasReportedFindings = findingsBySeverity.critical > 0 || findingsBySeverity.warning > 0 || findingsBySeverity.info > 0;

  if (!hasReportedFindings) {
    console.log(`0 findings  ·  ${parts.join('  ·  ')}  ·  ${fileCount} ${fileLabel}  ·  ${runtimeSec}s`);
  } else {
    console.log(`${parts.join('  ·  ')}  ·  ${fileCount} ${fileLabel}  ·  ${runtimeSec}s`);
  }
}

/**
 * Print error to stderr
 */
export function printError(message: string, detail?: string): void {
  console.error(`  ${styled('error', chalk.red.bold)}  ${message}`);
  if (detail) {
    console.error(`         ${styled(detail, chalk.dim)}`);
  }
}

/**
 * Print check status line
 */
export function printCheckStatus(name: string, ok: boolean, detail?: string): void {
  const status = ok
    ? styled('✓', chalk.green)
    : styled('✗', chalk.red);
  const nameFormatted = name.padEnd(25);
  const detailStr = detail ? styled(` ${detail}`, chalk.dim) : '';
  console.log(`  ${status} ${nameFormatted}${detailStr}`);
}

/**
 * Zero findings output
 */
export function printZeroFindings(report: AnalysisReport, targetPath: string, message: string = 'No findings reported.'): void {
  printHeader();
  printScanTarget(targetPath);
  console.log();
  console.log(`  ${styled(DIVIDER, chalk.dim)}`);
  console.log(`  ${styled(message, chalk.green)}`);
  if (report.totalCEEs > 0) {
    console.log(`  ${styled(`${report.totalCEEs} cees detected in the analyzed path set.`, chalk.dim)}`);
  }
  printUnclassifiedCEEs(report);
  printFooter(report);
}
