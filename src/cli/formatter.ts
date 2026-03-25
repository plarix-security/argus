/**
 * Terminal Output Formatter
 *
 * Clean, professional security tool output.
 * Uses chalk for colors, strips when not TTY.
 */

import chalk from 'chalk';
import * as path from 'path';
import { AFBFinding, AnalysisReport, Severity, ExecutionCategory } from '../types';
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
 * Get specific description for a finding based on category and severity
 */
function getDescription(finding: AFBFinding): string {
  const snippet = finding.codeSnippet.toLowerCase();

  // CRITICAL operations
  if (finding.severity === Severity.CRITICAL) {
    if (finding.category === ExecutionCategory.SHELL_EXECUTION) {
      return 'Shell command execution. No policy gate in call path.';
    }
    if (finding.category === ExecutionCategory.CODE_EXECUTION) {
      if (snippet.includes('eval')) {
        return 'Arbitrary code execution via eval(). No policy gate in call path.';
      }
      return 'Dynamic code execution. No policy gate in call path.';
    }
    if (finding.category === ExecutionCategory.FILE_OPERATION) {
      if (snippet.includes('rmtree') || snippet.includes('remove') || snippet.includes('unlink')) {
        return 'Recursive directory deletion. No policy gate in call path.';
      }
    }
  }

  // WARNING operations
  if (finding.severity === Severity.WARNING) {
    if (finding.category === ExecutionCategory.FILE_OPERATION) {
      if (snippet.includes('write')) {
        return 'File write operation. No policy gate in call path.';
      }
      if (snippet.includes('mkdir')) {
        return 'Directory creation. No policy gate in call path.';
      }
      if (snippet.includes('copy') || snippet.includes('move')) {
        return 'File copy/move operation. No policy gate in call path.';
      }
      return 'File system modification. No policy gate in call path.';
    }
    if (finding.category === ExecutionCategory.API_CALL) {
      if (snippet.includes('post')) {
        return 'HTTP POST to external endpoint. No policy gate in call path.';
      }
      if (snippet.includes('put') || snippet.includes('patch')) {
        return 'HTTP mutation to external endpoint. No policy gate in call path.';
      }
      if (snippet.includes('delete')) {
        return 'HTTP DELETE to external endpoint. No policy gate in call path.';
      }
      return 'External API mutation. No policy gate in call path.';
    }
    if (finding.category === ExecutionCategory.DATABASE_OPERATION) {
      return 'Database write operation. No policy gate in call path.';
    }
  }

  // INFO operations
  if (finding.severity === Severity.INFO) {
    if (finding.category === ExecutionCategory.API_CALL) {
      return 'External HTTP read. No policy gate in call path.';
    }
    if (finding.category === ExecutionCategory.DATABASE_OPERATION) {
      if (snippet.includes('execute')) {
        return 'Database query execution. No policy gate in call path.';
      }
      return 'Database read operation. No policy gate in call path.';
    }
    if (finding.category === ExecutionCategory.FILE_OPERATION) {
      if (snippet.includes('read') || snippet.includes('open')) {
        return 'File read operation. No policy gate in call path.';
      }
      if (snippet.includes('listdir') || snippet.includes('glob')) {
        return 'Directory listing. No policy gate in call path.';
      }
      return 'File system access. No policy gate in call path.';
    }
  }

  // Default
  return 'Operation reachable from tool. No policy gate in call path.';
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
    console.log(`  ${styled('No AFB exposures detected.', chalk.green)}`);
  } else {
    console.log(`  ${parts.join(styled('  ·  ', chalk.dim))}`);
  }

  console.log(`  ${styled(DIVIDER, chalk.dim)}`);
}

/**
 * Format a single finding
 */
export function formatFinding(finding: AFBFinding): string {
  const filename = path.basename(finding.file);
  const location = `${styled(filename, chalk.white.bold)}${styled(`:${finding.line}`, chalk.dim)}`;
  const snippet = formatSnippet(finding.codeSnippet);
  const description = getDescription(finding);

  const lines = [
    `  ${formatSeverityLabel(finding.severity)} ${location}`,
    `    ${styled(snippet, chalk.white)}`,
    `    ${styled(description, chalk.dim)}`,
  ];

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
  console.log(`  ${styled(`${fileCount} ${fileLabel}  ·  ${runtimeSec}s  ·  AFB04 coverage only`, chalk.dim)}`);
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

  if (parts.length === 0) {
    console.log(`0 findings  ·  ${fileCount} ${fileLabel}  ·  ${runtimeSec}s`);
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
 * Full scan output
 */
export function printScanReport(report: AnalysisReport, targetPath: string, level: Severity): void {
  printHeader();
  printScanTarget(targetPath);
  printSummaryCounts(report);
  printFindings(report.findings, level);
  printFooter(report);
}

/**
 * Zero findings output
 */
export function printZeroFindings(report: AnalysisReport, targetPath: string): void {
  printHeader();
  printScanTarget(targetPath);
  console.log();
  console.log(`  ${styled(DIVIDER, chalk.dim)}`);
  console.log(`  ${styled('No AFB exposures detected.', chalk.green)}`);
  printFooter(report);
}
