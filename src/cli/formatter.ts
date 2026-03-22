/**
 * Terminal Output Formatter
 *
 * Professional security tool output formatting.
 * Reference: nmap, nuclei, semgrep style.
 * No emoji. No ASCII art boxes. Clean and dense.
 */

import { AFBFinding, AnalysisReport, Severity, ExecutionCategory } from '../types';
import { VERSION, NAME, AUTHOR, REPO } from './version';

/**
 * ANSI color codes
 */
const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
};

/**
 * Check if stdout is a TTY (supports colors)
 */
export function isTTY(): boolean {
  return process.stdout.isTTY === true;
}

/**
 * Apply color if TTY, otherwise return plain text
 */
function color(text: string, ...codes: string[]): string {
  if (!isTTY()) return text;
  return codes.join('') + text + COLORS.reset;
}

/**
 * Get severity color
 */
function severityColor(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return COLORS.bold + COLORS.red;
    case Severity.WARNING:
      return COLORS.bold + COLORS.yellow;
    case Severity.INFO:
      return COLORS.cyan;
    default:
      return '';
  }
}

/**
 * Format severity label with padding
 */
function formatSeverity(severity: Severity): string {
  const label = severity.toUpperCase().padEnd(8);
  return color(label, severityColor(severity));
}

/**
 * Category to action description
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
  const snippet = finding.codeSnippet.toLowerCase();
  switch (finding.category) {
    case ExecutionCategory.SHELL_EXECUTION:
      return 'shell/execute capability';
    case ExecutionCategory.FILE_OPERATION:
      if (snippet.includes('remove') || snippet.includes('delete') || snippet.includes('unlink') || snippet.includes('rmtree')) {
        return 'delete capability';
      }
      if (snippet.includes('write')) {
        return 'write capability';
      }
      return 'file access capability';
    case ExecutionCategory.API_CALL:
      if (snippet.includes('post') || snippet.includes('put') || snippet.includes('patch') || snippet.includes('delete')) {
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
 * Wrap text at specified width
 */
function wrapText(text: string, width: number, indent: string = ''): string {
  const words = text.split(' ');
  const lines: string[] = [];
  let currentLine = '';

  for (const word of words) {
    if (currentLine.length + word.length + 1 > width) {
      lines.push(currentLine);
      currentLine = word;
    } else {
      currentLine = currentLine ? currentLine + ' ' + word : word;
    }
  }
  if (currentLine) lines.push(currentLine);

  return lines.join('\n' + indent);
}

/**
 * Print CLI header
 */
export function printHeader(): void {
  console.log();
  console.log(color(`${NAME}`, COLORS.bold) + `  v${VERSION}  by ${AUTHOR}`);
  console.log(color(`AFB Scanner`, COLORS.dim) + color(` \u2014 ${REPO}`, COLORS.dim));
  console.log();
}

/**
 * Print scan start info
 */
export function printScanStart(targetPath: string): void {
  console.log(`Scanning: ${targetPath}`);
  console.log('\u2500'.repeat(50));
  console.log();
}

/**
 * Format a single finding for terminal output
 */
export function formatFinding(finding: AFBFinding): string {
  const funcName = finding.context?.enclosingFunction || finding.codeSnippet.split('(')[0].trim();
  const toolReg = finding.context?.isToolDefinition ? ` reachable from @tool` : '';
  const framework = finding.context?.framework ? ` (${finding.context.framework})` : '';
  const gateStatus = finding.context?.isToolDefinition
    ? ', no policy gate in call path'
    : '';

  const lines: string[] = [];

  // Severity + file:line
  const location = color(`${finding.file}:${finding.line}`, COLORS.white);
  lines.push(`${formatSeverity(finding.severity)}${location}`);

  // Code snippet and explanation
  const snippet = finding.codeSnippet.length > 60
    ? finding.codeSnippet.slice(0, 60) + '...'
    : finding.codeSnippet;
  const action = CATEGORY_ACTION[finding.category] || 'operation';
  const capability = getCapabilityDescription(finding);

  const description = `${snippet} \u2014 ${action}${toolReg}${framework}${gateStatus}.`;
  lines.push(wrapText(description, 72, '         '));

  // AFB explanation
  if (finding.context?.isToolDefinition) {
    lines.push(color('Agent can execute this without authorization basis.', COLORS.dim));
  }

  return lines.join('\n');
}

/**
 * Print findings grouped by severity
 */
export function printFindings(findings: AFBFinding[], level: Severity = Severity.INFO): void {
  // Filter by level
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.WARNING]: 1,
    [Severity.INFO]: 2,
    [Severity.SUPPRESSED]: 3,
  };

  const filtered = findings.filter(f => severityOrder[f.severity] <= severityOrder[level]);

  for (const finding of filtered) {
    console.log(formatFinding(finding));
    console.log();
  }
}

/**
 * Print summary line
 */
export function printSummary(report: AnalysisReport): void {
  const { findingsBySeverity, filesAnalyzed, metadata } = report;
  const runtimeSec = (metadata.totalTimeMs / 1000).toFixed(1);

  console.log('\u2500'.repeat(50));

  if (report.totalFindings === 0) {
    console.log(color('No AFB exposures detected.', COLORS.green) +
      color(`  ${filesAnalyzed.length} files  ${runtimeSec}s`, COLORS.dim));
    return;
  }

  const parts: string[] = [];

  if (findingsBySeverity.critical > 0) {
    parts.push(color(String(findingsBySeverity.critical), COLORS.bold + COLORS.red) +
      color(' critical', COLORS.dim));
  }
  if (findingsBySeverity.warning > 0) {
    parts.push(color(String(findingsBySeverity.warning), COLORS.bold + COLORS.yellow) +
      color(' warning', COLORS.dim));
  }
  if (findingsBySeverity.info > 0) {
    parts.push(color(String(findingsBySeverity.info), COLORS.bold) +
      color(' info', COLORS.dim));
  }
  if (findingsBySeverity.suppressed > 0) {
    parts.push(color(`(${findingsBySeverity.suppressed} suppressed)`, COLORS.dim));
  }

  parts.push(color(`${filesAnalyzed.length} files`, COLORS.dim));
  parts.push(color(`${runtimeSec}s`, COLORS.dim));

  console.log(parts.join('  '));
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

  if (parts.length === 0) {
    console.log(`0 findings  ${filesAnalyzed.length} files  ${runtimeSec}s`);
  } else {
    console.log(`${parts.join('  ')}  ${filesAnalyzed.length} files  ${runtimeSec}s`);
  }
}

/**
 * Print error to stderr
 */
export function printError(message: string, detail?: string): void {
  console.error(`error: ${message}`);
  if (detail) {
    console.error(`       ${detail}`);
  }
}

/**
 * Print check status line
 */
export function printCheckStatus(name: string, ok: boolean, detail?: string): void {
  const status = ok
    ? color('\u2713', COLORS.green)
    : color('\u2717', COLORS.red);
  const nameFormatted = name.padEnd(25);
  const detailStr = detail ? color(` ${detail}`, COLORS.dim) : '';
  console.log(`  ${status} ${nameFormatted}${detailStr}`);
}
