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

interface CoverageDiagnostics {
  unresolvedCallEdges?: number;
  depthLimitedExposedPaths?: number;
  parseFailedFiles?: Array<{ file: string; error: string }>;
  uniqueEntrypointsWithExposure?: number;
}

function readCoverageDiagnostics(raw: Record<string, unknown> | undefined): CoverageDiagnostics | null {
  if (!raw) return null;
  return {
    unresolvedCallEdges: typeof raw.unresolvedCallEdges === 'number' ? raw.unresolvedCallEdges : undefined,
    depthLimitedExposedPaths: typeof raw.depthLimitedExposedPaths === 'number' ? raw.depthLimitedExposedPaths : undefined,
    parseFailedFiles: Array.isArray(raw.parseFailedFiles) ? raw.parseFailedFiles as Array<{ file: string; error: string }> : undefined,
    uniqueEntrypointsWithExposure: typeof raw.uniqueEntrypointsWithExposure === 'number' ? raw.uniqueEntrypointsWithExposure : undefined,
  };
}

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
    'install : wyscan install',
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

export interface InstallDashboardRow {
  step: string;
  status: 'ok' | 'fail';
  detail: string;
}

export function printInstallDashboard(rows: InstallDashboardRow[]): void {
  const title = 'WYSCAN INSTALL DASHBOARD';
  const formattedRows = rows.map((row) => {
    const mark = row.status === 'ok' ? '✔' : '✖';
    return `${mark} ${row.step}  ·  ${row.detail}`;
  });
  const footer = 'Next: wyscan scan <path>  |  wyscan help';
  const contentWidth = Math.max(title.length, footer.length, ...formattedRows.map((row) => row.length));

  const top = `  ┌${'─'.repeat(contentWidth + 2)}┐`;
  const header = `  │ ${styled(title.padEnd(contentWidth, ' '), chalk.white.bold)} │`;
  const divider = `  ├${'─'.repeat(contentWidth + 2)}┤`;
  const body = formattedRows.map((row) => `  │ ${row.padEnd(contentWidth, ' ')} │`);
  const endDivider = `  ├${'─'.repeat(contentWidth + 2)}┤`;
  const foot = `  │ ${styled(footer.padEnd(contentWidth, ' '), chalk.dim)} │`;
  const bottom = `  └${'─'.repeat(contentWidth + 2)}┘`;

  const lines = [top, header, divider, ...body, endDivider, foot, bottom];
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
  const diagnostics = readCoverageDiagnostics(report.metadata.coverageDiagnostics);

  if (failedFiles.length > 0) {
    const label = failedFiles.length === 1 ? 'file' : 'files';
    notes.push(`Failed to analyze ${failedFiles.length} ${label}. Exit code reflects scan failure.`);
  }

  if (skippedFiles.length > 0) {
    const skippedLanguages = Array.from(new Set(skippedFiles.map((file) => file.language))).sort();
    const label = skippedFiles.length === 1 ? 'file' : 'files';
    notes.push(`Skipped ${skippedFiles.length} unsupported ${label}: ${skippedLanguages.join(', ')}.`);
  }

  if (diagnostics) {
    const unresolvedEdges = diagnostics.unresolvedCallEdges || 0;
    const depthLimited = diagnostics.depthLimitedExposedPaths || 0;
    const parseFailed = diagnostics.parseFailedFiles?.length || 0;
    const uniqueEntrypoints = diagnostics.uniqueEntrypointsWithExposure || 0;

    if (uniqueEntrypoints > 0) {
      notes.push(`Unique entrypoints reaching sensitive operations: ${uniqueEntrypoints}.`);
    }
    if (unresolvedEdges > 0) {
      notes.push(`Coverage gap: ${unresolvedEdges} unresolved call edge(s) in call graph.`);
    }
    if (depthLimited > 0) {
      notes.push(`Coverage gap: ${depthLimited} exposed path(s) hit traversal depth budget.`);
    }
    if (parseFailed > 0) {
      notes.push(`Coverage gap: ${parseFailed} TypeScript/JavaScript parse failure(s).`);
    }
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

// ─── Analysis Dashboard ────────────────────────────────────────────────────

function bar(fraction: number, width = 20): string {
  const filled = Math.round(fraction * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function pct(n: number, total: number): string {
  if (total === 0) return '  0%';
  return `${Math.round((n / total) * 100).toString().padStart(3)}%`;
}

function dashPanel(title: string, lines: string[], width = 55): string[] {
  const top    = `  ┌─ ${title} ${'─'.repeat(Math.max(0, width - title.length - 4))}┐`;
  const body   = lines.map(l => `  │ ${l.padEnd(width - 2)} │`);
  const bottom = `  └${'─'.repeat(width)}┘`;
  return [top, ...body, bottom];
}

/**
 * Print a rich evaluation dashboard for analysis, policy writing, and reporting.
 * Shows: overview metrics, severity breakdown, framework & operation distribution,
 * tool risk matrix, policy coverage, and unique operation signatures.
 */
export function printAnalysisDashboard(report: AnalysisReport, targetPath: string): void {
  const W = 55;

  // ── header ────────────────────────────────────────────
  console.log();
  console.log(`  ${styled('wyscan', chalk.white)} v${VERSION}  ·  Plarix Security`);
  console.log(`  ${styled('EVALUATION DASHBOARD', chalk.white.bold)}`);
  console.log(`  ${styled('─'.repeat(W), chalk.dim)}`);
  console.log(`  ${styled('Target:', chalk.dim)} ${path.resolve(targetPath)}`);
  const ts = report.metadata?.timestamp ? new Date(report.metadata.timestamp).toLocaleString() : '';
  if (ts) console.log(`  ${styled('Scanned:', chalk.dim)} ${ts}`);
  console.log();

  const allCEEs    = report.cees ?? [];
  const findings   = report.findings ?? [];
  const totalCEEs  = allCEEs.length;
  const totalFiles = report.filesAnalyzed?.length ?? 0;
  const runtimeMs  = report.metadata?.totalTimeMs ?? 0;
  const gatePresent  = allCEEs.filter(c => c.gateStatus === 'present').length;
  const gateAbsent   = allCEEs.filter(c => c.gateStatus === 'absent').length;
  const policyRate   = totalCEEs > 0 ? Math.round((gatePresent / totalCEEs) * 100) : 0;

  // ── overview ──────────────────────────────────────────
  const overviewLines = [
    `Total CEEs      : ${styled(String(totalCEEs).padStart(5), chalk.white.bold)}   Files analyzed : ${String(totalFiles).padStart(5)}`,
    `Total findings  : ${styled(String(findings.length).padStart(5), chalk.white.bold)}   Runtime        : ${(runtimeMs / 1000).toFixed(2).padStart(5)}s`,
    `Gate-covered    : ${styled(String(gatePresent).padStart(5), chalk.green)}   Policy coverage: ${String(policyRate).padStart(4)}%`,
    `Ungated (AFB04) : ${styled(String(gateAbsent).padStart(5), chalk.red)}   Policies needed: ~${String(new Set(allCEEs.filter(c => c.gateStatus === 'absent').map(c => c.operation)).size).padStart(3)}`,
  ];
  for (const line of dashPanel('OVERVIEW', overviewLines, W)) console.log(styled(line, chalk.dim) || line);
  console.log();

  // ── severity breakdown ────────────────────────────────
  const sevCounts = {
    critical:   findings.filter(f => f.severity === Severity.CRITICAL).length,
    warning:    findings.filter(f => f.severity === Severity.WARNING).length,
    info:       findings.filter(f => f.severity === Severity.INFO).length,
    suppressed: findings.filter(f => f.severity === Severity.SUPPRESSED).length,
  };
  const sevTotal = findings.length || 1;
  const sevLines = [
    `${styled('● CRITICAL ', chalk.red.bold)}  ${String(sevCounts.critical).padStart(4)}  ${pct(sevCounts.critical, sevTotal)}  ${bar(sevCounts.critical / sevTotal)}`,
    `${styled('● WARNING  ', chalk.yellow.bold)}  ${String(sevCounts.warning).padStart(4)}  ${pct(sevCounts.warning, sevTotal)}  ${bar(sevCounts.warning / sevTotal)}`,
    `${styled('● INFO     ', chalk.cyan)}  ${String(sevCounts.info).padStart(4)}  ${pct(sevCounts.info, sevTotal)}  ${bar(sevCounts.info / sevTotal)}`,
    `${styled('○ SUPPRESSED', chalk.dim)}  ${String(sevCounts.suppressed).padStart(4)}  ${pct(sevCounts.suppressed, sevTotal)}`,
  ];
  for (const line of dashPanel('SEVERITY BREAKDOWN', sevLines, W)) console.log(line);
  console.log();

  // ── framework breakdown ───────────────────────────────
  const fwCounts = new Map<string, number>();
  for (const cee of allCEEs) {
    const fw = cee.framework || 'generic';
    fwCounts.set(fw, (fwCounts.get(fw) ?? 0) + 1);
  }
  const fwSorted = [...fwCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const fwLines = fwSorted.length > 0
    ? fwSorted.map(([fw, cnt]) => `${fw.padEnd(18)} ${String(cnt).padStart(4)} CEEs  ${pct(cnt, totalCEEs || 1)}  ${bar(cnt / (totalCEEs || 1), 12)}`)
    : ['  (no CEEs detected)'];
  for (const line of dashPanel('BY FRAMEWORK', fwLines, W)) console.log(line);
  console.log();

  // ── operation category breakdown ─────────────────────
  const catCounts = new Map<string, number>();
  for (const cee of allCEEs) {
    const cat = cee.category ?? 'unknown';
    catCounts.set(cat, (catCounts.get(cat) ?? 0) + 1);
  }
  const catSorted = [...catCounts.entries()].sort((a, b) => b[1] - a[1]);
  const catLines = catSorted.length > 0
    ? catSorted.map(([cat, cnt]) => `${cat.padEnd(22)} ${String(cnt).padStart(4)}  ${pct(cnt, totalCEEs || 1)}  ${bar(cnt / (totalCEEs || 1), 10)}`)
    : ['  (no CEEs detected)'];
  for (const line of dashPanel('BY OPERATION CATEGORY', catLines, W)) console.log(line);
  console.log();

  // ── tool risk matrix ──────────────────────────────────
  interface ToolRisk { count: number; maxSev: string; ops: Set<string>; }
  const toolRisk = new Map<string, ToolRisk>();
  const sevOrder: Record<string, number> = { critical: 0, warning: 1, info: 2, suppressed: 3 };
  for (const cee of allCEEs.filter(c => c.gateStatus === 'absent')) {
    const entry = toolRisk.get(cee.tool) ?? { count: 0, maxSev: 'suppressed', ops: new Set<string>() };
    entry.count++;
    entry.ops.add(cee.operation);
    if ((sevOrder[cee.severity] ?? 3) < (sevOrder[entry.maxSev] ?? 3)) entry.maxSev = cee.severity;
    toolRisk.set(cee.tool, entry);
  }
  const riskSorted = [...toolRisk.entries()].sort((a, b) => {
    const sd = (sevOrder[a[1].maxSev] ?? 3) - (sevOrder[b[1].maxSev] ?? 3);
    return sd !== 0 ? sd : b[1].count - a[1].count;
  }).slice(0, 10);
  const riskHeader = `${'Tool'.padEnd(22)} ${'Sev'.padEnd(9)} CEEs  Top operation`;
  const riskDivider = '─'.repeat(W - 2);
  const riskRows = riskSorted.map(([tool, info]) => {
    const sevLabel = info.maxSev.toUpperCase().slice(0, 4);
    const topOp = [...info.ops][0]?.slice(0, 18) ?? '';
    return `${tool.slice(0, 21).padEnd(22)} ${sevLabel.padEnd(9)} ${String(info.count).padStart(4)}  ${topOp}`;
  });
  const riskLines = riskSorted.length > 0
    ? [riskHeader, riskDivider, ...riskRows]
    : ['  (no ungated tool paths detected)'];
  for (const line of dashPanel('TOOL RISK MATRIX (ungated paths)', riskLines, W)) console.log(line);
  console.log();

  // ── policy coverage ───────────────────────────────────
  const uniqueUngatedOps = new Set(allCEEs.filter(c => c.gateStatus === 'absent').map(c => c.operation));
  const coverageLines = [
    `Gate present : ${String(gatePresent).padStart(4)} CEEs  ${bar(gatePresent / (totalCEEs || 1), 18)}  ${pct(gatePresent, totalCEEs || 1)}`,
    `Gate absent  : ${styled(String(gateAbsent).padStart(4), chalk.red)} CEEs  ${bar(gateAbsent / (totalCEEs || 1), 18)}  ${pct(gateAbsent, totalCEEs || 1)}`,
    ``,
    `Unique ungated operation signatures : ${styled(String(uniqueUngatedOps.size), chalk.yellow.bold)}`,
    `Recommended policies to write       : ~${String(uniqueUngatedOps.size)}`,
    ``,
    ...([...uniqueUngatedOps].slice(0, 8).map(op => `  · ${op.slice(0, W - 6)}`)),
    ...(uniqueUngatedOps.size > 8 ? [`  · ... and ${uniqueUngatedOps.size - 8} more`] : []),
  ];
  for (const line of dashPanel('POLICY COVERAGE', coverageLines, W)) console.log(line);
  console.log();

  // ── unique cee signatures (for analysis) ─────────────
  type SigKey = string;
  const uniqueSigs = new Map<SigKey, { count: number; severity: string; framework: string; files: Set<string> }>();
  for (const cee of allCEEs) {
    const key = `${cee.tool}::${cee.operation}::${cee.category}::${cee.gateStatus}`;
    const entry = uniqueSigs.get(key) ?? { count: 0, severity: cee.severity, framework: cee.framework ?? 'generic', files: new Set() };
    entry.count++;
    entry.files.add(cee.file);
    if ((sevOrder[cee.severity] ?? 3) < (sevOrder[entry.severity] ?? 3)) entry.severity = cee.severity;
    uniqueSigs.set(key, entry);
  }
  const sigCount = uniqueSigs.size;
  const sigLines = [
    `Total CEE instances         : ${styled(String(totalCEEs), chalk.white.bold)}`,
    `Unique CEE signatures       : ${styled(String(sigCount), chalk.white.bold)}  (tool × op × category × gate)`,
    `Deduplication ratio         : ${totalCEEs > 0 ? (totalCEEs / sigCount).toFixed(1) : '1.0'}x`,
    ``,
    `Use --json to export all CEEs for deeper analysis.`,
    `Each CEE carries: call path · gate status · evidence · resource`,
  ];
  for (const line of dashPanel('CEE SIGNATURE ANALYSIS', sigLines, W)) console.log(line);
  console.log();

  // ── footer ────────────────────────────────────────────
  console.log(`  ${styled('─'.repeat(W), chalk.dim)}`);
  console.log(`  ${styled('Export full data:', chalk.dim)} wyscan scan <path> --json`);
  console.log(`  ${styled('Filter by severity:', chalk.dim)} wyscan scan <path> --level critical`);
  console.log(`  ${styled('plarix.dev', chalk.dim)}`);
  console.log();
}
