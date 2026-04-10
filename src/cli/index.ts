#!/usr/bin/env node
/**
 * WyScan CLI
 *
 * Command-line interface for the AFB Scanner.
 * Wraps the existing scanner engine used by the GitHub App.
 *
 * Commands:
 *   wyscan scan <path> [flags]   Scan for AFB exposures
 *   wyscan check                 Verify dependencies
 *   wyscan install               Install/build/link/check local CLI
 *   wyscan tui                   Show compact command panel
 *   wyscan version               Print version
 *   wyscan help [command]        Show usage
 *
 * Exit codes:
 *   0  No critical or warning findings
 *   1  Warning findings detected
 *   2  Critical findings detected
 *   3  Scanner or dependency error
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { AFBAnalyzer } from '../analyzer';
import { AnalysisReport, Severity } from '../types';
import { VERSION, NAME } from './version';
import { buildMethodologyDisclosure } from './methodology-disclosure';
import {
  printHeader,
  printScanTarget,
  printSummaryCounts,
  printFindings,
  printUnclassifiedCEEs,
  printFooter,
  printOneLiner,
  printError,
  printCheckStatus,
  printZeroFindings,
  printTuiQuickPanel,
  printInstallDashboard,
  isTTY,
} from './formatter';

/**
 * Exit codes
 */
const EXIT = {
  CLEAN: 0,
  WARNING: 1,
  CRITICAL: 2,
  ERROR: 3,
};

function resolveCliProjectRoot(): string {
  const candidates = [
    path.resolve(__dirname, '../..'),
    process.cwd(),
  ];

  for (const candidate of candidates) {
    const pkgPath = path.join(candidate, 'package.json');
    if (!fs.existsSync(pkgPath)) {
      continue;
    }
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as { name?: string };
      if (pkg.name === NAME) {
        return candidate;
      }
    } catch {
      continue;
    }
  }

  return process.cwd();
}

/**
 * Scan options
 */
interface ScanOptions {
  level: Severity;
  output: string | null;
  json: boolean;
  summary: boolean;
  quiet: boolean;
  debug: boolean;
}

/**
 * Parse severity level from string
 */
function parseSeverity(level: string): Severity | null {
  const l = level.toLowerCase();
  if (l === 'critical') return Severity.CRITICAL;
  if (l === 'warning') return Severity.WARNING;
  if (l === 'info') return Severity.INFO;
  return null;
}

/**
 * Parse command line flags
 */
function parseFlags(args: string[]): { targetPath: string | null; options: ScanOptions; error: string | null } {
  const options: ScanOptions = {
    level: Severity.INFO,
    output: null,
    json: false,
    summary: false,
    quiet: false,
    debug: false,
  };

  let targetPath: string | null = null;
  let i = 0;

  while (i < args.length) {
    const arg = args[i];

    // Boolean flags
    if (arg === '-j' || arg === '--json') {
      options.json = true;
      i++;
      continue;
    }
    if (arg === '-s' || arg === '--summary') {
      options.summary = true;
      i++;
      continue;
    }
    if (arg === '-q' || arg === '--quiet') {
      options.quiet = true;
      i++;
      continue;
    }
    if (arg === '-d' || arg === '--debug') {
      options.debug = true;
      i++;
      continue;
    }

    // Flags with values
    if (arg === '-l' || arg === '--level') {
      if (!args[i + 1] || args[i + 1].startsWith('-')) {
        return { targetPath: null, options, error: `Missing value for ${arg}. Use: --level critical, --level warning, or --level info` };
      }
      const level = parseSeverity(args[i + 1]);
      if (!level) {
        return { targetPath: null, options, error: `"${args[i + 1]}" is not a valid level. Choose from: critical, warning, info` };
      }
      options.level = level;
      i += 2;
      continue;
    }
    if (arg === '-o' || arg === '--output') {
      if (!args[i + 1] || args[i + 1].startsWith('-')) {
        return { targetPath: null, options, error: `Missing value for ${arg}. Provide an output filename.` };
      }
      options.output = args[i + 1];
      i += 2;
      continue;
    }

    // Unknown flag
    if (arg.startsWith('-')) {
      return { targetPath: null, options, error: `Unknown flag "${arg}". Run "wyscan help" for available options.` };
    }

    // Positional argument (path)
    if (!targetPath) {
      targetPath = arg;
    }
    i++;
  }

  return { targetPath, options, error: null };
}

/**
 * Generate JSON report
 */
function generateJSON(report: AnalysisReport, scannedPath: string): string {
  const pythonFiles = report.filesAnalyzed.filter(f => f.endsWith('.py')).length;
  const tsJsFiles = report.filesAnalyzed.filter(f => f.endsWith('.ts') || f.endsWith('.tsx') || f.endsWith('.js') || f.endsWith('.jsx')).length;
  const skippedFiles = report.metadata.skippedFiles;
  const skippedLanguages = Array.from(new Set(skippedFiles.map((file) => file.language))).sort();

  const frameworks = new Set<string>();
  for (const finding of report.findings) {
    if (finding.context?.framework) {
      frameworks.add(finding.context.framework);
    }
  }
  for (const cee of report.cees) {
    if (cee.framework) {
      frameworks.add(cee.framework);
    }
  }

  const output = {
    version: VERSION,
    scanned_path: scannedPath,
    files_analyzed: report.filesAnalyzed.length,
    runtime_ms: report.metadata.totalTimeMs,
    total_cees: report.totalCEEs,
    findings: report.findings.map(f => ({
      severity: f.severity.toUpperCase(),
      file: f.file,
      line: f.line,
      column: f.column || 0,
      operation: f.operation || f.codeSnippet.split('(')[0].trim(),
      tool: f.context?.toolName || f.context?.enclosingFunction || null,
      framework: f.context?.framework || null,
      tool_file: f.context?.toolFile || null,
      tool_line: f.context?.toolLine || null,
      call_path: f.context?.callPath || [],
      involves_cross_file: f.context?.involvesCrossFile || false,
      unresolved_calls: f.context?.unresolvedCalls || [],
      depth_limit_hit: f.context?.depthLimitHit || false,
      evidence_kind: f.context?.evidenceKind || null,
      supporting_evidence: f.context?.supportingEvidence || [],
      resource: f.context?.resource || null,
      changes_state: f.context?.changesState || false,
      description: f.explanation,
      code_snippet: f.codeSnippet,
      category: f.category,
    })),
    cees: report.cees.map((cee) => ({
      severity: cee.severity.toUpperCase(),
      file: cee.file,
      line: cee.line,
      column: cee.column || 0,
      operation: cee.operation,
      tool: cee.tool,
      framework: cee.framework || null,
      tool_file: cee.toolFile || null,
      tool_line: cee.toolLine || null,
      call_path: cee.callPath,
      gate_status: cee.gateStatus,
      afb_type: cee.afbType,
      classification_note: cee.classificationNote,
      involves_cross_file: cee.involvesCrossFile || false,
      unresolved_calls: cee.unresolvedCalls || [],
      depth_limit_hit: cee.depthLimitHit || false,
      evidence_kind: cee.evidenceKind || null,
      supporting_evidence: cee.supportingEvidence || [],
      resource: cee.resource || null,
      changes_state: cee.changesState || false,
      code_snippet: cee.codeSnippet,
      category: cee.category,
    })),
    summary: {
      cees: report.totalCEEs,
      critical: report.findingsBySeverity.critical,
      warning: report.findingsBySeverity.warning,
      info: report.findingsBySeverity.info,
      suppressed: report.findingsBySeverity.suppressed,
    },
    coverage: {
      languages_scanned: [...(pythonFiles > 0 ? ['python'] : []), ...(tsJsFiles > 0 ? ['typescript', 'javascript'] : [])].sort(),
      languages_skipped: skippedLanguages,
      frameworks_detected: Array.from(frameworks).sort(),
      files_analyzed: report.filesAnalyzed.length,
      files_skipped: skippedFiles.length,
      failed_files: report.metadata.failedFiles,
      skipped_files: skippedFiles,
      partial: skippedFiles.length > 0 || report.metadata.failedFiles.length > 0,
      total_files_discovered: report.metadata.totalFilesDiscovered || report.filesAnalyzed.length,
      file_limit: report.metadata.fileLimit || null,
      file_limit_hit: report.metadata.fileLimitHit || false,
      limitations: [
        'The analyzed file set is graphed together per language. Changed-file scans do not guarantee full repository coverage.',
      ],
      coverage_gap_report: report.metadata.coverageDiagnostics || null,
    },
    methodology: buildMethodologyDisclosure(report),
  };
  return JSON.stringify(output, null, 2);
}

function countFindingsBySeverity(report: AnalysisReport): AnalysisReport['findingsBySeverity'] {
  return {
    critical: report.findings.filter((finding) => finding.severity === Severity.CRITICAL).length,
    warning: report.findings.filter((finding) => finding.severity === Severity.WARNING).length,
    info: report.findings.filter((finding) => finding.severity === Severity.INFO).length,
    suppressed: report.findings.filter((finding) => finding.severity === Severity.SUPPRESSED).length,
  };
}

function filterReportByLevel(report: AnalysisReport, level: Severity): AnalysisReport {
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.WARNING]: 1,
    [Severity.INFO]: 2,
    [Severity.SUPPRESSED]: 3,
  };
  const filteredFindings = report.findings.filter((finding) => severityOrder[finding.severity] <= severityOrder[level]);

  return {
    ...report,
    findings: filteredFindings,
    totalFindings: filteredFindings.length,
    findingsBySeverity: countFindingsBySeverity({ ...report, findings: filteredFindings } as AnalysisReport),
  };
}

function captureConsoleOutput(run: () => void): string {
  const origTTY = process.stdout.isTTY;
  Object.defineProperty(process.stdout, 'isTTY', { value: false, writable: true });

  const captured: string[] = [];
  const origLog = console.log;
  console.log = (...args) => captured.push(args.join(' '));

  try {
    run();
  } finally {
    console.log = origLog;
    Object.defineProperty(process.stdout, 'isTTY', { value: origTTY, writable: true });
  }

  return captured.join('\n') + '\n';
}

/**
 * Print help
 */
function printHelp(command?: string): void {
  if (command === 'tui') {
    printTuiQuickPanel();
    return;
  }

  if (command === 'scan') {
    console.log(`
  ${NAME} scan <path> [options]

  Find dangerous operations in AI agent tools.

  Options:
    -l, --level <level>   Show only findings at this level or higher
                          Values: critical, warning, info (default: info)
    -j, --json            Output as JSON
    -o, --output <file>   Write output to file
    -s, --summary         Show counts only, no details
    -q, --quiet           No output, exit code only
    -d, --debug           Show debug information

  Examples:
    ${NAME} scan .                        Scan current directory
    ${NAME} scan ./agent.py               Scan single file
    ${NAME} scan . -l critical            Only critical findings
    ${NAME} scan . -j -o report.json      Save JSON report
`);
    return;
  }

  console.log(`
  ${NAME} v${VERSION}

  Static analyzer for AFB04 (Unauthorized Action) vulnerabilities
  in agentic AI systems. Detects dangerous operations reachable
  from tool registration points through multi-file call graphs.

  Languages: Python, TypeScript/JavaScript (framework-core structural detection)

  Usage:
    ${NAME} install         Install/build/link/check local CLI
    ${NAME} scan <path>     Scan a file or directory
    ${NAME} check           Verify scanner dependencies
    ${NAME} tui             Show compact command panel
    ${NAME} help [command]  Show help

  Supported frameworks:
    Python: LangChain, LangGraph, CrewAI, AutoGen, Smolagents,
            OpenAI Assistants, and decorator-based tool registrations

  Options:
    -l, --level <level>   Filter by severity (critical|warning|info)
    -j, --json            JSON output format
    -o, --output <file>   Write to file
    -s, --summary         Counts only
    -q, --quiet           Exit code only
    -d, --debug           Show thrown errors on failure

  Exit codes:
    0 = No issues    1 = Warnings    2 = Critical    3 = Error

  Examples:
    ${NAME} install
    ${NAME} scan .
    ${NAME} scan ./agents -l critical
    ${NAME} scan . -j > report.json
`);
  console.log();
  printTuiQuickPanel();
}

/**
 * Print version
 */
function printVersion(): void {
  console.log(`${NAME} ${VERSION}`);
}

/**
 * Run check command
 */
async function runCheck(): Promise<number> {
  printHeader();
  console.log();
  console.log('  Checking dependencies...');
  console.log();

  let allOk = true;

  // Check Node.js version
  const nodeVersion = process.version;
  const nodeMajor = parseInt(nodeVersion.slice(1).split('.')[0], 10);
  const nodeOk = nodeMajor >= 18;
  printCheckStatus('Node.js', nodeOk, nodeVersion);
  if (!nodeOk) allOk = false;

  // Check tree-sitter WASM files
  const wasmDir = path.join(__dirname, '../../wasm');
  const pythonWasm = path.join(wasmDir, 'tree-sitter-python.wasm');
  const pythonWasmExists = fs.existsSync(pythonWasm);
  printCheckStatus('tree-sitter-python.wasm', pythonWasmExists, pythonWasmExists ? 'found' : 'missing');
  if (!pythonWasmExists) allOk = false;

  // Try to initialize the analyzer
  try {
    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    printCheckStatus('Parser initialization', true, 'ok');
  } catch (err) {
    printCheckStatus('Parser initialization', false, err instanceof Error ? err.message : 'failed');
    allOk = false;
  }

  console.log();
  if (allOk) {
    console.log('  All checks passed. Ready to scan.');
  } else {
    console.log('  Some checks failed. See above for details.');
  }
  console.log();

  return allOk ? EXIT.CLEAN : EXIT.ERROR;
}

/**
 * Run install command
 */
async function runInstall(): Promise<number> {
  printHeader();
  console.log();
  console.log('  Preparing local CLI installation...');
  console.log();

  const projectRoot = resolveCliProjectRoot();

  const steps = [
    { step: 'npm install', cmd: 'npm', args: ['install'] },
    { step: 'npm run build', cmd: 'npm', args: ['run', 'build'] },
    { step: 'npm link', cmd: 'npm', args: ['link'] },
  ];
  const rows: Array<{ step: string; status: 'ok' | 'fail'; detail: string }> = [];

  for (const s of steps) {
    const result = spawnSync(s.cmd, s.args, {
      cwd: projectRoot,
      encoding: 'utf-8',
      stdio: 'pipe',
    });
    if (result.status === 0) {
      rows.push({ step: s.step, status: 'ok', detail: 'ok' });
      continue;
    }

    const detail = (result.stderr || result.stdout || 'failed')
      .trim()
      .split('\n')
      .slice(-1)[0]
      .slice(0, 120);
    rows.push({ step: s.step, status: 'fail', detail });
    printInstallDashboard(rows);
    return EXIT.ERROR;
  }

  let checkCode = EXIT.CLEAN;
  try {
    const nodeMajor = parseInt(process.version.slice(1).split('.')[0], 10);
    if (nodeMajor < 18) {
      checkCode = EXIT.ERROR;
    } else {
      const analyzer = new AFBAnalyzer();
      await analyzer.ensureInitialized();
    }
  } catch {
    checkCode = EXIT.ERROR;
  }

  rows.push({
    step: 'wyscan check',
    status: checkCode === EXIT.CLEAN ? 'ok' : 'fail',
    detail: checkCode === EXIT.CLEAN ? 'ready' : 'dependency check failed',
  });
  printInstallDashboard(rows);
  return checkCode === EXIT.CLEAN ? EXIT.CLEAN : EXIT.ERROR;
}

/**
 * Run scan command
 */
async function runScan(args: string[]): Promise<number> {
  const { targetPath, options, error } = parseFlags(args);

  if (error) {
    printError(error);
    console.error();
    console.error('  Run "wyscan help scan" for usage.');
    return EXIT.ERROR;
  }

  const resolvedPath = path.resolve(targetPath || '.');

  if (!fs.existsSync(resolvedPath)) {
    printError(`Path not found: ${resolvedPath}`);
    return EXIT.ERROR;
  }

  // Initialize analyzer
  let analyzer: AFBAnalyzer;
  try {
    analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
  } catch (err) {
    if (options.debug) {
      console.error(err);
    }
    printError('Scanner initialization failed. Run "wyscan check" to diagnose.', err instanceof Error ? err.message : undefined);
    return EXIT.ERROR;
  }

  // Run scan
  let report: AnalysisReport;
  const stat = fs.statSync(resolvedPath);

  try {
    if (stat.isFile()) {
      const result = analyzer.analyzeFile(resolvedPath);
      report = {
        repository: path.basename(path.dirname(resolvedPath)),
        filesAnalyzed: result.success ? [result.file] : [],
        totalFindings: result.findings.length,
        totalCEEs: (result.cees || []).length,
        findingsBySeverity: {
          critical: result.findings.filter(f => f.severity === Severity.CRITICAL).length,
          warning: result.findings.filter(f => f.severity === Severity.WARNING).length,
          info: result.findings.filter(f => f.severity === Severity.INFO).length,
          suppressed: result.findings.filter(f => f.severity === Severity.SUPPRESSED).length,
        },
        findings: result.findings,
        cees: result.cees || [],
        metadata: {
          scannerVersion: VERSION,
          timestamp: new Date().toISOString(),
          totalTimeMs: result.analysisTimeMs,
          failedFiles: result.success ? [] : [result.file],
          skippedFiles: result.skipped ? [{
            file: result.file,
            language: result.language,
            reason: result.skipReason || 'File skipped.',
          }] : [],
          fileLimitHit: false,
          fileLimit: undefined,
          totalFilesDiscovered: 1,
        },
      };

      if (!result.success) {
        printError(`could not parse ${path.basename(result.file)}`, result.error);
        return EXIT.ERROR;
      }
    } else {
      report = analyzer.analyzeDirectory(resolvedPath);
    }
  } catch (err) {
    if (options.debug) {
      console.error(err);
    }
    printError('Scan failed', err instanceof Error ? err.message : undefined);
    return EXIT.ERROR;
  }

  const filteredReport = filterReportByLevel(report, options.level);
  const zeroMessage = report.totalFindings > 0 && filteredReport.totalFindings === 0
    ? `No findings reported at level ${options.level}.`
    : 'No findings reported.';

  if (options.quiet) {
  } else if (options.json) {
    const json = generateJSON(filteredReport, resolvedPath);
    if (options.output) {
      fs.writeFileSync(options.output, json + '\n');
    } else {
      console.log(json);
    }
  } else if (options.summary) {
    if (options.output) {
      fs.writeFileSync(options.output, captureConsoleOutput(() => printOneLiner(filteredReport)));
    } else {
      printOneLiner(filteredReport);
    }
  } else {
    if (options.output) {
      fs.writeFileSync(options.output, captureConsoleOutput(() => {
        if (filteredReport.totalFindings === 0) {
          printZeroFindings(filteredReport, resolvedPath, zeroMessage);
        } else {
          printHeader();
          printScanTarget(resolvedPath);
          printSummaryCounts(filteredReport);
          printFindings(filteredReport.findings, options.level);
          printUnclassifiedCEEs(filteredReport);
          printFooter(filteredReport);
        }
      }));
    } else {
      if (filteredReport.totalFindings === 0) {
        printZeroFindings(filteredReport, resolvedPath, zeroMessage);
      } else {
        printHeader();
        printScanTarget(resolvedPath);
        printSummaryCounts(filteredReport);
        printFindings(filteredReport.findings, options.level);
        printUnclassifiedCEEs(filteredReport);
        printFooter(filteredReport);
      }
    }
  }

  if (report.metadata.failedFiles.length > 0) {
    return EXIT.ERROR;
  }
  if (filteredReport.findingsBySeverity.critical > 0) {
    return EXIT.CRITICAL;
  }
  if (filteredReport.findingsBySeverity.warning > 0) {
    return EXIT.WARNING;
  }
  return EXIT.CLEAN;
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // No arguments - show help
  if (args.length === 0) {
    printHelp();
    process.exit(EXIT.CLEAN);
  }

  const command = args[0];

  // Global flags
  if (command === '-h' || command === '--help' || command === 'help') {
    printHelp(args[1]);
    process.exit(EXIT.CLEAN);
  }

  if (command === '-v' || command === '--version' || command === 'version') {
    printVersion();
    process.exit(EXIT.CLEAN);
  }

  if (command === 'tui') {
    printTuiQuickPanel();
    process.exit(EXIT.CLEAN);
  }

  // Commands
  if (command === 'check') {
    const code = await runCheck();
    process.exit(code);
  }

  if (command === 'install') {
    const code = await runInstall();
    process.exit(code);
  }

  if (command === 'scan') {
    const code = await runScan(args.slice(1));
    process.exit(code);
  }

  // Legacy: treat as path if it exists
  if (command.startsWith('.') || command.startsWith('/') || fs.existsSync(command)) {
    const code = await runScan(args);
    process.exit(code);
  }

  // Unknown command
  printError(`unknown command: ${command}`);
  console.error();
  console.error('  Run "wyscan help" for usage.');
  process.exit(EXIT.ERROR);
}

main().catch(err => {
  printError(err.message);
  process.exit(EXIT.ERROR);
});
