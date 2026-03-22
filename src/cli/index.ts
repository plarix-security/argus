#!/usr/bin/env node
/**
 * Argus CLI
 *
 * Command-line interface for the AFB Scanner.
 * Wraps the existing scanner engine used by the GitHub App.
 *
 * Commands:
 *   argus scan <path> [flags]   Scan for AFB exposures
 *   argus check                 Verify dependencies
 *   argus version               Print version
 *   argus help [command]        Show usage
 *
 * Exit codes:
 *   0  No critical or warning findings
 *   1  Warning findings detected
 *   2  Critical findings detected
 *   3  Scanner or dependency error
 */

import * as fs from 'fs';
import * as path from 'path';
import { AFBAnalyzer } from '../analyzer';
import { AnalysisReport, Severity } from '../types';
import { VERSION, NAME } from './version';
import {
  printHeader,
  printScanTarget,
  printSummaryCounts,
  printFindings,
  printFooter,
  printOneLiner,
  printError,
  printCheckStatus,
  printZeroFindings,
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

/**
 * Scan options
 */
interface ScanOptions {
  level: Severity;
  output: string | null;
  json: boolean;
  summary: boolean;
  recursive: boolean;
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
    recursive: true,
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
    if (arg === '-r' || arg === '--recursive') {
      options.recursive = true;
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
        return { targetPath: null, options, error: `${arg} requires a value (critical|warning|info)` };
      }
      const level = parseSeverity(args[i + 1]);
      if (!level) {
        return { targetPath: null, options, error: `invalid level: ${args[i + 1]} (use critical|warning|info)` };
      }
      options.level = level;
      i += 2;
      continue;
    }
    if (arg === '-o' || arg === '--output') {
      if (!args[i + 1] || args[i + 1].startsWith('-')) {
        return { targetPath: null, options, error: `${arg} requires a filename` };
      }
      options.output = args[i + 1];
      i += 2;
      continue;
    }

    // Unknown flag
    if (arg.startsWith('-')) {
      return { targetPath: null, options, error: `unknown flag: ${arg}` };
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
  const output = {
    version: VERSION,
    scanned_path: scannedPath,
    files_analyzed: report.filesAnalyzed.length,
    runtime_ms: report.metadata.totalTimeMs,
    findings: report.findings.map(f => ({
      severity: f.severity.toUpperCase(),
      file: f.file,
      line: f.line,
      function: f.codeSnippet.split('(')[0].trim().replace(/^[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*/, ''),
      tool_registration: f.context?.enclosingFunction || null,
      description: f.explanation,
      afb_type: f.type,
    })),
    summary: {
      critical: report.findingsBySeverity.critical,
      warning: report.findingsBySeverity.warning,
      info: report.findingsBySeverity.info,
      suppressed: report.findingsBySeverity.suppressed,
    },
  };
  return JSON.stringify(output, null, 2);
}

/**
 * Print help
 */
function printHelp(command?: string): void {
  if (command === 'scan') {
    console.log(`
  ${NAME} scan <path> [flags]

  Scan a file or directory for AFB exposures.

  Flags:
    -l, --level <level>   Minimum severity (critical|warning|info)
    -o, --output <file>   Write output to file
    -j, --json            JSON output
    -s, --summary         One-line summary only
    -r, --recursive       Scan recursively (default: true)
    -q, --quiet           Suppress output, exit code only
    -d, --debug           Show debug information

  Examples:
    ${NAME} scan .
    ${NAME} scan ./agent.py -l critical
    ${NAME} scan . -j -o findings.json
`);
    return;
  }

  console.log(`
  ${NAME} v${VERSION}  ·  Plarix
  AFB Scanner — Static analysis for AI agent codebases.

  Usage:
    ${NAME} scan <path> [flags]
    ${NAME} check
    ${NAME} version
    ${NAME} help [command]

  Flags:
    -l, --level <level>   Minimum severity to report
                          (critical|warning|info)
    -o, --output <file>   Write output to file
    -j, --json            JSON output
    -s, --summary         One-line summary only
    -r, --recursive       Scan recursively
    -q, --quiet           Suppress output, exit code only
    -d, --debug           Show debug information

  Exit codes:
    0   No findings at warning or critical level
    1   Warning findings detected
    2   Critical findings detected
    3   Scanner or dependency error

  Examples:
    ${NAME} scan .
    ${NAME} scan ./agent.py -l critical
    ${NAME} scan . -j -o findings.json
    ${NAME} scan . -s
    ${NAME} check
`);
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
 * Run scan command
 */
async function runScan(args: string[]): Promise<number> {
  const { targetPath, options, error } = parseFlags(args);

  if (error) {
    printError(error);
    console.error();
    console.error('  Run "argus help scan" for usage.');
    return EXIT.ERROR;
  }

  const resolvedPath = path.resolve(targetPath || '.');

  if (!fs.existsSync(resolvedPath)) {
    printError(`path does not exist: ${resolvedPath}`);
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
    printError('failed to initialize scanner', err instanceof Error ? err.message : 'unknown error');
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
        findingsBySeverity: {
          critical: result.findings.filter(f => f.severity === Severity.CRITICAL).length,
          warning: result.findings.filter(f => f.severity === Severity.WARNING).length,
          info: result.findings.filter(f => f.severity === Severity.INFO).length,
          suppressed: result.findings.filter(f => f.severity === Severity.SUPPRESSED).length,
        },
        findings: result.findings,
        metadata: {
          scannerVersion: VERSION,
          timestamp: new Date().toISOString(),
          totalTimeMs: result.analysisTimeMs,
          failedFiles: result.success ? [] : [result.file],
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
    printError('scan failed', err instanceof Error ? err.message : 'unknown error');
    return EXIT.ERROR;
  }

  // Filter findings by level
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.WARNING]: 1,
    [Severity.INFO]: 2,
    [Severity.SUPPRESSED]: 3,
  };
  const filteredFindings = report.findings.filter(f => severityOrder[f.severity] <= severityOrder[options.level]);
  const filteredReport = { ...report, findings: filteredFindings, totalFindings: filteredFindings.length };

  // Generate output
  if (options.quiet) {
    // No output, just exit code
  } else if (options.json) {
    const json = generateJSON(filteredReport, resolvedPath);
    if (options.output) {
      fs.writeFileSync(options.output, json + '\n');
    } else {
      console.log(json);
    }
  } else if (options.summary) {
    printOneLiner(report);
  } else {
    // Full terminal output
    if (options.output) {
      // Capture output for file (strip colors)
      const origTTY = process.stdout.isTTY;
      Object.defineProperty(process.stdout, 'isTTY', { value: false, writable: true });

      const captured: string[] = [];
      const origLog = console.log;
      console.log = (...a) => captured.push(a.join(' '));

      if (report.totalFindings === 0) {
        printZeroFindings(report, resolvedPath);
      } else {
        printHeader();
        printScanTarget(resolvedPath);
        printSummaryCounts(report);
        printFindings(filteredFindings, options.level);
        printFooter(report);
      }

      console.log = origLog;
      Object.defineProperty(process.stdout, 'isTTY', { value: origTTY, writable: true });

      fs.writeFileSync(options.output, captured.join('\n') + '\n');
    } else {
      // Print to console
      if (report.totalFindings === 0) {
        printZeroFindings(report, resolvedPath);
      } else {
        printHeader();
        printScanTarget(resolvedPath);
        printSummaryCounts(report);
        printFindings(filteredFindings, options.level);
        printFooter(report);
      }
    }
  }

  // Exit code based on unfiltered findings
  if (report.findingsBySeverity.critical > 0) {
    return EXIT.CRITICAL;
  }
  if (report.findingsBySeverity.warning > 0) {
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

  // Commands
  if (command === 'check') {
    const code = await runCheck();
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
  console.error('  Run "argus help" for usage.');
  process.exit(EXIT.ERROR);
}

main().catch(err => {
  printError(err.message);
  process.exit(EXIT.ERROR);
});
