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
  // Count files by language
  const pythonFiles = report.filesAnalyzed.filter(f => f.endsWith('.py')).length;
  const tsFiles = report.filesAnalyzed.filter(f => f.endsWith('.ts') || f.endsWith('.tsx')).length;
  const jsFiles = report.filesAnalyzed.filter(f => f.endsWith('.js') || f.endsWith('.jsx')).length;

  // Detect frameworks from findings
  const frameworks = new Set<string>();
  for (const finding of report.findings) {
    if (finding.context?.framework) {
      frameworks.add(finding.context.framework);
    }
  }

  const output = {
    version: VERSION,
    scanned_path: scannedPath,
    files_analyzed: report.filesAnalyzed.length,
    runtime_ms: report.metadata.totalTimeMs,
    findings: report.findings.map(f => ({
      severity: f.severity.toUpperCase(),
      file: f.file,
      line: f.line,
      column: f.column || 0,
      operation: f.operation || f.codeSnippet.split('(')[0].trim(),
      tool: f.context?.enclosingFunction || null,
      framework: f.context?.framework || null,
      description: f.explanation,
      code_snippet: f.codeSnippet,
      category: f.category,
    })),
    summary: {
      critical: report.findingsBySeverity.critical,
      warning: report.findingsBySeverity.warning,
      info: report.findingsBySeverity.info,
      suppressed: report.findingsBySeverity.suppressed,
    },
    coverage: {
      languages_scanned: ['python'],
      languages_skipped: tsFiles + jsFiles > 0 ? ['typescript', 'javascript'] : [],
      frameworks_detected: Array.from(frameworks).sort(),
      files_analyzed: pythonFiles,
      files_skipped: tsFiles + jsFiles,
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

  Find dangerous operations in AI agent tools before they reach production.
  Detects unsafe tool boundaries in LangChain, CrewAI, AutoGen, and more.

  Usage:
    ${NAME} scan <path>     Scan files for dangerous operations
    ${NAME} check           Verify scanner dependencies
    ${NAME} help [command]  Show help

  Supported frameworks:
    Python: LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex,
            smolagents, MCP servers, OpenAI function calling

  Options:
    -l, --level <level>   Filter by severity (critical|warning|info)
    -j, --json            JSON output format
    -o, --output <file>   Write to file
    -s, --summary         Counts only
    -q, --quiet           Exit code only

  Exit codes:
    0 = No issues    1 = Warnings    2 = Critical    3 = Error

  Examples:
    ${NAME} scan .
    ${NAME} scan ./agents -l critical
    ${NAME} scan . -j > report.json
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
    printError('Scan failed', err instanceof Error ? err.message : undefined);
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
  console.error('  Run "wyscan help" for usage.');
  process.exit(EXIT.ERROR);
}

main().catch(err => {
  printError(err.message);
  process.exit(EXIT.ERROR);
});
