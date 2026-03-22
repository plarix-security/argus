#!/usr/bin/env node
/**
 * Argus CLI
 *
 * Command-line interface for the AFB Scanner.
 * Wraps the existing scanner engine used by the GitHub App.
 *
 * Commands:
 *   argus scan <path>     Scan a directory or file for AFB exposures
 *   argus check           Verify dependencies are working
 *   argus version         Print version and exit
 *   argus help            Print usage information
 *
 * Exit codes:
 *   0  No critical or warning findings
 *   1  Warning level findings detected
 *   2  Critical level findings detected
 *   3  Scanner error (parse failure, missing dependency)
 */

import * as fs from 'fs';
import * as path from 'path';
import { AFBAnalyzer } from '../analyzer';
import { AnalysisReport, Severity } from '../types';
import { VERSION, NAME, AUTHOR, REPO } from './version';
import {
  printHeader,
  printScanStart,
  printFindings,
  printSummary,
  printOneLiner,
  printError,
  printCheckStatus,
  isTTY,
} from './formatter';

/**
 * Exit codes
 */
const EXIT_CODES = {
  CLEAN: 0,
  WARNING: 1,
  CRITICAL: 2,
  ERROR: 3,
};

/**
 * Parse severity level from string
 */
function parseSeverityLevel(level: string): Severity | null {
  const lower = level.toLowerCase();
  if (lower === 'critical') return Severity.CRITICAL;
  if (lower === 'warning') return Severity.WARNING;
  if (lower === 'info') return Severity.INFO;
  return null;
}

/**
 * Generate JSON report with stable schema
 */
function generateJSONOutput(report: AnalysisReport, scannedPath: string): string {
  const output = {
    version: VERSION,
    scanned_path: scannedPath,
    files_analyzed: report.filesAnalyzed.length,
    runtime_ms: report.metadata.totalTimeMs,
    findings: report.findings.map(f => ({
      severity: f.severity.toUpperCase(),
      file: f.file,
      line: f.line,
      function: f.codeSnippet.split('(')[0].trim(),
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
 * Print help message
 */
function printHelp(): void {
  console.log(`
${NAME} - AFB Scanner for agentic AI codebases

USAGE
  ${NAME} scan <path> [options]    Scan a directory or file
  ${NAME} check                    Verify dependencies
  ${NAME} version                  Print version
  ${NAME} help                     Print this help

SCAN OPTIONS
  --json                Output as JSON (stable schema for CI)
  --level <level>       Filter by severity: critical, warning, info
  --output <file>       Write report to file instead of stdout
  --summary             One-line output only (for CI pipelines)

EXIT CODES
  0    No critical or warning findings
  1    Warning level findings detected
  2    Critical level findings detected
  3    Scanner error (parse failure, missing dependency)

EXAMPLES
  ${NAME} scan ./my-agent-project
  ${NAME} scan ./tools.py --json
  ${NAME} scan ./project --level warning
  ${NAME} scan ./project --json --output report.json
  ${NAME} scan ./project --summary

JSON SCHEMA
  {
    "version": "0.1.0",
    "scanned_path": "/path/to/repo",
    "files_analyzed": 34,
    "runtime_ms": 1200,
    "findings": [
      {
        "severity": "CRITICAL",
        "file": "path/to/file.py",
        "line": 47,
        "function": "shutil.rmtree",
        "tool_registration": "setup_agent",
        "description": "...",
        "afb_type": "AFB04"
      }
    ],
    "summary": {
      "critical": 2,
      "warning": 3,
      "info": 5,
      "suppressed": 10
    }
  }

More info: ${REPO}
`);
}

/**
 * Print version
 */
function printVersion(): void {
  console.log(`${NAME} ${VERSION}`);
}

/**
 * Check dependencies
 */
async function runCheck(): Promise<number> {
  printHeader();
  console.log('Checking dependencies...');
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
  printCheckStatus('tree-sitter-python.wasm', pythonWasmExists,
    pythonWasmExists ? 'found' : 'missing');
  if (!pythonWasmExists) allOk = false;

  // Try to initialize the analyzer
  try {
    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    printCheckStatus('Parser initialization', true, 'ok');
  } catch (err) {
    printCheckStatus('Parser initialization', false,
      err instanceof Error ? err.message : 'failed');
    allOk = false;
  }

  console.log();
  if (allOk) {
    console.log('All checks passed. Ready to scan.');
    return EXIT_CODES.CLEAN;
  } else {
    console.log('Some checks failed. See above for details.');
    return EXIT_CODES.ERROR;
  }
}

/**
 * Run scan command
 */
async function runScan(args: string[]): Promise<number> {
  // Parse arguments
  const targetArg = args.find(a => !a.startsWith('--'));
  const jsonOutput = args.includes('--json');
  const summaryOnly = args.includes('--summary');

  // Parse --level flag
  const levelIdx = args.indexOf('--level');
  let level = Severity.INFO;
  if (levelIdx !== -1 && args[levelIdx + 1]) {
    const parsed = parseSeverityLevel(args[levelIdx + 1]);
    if (!parsed) {
      printError(`invalid level: ${args[levelIdx + 1]}`, 'use: critical, warning, or info');
      return EXIT_CODES.ERROR;
    }
    level = parsed;
  }

  // Parse --output flag
  const outputIdx = args.indexOf('--output');
  let outputFile: string | null = null;
  if (outputIdx !== -1 && args[outputIdx + 1]) {
    outputFile = args[outputIdx + 1];
  }

  // Resolve target path
  const targetPath = path.resolve(targetArg || '.');

  if (!fs.existsSync(targetPath)) {
    printError(`path does not exist: ${targetPath}`);
    return EXIT_CODES.ERROR;
  }

  // Initialize analyzer
  let analyzer: AFBAnalyzer;
  try {
    analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
  } catch (err) {
    printError('failed to initialize scanner',
      err instanceof Error ? err.message : 'unknown error');
    return EXIT_CODES.ERROR;
  }

  // Run scan
  let report: AnalysisReport;
  const stat = fs.statSync(targetPath);

  try {
    if (stat.isFile()) {
      const result = analyzer.analyzeFile(targetPath);
      report = {
        repository: path.basename(path.dirname(targetPath)),
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
        printError(`failed to parse: ${result.file}`, result.error);
        return EXIT_CODES.ERROR;
      }
    } else {
      report = analyzer.analyzeDirectory(targetPath);
    }
  } catch (err) {
    printError('scan failed',
      err instanceof Error ? err.message : 'unknown error');
    return EXIT_CODES.ERROR;
  }

  // Filter findings by level
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.WARNING]: 1,
    [Severity.INFO]: 2,
    [Severity.SUPPRESSED]: 3,
  };
  const filteredFindings = report.findings.filter(
    f => severityOrder[f.severity] <= severityOrder[level]
  );
  const filteredReport = {
    ...report,
    findings: filteredFindings,
    totalFindings: filteredFindings.length,
  };

  // Generate and output results
  if (jsonOutput) {
    const output = generateJSONOutput(filteredReport, targetPath);
    if (outputFile) {
      try {
        fs.writeFileSync(outputFile, output + '\n');
      } catch (err) {
        printError(`failed to write output file: ${outputFile}`,
          err instanceof Error ? err.message : 'unknown error');
        return EXIT_CODES.ERROR;
      }
    } else {
      console.log(output);
    }
  } else if (summaryOnly) {
    // Summary only - one line
    const parts: string[] = [];
    if (report.findingsBySeverity.critical > 0) {
      parts.push(`${report.findingsBySeverity.critical} critical`);
    }
    if (report.findingsBySeverity.warning > 0) {
      parts.push(`${report.findingsBySeverity.warning} warning`);
    }
    if (report.findingsBySeverity.info > 0) {
      parts.push(`${report.findingsBySeverity.info} info`);
    }
    const runtimeSec = (report.metadata.totalTimeMs / 1000).toFixed(1);
    let output: string;
    if (parts.length === 0) {
      output = `0 findings  ${report.filesAnalyzed.length} files  ${runtimeSec}s`;
    } else {
      output = `${parts.join('  ')}  ${report.filesAnalyzed.length} files  ${runtimeSec}s`;
    }
    if (outputFile) {
      try {
        fs.writeFileSync(outputFile, output + '\n');
      } catch (err) {
        printError(`failed to write output file: ${outputFile}`,
          err instanceof Error ? err.message : 'unknown error');
        return EXIT_CODES.ERROR;
      }
    } else {
      console.log(output);
    }
  } else {
    // Full terminal output - print directly or capture for file
    if (outputFile) {
      // Capture output for file
      const originalLog = console.log;
      const captured: string[] = [];
      console.log = (...args) => captured.push(args.join(' '));

      printHeader();
      printScanStart(targetPath);
      printFindings(filteredFindings, level);
      printSummary(report);

      console.log = originalLog;
      try {
        fs.writeFileSync(outputFile, captured.join('\n') + '\n');
      } catch (err) {
        printError(`failed to write output file: ${outputFile}`,
          err instanceof Error ? err.message : 'unknown error');
        return EXIT_CODES.ERROR;
      }
    } else {
      // Print directly to console
      printHeader();
      printScanStart(targetPath);
      printFindings(filteredFindings, level);
      printSummary(report);
    }
  }

  // Determine exit code based on unfiltered findings
  if (report.findingsBySeverity.critical > 0) {
    return EXIT_CODES.CRITICAL;
  }
  if (report.findingsBySeverity.warning > 0) {
    return EXIT_CODES.WARNING;
  }
  return EXIT_CODES.CLEAN;
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // No arguments - show help
  if (args.length === 0) {
    printHelp();
    process.exit(EXIT_CODES.CLEAN);
  }

  const command = args[0];

  // Handle commands
  if (command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    process.exit(EXIT_CODES.CLEAN);
  }

  if (command === 'version' || command === '--version' || command === '-v') {
    printVersion();
    process.exit(EXIT_CODES.CLEAN);
  }

  if (command === 'check') {
    const exitCode = await runCheck();
    process.exit(exitCode);
  }

  if (command === 'scan') {
    const exitCode = await runScan(args.slice(1));
    process.exit(exitCode);
  }

  // Legacy: treat first arg as path if it looks like a path
  if (command.startsWith('.') || command.startsWith('/') || fs.existsSync(command)) {
    const exitCode = await runScan(args);
    process.exit(exitCode);
  }

  // Unknown command
  printError(`unknown command: ${command}`, 'run "argus help" for usage');
  process.exit(EXIT_CODES.ERROR);
}

main().catch(err => {
  printError(err.message);
  process.exit(EXIT_CODES.ERROR);
});
