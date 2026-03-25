#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { AFBAnalyzer } from './analyzer';
import { generatePRComment, generateJSONReport, generateTerminalReport } from './reporter/pr-comment';
import { Severity } from './types';
import { VERSION } from './cli/version';

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Handle help
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
AFB Scanner - Agent Failure Boundary detection through static analysis

Usage: afb-scanner [path] [options]

Arguments:
  path          Path to analyze (file or directory). Default: current directory

Options:
  --json        Output JSON report
  --markdown    Output markdown report (PR comment format)
  --confidence  Minimum confidence threshold (0.0-1.0). Default: 0.7
  --help        Show this help message

Examples:
  afb-scanner ./my-agent-project
  afb-scanner ./tools.py --json
  afb-scanner . --markdown
`);
    process.exit(0);
  }

  const targetPath = path.resolve(args.find(a => !a.startsWith('--')) || '.');

  if (!fs.existsSync(targetPath)) {
    console.error(`Error: Path does not exist: ${targetPath}`);
    process.exit(1);
  }

  const analyzer = new AFBAnalyzer();
  await analyzer.ensureInitialized();

  const stat = fs.statSync(targetPath);
  let report;

  if (stat.isFile()) {
    const result = analyzer.analyzeFile(targetPath);
    // Count findings by severity
    const findingsBySeverity = {
      critical: result.findings.filter(f => f.severity === Severity.CRITICAL).length,
      warning: result.findings.filter(f => f.severity === Severity.WARNING).length,
      info: result.findings.filter(f => f.severity === Severity.INFO).length,
      suppressed: result.findings.filter(f => f.severity === Severity.SUPPRESSED).length,
    };
    report = {
      repository: path.basename(path.dirname(targetPath)),
      filesAnalyzed: [result.file],
      totalFindings: result.findings.length,
      findingsBySeverity,
      findings: result.findings,
      metadata: {
        scannerVersion: VERSION,
        timestamp: new Date().toISOString(),
        totalTimeMs: result.analysisTimeMs,
        failedFiles: result.success ? [] : [result.file],
      },
    };
  } else {
    report = analyzer.analyzeDirectory(targetPath);
  }

  if (args.includes('--json')) {
    console.log(generateJSONReport(report));
  } else if (args.includes('--markdown') || args.includes('--md')) {
    console.log(generatePRComment(report));
  } else {
    console.log(generateTerminalReport(report));
  }

  process.exit(report.findingsBySeverity.critical > 0 ? 2 : report.findingsBySeverity.warning > 0 ? 1 : 0);
}

main().catch(error => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
