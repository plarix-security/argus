#!/usr/bin/env node
/**
 * AFB Scanner CLI
 *
 * Command-line interface for running AFB analysis locally.
 * Useful for testing and CI/CD integration without the GitHub App.
 *
 * Usage:
 *   npx ts-node src/cli.ts <directory>
 *   npx ts-node src/cli.ts <directory> --json
 *   npx ts-node src/cli.ts <directory> --files file1.py file2.ts
 */

import * as fs from "fs";
import * as path from "path";
import { analyzeDirectory, analyzeSpecificFiles, SCANNER_VERSION } from "./analyzer";
import { generatePRComment, generateJSONReport, generateStatusSummary } from "./reporter/pr-comment";
import { Severity } from "./types";

/** CLI arguments */
interface CLIArgs {
  directory: string;
  jsonOutput: boolean;
  markdownOutput: boolean;
  files?: string[];
  minConfidence: number;
  help: boolean;
}

/** Parse command line arguments */
function parseArgs(): CLIArgs {
  const args = process.argv.slice(2);

  const result: CLIArgs = {
    directory: ".",
    jsonOutput: false,
    markdownOutput: false,
    minConfidence: 0.5,
    help: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === "--help" || arg === "-h") {
      result.help = true;
    } else if (arg === "--json" || arg === "-j") {
      result.jsonOutput = true;
    } else if (arg === "--markdown" || arg === "-m") {
      result.markdownOutput = true;
    } else if (arg === "--files" || arg === "-f") {
      result.files = [];
      i++;
      while (i < args.length && !args[i].startsWith("-")) {
        result.files.push(args[i]);
        i++;
      }
      continue;
    } else if (arg === "--confidence" || arg === "-c") {
      i++;
      result.minConfidence = parseFloat(args[i]) || 0.5;
    } else if (!arg.startsWith("-")) {
      result.directory = arg;
    }

    i++;
  }

  return result;
}

/** Print help message */
function printHelp(): void {
  console.log(`
AFB Scanner v${SCANNER_VERSION}
Detects AFB04 (Unauthorized Action) boundaries in agent codebases.

USAGE:
  afb-scanner [OPTIONS] <DIRECTORY>

OPTIONS:
  -h, --help              Show this help message
  -j, --json              Output results as JSON
  -m, --markdown          Output results as Markdown (PR comment format)
  -f, --files <FILES>     Analyze specific files only
  -c, --confidence <NUM>  Minimum confidence threshold (0.0-1.0, default: 0.5)

EXAMPLES:
  # Analyze current directory
  afb-scanner .

  # Analyze with JSON output
  afb-scanner ./my-agent-project --json

  # Analyze specific files
  afb-scanner ./project --files tools.py agent.ts

  # Analyze with higher confidence threshold
  afb-scanner ./project --confidence 0.8

OUTPUT:
  By default, outputs a human-readable summary to stdout.
  Use --json for machine-parseable output.
  Use --markdown for PR comment format.

WHAT IT DETECTS:
  AFB04 (Unauthorized Action) boundaries:
  - Agent tool definitions (LangChain, CrewAI, custom)
  - Shell command execution (subprocess, os.system, child_process)
  - File system operations (open, write, delete)
  - External API calls (requests, fetch, axios)
  - Database operations (cursor.execute, Prisma, SQLAlchemy)
  - Dynamic code execution (eval, exec)

For more information: https://github.com/plarix-security/afb-spec
`);
}

/** Format findings for console output */
function formatConsoleOutput(report: ReturnType<typeof analyzeDirectory>): string {
  const { findings, findingsBySeverity, totalFindings, filesAnalyzed, metadata } = report;

  if (totalFindings === 0) {
    return `
AFB Scanner v${SCANNER_VERSION}
===================================

\u2705 No AFB04 boundaries detected.

Files analyzed: ${filesAnalyzed.length}
Analysis time: ${metadata.totalTimeMs}ms
`;
  }

  // Sort by severity
  const sortedFindings = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2 };
    return order[a.severity] - order[b.severity];
  });

  let output = `
AFB Scanner v${SCANNER_VERSION}
===================================

\u26A0\uFE0F  ${totalFindings} AFB04 ${totalFindings === 1 ? "boundary" : "boundaries"} detected.

Summary:
  Critical: ${findingsBySeverity.critical}
  High:     ${findingsBySeverity.high}
  Medium:   ${findingsBySeverity.medium}

Findings:
`;

  for (const finding of sortedFindings) {
    const severityIcon =
      finding.severity === Severity.CRITICAL
        ? "\u26A0\uFE0F"
        : finding.severity === Severity.HIGH
        ? "\uD83D\uDD34"
        : "\uD83D\uDFE1";

    const toolContext = finding.context?.isToolDefinition
      ? " [TOOL]"
      : "";

    output += `
${severityIcon} ${finding.severity.toUpperCase()}${toolContext}
   File: ${finding.file}:${finding.line}
   Category: ${finding.category}
   Operation: ${finding.operation}
   Code: ${finding.codeSnippet.slice(0, 60)}${finding.codeSnippet.length > 60 ? "..." : ""}
`;
  }

  output += `
---
Files analyzed: ${filesAnalyzed.length}
Analysis time: ${metadata.totalTimeMs}ms
${metadata.failedFiles.length > 0 ? `Failed files: ${metadata.failedFiles.length}` : ""}
`;

  return output;
}

/** Main CLI function */
async function main(): Promise<void> {
  const args = parseArgs();

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  // Resolve directory path
  const directory = path.resolve(args.directory);

  // Validate directory exists
  if (!fs.existsSync(directory)) {
    console.error(`Error: Directory not found: ${directory}`);
    process.exit(1);
  }

  if (!fs.statSync(directory).isDirectory()) {
    console.error(`Error: Not a directory: ${directory}`);
    process.exit(1);
  }

  console.error(`[AFB Scanner] Analyzing: ${directory}`);

  // Run analysis
  let report;
  if (args.files && args.files.length > 0) {
    report = analyzeSpecificFiles(directory, args.files, {
      minConfidence: args.minConfidence,
    });
  } else {
    report = analyzeDirectory(directory, {
      minConfidence: args.minConfidence,
    });
  }

  // Output results
  if (args.jsonOutput) {
    console.log(generateJSONReport(report));
  } else if (args.markdownOutput) {
    console.log(generatePRComment(report));
  } else {
    console.log(formatConsoleOutput(report));
  }

  // Exit with non-zero if critical findings
  if (report.findingsBySeverity.critical > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Error:", error.message);
  process.exit(1);
});
