#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { AFBAnalyzer } from './analyzer';
import { generatePRComment, generateJSONReport } from './reporter/pr-comment';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const targetPath = path.resolve(args[0] || '.');
  
  if (!fs.existsSync(targetPath)) {
    console.error(`Error: Path does not exist: ${targetPath}`);
    process.exit(1);
  }

  const analyzer = new AFBAnalyzer();
  await analyzer.ensureInitialized();

  const stat = fs.statSync(targetPath);
  const report = stat.isFile() ? 
    (() => { const r = analyzer.analyzeFile(targetPath); return { repository: '.', filesAnalyzed: [r.file], totalFindings: r.findings.length, findingsBySeverity: { critical: 0, high: 0, medium: 0 }, findings: r.findings, metadata: { scannerVersion: '0.1.0', timestamp: new Date().toISOString(), totalTimeMs: r.analysisTimeMs, failedFiles: [] } }; })() :
    analyzer.analyzeDirectory(targetPath);

  if (args.includes('--json')) {
    console.log(generateJSONReport(report));
  } else if (args.includes('--markdown') || args.includes('--md')) {
    console.log(generatePRComment(report));
  } else {
    console.log(`\n🛡️  AFB Scanner Report\n${'='.repeat(50)}\n`);
    if (report.totalFindings === 0) {
      console.log(`✓ No AFB04 execution points detected`);
      console.log(`  Files analyzed: ${report.filesAnalyzed.length}\n`);
    } else {
      console.log(`Total findings: ${report.totalFindings}`);
      console.log(`  Critical: ${report.findingsBySeverity.critical}`);
      console.log(`  High: ${report.findingsBySeverity.high}`);
      console.log(`  Medium: ${report.findingsBySeverity.medium}\n`);
      for (const finding of report.findings.slice(0, 10)) {
        console.log(`${finding.severity.toUpperCase()} - ${finding.file}:${finding.line}`);
        console.log(`  ${finding.operation}`);
        console.log(`  ${finding.codeSnippet}\n`);
      }
      if (report.totalFindings > 10) console.log(`... and ${report.totalFindings - 10} more`);
    }
  }

  process.exit(report.findingsBySeverity.critical > 0 ? 2 : report.findingsBySeverity.high > 0 ? 1 : 0);
}

main().catch(error => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
