import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as path from 'path';

async function run(): Promise<void> {
  try {
    const target = core.getInput('target') || '.';
    const mode = core.getInput('mode') || 'scan';
    const level = core.getInput('level') || 'warning';
    const failOnFindings = core.getBooleanInput('fail-on-findings');

    core.info(`Running wyscan ${mode} on ${target} (level: ${level})`);

    // The action will be bundled into action/dist/index.js, 
    // and wyscan executable is in bin/wyscan (if built) or we can use node to run src/cli/index.ts
    // In a published action, the entire repo is checked out if it's the same repo.
    // However, if users are using `uses: plarix/wyscan-action@v1`, it runs from the action's repo.
    // The wyscan script should be available relative to the action directory.
    const wyscanScript = path.resolve(__dirname, '../../dist/cli/index.js');

    let output = '';
    let errorOutput = '';

    const options: exec.ExecOptions = {
      ignoreReturnCode: true,
      listeners: {
        stdout: (data: Buffer) => {
          output += data.toString();
        },
        stderr: (data: Buffer) => {
          errorOutput += data.toString();
        }
      }
    };

    // Run wyscan and output JSON
    const args = [wyscanScript, mode, target, '--level', level, '--json'];
    const exitCode = await exec.exec('node', args, options);

    if (errorOutput && !output.trim()) {
      core.error(`Wyscan execution failed: ${errorOutput}`);
      core.setFailed(`Execution failed with code ${exitCode}`);
      return;
    }

    try {
      // Find JSON block in case there's any stray console logs
      const jsonStr = output.substring(output.indexOf('{'), output.lastIndexOf('}') + 1);
      const report = JSON.parse(jsonStr);

      const findings = report.findings || [];
      
      core.info(`Scan completed: ${findings.length} findings detected.`);

      // Create annotations
      for (const finding of findings) {
        const severity = finding.severity.toLowerCase();
        const annotationParams = {
          title: `[${finding.owasp || 'AFB04'}] ${finding.operation}`,
          file: finding.file,
          startLine: finding.line,
          endLine: finding.line,
          startColumn: finding.column,
          endColumn: finding.column,
        };

        let message = finding.description;
        if (finding.remediation) {
          message += `\nFix: ${finding.remediation}`;
        }
        if (finding.tool) {
          message += `\nTool: ${finding.tool}`;
        }

        if (severity === 'critical' || severity === 'error') {
          core.error(message, annotationParams);
        } else if (severity === 'warning') {
          core.warning(message, annotationParams);
        } else {
          core.notice(message, annotationParams);
        }
      }

      // Handle exit code
      if (failOnFindings && exitCode !== 0) {
        core.setFailed(`Wyscan detected security findings (exit code ${exitCode})`);
      } else {
        process.exitCode = 0; // Force success if fail-on-findings is false
      }

    } catch (parseError) {
      core.error(`Failed to parse wyscan JSON output: ${parseError}`);
      core.debug(`Raw output: ${output}`);
      core.setFailed('Output parsing failed');
    }

  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message);
  }
}

run();
