"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const core = __importStar(require("@actions/core"));
const exec = __importStar(require("@actions/exec"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
/**
 * Detect if the target path contains an MCP server by looking for
 * @modelcontextprotocol/sdk imports in .ts/.js files.
 */
function detectMCPServer(targetPath) {
    const resolvedPath = path.resolve(targetPath);
    try {
        const stat = fs.statSync(resolvedPath);
        const filesToCheck = [];
        if (stat.isFile()) {
            filesToCheck.push(resolvedPath);
        }
        else if (stat.isDirectory()) {
            // Shallow scan for MCP indicators (max 200 files)
            const walk = (dir, depth) => {
                if (depth > 4 || filesToCheck.length > 200)
                    return;
                try {
                    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist')
                            continue;
                        const full = path.join(dir, entry.name);
                        if (entry.isDirectory()) {
                            walk(full, depth + 1);
                        }
                        else if (entry.isFile() && /\.(ts|js|tsx|jsx)$/.test(entry.name)) {
                            filesToCheck.push(full);
                        }
                    }
                }
                catch { /* skip unreadable dirs */ }
            };
            walk(resolvedPath, 0);
        }
        for (const file of filesToCheck) {
            try {
                const content = fs.readFileSync(file, 'utf-8');
                if (content.includes('@modelcontextprotocol/sdk') ||
                    content.includes('McpServer') ||
                    content.includes('mcp-framework')) {
                    return true;
                }
            }
            catch { /* skip unreadable files */ }
        }
    }
    catch { /* target doesn't exist yet */ }
    return false;
}
async function run() {
    try {
        const target = core.getInput('target') || '.';
        const inputMode = core.getInput('mode') || 'auto';
        const level = core.getInput('level') || 'warning';
        const failOnFindings = core.getBooleanInput('fail-on-findings');
        // Auto-detect MCP server if mode is 'auto'
        let mode = inputMode;
        if (mode === 'auto') {
            if (detectMCPServer(target)) {
                mode = 'mcp';
                core.info('Detected MCP server — using mcp scan mode');
            }
            else {
                mode = 'scan';
            }
        }
        core.info(`Running wyscan ${mode} on ${target} (level: ${level})`);
        // Resolve the wyscan CLI script relative to this action bundle
        const wyscanScript = path.resolve(__dirname, '../../dist/cli/index.js');
        let output = '';
        let errorOutput = '';
        const options = {
            ignoreReturnCode: true,
            listeners: {
                stdout: (data) => {
                    output += data.toString();
                },
                stderr: (data) => {
                    errorOutput += data.toString();
                }
            }
        };
        // Run wyscan with JSON output
        const args = [wyscanScript, mode, target, '--level', level, '--json'];
        const exitCode = await exec.exec('node', args, options);
        if (errorOutput && !output.trim()) {
            core.error(`Wyscan execution failed: ${errorOutput}`);
            core.setFailed(`Execution failed with code ${exitCode}`);
            return;
        }
        try {
            // Find JSON block in output (skip any stray stderr/progress lines)
            const jsonStr = output.substring(output.indexOf('{'), output.lastIndexOf('}') + 1);
            const report = JSON.parse(jsonStr);
            const findings = report.findings || [];
            const criticalCount = findings.filter(f => f.severity.toLowerCase() === 'critical').length;
            const warningCount = findings.filter(f => f.severity.toLowerCase() === 'warning').length;
            core.info(`Scan completed: ${findings.length} findings (${criticalCount} critical, ${warningCount} high)`);
            // Create GitHub Check Run annotations for each finding
            for (const finding of findings) {
                const severity = finding.severity.toLowerCase();
                const owaspTag = finding.owasp ? `[${finding.owasp}] ` : '';
                const annotationParams = {
                    title: `${owaspTag}${finding.operation}`,
                    file: finding.file,
                    startLine: finding.line,
                    endLine: finding.line,
                    startColumn: finding.column || undefined,
                    endColumn: finding.column || undefined,
                };
                let message = finding.description;
                if (finding.remediation) {
                    message += `\nFix: ${finding.remediation}`;
                }
                if (finding.tool) {
                    message += `\nTool: ${finding.tool}`;
                }
                if (finding.framework) {
                    message += `\nFramework: ${finding.framework}`;
                }
                // CRITICAL → error annotation, WARNING/HIGH → warning annotation, INFO → notice
                if (severity === 'critical') {
                    core.error(message, annotationParams);
                }
                else if (severity === 'warning') {
                    core.warning(message, annotationParams);
                }
                else {
                    core.notice(message, annotationParams);
                }
            }
            // Set output values
            core.setOutput('findings', findings.length.toString());
            core.setOutput('critical', criticalCount.toString());
            core.setOutput('high', warningCount.toString());
            // Fail the check if any CRITICAL findings exist (when fail-on-findings is true)
            if (failOnFindings && criticalCount > 0) {
                core.setFailed(`Wyscan detected ${criticalCount} CRITICAL finding(s). Fix these before merging.`);
            }
            else if (failOnFindings && warningCount > 0) {
                // Pass with warnings — don't fail, just annotate
                core.warning(`Wyscan detected ${warningCount} HIGH finding(s). Review recommended.`);
                process.exitCode = 0;
            }
            else {
                process.exitCode = 0;
            }
        }
        catch (parseError) {
            core.error(`Failed to parse wyscan JSON output: ${parseError}`);
            core.debug(`Raw output: ${output}`);
            core.setFailed('Output parsing failed');
        }
    }
    catch (error) {
        if (error instanceof Error)
            core.setFailed(error.message);
    }
}
run();
//# sourceMappingURL=index.js.map