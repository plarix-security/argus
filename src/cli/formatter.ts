/**
 * Terminal Output Formatter
 *
 * Clean, professional security tool output.
 * Uses chalk for colors, strips when not TTY.
 */

import chalk from 'chalk';
import * as path from 'path';
import { AFBFinding, AnalysisReport, Severity, ExecutionCategory } from '../types';
import { VERSION } from './version';

const DIVIDER = '─'.repeat(53);

/**
 * Module descriptions for dynamic description generation
 * Maps module names to their general purpose
 */
const MODULE_DESCRIPTIONS: Record<string, string> = {
  // Process/shell
  subprocess: 'Executes system processes',
  os: 'System operations',
  asyncio: 'Async operations',
  pty: 'Pseudo-terminal control',
  pexpect: 'Interactive process control',
  multiprocessing: 'Process spawning',
  fabric: 'Remote execution',
  paramiko: 'SSH operations',

  // Code execution
  pickle: 'Object deserialization',
  marshal: 'Code object serialization',
  yaml: 'YAML parsing',
  ctypes: 'Native code interface',
  importlib: 'Dynamic imports',

  // File system
  shutil: 'File operations',
  pathlib: 'Path operations',
  tempfile: 'Temporary files',
  io: 'I/O operations',
  zipfile: 'Archive operations',
  tarfile: 'Archive operations',
  builtins: 'Built-in operations',

  // Network
  requests: 'HTTP requests',
  httpx: 'HTTP requests',
  urllib: 'URL operations',
  aiohttp: 'Async HTTP requests',
  socket: 'Network socket operations',
  http: 'HTTP operations',

  // Database
  sqlite3: 'SQLite database operations',
  psycopg2: 'PostgreSQL database operations',
  psycopg: 'PostgreSQL database operations',
  pymysql: 'MySQL database operations',
  pymongo: 'MongoDB operations',
  redis: 'Redis operations',

  // Email
  smtplib: 'Email sending',
  email: 'Email operations',
};

/**
 * Verb-to-capability mapping for dynamic descriptions
 * Maps method verbs to what they enable an agent to do
 */
const VERB_CAPABILITIES: Record<string, { verb: string; capability: string }> = {
  // Critical operations
  delete: { verb: 'Deletes', capability: 'remove data permanently' },
  remove: { verb: 'Removes', capability: 'delete files or resources' },
  unlink: { verb: 'Unlinks', capability: 'delete files' },
  rmtree: { verb: 'Removes', capability: 'recursively delete directories' },
  rmdir: { verb: 'Removes', capability: 'delete directories' },
  exec: { verb: 'Executes', capability: 'run arbitrary code' },
  eval: { verb: 'Evaluates', capability: 'execute arbitrary expressions' },
  run: { verb: 'Runs', capability: 'execute commands or processes' },
  spawn: { verb: 'Spawns', capability: 'create new processes' },
  popen: { verb: 'Opens', capability: 'execute shell commands' },
  system: { verb: 'Executes', capability: 'run system commands' },
  call: { verb: 'Calls', capability: 'invoke external processes' },
  kill: { verb: 'Kills', capability: 'terminate processes' },
  terminate: { verb: 'Terminates', capability: 'stop processes' },
  load: { verb: 'Deserializes', capability: 'execute code during loading' },
  loads: { verb: 'Deserializes', capability: 'execute code during loading' },

  // Write operations
  write: { verb: 'Writes', capability: 'modify or create files' },
  writelines: { verb: 'Writes', capability: 'modify files' },
  write_text: { verb: 'Writes', capability: 'create or modify text files' },
  write_bytes: { verb: 'Writes', capability: 'create or modify binary files' },
  save: { verb: 'Saves', capability: 'persist data' },
  dump: { verb: 'Dumps', capability: 'serialize and write data' },
  mkdir: { verb: 'Creates', capability: 'create directories' },
  makedirs: { verb: 'Creates', capability: 'create directory trees' },
  copy: { verb: 'Copies', capability: 'duplicate files' },
  copy2: { verb: 'Copies', capability: 'duplicate files with metadata' },
  copytree: { verb: 'Copies', capability: 'duplicate directory trees' },
  move: { verb: 'Moves', capability: 'relocate files' },
  rename: { verb: 'Renames', capability: 'change file names' },
  replace: { verb: 'Replaces', capability: 'overwrite files' },
  insert: { verb: 'Inserts', capability: 'add data to storage' },
  insert_one: { verb: 'Inserts', capability: 'add records' },
  insert_many: { verb: 'Inserts', capability: 'add multiple records' },
  update: { verb: 'Updates', capability: 'modify stored data' },
  update_one: { verb: 'Updates', capability: 'modify records' },
  update_many: { verb: 'Updates', capability: 'modify multiple records' },
  upsert: { verb: 'Upserts', capability: 'insert or update data' },
  set: { verb: 'Sets', capability: 'store key-value data' },
  hset: { verb: 'Sets', capability: 'store hash data' },
  lpush: { verb: 'Pushes', capability: 'add to lists' },
  rpush: { verb: 'Pushes', capability: 'add to lists' },
  sadd: { verb: 'Adds', capability: 'modify sets' },

  // Network write operations
  post: { verb: 'Sends', capability: 'submit data externally' },
  put: { verb: 'Sends', capability: 'update external resources' },
  patch: { verb: 'Sends', capability: 'partially update external data' },
  send: { verb: 'Sends', capability: 'transmit data externally' },
  sendmail: { verb: 'Sends', capability: 'transmit emails' },
  upload: { verb: 'Uploads', capability: 'transfer files externally' },
  connect: { verb: 'Connects', capability: 'establish network connections' },

  // Read operations
  read: { verb: 'Reads', capability: 'access file contents' },
  readline: { verb: 'Reads', capability: 'access file contents' },
  readlines: { verb: 'Reads', capability: 'access file contents' },
  read_text: { verb: 'Reads', capability: 'access text file contents' },
  read_bytes: { verb: 'Reads', capability: 'access binary file contents' },
  open: { verb: 'Opens', capability: 'access files' },
  get: { verb: 'Gets', capability: 'retrieve data' },
  fetch: { verb: 'Fetches', capability: 'retrieve external data' },
  download: { verb: 'Downloads', capability: 'retrieve files externally' },
  find: { verb: 'Finds', capability: 'query data' },
  find_one: { verb: 'Finds', capability: 'query records' },
  find_many: { verb: 'Finds', capability: 'query multiple records' },
  select: { verb: 'Selects', capability: 'query data' },
  query: { verb: 'Queries', capability: 'access stored data' },
  execute: { verb: 'Executes', capability: 'run database queries' },
  executemany: { verb: 'Executes', capability: 'run batch database queries' },
  fetchone: { verb: 'Fetches', capability: 'retrieve query results' },
  fetchall: { verb: 'Fetches', capability: 'retrieve all query results' },
  fetchmany: { verb: 'Fetches', capability: 'retrieve query results' },
  hget: { verb: 'Gets', capability: 'retrieve hash data' },
  hgetall: { verb: 'Gets', capability: 'retrieve all hash data' },
  keys: { verb: 'Lists', capability: 'enumerate keys' },
  values: { verb: 'Lists', capability: 'enumerate values' },
  lrange: { verb: 'Gets', capability: 'retrieve list data' },
  smembers: { verb: 'Gets', capability: 'retrieve set members' },

  // List/glob operations
  listdir: { verb: 'Lists', capability: 'enumerate directory contents' },
  scandir: { verb: 'Scans', capability: 'enumerate directory contents' },
  walk: { verb: 'Walks', capability: 'traverse directory trees' },
  glob: { verb: 'Globs', capability: 'find files by pattern' },
  iterdir: { verb: 'Iterates', capability: 'enumerate directory contents' },
};

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
 * Parse callee from the operation field
 * Operation format: "Category description: callee" (e.g., "File system operation: filepath.write_text")
 */
function parseCallee(operation: string): { module: string; method: string; raw: string } {
  // Extract callee after the colon
  const colonIdx = operation.indexOf(':');
  const raw = colonIdx >= 0 ? operation.slice(colonIdx + 1).trim() : operation;

  // Split by last dot to get module.method
  const lastDotIdx = raw.lastIndexOf('.');
  if (lastDotIdx >= 0) {
    return {
      module: raw.slice(0, lastDotIdx),
      method: raw.slice(lastDotIdx + 1),
      raw,
    };
  }

  // No dot - it's a bare function name (e.g., "eval", "exec")
  return { module: '', method: raw, raw };
}

/**
 * Get module description for a callee
 */
function getModuleDescription(callee: { module: string; method: string }): string | null {
  // Try exact module match
  if (MODULE_DESCRIPTIONS[callee.module]) {
    return MODULE_DESCRIPTIONS[callee.module];
  }

  // Try first part of module path (e.g., "http.client" -> "http")
  const firstPart = callee.module.split('.')[0];
  if (firstPart && MODULE_DESCRIPTIONS[firstPart]) {
    return MODULE_DESCRIPTIONS[firstPart];
  }

  return null;
}

/**
 * Get verb-based capability for a method
 */
function getVerbCapability(method: string): { verb: string; capability: string } | null {
  // Check exact match first
  const lowerMethod = method.toLowerCase();
  if (VERB_CAPABILITIES[lowerMethod]) {
    return VERB_CAPABILITIES[lowerMethod];
  }

  // Check if method starts with a known verb
  for (const [verb, info] of Object.entries(VERB_CAPABILITIES)) {
    if (lowerMethod.startsWith(verb)) {
      return info;
    }
  }

  // Check if method contains a known verb
  for (const [verb, info] of Object.entries(VERB_CAPABILITIES)) {
    if (lowerMethod.includes(verb)) {
      return info;
    }
  }

  return null;
}

/**
 * Detect risk factors from code snippet and callee
 */
function detectRiskFactors(snippet: string, callee: { module: string; method: string }): string[] {
  const risks: string[] = [];
  const lowerSnippet = snippet.toLowerCase();

  // Shell execution risks
  if (lowerSnippet.includes('shell=true') || lowerSnippet.includes('shell = true')) {
    risks.push('Command passed to shell for execution.');
  }

  // Path traversal risks
  if (callee.method.includes('path') || callee.method.includes('file')) {
    if (!lowerSnippet.includes('sanitize') && !lowerSnippet.includes('validate')) {
      risks.push('Path parameter may allow directory traversal.');
    }
  }

  // URL/SSRF risks
  if (lowerSnippet.includes('url') || lowerSnippet.includes('http')) {
    risks.push('URL parameter may enable SSRF.');
  }

  // SQL injection risks
  if (lowerSnippet.includes("f'") || lowerSnippet.includes('f"') || lowerSnippet.includes('.format(')) {
    if (['execute', 'executemany', 'query'].includes(callee.method.toLowerCase())) {
      risks.push('Query may be vulnerable to injection.');
    }
  }

  // Deserialization risks
  if (['load', 'loads', 'Unpickler'].includes(callee.method)) {
    if (callee.module.includes('pickle') || callee.module.includes('yaml') || callee.module.includes('marshal')) {
      risks.push('Deserialization can execute arbitrary code.');
    }
  }

  return risks;
}

/**
 * Generate description dynamically from callee semantics
 *
 * Format: "{Operation description}. Agent can {capability}. {Risk factors}"
 *
 * This approach ensures novel operations get meaningful descriptions
 * based on their module and method semantics, not hardcoded templates.
 */
function getDescription(finding: AFBFinding): string {
  return finding.explanation;
}

/**
 * Get a clean subject for bare functions based on verb
 */
function getSubjectForVerb(method: string, category: ExecutionCategory): string {
  // Map common bare functions to clean subjects
  const bareSubjects: Record<string, string> = {
    eval: 'Python expression',
    exec: 'Python code',
    compile: 'Python code',
    open: 'file handle',
    input: 'user input',
    print: 'to output',
    __import__: 'module dynamically',
  };

  if (bareSubjects[method]) {
    return bareSubjects[method];
  }

  // Derive from category
  switch (category) {
    case ExecutionCategory.CODE_EXECUTION:
      return 'code';
    case ExecutionCategory.SHELL_EXECUTION:
      return 'command';
    case ExecutionCategory.FILE_OPERATION:
      return 'file';
    case ExecutionCategory.API_CALL:
      return 'request';
    case ExecutionCategory.DATABASE_OPERATION:
      return 'query';
    default:
      return 'operation';
  }
}

/**
 * Get contextual subject for module.method calls
 */
function getContextualSubject(callee: { module: string; method: string; raw: string }, category: ExecutionCategory): string {
  const lowerMethod = callee.method.toLowerCase();
  const lowerModule = callee.module.toLowerCase();

  // HTTP methods - return full phrase, verb will be skipped
  if (['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(lowerMethod)) {
    if (lowerModule.includes('http') || lowerModule.includes('requests') || lowerModule.includes('aiohttp')) {
      return `_HTTP_${lowerMethod.toUpperCase()}_`; // Special marker for HTTP methods
    }
  }

  // File operations - use cleaner subjects
  if (lowerMethod.includes('write')) {
    return 'to file';
  }
  if (lowerMethod.includes('read')) {
    return 'file contents';
  }
  if (lowerMethod === 'mkdir' || lowerMethod === 'makedirs') {
    return 'directory';
  }
  if (lowerMethod === 'glob' || lowerMethod === 'iterdir' || lowerMethod === 'listdir') {
    return 'directory contents';
  }
  if (lowerMethod === 'remove' || lowerMethod === 'unlink' || lowerMethod === 'rmdir') {
    return 'file or directory';
  }
  if (lowerMethod === 'rmtree') {
    return 'directory tree';
  }

  // Database operations
  if (lowerMethod === 'execute' || lowerMethod === 'executemany') {
    return 'database query';
  }
  if (lowerMethod.startsWith('fetch')) {
    return 'query results';
  }
  if (lowerMethod.startsWith('insert')) {
    return 'database record';
  }
  if (lowerMethod.startsWith('update')) {
    return 'database record';
  }
  if (lowerMethod.startsWith('delete')) {
    return 'database record';
  }

  // Redis operations
  if (lowerMethod === 'set' || lowerMethod === 'hset') {
    return 'key-value data';
  }
  if (lowerMethod === 'keys') {
    return 'stored keys';
  }

  // Process operations
  if (lowerMethod === 'run' || lowerMethod === 'popen' || lowerMethod === 'call') {
    if (lowerModule.includes('subprocess') || lowerModule.includes('os')) {
      return 'system process';
    }
  }

  // Fallback: derive from category
  switch (category) {
    case ExecutionCategory.FILE_OPERATION:
      return 'filesystem';
    case ExecutionCategory.API_CALL:
      return 'external data';
    case ExecutionCategory.DATABASE_OPERATION:
      return 'database';
    case ExecutionCategory.SHELL_EXECUTION:
      return 'system command';
    case ExecutionCategory.CODE_EXECUTION:
      return 'code';
    default:
      return 'data';
  }
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

  if (failedFiles.length > 0) {
    const label = failedFiles.length === 1 ? 'file' : 'files';
    notes.push(`Failed to analyze ${failedFiles.length} ${label}. Exit code reflects scan failure.`);
  }

  if (skippedFiles.length > 0) {
    const skippedLanguages = Array.from(new Set(skippedFiles.map((file) => file.language))).sort();
    const label = skippedFiles.length === 1 ? 'file' : 'files';
    notes.push(`Skipped ${skippedFiles.length} unsupported ${label}: ${skippedLanguages.join(', ')}.`);
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

  if (parts.length === 0) {
    console.log(`0 findings  ·  ${fileCount} ${fileLabel}  ·  ${runtimeSec}s`);
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
  printFooter(report);
}
