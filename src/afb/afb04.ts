/**
 * AFB04 - Unauthorized Action Detection
 *
 * This module contains the classification logic for AFB04 boundaries.
 * AFB04 represents the Agent → Act transition where an agent attempts
 * to perform an action that may not be authorized.
 *
 * Key insight from the AFB specification:
 * - AFB04 is the most detectable boundary through static analysis
 * - It involves concrete execution points: tool calls, API calls,
 *   file operations, shell commands, database operations
 * - Even if upstream boundaries (AFB01-03) are compromised,
 *   proper AFB04 enforcement can contain the blast radius
 */

import {
  AFBFinding,
  AFBType,
  ExecutionCategory,
  Severity,
  NodeLocation,
} from '../types';

/**
 * Pattern definition for detecting execution points.
 */
export interface ExecutionPattern {
  /** Pattern identifier */
  id: string;
  /** Category of execution */
  category: ExecutionCategory;
  /** Base severity (may be elevated based on context) */
  baseSeverity: Severity;
  /** Human-readable description of what this pattern detects */
  description: string;
  /** Why this represents a boundary exposure */
  rationale: string;
}

/**
 * Python execution patterns for AFB04 detection.
 * These are structural patterns identified through AST analysis,
 * not string matching.
 */
export const PYTHON_PATTERNS: Record<string, ExecutionPattern> = {
  // Tool calling patterns
  tool_decorator: {
    id: 'py-tool-decorator',
    category: ExecutionCategory.TOOL_CALL,
    baseSeverity: Severity.HIGH,
    description: 'LangChain/CrewAI tool definition',
    rationale:
      'Tool definitions expose execution capabilities that agents can invoke without explicit user approval per-call',
  },
  tool_instantiation: {
    id: 'py-tool-instantiation',
    category: ExecutionCategory.TOOL_CALL,
    baseSeverity: Severity.HIGH,
    description: 'Tool object instantiation',
    rationale:
      'Tool instantiation creates an execution capability that can be invoked by agent reasoning',
  },

  // Shell command patterns
  subprocess_run: {
    id: 'py-subprocess-run',
    category: ExecutionCategory.SHELL_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Subprocess execution',
    rationale:
      'Shell command execution allows arbitrary system commands, highest blast radius potential',
  },
  os_system: {
    id: 'py-os-system',
    category: ExecutionCategory.SHELL_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'OS system command execution',
    rationale:
      'Direct shell execution without output capture, vulnerable to command injection',
  },
  os_popen: {
    id: 'py-os-popen',
    category: ExecutionCategory.SHELL_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'OS popen command execution',
    rationale:
      'Shell command execution with pipe, vulnerable to command injection',
  },

  // File operation patterns
  file_open: {
    id: 'py-file-open',
    category: ExecutionCategory.FILE_OPERATION,
    baseSeverity: Severity.MEDIUM,
    description: 'File open operation',
    rationale:
      'File operations can read sensitive data or write malicious content',
  },
  pathlib_write: {
    id: 'py-pathlib-write',
    category: ExecutionCategory.FILE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'Pathlib file write',
    rationale:
      'File write operations can overwrite critical files or plant malicious content',
  },
  shutil_operation: {
    id: 'py-shutil',
    category: ExecutionCategory.FILE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'Shutil file operation',
    rationale:
      'Bulk file operations (copy, move, delete) with broader filesystem impact',
  },

  // API/HTTP patterns
  requests_call: {
    id: 'py-requests',
    category: ExecutionCategory.API_CALL,
    baseSeverity: Severity.HIGH,
    description: 'HTTP request via requests library',
    rationale:
      'External HTTP calls can exfiltrate data or trigger external actions',
  },
  httpx_call: {
    id: 'py-httpx',
    category: ExecutionCategory.API_CALL,
    baseSeverity: Severity.HIGH,
    description: 'HTTP request via httpx library',
    rationale:
      'External HTTP calls can exfiltrate data or trigger external actions',
  },
  aiohttp_call: {
    id: 'py-aiohttp',
    category: ExecutionCategory.API_CALL,
    baseSeverity: Severity.HIGH,
    description: 'Async HTTP request via aiohttp',
    rationale:
      'External HTTP calls can exfiltrate data or trigger external actions',
  },
  urllib_call: {
    id: 'py-urllib',
    category: ExecutionCategory.API_CALL,
    baseSeverity: Severity.HIGH,
    description: 'HTTP request via urllib',
    rationale:
      'External HTTP calls can exfiltrate data or trigger external actions',
  },

  // Database patterns
  cursor_execute: {
    id: 'py-cursor-execute',
    category: ExecutionCategory.DATABASE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'Database cursor execute',
    rationale: 'Direct SQL execution can read, modify, or delete database records',
  },
  sqlalchemy_execute: {
    id: 'py-sqlalchemy',
    category: ExecutionCategory.DATABASE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'SQLAlchemy query execution',
    rationale: 'ORM operations can modify database state',
  },

  // Code execution patterns
  eval_call: {
    id: 'py-eval',
    category: ExecutionCategory.CODE_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Dynamic code evaluation',
    rationale: 'eval() executes arbitrary Python code, maximum attack surface',
  },
  exec_call: {
    id: 'py-exec',
    category: ExecutionCategory.CODE_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Dynamic code execution',
    rationale: 'exec() executes arbitrary Python code, maximum attack surface',
  },
  compile_call: {
    id: 'py-compile',
    category: ExecutionCategory.CODE_EXECUTION,
    baseSeverity: Severity.HIGH,
    description: 'Code compilation',
    rationale: 'compile() prepares code for execution, often used with eval/exec',
  },
};

/**
 * TypeScript/JavaScript execution patterns for AFB04 detection.
 */
export const TYPESCRIPT_PATTERNS: Record<string, ExecutionPattern> = {
  // Tool calling patterns
  tool_function: {
    id: 'ts-tool-function',
    category: ExecutionCategory.TOOL_CALL,
    baseSeverity: Severity.HIGH,
    description: 'LangChain tool definition',
    rationale:
      'Tool definitions expose execution capabilities that agents can invoke without explicit user approval per-call',
  },
  dynamic_tool: {
    id: 'ts-dynamic-tool',
    category: ExecutionCategory.TOOL_CALL,
    baseSeverity: Severity.HIGH,
    description: 'Dynamic tool creation',
    rationale:
      'Dynamic tool creation exposes execution capabilities to agent reasoning',
  },

  // Shell command patterns
  child_process_exec: {
    id: 'ts-exec',
    category: ExecutionCategory.SHELL_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Child process exec',
    rationale:
      'Shell command execution allows arbitrary system commands, highest blast radius potential',
  },
  child_process_spawn: {
    id: 'ts-spawn',
    category: ExecutionCategory.SHELL_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Child process spawn',
    rationale:
      'Process spawning allows arbitrary system commands with argument control',
  },
  child_process_execSync: {
    id: 'ts-execSync',
    category: ExecutionCategory.SHELL_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Synchronous shell execution',
    rationale:
      'Synchronous shell execution blocks and executes arbitrary commands',
  },

  // File operation patterns
  fs_writeFile: {
    id: 'ts-fs-write',
    category: ExecutionCategory.FILE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'File write operation',
    rationale:
      'File write operations can overwrite critical files or plant malicious content',
  },
  fs_readFile: {
    id: 'ts-fs-read',
    category: ExecutionCategory.FILE_OPERATION,
    baseSeverity: Severity.MEDIUM,
    description: 'File read operation',
    rationale: 'File read operations can access sensitive data',
  },
  fs_unlink: {
    id: 'ts-fs-unlink',
    category: ExecutionCategory.FILE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'File deletion',
    rationale: 'File deletion can cause data loss or system instability',
  },
  fs_rm: {
    id: 'ts-fs-rm',
    category: ExecutionCategory.FILE_OPERATION,
    baseSeverity: Severity.CRITICAL,
    description: 'Recursive file removal',
    rationale:
      'Recursive deletion can destroy entire directory structures',
  },

  // API/HTTP patterns
  fetch_call: {
    id: 'ts-fetch',
    category: ExecutionCategory.API_CALL,
    baseSeverity: Severity.HIGH,
    description: 'Fetch API call',
    rationale:
      'External HTTP calls can exfiltrate data or trigger external actions',
  },
  axios_call: {
    id: 'ts-axios',
    category: ExecutionCategory.API_CALL,
    baseSeverity: Severity.HIGH,
    description: 'Axios HTTP request',
    rationale:
      'External HTTP calls can exfiltrate data or trigger external actions',
  },
  http_request: {
    id: 'ts-http',
    category: ExecutionCategory.API_CALL,
    baseSeverity: Severity.HIGH,
    description: 'Node.js HTTP request',
    rationale:
      'External HTTP calls can exfiltrate data or trigger external actions',
  },

  // Database patterns
  query_execute: {
    id: 'ts-db-query',
    category: ExecutionCategory.DATABASE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'Database query execution',
    rationale: 'Database operations can read, modify, or delete records',
  },
  prisma_operation: {
    id: 'ts-prisma',
    category: ExecutionCategory.DATABASE_OPERATION,
    baseSeverity: Severity.HIGH,
    description: 'Prisma database operation',
    rationale: 'ORM operations can modify database state',
  },

  // Code execution patterns
  eval_call: {
    id: 'ts-eval',
    category: ExecutionCategory.CODE_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Dynamic code evaluation',
    rationale: 'eval() executes arbitrary JavaScript code, maximum attack surface',
  },
  function_constructor: {
    id: 'ts-function-constructor',
    category: ExecutionCategory.CODE_EXECUTION,
    baseSeverity: Severity.CRITICAL,
    description: 'Function constructor',
    rationale: 'new Function() creates executable code from strings',
  },
};

/**
 * Elevates severity based on context.
 * - Inside tool definitions: severity elevated
 * - Has dynamic/user-controlled input: severity elevated
 */
export function adjustSeverity(
  baseSeverity: Severity,
  isInTool: boolean,
  hasDynamicInput: boolean
): Severity {
  // Convert to numeric level for comparison
  const severityLevel = (s: Severity): number => {
    switch (s) {
      case Severity.CRITICAL: return 3;
      case Severity.HIGH: return 2;
      case Severity.MEDIUM: return 1;
    }
  };

  const levelToSeverity = (level: number): Severity => {
    if (level >= 3) return Severity.CRITICAL;
    if (level >= 2) return Severity.HIGH;
    return Severity.MEDIUM;
  };

  let level = severityLevel(baseSeverity);

  if (isInTool) level = Math.min(level + 1, 3);
  if (hasDynamicInput) level = Math.min(level + 1, 3);

  return levelToSeverity(level);
}

/**
 * Creates an AFB04 finding from a detected execution point.
 */
export function createFinding(
  file: string,
  location: NodeLocation,
  codeSnippet: string,
  pattern: ExecutionPattern,
  enclosingFunction?: string,
  enclosingClass?: string,
  isInToolDefinition: boolean = false,
  framework?: string,
  confidence: number = 0.8
): AFBFinding {
  const severity = adjustSeverity(
    pattern.baseSeverity,
    isInToolDefinition,
    false // TODO: Implement dynamic input detection
  );

  return {
    type: AFBType.UNAUTHORIZED_ACTION,
    category: pattern.category,
    severity,
    file,
    line: location.startLine,
    column: location.startColumn,
    codeSnippet: codeSnippet.length > 100
      ? codeSnippet.slice(0, 100) + '...'
      : codeSnippet,
    operation: pattern.description,
    explanation: pattern.rationale,
    confidence,
    context: {
      enclosingFunction,
      enclosingClass,
      isToolDefinition: isInToolDefinition,
      framework,
    },
  };
}
