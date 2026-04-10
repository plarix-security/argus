/**
 * Call Graph Builder
 *
 * Builds a call graph from parsed Python files to trace:
 * 1. Tool registration points via semantic root extraction
 * 2. Execution paths from tools to dangerous operations
 * 3. Presence or absence of structural policy gates in call paths
 *
 * This is the core of AFB04 detection: we need to know if a tool
 * can reach a dangerous operation without passing through authorization.
 *
 * IMPORTANT: Policy gate detection is STRUCTURAL, not nominal.
 * A function named "check_permission" that always returns True is NOT a gate.
 * A function named "process_data" that raises PermissionError conditionally IS.
 *
 * v1.2.2: Removed framework-specific pattern tables. Tool detection now
 * relies entirely on semantic root extraction via PythonSemanticIndex.
 */

import {
  ParsedPythonFile,
  FunctionDef,
  ClassDef,
  CallSite,
  ImportInfo,
  ControlFlowInfo,
  DecoratorDef,
  OpenAIToolSchema,
  FunctionDispatchMapping,
  CallArgumentInfo,
} from './ast-parser';
import {
  PythonSemanticIndex,
  extractSemanticInvocationRoots,
  SemanticCallIdentity,
  SemanticInvocationRoot,
} from './semantic-index';
import { ExecutionCategory, Severity } from '../../types';
import * as path from 'path';

/**
 * Import resolution result
 */
export interface ResolvedImport {
  /** The name being imported */
  name: string;
  /** Alias if any */
  alias?: string;
  /** Resolved file path (if found) */
  resolvedFile?: string;
  /** Whether this import could be resolved */
  resolved: boolean;
  /** Module path from import statement */
  modulePath: string;
}

/**
 * A node in the call graph representing a function or method
 */
export interface CallGraphNode {
  /** Unique identifier: className.methodName or functionName */
  id: string;
  /** Function or method name */
  name: string;
  /** Class name if this is a method */
  className?: string;
  /** Line number where defined */
  startLine: number;
  /** End line */
  endLine: number;
  /** Decorators applied to this function */
  decorators: string[];
  /** IDs of functions this function calls */
  callees: Set<string>;
  /** IDs of functions that call this function */
  callers: Set<string>;
  /** Whether this is a tool registration point */
  isToolRegistration: boolean;
  /** Framework that registered this tool */
  framework?: string;
  /** How the tool registration was identified */
  toolDetectionKind?: 'semantic' | 'heuristic';
  /** Evidence describing the registration source */
  toolDetectionEvidence?: string;
  /** Dangerous operations directly in this function */
  dangerousOps: DangerousOperation[];
  /** Whether this function is a structural policy gate */
  hasPolicyGate: boolean;
  /** Whether this node only has auth-like naming evidence, not structural proof */
  hasHeuristicGateIndicator?: boolean;
  /** Whether this function is a likely validation helper */
  isValidationHelper: boolean;
  /** Control flow information */
  controlFlow?: ControlFlowInfo;
  /** Source file path */
  sourceFile?: string;
  /** Declared parameter names in source order */
  parameters?: string[];
  /** Outgoing callsites captured for path reconstruction */
  outgoingCalls: Array<{
    targetId?: string;
    call: CallSite;
  }>;
  /** Whether this node was resolved from a cross-file import */
  isCrossFileResolved?: boolean;
}

/**
 * A dangerous operation detected in code
 */
export interface DangerousOperation {
  callee: string;
  category: ExecutionCategory;
  severity: Severity;
  line: number;
  column: number;
  codeSnippet: string;
  sourceFile?: string;
  enclosingNodeId?: string;
  argumentDetails?: CallArgumentInfo[];
  resourceHint?: string;
  changesState?: boolean;
  detectionKind?: 'semantic' | 'heuristic';
  detectionEvidence?: string;
  resolvedIdentity?: string;
}

/**
 * Result of call graph analysis
 */
export interface CallGraphAnalysis {
  /** All nodes in the call graph */
  nodes: Map<string, CallGraphNode>;
  /** Tool registration points */
  toolRegistrations: CallGraphNode[];
  /** Exposed paths: tool -> dangerous operation without policy gate */
  exposedPaths: ExposedPath[];
}

/**
 * An exposed execution path from tool to dangerous operation
 */
export interface ExposedPath {
  /** The tool registration point */
  tool: CallGraphNode;
  /** The dangerous operation */
  operation: DangerousOperation;
  /** Path from tool to operation (function IDs) */
  path: string[];
  /** Whether any node in path has a policy gate */
  hasGateInPath: boolean;
  /** Whether auth-like gate names appeared without structural proof */
  hasHeuristicGateInPath?: boolean;
  /** Whether any node in path is a likely validation helper */
  hasValidationHelperInPath: boolean;
  /** File path */
  file: string;
  /** Whether cross-file resolution was involved */
  involvesCrossFile?: boolean;
  /** If cross-file resolution failed, note it here */
  unresolvedCrossFileCalls?: string[];
  /** Whether depth limit was hit during path tracing */
  depthLimitHit?: boolean;
  /** Whether tool input was traced into the operation */
  inputFlowsToOperation?: boolean;
  /** Whether the path carries instruction or context-like input */
  instructionLikeInput?: boolean;
  /** Resource hint derived from the operation arguments */
  resourceHint?: string;
  /** Whether the operation likely changes state */
  changesState?: boolean;
  /** Supporting evidence gathered while tracing */
  supportingEvidence?: string[];
  /** Strongest proof category used on this path */
  evidenceKind?: 'structural' | 'semantic' | 'heuristic';
}

/**
 * Cross-file import map for tracking imports across files
 */
export interface CrossFileImportMap {
  /** Map from file path to its resolved imports */
  fileImports: Map<string, ResolvedImport[]>;
  /** Map from imported name to its source file */
  nameToFile: Map<string, string>;
  /** Map from (file, name) to the actual function node ID */
  nameToNodeId: Map<string, string>;
}

/**
 * Configuration for cross-file import resolution
 */
export interface ImportResolutionConfig {
  /** Maximum depth for transitive import resolution (default: 5) */
  maxDepth: number;
  /** Whether to emit SUPPRESSED findings when depth limit is hit (default: true) */
  emitSuppressedOnLimit: boolean;
}

/** Default import resolution configuration */
export const DEFAULT_IMPORT_CONFIG: ImportResolutionConfig = {
  maxDepth: 20,
  emitSuppressedOnLimit: true,
};

function extractFileFromNodeId(nodeId: string): string | null {
  const separatorIndex = nodeId.lastIndexOf(':');
  if (separatorIndex === -1) {
    return null;
  }

  return nodeId.slice(0, separatorIndex);
}

// NOTE: Framework-specific TOOL_REGISTRATION_PATTERNS removed in v1.2.2.
// Tool detection now relies entirely on semantic root extraction via
// PythonSemanticIndex which performs structural analysis of:
// - tool= parameters passed to agent constructors
// - bind_tools() method calls
// - function_map assignments
// - OpenAI-style tool schema dictionaries
// - Decorator-based registration (via import resolution)

/**
 * Patterns that indicate dangerous operations
 *
 * STRICT FOUR-LEVEL SEVERITY CRITERIA:
 *
 * CRITICAL: Irreversible destruction, exfiltration, or arbitrary execution
 *   - Shell execution (can delete/modify/exfiltrate anything)
 *   - Code execution (eval, exec - can do anything)
 *   - File/directory deletion (rmtree, remove, unlink)
 *
 * WARNING: Recoverable but consequential state modification or transmission
 *   - File writes (write_text, write_bytes, copy, move, rename)
 *   - HTTP POST/PUT/PATCH/DELETE (transmitting data externally)
 *   - Database writes (INSERT, UPDATE, DELETE via ORM)
 *
 * INFO: Read-only access to sensitive data or external systems
 *   - File reads (open with 'r' mode, read_text, read_bytes)
 *   - HTTP GET requests (reading from external APIs)
 *   - Database SELECT queries
 *   - Environment variable access
 *
 * SUPPRESSED: Everything else (low-confidence, internal operations, safe targets)
 *   - Not matched by any pattern
 *   - Not included in PR reports
 */
const DANGEROUS_OPERATION_PATTERNS: {
  pattern: RegExp;
  category: ExecutionCategory;
  severity: Severity;
  description: string;
}[] = [
  // ==================== CRITICAL ====================
  // Shell execution - can delete/modify/exfiltrate anything
  { pattern: /^subprocess\.(run|Popen|call|check_output|check_call|getoutput|getstatusoutput)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell command execution' },
  { pattern: /^asyncio\.create_subprocess_(exec|shell)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Async subprocess execution' },
  { pattern: /^os\.(system|popen|popen2|popen3|popen4|exec.*)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'OS shell command' },
  { pattern: /^os\.(spawn[lv]p?e?)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'OS process spawn' },
  { pattern: /^commands\.(getoutput|getstatusoutput)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Commands module execution' },
  // pty/pexpect - interactive shells
  { pattern: /^pty\.(spawn|fork)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'PTY shell spawn' },
  { pattern: /^pexpect\.(spawn|run)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Pexpect process spawn' },
  // fabric/paramiko - remote execution
  { pattern: /^fabric\.(run|sudo|local)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Fabric remote execution' },
  { pattern: /\.exec_command$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'SSH command execution' },

  // Code execution - can do anything
  { pattern: /^eval$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic code evaluation' },
  { pattern: /^exec$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic code execution' },
  // Dangerous deserialization - can execute arbitrary code
  { pattern: /^pickle\.(load|loads|Unpickler)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Pickle deserialization (code execution)' },
  { pattern: /^marshal\.(load|loads)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Marshal deserialization (code execution)' },
  { pattern: /^shelve\.open$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Shelve open (uses pickle)' },
  { pattern: /^yaml\.(load|unsafe_load|full_load)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'YAML unsafe load (code execution)' },
  { pattern: /^dill\.(load|loads)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dill deserialization (code execution)' },
  { pattern: /^joblib\.load$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Joblib load (uses pickle)' },
  // ctypes - C library access
  { pattern: /^ctypes\.(CDLL|WinDLL|PyDLL)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'C library loading' },

  // File deletion - irreversible data loss
  { pattern: /^shutil\.rmtree$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Recursive directory deletion' },
  { pattern: /^os\.(remove|unlink|rmdir|removedirs)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File/directory deletion' },
  { pattern: /\.unlink$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Path unlink (deletion)' },
  { pattern: /\.rmdir$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Directory deletion' },
  { pattern: /\.rmtree$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Recursive directory deletion' },

  // ==================== WARNING ====================
  // File writes - can modify system state (recoverable but consequential)
  { pattern: /\.write_text$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write' },
  { pattern: /\.write_bytes$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Binary file write' },
  { pattern: /^shutil\.(copy|copy2|copyfile|copyfileobj|copytree|move|make_archive)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File copy/move' },
  { pattern: /^os\.(rename|renames|replace|link|symlink)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File rename/link' },
  { pattern: /^os\.(makedirs|mkdir)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Directory creation' },
  { pattern: /^os\.(chmod|chown)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File permission change' },
  { pattern: /\.mkdir$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Directory creation' },
  { pattern: /\.write$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write' },
  { pattern: /\.touch$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File touch/create' },
  // zipfile/tarfile extraction
  { pattern: /\.extractall$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Archive extract all' },

  // HTTP methods - full coverage of all Python HTTP clients
  { pattern: /^requests\.(get|post|put|patch|delete|request|head|options|Session\.get|Session\.post|Session\.put|Session\.patch|Session\.delete|Session\.request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request via requests' },
  { pattern: /^httpx\.(get|post|put|patch|delete|request|head|options)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request via httpx' },
  { pattern: /^httpx\.(AsyncClient|Client)\.(get|post|put|patch|delete|request|head|options)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request via httpx client' },
  { pattern: /^aiohttp\.ClientSession\.(get|post|put|patch|delete|request|head|options)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Async HTTP request via aiohttp' },
  { pattern: /^urllib\.request\.(urlopen|Request|urlretrieve)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'URL request via urllib' },
  { pattern: /^urllib3\.(PoolManager|HTTPConnectionPool|HTTPSConnectionPool)\.(request|urlopen)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request via urllib3' },
  // AWS boto3 - any client method call is an external API call
  { pattern: /^boto3\.client\.[a-z_]+$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS SDK call via boto3' },
  { pattern: /^boto3\.resource\.[a-z_]+$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS resource operation via boto3' },
  // Generic http/api object calls
  { pattern: /\.(post|put|patch|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation method call' },

  // Database: SQLite3
  { pattern: /^sqlite3\.(Connection|Cursor)\.(execute|executemany|executescript)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'SQLite3 database execution' },
  { pattern: /\.execute$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database execute' },
  { pattern: /\.executemany$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Batch database execution' },
  { pattern: /\.executescript$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'SQL script execution' },
  // Database: PostgreSQL (psycopg2, asyncpg)
  { pattern: /^psycopg2\.(cursor|connection)\.(execute|executemany)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'PostgreSQL execution via psycopg2' },
  { pattern: /^asyncpg\.Connection\.(execute|executemany|fetch|fetchrow|fetchval)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Async PostgreSQL operation via asyncpg' },
  // Database: SQLAlchemy
  { pattern: /\.session\.(add|add_all|delete|merge|commit|flush|execute)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'SQLAlchemy ORM write' },
  { pattern: /\.objects\.(update|create|delete|get_or_create|bulk_create|bulk_update)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM queryset write' },
  { pattern: /\.objects\.(filter|all|get|first|last|select_related|prefetch_related)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'ORM queryset read' },
  { pattern: /\.(bulk_create|bulk_update)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM bulk write' },
  // Database: MongoDB
  { pattern: /\.(insert_one|insert_many|update_one|update_many|delete_one|delete_many|replace_one|bulk_write)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB mutation' },
  { pattern: /\.(find_one|find|aggregate|count_documents|distinct)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'MongoDB read' },
  // Database: Redis
  { pattern: /\.(set|hset|lpush|rpush|sadd|zadd|delete|hdel|expire|setex|incr|decr|append|mset|msetnx)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Redis write' },
  { pattern: /\.(get|hget|hgetall|lrange|smembers|zrange|keys|exists|ttl|mget)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Redis read' },
  { pattern: /\.(flushdb|flushall)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Redis flush' },
  // Database: misc inserts
  { pattern: /\.insert$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database insert' },

  // File: open() with write modes
  { pattern: /^open$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File open' },
  // pathlib write operations
  { pattern: /\.(write_text|write_bytes)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write' },
  { pattern: /\.mkdir$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Directory creation' },
  { pattern: /\.touch$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File create' },
  { pattern: /\.(write|writelines)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File handle write' },
  { pattern: /^shutil\.(copy|copy2|copyfile|copyfileobj|copytree|move|make_archive)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File copy/move' },
  { pattern: /^os\.(rename|renames|replace|link|symlink)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File rename/link' },
  { pattern: /^os\.(makedirs|mkdir)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Directory creation' },
  { pattern: /^os\.(chmod|chown)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File permission change' },
  { pattern: /\.extractall$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Archive extraction' },

  // File: read operations
  { pattern: /\.(read_text|read_bytes)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read' },
  { pattern: /\.(read|readline|readlines)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read' },
  { pattern: /\.(glob|rglob|iterdir)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory listing' },
  { pattern: /^os\.(listdir|scandir|walk)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory listing' },

  // Email sending
  { pattern: /^smtplib\.SMTP$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'SMTP connection' },
  { pattern: /\.(sendmail|send_message|send_email)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email send' },

  // Database reads - fetchall/fetchone still included
  { pattern: /\.(fetchall|fetchone|fetchmany)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database fetch' },

];

const SEMANTIC_DANGEROUS_OPERATION_PATTERNS: {
  identity: RegExp;
  category: ExecutionCategory;
  severity: Severity;
  description: string;
}[] = [
  { identity: /^builtins\.(eval|exec)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Built-in dynamic code execution' },
  { identity: /^subprocess\.(run|Popen|call|check_output|check_call|getoutput|getstatusoutput)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Subprocess execution' },
  { identity: /^asyncio\.create_subprocess_(exec|shell)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Async subprocess execution' },
  { identity: /^os\.(system|popen|popen2|popen3|popen4|exec.*|spawn[lv]p?e?)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'OS process execution' },
  { identity: /^shutil\.rmtree$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Recursive directory deletion' },
  { identity: /^os\.(remove|unlink|rmdir|removedirs)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion' },
  { identity: /^pathlib\.Path(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(unlink|rmdir)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Path deletion' },
  { identity: /^pathlib\.Path(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(write_text|write_bytes|mkdir|touch)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Path state change' },
  { identity: /^pathlib\.Path(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(read_text|read_bytes|glob|rglob|iterdir)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Path read/list operation' },
  { identity: /^builtins\.open$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Built-in file open' },
  { identity: /^builtins\.open\.(write|writelines)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File handle write' },
  { identity: /^builtins\.open\.(read|readline|readlines)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File handle read' },
  { identity: /^requests\.(get)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP GET request' },
  { identity: /^requests\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP write request' },
  { identity: /^requests\.Session\.(get)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP session GET request' },
  { identity: /^requests\.Session\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP session write request' },
  { identity: /^httpx\.(get)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP GET request' },
  { identity: /^httpx\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP write request' },
  { identity: /^httpx\.Client\.(get)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP client GET request' },
  { identity: /^httpx\.Client\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP client write request' },
  { identity: /^httpx\.AsyncClient\.(get)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Async HTTP client GET request' },
  { identity: /^httpx\.AsyncClient\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Async HTTP client write request' },
  { identity: /^aiohttp\.ClientSession\.(get)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Async HTTP GET request' },
  { identity: /^aiohttp\.ClientSession\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Async HTTP write request' },
  { identity: /^urllib\.request\.(urlopen|Request|urlretrieve)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'URL request' },
  { identity: /^smtplib\.SMTP$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'SMTP connection' },
  { identity: /^smtplib\.SMTP(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(sendmail|send_message)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email sending' },
  { identity: /^(sqlite3|psycopg2)(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.executescript$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'SQL script execution' },
  { identity: /^(sqlite3|psycopg2)(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.executemany$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Batch SQL execution' },
  { identity: /^(sqlite3|psycopg2)(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.execute$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'SQL execution' },
  { identity: /^(sqlite3|psycopg2)(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.fetch(one|all|many)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database fetch' },
  { identity: /^(sqlite3|psycopg2)(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.commit$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database commit' },
  { identity: /^redis\.Redis(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(set|expire|delete)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Redis write or delete' },
  { identity: /^redis\.Redis(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(flushdb|flushall)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Redis flush' },
  { identity: /^redis\.Redis(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(get|keys)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Redis read or enumeration' },

  // ==================== ADDITIONAL HTTP CLIENTS ====================
  // urllib3 - low-level HTTP client
  { identity: /^urllib3\.HTTPConnectionPool\.(urlopen|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'urllib3 HTTP request' },
  { identity: /^urllib3\.PoolManager\.(urlopen|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'urllib3 HTTP request' },
  // http.client - standard library
  { identity: /^http\.client\.HTTPConnection\.(request|putrequest|endheaders)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'http.client request' },
  { identity: /^http\.client\.HTTPSConnection\.(request|putrequest|endheaders)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'https request' },
  // httpcore - async HTTP
  { identity: /^httpcore\.(Request|AsyncRequest)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'httpcore request' },
  // treq - Twisted HTTP
  { identity: /^treq\.(get|post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Twisted HTTP request' },
  // asks - curio/trio HTTP
  { identity: /^asks\.(get|post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'asks async HTTP request' },
  // niquests - modern requests fork
  { identity: /^niquests\.(get|post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'niquests HTTP request' },
  { identity: /^niquests\.Session\.(get|post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'niquests session request' },

  // ==================== ADDITIONAL DATABASE CLIENTS ====================
  // asyncpg - async PostgreSQL
  { identity: /^asyncpg\.Connection\.(execute|executemany|fetch|fetchrow|fetchval)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'asyncpg database operation' },
  { identity: /^asyncpg\.Pool\.(execute|executemany|fetch|fetchrow|fetchval)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'asyncpg pool operation' },
  // aiomysql - async MySQL
  { identity: /^aiomysql\.Connection\.(execute|cursor)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'aiomysql database operation' },
  { identity: /^aiomysql\.Cursor\.(execute|executemany|fetchone|fetchall|fetchmany)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'aiomysql cursor operation' },
  // databases - async database interface
  { identity: /^databases\.Database\.(execute|fetch_one|fetch_all|fetch_val|iterate)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'databases async operation' },
  // peewee - lightweight ORM
  { identity: /^peewee\.Model\.(create|save|delete_instance|get_or_create)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Peewee model operation' },
  { identity: /^peewee\.\w+\.(insert|update|delete)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Peewee query operation' },
  // tortoise-orm - async ORM
  { identity: /^tortoise\.Model\.(save|delete|create|update|bulk_create|bulk_update)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Tortoise ORM operation' },
  { identity: /^tortoise\.queryset\.QuerySet\.(update|delete|create)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Tortoise queryset operation' },
  // SQLModel - FastAPI/Pydantic ORM
  { identity: /^sqlmodel\.Session\.(add|add_all|delete|commit|exec)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'SQLModel session operation' },
  // motor - async MongoDB
  { identity: /^motor\.motor_asyncio\.\w+\.(insert_one|insert_many|update_one|update_many|delete_one|delete_many|replace_one)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Motor async MongoDB operation' },
  // pymongo additional
  { identity: /^pymongo\.collection\.Collection\.(insert_one|insert_many|update_one|update_many|delete_one|delete_many|replace_one|bulk_write)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'PyMongo collection operation' },

  // ==================== MESSAGE QUEUES ====================
  // Celery
  { identity: /^celery\.Celery\.(send_task|signature)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Celery task dispatch' },
  { identity: /^celery\.Task\.(apply_async|delay|s|si)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Celery task invocation' },
  // RQ (Redis Queue)
  { identity: /^rq\.Queue\.(enqueue|enqueue_call|enqueue_at|enqueue_in)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'RQ task enqueue' },
  // Pika (RabbitMQ)
  { identity: /^pika\.channel\.Channel\.(basic_publish|publish)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'RabbitMQ message publish' },
  // Kafka
  { identity: /^kafka\.KafkaProducer\.(send|send_and_wait)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Kafka message send' },
  { identity: /^confluent_kafka\.Producer\.(produce|poll|flush)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Confluent Kafka produce' },

  // ==================== CLOUD SERVICES ====================
  // AWS boto3
  { identity: /^boto3\.client\.(put_object|delete_object|upload_file|upload_fileobj)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS S3 write operation' },
  { identity: /^boto3\.resource\..*\.(put|delete|upload_file|upload_fileobj)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS resource write' },
  // Google Cloud
  { identity: /^google\.cloud\.storage\.Blob\.(upload_from_string|upload_from_filename|upload_from_file|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'GCS blob write/delete' },
  // Azure
  { identity: /^azure\.storage\.blob\.BlobClient\.(upload_blob|delete_blob)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Azure blob write/delete' },

  // ==================== ADDITIONAL SHELL/PROCESS ====================
  // sh library
  { identity: /^sh\.\w+$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'sh library command execution' },
  // plumbum
  { identity: /^plumbum\.local\.\w+$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Plumbum local command' },
  { identity: /^plumbum\.machines\..*\.session\.run$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Plumbum remote execution' },
  // invoke
  { identity: /^invoke\.run$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Invoke task runner command' },
  { identity: /^invoke\.context\.Context\.run$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Invoke context command' },

  // ==================== NETWORK ====================
  // socket - raw network access
  { identity: /^socket\.socket\.(connect|send|sendall|sendto)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Raw socket operation' },
  // paramiko - SSH
  { identity: /^paramiko\.SSHClient\.(exec_command|invoke_shell)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'SSH command execution' },
  { identity: /^paramiko\.SFTPClient\.(put|putfo|remove|rmdir|rename)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'SFTP write operation' },

];

/**
 * Exception types that indicate authorization/permission denial.
 * If a function raises these conditionally, it may be a policy gate.
 */
const AUTHORIZATION_EXCEPTION_TYPES = [
  'PermissionError',
  'AuthorizationError',
  'UnauthorizedError',
  'AccessDenied',
  'Forbidden',
  'PermissionDenied',
  'NotAuthorized',
  'SecurityError',
  // Additional common patterns
  'AuthError',
  'AuthenticationError',
  'AccessError',
  'CredentialsError',
  'TokenError',
  'InvalidTokenError',
  'ExpiredTokenError',
  'InsufficientPermissions',
  'AccessDeniedException',
  'NotAuthorizedException',
  'UnauthorizedException',
  'ForbiddenError',
  'ForbiddenException',
  'PermissionException',
  'AuthorizationException',
  'SecurityException',
  'PolicyViolation',
  'PolicyError',
];

/**
 * Pattern-based authorization exception detection.
 * Matches exception names that contain auth/permission/access keywords.
 */
const AUTHORIZATION_EXCEPTION_PATTERNS = [
  /\b(auth|permission|access|forbidden|unauthorized|denied|security|credential|token|policy)\b/i,
  /\b(not_?allowed|no_?access|invalid_?auth|require_?auth|check_?auth)\b/i,
];

/**
 * Check if an exception type indicates authorization denial.
 * Uses both explicit list and pattern matching for flexibility.
 */
function isAuthorizationException(exceptionType: string): boolean {
  // Normalize the exception type
  const normalized = exceptionType.toLowerCase().replace(/[_-]/g, '');

  // Check explicit list (case-insensitive)
  if (AUTHORIZATION_EXCEPTION_TYPES.some(t => normalized.includes(t.toLowerCase().replace(/[_-]/g, '')))) {
    return true;
  }

  // Check patterns for custom exception names
  return AUTHORIZATION_EXCEPTION_PATTERNS.some(pattern => pattern.test(exceptionType));
}

// NOTE: KNOWN_AUTHORIZATION_DECORATORS removed in v1.2.2.
// Gate detection is now purely structural - requires conditional branches,
// parameter checks, and authorization exception raises. Decorator naming
// alone does not credit a gate.

// NOTE: VALIDATION_HELPER_PATTERNS removed in v1.2.2.
// Severity is now determined solely by operation category.
// Naming heuristics do not adjust severity.
// isLikelyValidationHelper() function removed in v1.4.0.

/**
 * Determine if a function is a structural policy gate.
 *
 * STRICT THREE-PROPERTY VALIDATION (per AFB specification):
 *
 * A real gate has ALL THREE of these properties:
 * 1. It sits between tool registration and dangerous operation in call path
 *    (checked externally in findDangerousPathsFromNode)
 * 2. It receives the operation, its parameters, or the principal as input
 *    (checked here via checksParameters)
 * 3. It has a branch that can PREVENT the dangerous operation from executing
 *    (checked here via strict execution prevention)
 *
 * NOT gates:
 * - A conditional that does something else and then calls the operation anyway
 * - A try/except around the dangerous operation
 * - A logging call before the operation
 * - A type check that doesn't prevent execution on failure
 *
 * IS a gate:
 * - Raises PermissionError/AuthorizationError when condition fails
 * - Returns False/None and caller checks the result before executing operation
 * - Exits function without calling operation when condition fails
 */
function isStructuralPolicyGate(controlFlow: ControlFlowInfo | undefined): boolean {
  if (!controlFlow) {
    return false;
  }

  // PROPERTY #3: Must have conditional branches
  if (!controlFlow.hasConditionalBranches) {
    return false;
  }

  // PROPERTY #3: Must be able to prevent execution via raise or early return
  const canPreventExecution = controlFlow.hasConditionalRaise || controlFlow.hasConditionalReturn;
  if (!canPreventExecution) {
    return false;
  }

  // PROPERTY #2: Must check input parameters
  // Without this, it's not receiving operation context
  if (!controlFlow.checksParameters) {
    return false;
  }

  // STRICT: Require authorization-related exception types
  // A generic ValueError or TypeError is not sufficient for gate detection
  // Uses pattern-based matching to catch custom auth exceptions
  const raisesAuthException = controlFlow.raiseTypes.some((type) =>
    isAuthorizationException(type)
  );

  // Gate detection is ALL THREE properties:
  // - Has conditional branches (checked above)
  // - Checks parameters (checked above)
  // - Can prevent execution via auth exception OR early return
  //
  // If uncertain (no auth exception but has early return), do NOT credit as gate
  // Per spec: "If gate detection is uncertain, do not credit a gate"
  return raisesAuthException;
}

/**
 * Resolve a Python module path to a file path.
 *
 * Given a module path like "utils.auth" and a base directory,
 * returns the resolved file path like "/project/utils/auth.py".
 *
 * This supports transitive resolution when used as part of the
 * cross-file import map building process.
 */
function resolveModulePath(
  modulePath: string,
  currentFilePath: string,
  allFilePaths: string[]
): string | undefined {
  // Convert module path to potential file paths
  const moduleAsPath = modulePath.replace(/\./g, '/');
  const currentDir = path.dirname(currentFilePath);

  // Try relative import first (from . or from ..)
  if (modulePath.startsWith('.')) {
    const dots = modulePath.match(/^\.+/)?.[0].length || 0;
    let baseDir = currentDir;
    for (let i = 1; i < dots; i++) {
      baseDir = path.dirname(baseDir);
    }
    const relativeModule = modulePath.slice(dots).replace(/\./g, '/');
    const candidates = [
      path.join(baseDir, relativeModule + '.py'),
      path.join(baseDir, relativeModule, '__init__.py'),
    ];
    for (const candidate of candidates) {
      const normalized = path.normalize(candidate);
      if (allFilePaths.includes(normalized)) {
        return normalized;
      }
    }
  }

  // Try absolute import from common roots
  const possibleRoots = new Set<string>();
  for (const filePath of allFilePaths) {
    // Find common package roots
    const parts = filePath.split(path.sep);
    for (let i = 0; i < parts.length - 1; i++) {
      if (parts[i] === 'src' || parts[i] === 'lib' || parts[i] === 'packages' || parts[i] === 'backend') {
        possibleRoots.add(parts.slice(0, i + 1).join(path.sep));
      }
    }
    // Also try from dirname
    possibleRoots.add(path.dirname(filePath));
  }

  for (const root of possibleRoots) {
    const candidates = [
      path.join(root, moduleAsPath + '.py'),
      path.join(root, moduleAsPath, '__init__.py'),
    ];
    for (const candidate of candidates) {
      const normalized = path.normalize(candidate);
      if (allFilePaths.includes(normalized)) {
        return normalized;
      }
    }
  }

  return undefined;
}

/**
 * Build a cross-file import map from parsed files.
 *
 * This maps imported names to their source files, enabling
 * resolution of function calls to their definitions across files.
 */
function buildCrossFileImportMap(
  files: Map<string, ParsedPythonFile>,
  allFilePaths: string[]
): CrossFileImportMap {
  const fileImports = new Map<string, ResolvedImport[]>();
  const nameToFile = new Map<string, string>();
  const nameToNodeId = new Map<string, string>();

  for (const [filePath, parsed] of files) {
    const resolvedImports: ResolvedImport[] = [];

    for (const imp of parsed.imports) {
      const resolvedFile = resolveModulePath(imp.module, filePath, allFilePaths);

      if (imp.isFrom) {
        // from module import name1, name2
        for (const { name, alias } of imp.names) {
          const resolved: ResolvedImport = {
            name,
            alias,
            modulePath: imp.module,
            resolved: resolvedFile !== undefined,
            resolvedFile,
          };
          resolvedImports.push(resolved);

          if (resolvedFile) {
            const key = `${filePath}:${alias || name}`;
            nameToFile.set(key, resolvedFile);
          }
        }
      } else {
        // import module
        const resolved: ResolvedImport = {
          name: imp.module,
          alias: imp.names[0]?.alias,
          modulePath: imp.module,
          resolved: resolvedFile !== undefined,
          resolvedFile,
        };
        resolvedImports.push(resolved);

        if (resolvedFile) {
          const key = `${filePath}:${imp.names[0]?.alias || imp.module}`;
          nameToFile.set(key, resolvedFile);
        }
      }
    }

    fileImports.set(filePath, resolvedImports);
  }

  // Second pass: map imported names to their actual node IDs
  for (const [filePath, imports] of fileImports) {
    for (const imp of imports) {
      if (!imp.resolved || !imp.resolvedFile) continue;

      const targetParsed = files.get(imp.resolvedFile);
      if (!targetParsed) continue;

      // Find the function/class in the target file
      const func = targetParsed.functions.find(f => f.name === imp.name);
      if (func) {
        const nodeId = func.className
          ? `${func.className}.${func.name}`
          : func.name;
        const key = `${filePath}:${imp.alias || imp.name}`;
        nameToNodeId.set(key, `${imp.resolvedFile}:${nodeId}`);
      }

      // Also check classes
      const cls = targetParsed.classes.find(c => c.name === imp.name);
      if (cls) {
        const key = `${filePath}:${imp.alias || imp.name}`;
        nameToNodeId.set(key, `${imp.resolvedFile}:${cls.name}`);
      }
    }
  }

  return { fileImports, nameToFile, nameToNodeId };
}

/**
 * Try to resolve a call to a cross-file import.
 * Returns the resolved node ID if found, undefined otherwise.
 */
function resolveCrossFileCall(
  callee: string,
  currentFilePath: string,
  importMap: CrossFileImportMap,
  files: Map<string, ParsedPythonFile>
): { nodeId: string; sourceFile: string } | undefined {
  // Check if the callee matches an imported name
  const baseName = callee.split('.')[0];
  const key = `${currentFilePath}:${baseName}`;

  const sourceFile = importMap.nameToFile.get(key);
  if (!sourceFile) return undefined;

  const targetParsed = files.get(sourceFile);
  if (!targetParsed) return undefined;

  // If callee is "module.func", try to find func in the target file
  if (callee.includes('.')) {
    const parts = callee.split('.');
    const funcName = parts[parts.length - 1];

    // Look for the function in the target file
    const func = targetParsed.functions.find(f => f.name === funcName);
    if (func) {
      const nodeId = func.className
        ? `${func.className}.${func.name}`
        : func.name;
      return { nodeId: `${sourceFile}:${nodeId}`, sourceFile };
    }

    // Look in classes for methods
    for (const cls of targetParsed.classes) {
      if (parts.includes(cls.name)) {
        const methodName = parts[parts.length - 1];
        const method = cls.methods.find(m => m.name === methodName);
        if (method) {
          return { nodeId: `${sourceFile}:${cls.name}.${methodName}`, sourceFile };
        }
      }
    }
  } else {
    // Direct function call of imported name
    const func = targetParsed.functions.find(f => f.name === callee);
    if (func) {
      const nodeId = func.className
        ? `${func.className}.${func.name}`
        : func.name;
      return { nodeId: `${sourceFile}:${nodeId}`, sourceFile };
    }
  }

  return undefined;
}

/**
 * Build a call graph from parsed Python files
 *
 * Supports transitive cross-file resolution up to configurable depth (default: 3).
 * When a function call cannot be resolved in the current file,
 * it tries to resolve through imports to find the definition.
 * Resolution continues transitively through imported modules.
 *
 * When the depth limit is hit on an unresolved call path, a SUPPRESSED
 * finding is emitted with a note explaining that deeper tracing was not performed.
 */
export function buildCallGraph(
  files: Map<string, ParsedPythonFile>,
  config: ImportResolutionConfig = DEFAULT_IMPORT_CONFIG
): CallGraphAnalysis {
  const nodes = new Map<string, CallGraphNode>();
  const toolRegistrations: CallGraphNode[] = [];
  const exposedPaths: ExposedPath[] = [];

  // Get all file paths for cross-file resolution
  const allFilePaths = Array.from(files.keys());
  const semanticIndex = new PythonSemanticIndex(files);
  const semanticRoots = semanticIndex.extractInvocationRoots();

  // Build cross-file import map
  const importMap = buildCrossFileImportMap(files, allFilePaths);

  // First pass: create nodes for all functions and classes
  // Use file-prefixed IDs for cross-file uniqueness
  for (const [filePath, parsed] of files) {
    // Process standalone functions
    for (const func of parsed.functions) {
      const localId = func.className
        ? `${func.className}.${func.name}`
        : func.name;
      const globalId = `${filePath}:${localId}`;

      // A function has a policy gate if:
      // 1. Its own control flow is a structural gate, OR
      // 2. It has a decorator that acts as a structural gate (from same file)
      // NOTE: Decorator naming heuristics removed in v1.2.2. Gate credit requires
      // structural proof only.
      const hasStructuralGate = isStructuralPolicyGate(func.controlFlow);
      const hasDecoratorGate = (func.hasDecoratorGate || false) || hasImportedStructuralDecoratorGate(func.decorators, filePath, importMap, files);

      const node: CallGraphNode = {
        id: globalId,
        name: func.name,
        className: func.className,
        startLine: func.startLine,
        endLine: func.endLine,
        decorators: func.decorators,
        callees: new Set(),
        callers: new Set(),
        isToolRegistration: false,
        dangerousOps: [],
        // Full gate credit requires structural proof in the analyzed code path.
        hasPolicyGate: hasStructuralGate || hasDecoratorGate,
        hasHeuristicGateIndicator: false, // Removed in v1.2.2
        // Check if this function name suggests it's a validation helper
        isValidationHelper: false, // v1.2.2: Always false, naming heuristics removed
        controlFlow: func.controlFlow,
        sourceFile: filePath,
        parameters: func.parameters,
        outgoingCalls: [],
      };

      // Prefer semantic framework roots; keep pattern-based registration as fallback.
      const toolInfo = getToolRegistrationInfo(
        globalId,
        semanticRoots,
        func,
        parsed.imports,
        parsed.openaiToolSchemas,
        parsed.dispatchMappings
      );
      if (toolInfo) {
        node.isToolRegistration = true;
        node.framework = toolInfo.framework;
        node.toolDetectionKind = toolInfo.kind;
        node.toolDetectionEvidence = toolInfo.evidence;
        toolRegistrations.push(node);
      }

      nodes.set(globalId, node);
    }

    // Process class definitions
    for (const cls of parsed.classes) {
      // NOTE: detectToolClass removed in v1.2.2. Class-based tool detection
      // now goes through semantic root extraction only.

      for (const method of cls.methods) {
        const localId = `${cls.name}.${method.name}`;
        const globalId = `${filePath}:${localId}`;
        const toolInfo = getToolRegistrationInfo(
          globalId,
          semanticRoots,
          method,
          parsed.imports,
          parsed.openaiToolSchemas,
          parsed.dispatchMappings
        );

        // A method has a policy gate if:
        // 1. Its own control flow is a structural gate, OR
        // 2. It has a decorator that acts as a structural gate (from same file)
        // NOTE: Decorator naming heuristics removed in v1.2.2.
        const hasStructuralGate = isStructuralPolicyGate(method.controlFlow);
        const hasDecoratorGate = (method.hasDecoratorGate || false) || hasImportedStructuralDecoratorGate(method.decorators, filePath, importMap, files);

        const node: CallGraphNode = {
          id: globalId,
          name: method.name,
          className: cls.name,
          startLine: method.startLine,
          endLine: method.endLine,
          decorators: method.decorators,
          callees: new Set(),
          callers: new Set(),
          isToolRegistration: toolInfo !== null && (toolInfo.kind === 'semantic' || method.name === '_run' || method.name === 'run' || method.name === 'invoke' || method.name === '_execute' || method.name === 'execute'),
          framework: toolInfo?.framework,
          toolDetectionKind: toolInfo?.kind,
          toolDetectionEvidence: toolInfo?.evidence,
          dangerousOps: [],
          // Full gate credit requires structural proof in the analyzed code path.
          hasPolicyGate: hasStructuralGate || hasDecoratorGate,
          hasHeuristicGateIndicator: false, // Removed in v1.2.2
          // Check if this method name suggests it's a validation helper
          isValidationHelper: false, // v1.2.2: Always false, naming heuristics removed
          controlFlow: method.controlFlow,
          sourceFile: filePath,
          parameters: method.parameters,
          outgoingCalls: [],
        };

        if (node.isToolRegistration) {
          toolRegistrations.push(node);
        }

        nodes.set(globalId, node);
      }
    }
  }

  // Second pass: populate call edges and detect dangerous operations
  // Now with cross-file resolution support
  for (const [filePath, parsed] of files) {
    for (const call of parsed.calls) {
      // Find the enclosing function node with file-prefixed ID
      let callerId: string | undefined;
      if (call.enclosingClass && call.enclosingFunction) {
        callerId = `${filePath}:${call.enclosingClass}.${call.enclosingFunction}`;
      } else if (call.enclosingFunction) {
        callerId = `${filePath}:${call.enclosingFunction}`;
      }

      if (callerId && nodes.has(callerId)) {
        const callerNode = nodes.get(callerId)!;

        // Try to resolve the callee
        // First, check if it's a local function (same file)
        let resolvedCalleeIds: string[] = [];
        const localCalleeId = `${filePath}:${call.callee}`;

        if (nodes.has(localCalleeId)) {
          resolvedCalleeIds = [localCalleeId];
        } else {
          resolvedCalleeIds = semanticIndex.resolveCallableNodeIds(
            call.callee,
            filePath,
            call.enclosingClass,
            call.enclosingFunction
          );

          if (resolvedCalleeIds.length === 0) {
            // Try cross-file resolution fallback
            const crossFileResult = resolveCrossFileCall(
              call.callee,
              filePath,
              importMap,
              files
            );
            if (crossFileResult) {
              resolvedCalleeIds = [crossFileResult.nodeId];
            }
          }
        }

        if (resolvedCalleeIds.length > 0) {
          for (const resolvedCalleeId of resolvedCalleeIds) {
            callerNode.callees.add(resolvedCalleeId);
            callerNode.outgoingCalls.push({ targetId: resolvedCalleeId, call });

            if (nodes.has(resolvedCalleeId)) {
              const calleeNode = nodes.get(resolvedCalleeId)!;
              calleeNode.callers.add(callerId);
            }
          }
        } else {
          callerNode.callees.add(call.callee);
          callerNode.outgoingCalls.push({ call });
        }

        // Check if this call is a dangerous operation
        const dangerousOp = detectDangerousOperation(call, callerId, filePath, semanticIndex);
        if (dangerousOp) {
          callerNode.dangerousOps.push(dangerousOp);
        }
      }
    }
  }

  // Third pass: trace paths from tool registrations to dangerous operations
  for (const tool of toolRegistrations) {
    const visited = new Set<string>();
    const paths = findDangerousPathsFromNode(
      tool,
      nodes,
      visited,
      [tool.id],
      [],
      config,
      0
    );

    if (paths.length > 0) {
      for (const { operation, path, hasGate, involvesCrossFile, unresolvedCalls, depthLimitHit } of paths) {
        const file = operation.sourceFile || tool.sourceFile || '<unknown>';
        const flowEvidence = analyzePathFlow(tool, path, operation, nodes, files);

        const hasValidationHelperInPath = path.some(nodeId => {
          const node = nodes.get(nodeId);
          return node?.isValidationHelper || false;
        });
        const hasHeuristicGateInPath = path.some((nodeId) => {
          const node = nodes.get(nodeId);
          return node?.hasHeuristicGateIndicator || false;
        });
        const supportingEvidence = [...(flowEvidence.supportingEvidence || [])];
        if (tool.toolDetectionEvidence) {
          supportingEvidence.unshift(`Tool registration evidence: ${tool.toolDetectionEvidence}`);
        }
        if (operation.detectionEvidence) {
          supportingEvidence.push(`Operation evidence: ${operation.detectionEvidence}`);
        }
        if (hasHeuristicGateInPath) {
          supportingEvidence.push('Authorization-like decorator names were present, but no structural gate was proven in the analyzed path');
        }

        const evidenceKind = determinePathEvidenceKind(tool.toolDetectionKind, operation.detectionKind, flowEvidence.inputFlowsToOperation);

        exposedPaths.push({
          tool,
          operation,
          path,
          hasGateInPath: hasGate,
          hasHeuristicGateInPath,
          hasValidationHelperInPath,
          file,
          involvesCrossFile,
          unresolvedCrossFileCalls: unresolvedCalls,
          depthLimitHit,
          inputFlowsToOperation: flowEvidence.inputFlowsToOperation,
          instructionLikeInput: flowEvidence.instructionLikeInput,
          resourceHint: operation.resourceHint,
          changesState: operation.changesState,
          supportingEvidence,
          evidenceKind,
        });
      }
    } else {
      // STEP 5: Emit a registration-level CEE when no dangerous operation is traced.
      // Every identified tool produces at least one CEE for audit completeness.
      const unresolvedCalls: string[] = [];
      for (const outgoing of tool.outgoingCalls) {
        if (!outgoing.targetId) {
          unresolvedCalls.push(outgoing.call.callee);
        }
      }
      const registrationOp: DangerousOperation = {
        callee: `agent-tool-registration:${tool.name}`,
        category: ExecutionCategory.TOOL_CALL,
        severity: Severity.INFO,
        line: tool.startLine,
        column: 0,
        codeSnippet: tool.name,
        sourceFile: tool.sourceFile,
        changesState: false,
        detectionKind: 'semantic',
        detectionEvidence: tool.toolDetectionEvidence || `Tool registration: ${tool.framework || 'unknown'}`,
      };

      exposedPaths.push({
        tool,
        operation: registrationOp,
        path: [tool.id],
        hasGateInPath: tool.hasPolicyGate,
        hasHeuristicGateInPath: false,
        hasValidationHelperInPath: false,
        file: tool.sourceFile || '<unknown>',
        involvesCrossFile: false,
        unresolvedCrossFileCalls: unresolvedCalls,
        depthLimitHit: false,
        inputFlowsToOperation: false,
        instructionLikeInput: false,
        resourceHint: undefined,
        changesState: false,
        supportingEvidence: [
          `Tool registration evidence: ${tool.toolDetectionEvidence || tool.framework || 'structural'}`,
          `No external operations traced from this entry point.`,
        ],
        evidenceKind: 'semantic',
      });
    }
  }

  return {
    nodes,
    toolRegistrations,
    exposedPaths,
  };
}

/**
 * Check if imports include OpenAI SDK
 */
function hasOpenAIImport(imports: ImportInfo[]): boolean {
  return imports.some(imp =>
    imp.module.toLowerCase().includes('openai') ||
    imp.names.some(n => n.name.toLowerCase().includes('openai'))
  );
}

/**
 * Check if imports include AutoGen
 */
function hasAutoGenImport(imports: ImportInfo[]): boolean {
  return imports.some(imp =>
    imp.module.toLowerCase().includes('autogen') ||
    imp.names.some(n => n.name.toLowerCase().includes('autogen') ||
                       n.name.toLowerCase().includes('userproxyagent') ||
                       n.name.toLowerCase().includes('assistantagent'))
  );
}

// NOTE: detectToolRegistration removed in v1.2.2.
// Tool detection relies on semantic root extraction only.

function getToolRegistrationInfo(
  nodeId: string,
  semanticRoots: Map<string, SemanticInvocationRoot>,
  func: FunctionDef,
  imports: ImportInfo[],
  openaiToolSchemas: OpenAIToolSchema[] = [],
  dispatchMappings: FunctionDispatchMapping[] = []
): { framework: string; kind: 'semantic' | 'heuristic'; evidence: string } | null {
  const semanticRoot = semanticRoots.get(nodeId);
  if (semanticRoot) {
    return {
      framework: semanticRoot.framework,
      kind: 'semantic',
      evidence: semanticRoot.evidence,
    };
  }

  // NOTE: Pattern-based fallback removed in v1.2.2.
  // If semantic resolution fails, we do not detect the tool.
  // A missed finding is acceptable; a false finding is not.
  return null;
}

// NOTE: detectToolClass removed in v1.2.2.
// Class inheritance detection relied on TOOL_REGISTRATION_PATTERNS.
// Tool detection now goes through semantic root extraction only.

/**
 * Detect if a call is a dangerous operation
 *
 * For open() calls, checks the mode argument to determine if write (WARNING)
 * or read (INFO). Default mode 'r' is read.
 */
function detectDangerousOperation(
  call: CallSite,
  callerId: string,
  filePath: string,
  semanticIndex: PythonSemanticIndex
): DangerousOperation | null {
  const semanticCall = semanticIndex.resolveCallIdentity(call, filePath, call.enclosingClass);
  const semanticDangerousOp = detectSemanticDangerousOperation(call, callerId, filePath, semanticCall);
  if (semanticDangerousOp) {
    return semanticDangerousOp;
  }

  for (const pattern of DANGEROUS_OPERATION_PATTERNS) {
    if (pattern.pattern.test(call.callee)) {
      const severity = adjustSeverityForOpen(call, pattern.severity);

      return {
        callee: call.callee,
        category: pattern.category,
        severity,
        line: call.startLine,
        column: call.startColumn,
        codeSnippet: call.codeSnippet,
        sourceFile: filePath,
        enclosingNodeId: callerId,
        argumentDetails: call.argumentDetails,
        resourceHint: summarizeOperationResource(call),
        changesState: severity === Severity.WARNING || severity === Severity.CRITICAL,
        detectionKind: 'heuristic',
        detectionEvidence: `pattern fallback matched ${pattern.pattern}`,
      };
    }
  }
  return null;
}

function detectSemanticDangerousOperation(
  call: CallSite,
  callerId: string,
  filePath: string,
  semanticCall: SemanticCallIdentity | undefined
): DangerousOperation | null {
  if (!semanticCall) {
    return null;
  }

  for (const pattern of SEMANTIC_DANGEROUS_OPERATION_PATTERNS) {
    if (!pattern.identity.test(semanticCall.identity)) {
      continue;
    }

    const severity = adjustSeverityForOpen(call, pattern.severity, semanticCall.identity);
    return {
      callee: semanticCall.identity,
      category: pattern.category,
      severity,
      line: call.startLine,
      column: call.startColumn,
      codeSnippet: call.codeSnippet,
      sourceFile: filePath,
      enclosingNodeId: callerId,
      argumentDetails: call.argumentDetails,
      resourceHint: summarizeOperationResource(call),
      changesState: severity === Severity.WARNING || severity === Severity.CRITICAL,
      detectionKind: semanticCall.kind === 'structural' ? 'semantic' : 'semantic',
      detectionEvidence: semanticCall.evidence,
      resolvedIdentity: semanticCall.identity,
    };
  }

  return null;
}

function adjustSeverityForOpen(call: CallSite, baseSeverity: Severity, resolvedIdentity?: string): Severity {
  if (call.callee !== 'open' && resolvedIdentity !== 'builtins.open') {
    return baseSeverity;
  }

  const modeArgument = call.argumentDetails.find((arg) => arg.name === 'mode') || call.argumentDetails.filter((arg) => !arg.name)[1];
  const modeValue = modeArgument?.value.stringLiterals[0] || modeArgument?.value.text || '';
  if (/[wax+]/i.test(modeValue)) {
    return Severity.WARNING;
  }

  return Severity.INFO;
}

function determinePathEvidenceKind(
  toolDetectionKind: 'semantic' | 'heuristic' | undefined,
  operationDetectionKind: 'semantic' | 'heuristic' | undefined,
  inputFlowsToOperation: boolean
): 'structural' | 'semantic' | 'heuristic' {
  if (toolDetectionKind === 'heuristic' || operationDetectionKind === 'heuristic') {
    return 'heuristic';
  }

  if (inputFlowsToOperation) {
    return 'structural';
  }

  return 'semantic';
}

function summarizeOperationResource(call: CallSite): string | undefined {
  for (const arg of call.argumentDetails) {
    const candidate = arg.value.stringLiterals[0] || arg.value.references[0];
    if (candidate) {
      return candidate;
    }
  }

  return undefined;
}

function hasImportedStructuralDecoratorGate(
  decorators: string[],
  filePath: string,
  importMap: CrossFileImportMap,
  files: Map<string, ParsedPythonFile>
): boolean {
  const imports = importMap.fileImports.get(filePath) || [];

  for (const decorator of decorators) {
    const baseName = decorator.split('(')[0].trim();
    const imported = imports.find((imp) => (imp.alias || imp.name) === baseName && imp.resolved && imp.resolvedFile);
    if (!imported?.resolvedFile) {
      continue;
    }

    const targetParsed = files.get(imported.resolvedFile);
    if (!targetParsed) {
      continue;
    }

    const decoratorDef = targetParsed.decoratorDefs.find((def) => def.name === imported.name);
    if (decoratorDef?.isStructuralGate) {
      return true;
    }
  }

  return false;
}

function analyzePathFlow(
  tool: CallGraphNode,
  path: string[],
  operation: DangerousOperation,
  nodes: Map<string, CallGraphNode>,
  files: Map<string, ParsedPythonFile>
): { inputFlowsToOperation: boolean; instructionLikeInput: boolean; supportingEvidence: string[] } {
  const supportingEvidence: string[] = [];
  const taintedByNode = new Map<string, Set<string>>();
  const toolInputs = new Set(tool.parameters || []);
  taintedByNode.set(tool.id, new Set(toolInputs));

  let instructionLikeInput = Array.from(toolInputs).some(isInstructionLikeName);

  for (let index = 0; index < path.length; index++) {
    const nodeId = path[index];
    const node = nodes.get(nodeId);
    if (!node?.sourceFile) {
      continue;
    }

    const parsed = files.get(node.sourceFile);
    if (!parsed) {
      continue;
    }

    const tainted = expandScopedTaint(parsed, node, taintedByNode.get(nodeId) || new Set<string>());
    taintedByNode.set(nodeId, tainted);

    const nextNodeId = path[index + 1];
    if (!nextNodeId) {
      continue;
    }

    const nextNode = nodes.get(nextNodeId);
    if (!nextNode?.parameters || nextNode.parameters.length === 0) {
      continue;
    }

    const matchingCalls = node.outgoingCalls.filter((outgoing) => outgoing.targetId === nextNodeId);
    if (matchingCalls.length === 0) {
      continue;
    }

    const nextTaint = new Set(taintedByNode.get(nextNodeId) || []);
    for (const outgoing of matchingCalls) {
      const positionalArguments = outgoing.call.argumentDetails.filter((arg) => !arg.name);
      for (let paramIndex = 0; paramIndex < nextNode.parameters.length; paramIndex++) {
        const parameterName = nextNode.parameters[paramIndex];
        const argument = outgoing.call.argumentDetails.find((arg) => arg.name === parameterName) || positionalArguments[paramIndex];
        if (!argument) {
          continue;
        }

        if (expressionTouchesTaint(argument.value, tainted)) {
          nextTaint.add(parameterName);
          supportingEvidence.push(`${node.name} passes traced input into ${nextNode.name}.${parameterName}`);
        }

        if (!instructionLikeInput && expressionLooksInstructionLike(argument.value)) {
          instructionLikeInput = true;
        }
      }
    }

    taintedByNode.set(nextNodeId, nextTaint);
  }

  const operationNode = operation.enclosingNodeId ? nodes.get(operation.enclosingNodeId) : undefined;
  const operationTaint = operationNode?.id ? (taintedByNode.get(operationNode.id) || new Set<string>()) : new Set<string>();
  const inputFlowsToOperation = Boolean(operation.argumentDetails?.some((argument) => expressionTouchesTaint(argument.value, operationTaint)));

  if (inputFlowsToOperation && operation.callee) {
    supportingEvidence.push(`Traced tool input into ${operation.callee} arguments`);
  }

  if (!instructionLikeInput && operation.argumentDetails) {
    instructionLikeInput = operation.argumentDetails.some((argument) => expressionLooksInstructionLike(argument.value));
  }

  return {
    inputFlowsToOperation,
    instructionLikeInput,
    supportingEvidence: Array.from(new Set(supportingEvidence)),
  };
}

function expandScopedTaint(parsed: ParsedPythonFile, node: CallGraphNode, seed: Set<string>): Set<string> {
  const tainted = new Set(seed);
  let changed = true;

  while (changed) {
    changed = false;
    for (const assignment of parsed.assignments) {
      if (assignment.enclosingFunction !== node.name) {
        continue;
      }

      if ((assignment.enclosingClass || undefined) !== (node.className || undefined)) {
        continue;
      }

      if (!expressionTouchesTaint(assignment.value, tainted) || tainted.has(assignment.target)) {
        continue;
      }

      tainted.add(assignment.target);
      changed = true;
    }
  }

  return tainted;
}

function expressionTouchesTaint(
  expression: { references: string[]; stringLiterals: string[] },
  tainted: Set<string>
): boolean {
  return expression.references.some((reference) => tainted.has(reference));
}

function expressionLooksInstructionLike(expression: { references: string[]; stringLiterals: string[] }): boolean {
  return expression.references.some(isInstructionLikeName) || expression.stringLiterals.some((value) => /system|prompt|instruction|history|context|message/i.test(value));
}

function isInstructionLikeName(name: string): boolean {
  return /input|prompt|message|history|context|task|query|request|instruction|content|payload|state/i.test(name);
}

/**
 * Find all dangerous operation paths from a starting node.
 * Tracks cross-file resolution and unresolved calls.
 *
 * Cross-file depth is tracked separately and limited by config.maxDepth.
 * When the cross-file depth limit is hit, a SUPPRESSED finding is emitted
 * with a note explaining that deeper tracing was not performed.
 */
function findDangerousPathsFromNode(
  node: CallGraphNode,
  allNodes: Map<string, CallGraphNode>,
  visited: Set<string>,
  currentPath: string[],
  foundPaths: { operation: DangerousOperation; path: string[]; hasGate: boolean; involvesCrossFile: boolean; unresolvedCalls: string[]; depthLimitHit?: boolean }[],
  config: ImportResolutionConfig = DEFAULT_IMPORT_CONFIG,
  currentCrossFileDepth: number = 0
): { operation: DangerousOperation; path: string[]; hasGate: boolean; involvesCrossFile: boolean; unresolvedCalls: string[]; depthLimitHit?: boolean }[] {
  // Prevent infinite loops
  if (visited.has(node.id)) {
    return foundPaths;
  }
  visited.add(node.id);

  // Track if we've seen a structural policy gate in this path
  const hasGateInPath = currentPath.some((nodeId) => {
    const n = allNodes.get(nodeId);
    return n?.hasPolicyGate || false;
  });

  // Track cross-file involvement: check if path spans multiple files
  const filesInPath = new Set<string>();
  for (const nodeId of currentPath) {
    const file = extractFileFromNodeId(nodeId);
    if (file) {
      filesInPath.add(file);
    }
  }
  const involvesCrossFile = filesInPath.size > 1;

  // Track unresolved calls
  const unresolvedCalls: string[] = [];

  // Report dangerous operations in this node
  for (const op of node.dangerousOps) {
    foundPaths.push({
      operation: op,
      path: [...currentPath],
      hasGate: hasGateInPath || node.hasPolicyGate,
      involvesCrossFile,
      unresolvedCalls: [...unresolvedCalls],
    });
  }

  // Recursively check callees (limit total depth to 20, cross-file depth to config.maxDepth)
  if (currentPath.length < 20) {
    for (const calleeId of node.callees) {
      const calleeNode = allNodes.get(calleeId);

      // Determine if this call crosses a file boundary
      const currentFile = extractFileFromNodeId(node.id) || '';
      const calleeFile = extractFileFromNodeId(calleeId) || '';
      const crossesFileBoundary = currentFile !== calleeFile && calleeFile !== '';
      const newCrossFileDepth = crossesFileBoundary ? currentCrossFileDepth + 1 : currentCrossFileDepth;

      if (calleeNode) {
        // Check if we've hit the cross-file depth limit
        if (newCrossFileDepth > config.maxDepth) {
          // Emit a SUPPRESSED finding indicating depth limit was hit
          if (config.emitSuppressedOnLimit) {
            // Check if callee has any dangerous ops that we won't trace
            const calleeHasDangerousOps = calleeNode.dangerousOps.length > 0 ||
              Array.from(calleeNode.callees).some(c => {
                const n = allNodes.get(c);
                return n && n.dangerousOps && n.dangerousOps.length > 0;
              });

            if (calleeHasDangerousOps || !allNodes.has(calleeId)) {
              foundPaths.push({
                operation: {
                  callee: calleeId,
                  category: ExecutionCategory.TOOL_CALL,
                  severity: Severity.SUPPRESSED,
                  line: calleeNode.startLine,
                  column: 1,
                  codeSnippet: `Cross-file resolution limit (depth ${config.maxDepth}) reached. Manual review recommended for: ${calleeId}`,
                },
                path: [...currentPath, calleeId],
                hasGate: hasGateInPath,
                involvesCrossFile: true,
                unresolvedCalls: [calleeId],
                depthLimitHit: true,
              });
            }
          }
        } else {
          findDangerousPathsFromNode(
            calleeNode,
            allNodes,
            new Set(visited),
            [...currentPath, calleeId],
            foundPaths,
            config,
            newCrossFileDepth
          );
        }
      } else {
        // Track unresolved cross-file calls (not in our node map)
        // These are calls we couldn't resolve - mark as potentially gated
        // Don't add to unresolved if it's a known dangerous operation pattern
        const isKnownDangerousPattern = DANGEROUS_OPERATION_PATTERNS.some(
          (p) => p.pattern.test(calleeId)
        );
        if (!isKnownDangerousPattern && !calleeId.startsWith('_')) {
          unresolvedCalls.push(calleeId);
        }
      }
    }
  }

  return foundPaths;
}
