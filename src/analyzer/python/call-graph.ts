/**
 * Call Graph Builder
 *
 * Builds a call graph from parsed Python files to trace:
 * 1. Tool registration points (LangChain, CrewAI, AutoGen, LlamaIndex, MCP, OpenAI)
 * 2. Execution paths from tools to dangerous operations
 * 3. Presence or absence of policy gates in call paths
 *
 * This is the core of AFB04 detection: we need to know if a tool
 * can reach a dangerous operation without passing through authorization.
 *
 * IMPORTANT: Policy gate detection is STRUCTURAL, not nominal.
 * A function named "check_permission" that always returns True is NOT a gate.
 * A function named "process_data" that raises PermissionError conditionally IS.
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
  maxDepth: 5,
  emitSuppressedOnLimit: true,
};

function extractFileFromNodeId(nodeId: string): string | null {
  const separatorIndex = nodeId.lastIndexOf(':');
  if (separatorIndex === -1) {
    return null;
  }

  return nodeId.slice(0, separatorIndex);
}

/**
 * Framework detection patterns for tool registration
 *
 * These patterns identify functions that can be invoked by an LLM/agent.
 * Detection uses both explicit framework patterns and generic heuristics.
 */
const TOOL_REGISTRATION_PATTERNS: {
  pattern: RegExp;
  framework: string;
  decoratorCheck?: (decorator: string) => boolean;
}[] = [
  // ================== KNOWN FRAMEWORKS ==================

  // LangChain
  { pattern: /^@tool$/i, framework: 'langchain', decoratorCheck: (d) => d === 'tool' || d.startsWith('tool(') },
  { pattern: /BaseTool/i, framework: 'langchain' },
  { pattern: /StructuredTool/i, framework: 'langchain' },
  { pattern: /Tool\s*\(/i, framework: 'langchain' },
  { pattern: /create_react_agent/i, framework: 'langchain' },
  { pattern: /AgentExecutor/i, framework: 'langchain' },

  // CrewAI
  { pattern: /^@task$/i, framework: 'crewai', decoratorCheck: (d) => d === 'task' || d.startsWith('task(') },
  { pattern: /^@agent$/i, framework: 'crewai', decoratorCheck: (d) => d === 'agent' || d.startsWith('agent(') },
  { pattern: /crewai\.tool/i, framework: 'crewai' },
  { pattern: /CrewAITool/i, framework: 'crewai' },

  // AutoGen
  { pattern: /register_function/i, framework: 'autogen' },
  { pattern: /function_map/i, framework: 'autogen' },
  { pattern: /UserProxyAgent/i, framework: 'autogen' },
  { pattern: /AssistantAgent/i, framework: 'autogen' },

  // LlamaIndex
  { pattern: /FunctionTool/i, framework: 'llamaindex' },
  { pattern: /QueryEngineTool/i, framework: 'llamaindex' },
  { pattern: /ToolOutput/i, framework: 'llamaindex' },

  // MCP (Model Context Protocol)
  { pattern: /mcp\.server/i, framework: 'mcp' },
  { pattern: /@server\.tool/i, framework: 'mcp', decoratorCheck: (d) => d.includes('server.tool') },
  { pattern: /tool_handler/i, framework: 'mcp' },
  { pattern: /ToolProvider/i, framework: 'mcp' },

  // Raw OpenAI function calling
  { pattern: /tools\s*=\s*\[/i, framework: 'openai' },
  { pattern: /function_call/i, framework: 'openai' },
  { pattern: /tool_choice/i, framework: 'openai' },
  { pattern: /"type"\s*:\s*"function"/i, framework: 'openai' },

  // Anthropic Claude tool use
  { pattern: /tool_use/i, framework: 'anthropic' },
  { pattern: /anthropic.*tools/i, framework: 'anthropic' },

  // Google Gemini function calling
  { pattern: /FunctionDeclaration/i, framework: 'gemini' },
  { pattern: /genai.*tools/i, framework: 'gemini' },

  // Hugging Face Transformers Agents
  { pattern: /transformers.*Tool/i, framework: 'transformers' },
  { pattern: /HfAgent/i, framework: 'transformers' },

  // Smolagents
  { pattern: /smolagents/i, framework: 'smolagents' },
  { pattern: /CodeAgent/i, framework: 'smolagents' },
  { pattern: /ToolCallingAgent/i, framework: 'smolagents' },

  // DSPy
  { pattern: /dspy\.Signature/i, framework: 'dspy' },
  { pattern: /dspy\.Module/i, framework: 'dspy' },

  // ================== GENERIC PATTERNS ==================
  // These catch custom agentic frameworks that don't use known decorators

  // Generic tool decorator patterns
  { pattern: /^@.*tool$/i, framework: 'custom', decoratorCheck: (d) => d.endsWith('tool') || d.endsWith('Tool') },
  { pattern: /^@.*_tool$/i, framework: 'custom', decoratorCheck: (d) => d.endsWith('_tool') },
  { pattern: /^@tool_/i, framework: 'custom', decoratorCheck: (d) => d.startsWith('tool_') || d.startsWith('tool(') },

  // Action/capability patterns
  { pattern: /^@action$/i, framework: 'custom', decoratorCheck: (d) => d === 'action' || d.startsWith('action(') },
  { pattern: /^@capability$/i, framework: 'custom', decoratorCheck: (d) => d === 'capability' || d.startsWith('capability(') },
  { pattern: /^@skill$/i, framework: 'custom', decoratorCheck: (d) => d === 'skill' || d.startsWith('skill(') },
  { pattern: /^@command$/i, framework: 'custom', decoratorCheck: (d) => d === 'command' || d.startsWith('command(') },
  { pattern: /^@handler$/i, framework: 'custom', decoratorCheck: (d) => d === 'handler' || d.startsWith('handler(') },

  // Registration patterns
  { pattern: /^@register$/i, framework: 'custom', decoratorCheck: (d) => d === 'register' || d.startsWith('register(') },
  { pattern: /^@expose$/i, framework: 'custom', decoratorCheck: (d) => d === 'expose' || d.startsWith('expose(') },
  { pattern: /^@callable$/i, framework: 'custom', decoratorCheck: (d) => d === 'callable' || d.startsWith('callable(') },

  // Agent/AI prefixed patterns
  { pattern: /^@agent_/i, framework: 'custom', decoratorCheck: (d) => d.startsWith('agent_') },
  { pattern: /^@ai_/i, framework: 'custom', decoratorCheck: (d) => d.startsWith('ai_') },
  { pattern: /^@llm_/i, framework: 'custom', decoratorCheck: (d) => d.startsWith('llm_') },

  // Class inheritance patterns
  { pattern: /AgentTool/i, framework: 'custom' },
  { pattern: /BaseAction/i, framework: 'custom' },
  { pattern: /CustomTool/i, framework: 'custom' },
];

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

  // HTTP methods that transmit data externally (various client styles)
  { pattern: /^requests\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP write request' },
  { pattern: /^httpx\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP write request' },
  { pattern: /^aiohttp\.ClientSession\.(post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Async HTTP write' },
  { pattern: /^urllib\.request\.(urlopen|Request|urlretrieve)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'URL request' },
  { pattern: /\.session\.(post|put|patch|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Session HTTP write' },
  // Match any .post(), .put(), .patch(), .delete() method calls (common API client patterns)
  { pattern: /\.(post|put|patch|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP write request' },

  // ORM write operations
  { pattern: /\.session\.(add|add_all|delete|merge|commit|flush)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM write operation' },
  { pattern: /\.save$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM save' },
  { pattern: /\.create$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM create' },
  { pattern: /\.objects\.update$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM queryset update' },
  { pattern: /\.objects\.create$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM queryset create' },
  { pattern: /\.objects\.delete$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM queryset delete' },
  { pattern: /\.filter\([^)]*\)\.update$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM filtered update' },
  { pattern: /\.bulk_create$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM bulk create' },
  { pattern: /\.bulk_update$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'ORM bulk update' },
  { pattern: /\.insert$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database insert' },
  // MongoDB specific
  { pattern: /\.insert_one$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB insert' },
  { pattern: /\.insert_many$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB bulk insert' },
  { pattern: /\.update_one$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB update' },
  { pattern: /\.update_many$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB bulk update' },
  { pattern: /\.delete_one$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB delete' },
  { pattern: /\.delete_many$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB bulk delete' },
  // SQL script execution is critical
  { pattern: /\.executescript$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'SQL script execution' },
  { pattern: /\.executemany$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Batch SQL execution' },

  // Redis/cache operations - can read/write/delete persistent data
  { pattern: /redis.*\.set$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Redis write' },
  { pattern: /cache.*\.set$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Cache write' },
  { pattern: /redis.*\.delete$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Redis delete' },
  { pattern: /cache.*\.delete$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Cache delete' },
  { pattern: /redis.*\.(flushdb|flushall)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Redis flush' },
  { pattern: /redis.*\.get$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Redis read' },
  { pattern: /redis.*\.keys$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Redis key enumeration' },

  // Email sending
  { pattern: /^smtplib\.SMTP$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'SMTP connection' },
  { pattern: /\.send_message$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Send message/email' },
  { pattern: /\.send_email$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Send email' },
  { pattern: /smtp.*\.sendmail$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'SMTP send' },
  { pattern: /\.sendmail$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email send via SMTP' },

  // ==================== INFO ====================
  // File reads - read-only access to sensitive data
  { pattern: /^open$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File open (read)' },
  { pattern: /\.read_text$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read' },
  { pattern: /\.read_bytes$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Binary file read' },
  { pattern: /\.read$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read' },
  { pattern: /\.readline$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read line' },
  { pattern: /\.readlines$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read lines' },

  // HTTP GET - outbound API calls can exfiltrate data, elevated to WARNING
  { pattern: /^requests\.get$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP GET request' },
  { pattern: /^httpx\.get$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP GET request' },
  { pattern: /^urllib\.request\.(urlopen|urlretrieve)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'URL fetch' },
  { pattern: /^aiohttp\.ClientSession\.get$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Async HTTP GET' },
  // Generic .get() is too common (dict.get, etc.) - don't match it

  // Database reads
  { pattern: /\.execute$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database query execution' },
  { pattern: /\.fetchall$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database fetch' },
  { pattern: /\.fetchone$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database fetch' },
  { pattern: /\.fetchmany$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database fetch' },
  { pattern: /\.query$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database query' },
  { pattern: /\.select$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Database select' },
  // MongoDB read
  { pattern: /\.find_one$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'MongoDB find' },
  { pattern: /\.aggregate$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'MongoDB aggregate' },

  // Directory operations (read-only)
  { pattern: /\.listdir$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory listing' },
  { pattern: /^os\.listdir$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory listing' },
  { pattern: /^os\.scandir$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory scan' },
  { pattern: /^os\.walk$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory walk' },
  { pattern: /\.glob$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File glob' },
  { pattern: /\.rglob$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Recursive file glob' },
  { pattern: /\.iterdir$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory iteration' },
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
];

/**
 * Known authorization decorator patterns.
 * These decorators are commonly used access control gates that should be
 * recognized even when their source code is in a different file.
 */
const KNOWN_AUTHORIZATION_DECORATORS = [
  // Permission/authorization decorators
  /^require_permission$/i,
  /^require_permissions$/i,
  /^permission_required$/i,
  /^permissions_required$/i,
  /^require_admin$/i,
  /^admin_required$/i,
  /^login_required$/i,
  /^authenticated$/i,
  /^auth_required$/i,
  /^authorization_required$/i,
  /^requires_auth$/i,
  /^requires_permission$/i,
  /^check_permission$/i,
  /^check_permissions$/i,
  /^has_permission$/i,
  /^has_permissions$/i,
  // Role-based access control
  /^require_role$/i,
  /^role_required$/i,
  /^roles_required$/i,
  /^has_role$/i,
  /^user_passes_test$/i,
  // Django-style decorators
  /^permission_classes$/i,
  /^api_view$/i,
  // Flask-style decorators
  /^login_manager\.user_loader$/i,
  // Generic access control
  /^access_control$/i,
  /^authorize$/i,
  /^protected$/i,
  // Additional patterns (Task 4)
  /^guard$/i,
  /^policy$/i,
  /^secure$/i,
  /^restricted$/i,
  /^verified$/i,
  /^requires$/i,
  /^require$/i,
  // Wildcard patterns - match anything containing these terms
  /permission/i,
  /auth(?:orize|enticate)?/i,
  /require[sd]?_/i,
];

/**
 * Check if a decorator name matches a known authorization pattern.
 * This handles imported decorators that can't be structurally analyzed.
 */
function isKnownAuthorizationDecorator(decoratorName: string): boolean {
  // Extract the base name without arguments
  const baseName = decoratorName.split('(')[0].trim();
  return KNOWN_AUTHORIZATION_DECORATORS.some(pattern => pattern.test(baseName));
}

/**
 * Patterns for helper functions that likely perform validation.
 * If a call path passes through a function matching these patterns,
 * we downgrade severity by one level (not suppress) because we cannot
 * confirm it is a real gate, but it suggests validation may occur.
 */
const VALIDATION_HELPER_PATTERNS = [
  /^sanitize/i,
  /^validate/i,
  /^check_/i,
  /^verify/i,
  /^is_valid/i,
  /^is_allowed/i,
  /^can_/i,
  /^has_access/i,
  /^ensure_/i,
  /^assert_/i,
];

/**
 * Check if a function name suggests it performs validation.
 * Used to downgrade severity when a call path includes probable validation.
 */
export function isLikelyValidationHelper(functionName: string): boolean {
  return VALIDATION_HELPER_PATTERNS.some(pattern => pattern.test(functionName));
}

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
  const raisesAuthException = controlFlow.raiseTypes.some((type) =>
    AUTHORIZATION_EXCEPTION_TYPES.some((authType) =>
      type.toLowerCase().includes(authType.toLowerCase())
    )
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
      // 2. It has a decorator that acts as a structural gate (from same file), OR
      // 3. It has a decorator matching known authorization patterns (from any file)
      const hasStructuralGate = isStructuralPolicyGate(func.controlFlow);
      const hasDecoratorGate = (func.hasDecoratorGate || false) || hasImportedStructuralDecoratorGate(func.decorators, filePath, importMap, files);
      const hasKnownAuthDecorator = func.decorators.some(d => isKnownAuthorizationDecorator(d));

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
        hasHeuristicGateIndicator: hasKnownAuthDecorator && !(hasStructuralGate || hasDecoratorGate),
        // Check if this function name suggests it's a validation helper
        isValidationHelper: isLikelyValidationHelper(func.name),
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
      // Check if class itself is a tool (e.g., BaseTool subclass)
      const classToolInfo = detectToolClass(cls, parsed.imports);

      for (const method of cls.methods) {
        const localId = `${cls.name}.${method.name}`;
        const globalId = `${filePath}:${localId}`;
        const toolInfo = getToolRegistrationInfo(
          globalId,
          semanticRoots,
          method,
          parsed.imports,
          parsed.openaiToolSchemas,
          parsed.dispatchMappings,
          classToolInfo || undefined
        );

        // A method has a policy gate if:
        // 1. Its own control flow is a structural gate, OR
        // 2. It has a decorator that acts as a structural gate (from same file), OR
        // 3. It has a decorator matching known authorization patterns (from any file)
        const hasStructuralGate = isStructuralPolicyGate(method.controlFlow);
        const hasDecoratorGate = (method.hasDecoratorGate || false) || hasImportedStructuralDecoratorGate(method.decorators, filePath, importMap, files);
        const hasKnownAuthDecorator = method.decorators.some(d => isKnownAuthorizationDecorator(d));

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
          hasHeuristicGateIndicator: hasKnownAuthDecorator && !(hasStructuralGate || hasDecoratorGate),
          // Check if this method name suggests it's a validation helper
          isValidationHelper: isLikelyValidationHelper(method.name),
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

    for (const { operation, path, hasGate, involvesCrossFile, unresolvedCalls, depthLimitHit } of paths) {
      const file = operation.sourceFile || tool.sourceFile || '<unknown>';
      const flowEvidence = analyzePathFlow(tool, path, operation, nodes, files);

      // Check if any node in the path is a validation helper
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

/**
 * Detect if a function is a tool registration.
 *
 * Supports:
 * 1. Decorator-based detection (LangChain @tool, CrewAI @task, etc.)
 * 2. OpenAI SDK dictionary-based schemas
 * 3. AutoGen function_map patterns
 *
 * Note: For OpenAI schemas, the presence of the schema pattern itself
 * ({"type": "function", "function": {"name": "..."}}) is strong enough
 * evidence that we don't require the openai import in the same file.
 */
function detectToolRegistration(
  func: FunctionDef,
  imports: ImportInfo[],
  openaiToolSchemas: OpenAIToolSchema[] = [],
  dispatchMappings: FunctionDispatchMapping[] = []
): { framework: string } | null {
  // Check decorators
  for (const decorator of func.decorators) {
    for (const pattern of TOOL_REGISTRATION_PATTERNS) {
      if (pattern.decoratorCheck) {
        if (pattern.decoratorCheck(decorator)) {
          return { framework: pattern.framework };
        }
      } else if (pattern.pattern.test(decorator)) {
        return { framework: pattern.framework };
      }
    }
  }

  // Check if function appears in OpenAI tool schemas
  // The schema pattern {"type": "function", "function": {"name": "..."}} is unique enough
  // that we trust it even without requiring openai import in the same file
  for (const schema of openaiToolSchemas) {
    if (schema.toolNames.includes(func.name)) {
      return { framework: 'openai' };
    }
  }

  // Check if function appears in dispatch mappings
  for (const mapping of dispatchMappings) {
    for (const [toolName, funcRef] of mapping.mappings) {
      if (funcRef === func.name) {
        // If the tool name appears in an OpenAI schema, it's an OpenAI tool
        const inSchema = openaiToolSchemas.some(s => s.toolNames.includes(toolName));
        if (inSchema) {
          return { framework: 'openai' };
        }
        // If we have openai imports, trust the dispatch mapping as OpenAI
        if (hasOpenAIImport(imports)) {
          return { framework: 'openai' };
        }
        // If we have autogen imports, trust the dispatch mapping as AutoGen
        // This handles the function_map pattern used by AutoGen
        if (hasAutoGenImport(imports)) {
          return { framework: 'autogen' };
        }
      }
    }
  }

  return null;
}

function getToolRegistrationInfo(
  nodeId: string,
  semanticRoots: Map<string, SemanticInvocationRoot>,
  func: FunctionDef,
  imports: ImportInfo[],
  openaiToolSchemas: OpenAIToolSchema[] = [],
  dispatchMappings: FunctionDispatchMapping[] = [],
  inheritedToolInfo?: { framework: string } | null
): { framework: string; kind: 'semantic' | 'heuristic'; evidence: string } | null {
  const semanticRoot = semanticRoots.get(nodeId);
  if (semanticRoot) {
    return {
      framework: semanticRoot.framework,
      kind: 'semantic',
      evidence: semanticRoot.evidence,
    };
  }

  if (inheritedToolInfo) {
    return {
      framework: inheritedToolInfo.framework,
      kind: 'heuristic',
      evidence: `tool-class fallback for ${func.className || func.name}`,
    };
  }

  const fallback = detectToolRegistration(func, imports, openaiToolSchemas, dispatchMappings);
  if (!fallback) {
    return null;
  }

  return {
    framework: fallback.framework,
    kind: 'heuristic',
    evidence: `pattern fallback for ${func.name}`,
  };
}

/**
 * Detect if a class is a tool class (e.g., BaseTool subclass)
 */
function detectToolClass(
  cls: ClassDef,
  imports: ImportInfo[]
): { framework: string } | null {
  for (const base of cls.bases) {
    for (const pattern of TOOL_REGISTRATION_PATTERNS) {
      if (pattern.pattern.test(base)) {
        return { framework: pattern.framework };
      }
    }
  }

  return null;
}

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

  // Recursively check callees (limit total depth to 10, cross-file depth to config.maxDepth)
  if (currentPath.length < 10) {
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
