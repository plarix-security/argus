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
} from './ast-parser';
import { ExecutionCategory, Severity } from '../../types';

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
  /** Dangerous operations directly in this function */
  dangerousOps: DangerousOperation[];
  /** Whether this function is a structural policy gate */
  hasPolicyGate: boolean;
  /** Control flow information */
  controlFlow?: ControlFlowInfo;
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
  /** File path */
  file: string;
}

/**
 * Framework detection patterns for tool registration
 */
const TOOL_REGISTRATION_PATTERNS: {
  pattern: RegExp;
  framework: string;
  decoratorCheck?: (decorator: string) => boolean;
}[] = [
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
];

/**
 * Patterns that indicate dangerous operations
 */
const DANGEROUS_OPERATION_PATTERNS: {
  pattern: RegExp;
  category: ExecutionCategory;
  severity: Severity;
  description: string;
}[] = [
  // Shell execution - CRITICAL
  { pattern: /^subprocess\.(run|Popen|call|check_output|check_call)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Subprocess execution' },
  { pattern: /^os\.(system|popen|exec.*)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'OS shell command' },
  { pattern: /^commands\.(getoutput|getstatusoutput)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Commands module execution' },

  // Code execution - CRITICAL
  { pattern: /^eval$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic code evaluation' },
  { pattern: /^exec$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic code execution' },
  { pattern: /^compile$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.HIGH, description: 'Code compilation' },
  { pattern: /^__import__$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.HIGH, description: 'Dynamic import' },

  // File operations - HIGH
  { pattern: /^open$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.MEDIUM, description: 'File open' },
  { pattern: /\.write_text$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, description: 'File write' },
  { pattern: /\.write_bytes$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, description: 'File write bytes' },
  { pattern: /^shutil\.(copy|move|rmtree|remove)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, description: 'Bulk file operation' },
  { pattern: /^os\.(remove|unlink|rmdir|mkdir|makedirs|rename)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, description: 'OS file operation' },
  { pattern: /^pathlib\.Path.*\.(write|unlink|rmdir|mkdir)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, description: 'Pathlib file operation' },

  // API/HTTP calls - HIGH
  { pattern: /^requests\.(get|post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.HIGH, description: 'HTTP request' },
  { pattern: /^httpx\.(get|post|put|patch|delete|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.HIGH, description: 'HTTP request' },
  { pattern: /^aiohttp\.ClientSession$/i, category: ExecutionCategory.API_CALL, severity: Severity.HIGH, description: 'Async HTTP client' },
  { pattern: /^urllib\.request\.(urlopen|Request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.HIGH, description: 'URL request' },
  { pattern: /\.session\.(get|post|put|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.HIGH, description: 'Session HTTP request' },

  // Database operations - HIGH
  { pattern: /\.execute$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.HIGH, description: 'SQL execute' },
  { pattern: /\.executemany$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.HIGH, description: 'SQL batch execute' },
  { pattern: /\.raw$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.HIGH, description: 'Raw SQL query' },
  { pattern: /session\.(add|delete|commit|flush)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.HIGH, description: 'ORM write operation' },
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
 * Determine if a function is a structural policy gate.
 *
 * A policy gate is STRUCTURAL, not nominal. It must have:
 * 1. A conditional branch (if statement) that can prevent execution
 * 2. That branch should either raise an exception or return early
 * 3. The condition should be based on input parameters
 *
 * A function named "check_permission" that always returns True is NOT a gate.
 * A function named "process_data" that raises PermissionError conditionally IS.
 */
function isStructuralPolicyGate(controlFlow: ControlFlowInfo | undefined): boolean {
  if (!controlFlow) {
    return false;
  }

  // Must have conditional branches
  if (!controlFlow.hasConditionalBranches) {
    return false;
  }

  // Must be able to prevent execution (raise or return early)
  const canPreventExecution = controlFlow.hasConditionalRaise || controlFlow.hasConditionalReturn;
  if (!canPreventExecution) {
    return false;
  }

  // Higher confidence if it raises authorization-related exceptions
  const raisesAuthException = controlFlow.raiseTypes.some((type) =>
    AUTHORIZATION_EXCEPTION_TYPES.some((authType) =>
      type.toLowerCase().includes(authType.toLowerCase())
    )
  );

  // Higher confidence if conditions check parameters
  const checksInput = controlFlow.checksParameters;

  // A function is a policy gate if:
  // - It can prevent execution AND
  // - (It raises auth exceptions OR it checks its parameters)
  return raisesAuthException || checksInput;
}

/**
 * Build a call graph from parsed Python files
 */
export function buildCallGraph(
  files: Map<string, ParsedPythonFile>
): CallGraphAnalysis {
  const nodes = new Map<string, CallGraphNode>();
  const toolRegistrations: CallGraphNode[] = [];
  const exposedPaths: ExposedPath[] = [];

  // First pass: create nodes for all functions and classes
  for (const [filePath, parsed] of files) {
    // Process standalone functions
    for (const func of parsed.functions) {
      const id = func.className
        ? `${func.className}.${func.name}`
        : func.name;

      const node: CallGraphNode = {
        id,
        name: func.name,
        className: func.className,
        startLine: func.startLine,
        endLine: func.endLine,
        decorators: func.decorators,
        callees: new Set(),
        callers: new Set(),
        isToolRegistration: false,
        dangerousOps: [],
        // Use structural analysis to determine if this is a policy gate
        hasPolicyGate: isStructuralPolicyGate(func.controlFlow),
        controlFlow: func.controlFlow,
      };

      // Check if this is a tool registration
      const toolInfo = detectToolRegistration(func, parsed.imports);
      if (toolInfo) {
        node.isToolRegistration = true;
        node.framework = toolInfo.framework;
        toolRegistrations.push(node);
      }

      nodes.set(id, node);
    }

    // Process class definitions
    for (const cls of parsed.classes) {
      // Check if class itself is a tool (e.g., BaseTool subclass)
      const toolInfo = detectToolClass(cls, parsed.imports);

      for (const method of cls.methods) {
        const id = `${cls.name}.${method.name}`;

        const node: CallGraphNode = {
          id,
          name: method.name,
          className: cls.name,
          startLine: method.startLine,
          endLine: method.endLine,
          decorators: method.decorators,
          callees: new Set(),
          callers: new Set(),
          isToolRegistration: toolInfo !== null && (method.name === '_run' || method.name === 'run' || method.name === 'invoke'),
          framework: toolInfo?.framework,
          dangerousOps: [],
          // Use structural analysis to determine if this is a policy gate
          hasPolicyGate: isStructuralPolicyGate(method.controlFlow),
          controlFlow: method.controlFlow,
        };

        if (node.isToolRegistration) {
          toolRegistrations.push(node);
        }

        nodes.set(id, node);
      }
    }
  }

  // Second pass: populate call edges and detect dangerous operations
  for (const [filePath, parsed] of files) {
    for (const call of parsed.calls) {
      // Find the enclosing function node
      let callerId: string | undefined;
      if (call.enclosingClass && call.enclosingFunction) {
        callerId = `${call.enclosingClass}.${call.enclosingFunction}`;
      } else if (call.enclosingFunction) {
        callerId = call.enclosingFunction;
      }

      if (callerId && nodes.has(callerId)) {
        const callerNode = nodes.get(callerId)!;

        // Add callee to caller's outgoing edges
        callerNode.callees.add(call.callee);

        // Check if callee is a known node
        if (nodes.has(call.callee)) {
          const calleeNode = nodes.get(call.callee)!;
          calleeNode.callers.add(callerId);
        }

        // Check if this call is a dangerous operation
        const dangerousOp = detectDangerousOperation(call);
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
      []
    );

    for (const { operation, path, hasGate } of paths) {
      // Find the file containing this operation
      let file = '<unknown>';
      for (const [filePath, parsed] of files) {
        const matchingCall = parsed.calls.find(
          (c) => c.startLine === operation.line && c.callee === operation.callee
        );
        if (matchingCall) {
          file = filePath;
          break;
        }
      }

      exposedPaths.push({
        tool,
        operation,
        path,
        hasGateInPath: hasGate,
        file,
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
 * Detect if a function is a tool registration
 */
function detectToolRegistration(
  func: FunctionDef,
  imports: ImportInfo[]
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

  // Check if function name suggests tool registration
  const funcNameLower = func.name.toLowerCase();
  if (
    funcNameLower.includes('tool') ||
    funcNameLower.includes('action') ||
    funcNameLower.includes('capability')
  ) {
    // Only if there's a framework import
    for (const imp of imports) {
      const moduleLower = imp.module.toLowerCase();
      if (moduleLower.includes('langchain')) return { framework: 'langchain' };
      if (moduleLower.includes('crewai')) return { framework: 'crewai' };
      if (moduleLower.includes('autogen')) return { framework: 'autogen' };
      if (moduleLower.includes('llama_index') || moduleLower.includes('llamaindex')) return { framework: 'llamaindex' };
      if (moduleLower.includes('mcp')) return { framework: 'mcp' };
      if (moduleLower.includes('openai')) return { framework: 'openai' };
    }
  }

  return null;
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

  // Check class name
  const classNameLower = cls.name.toLowerCase();
  if (classNameLower.includes('tool')) {
    for (const imp of imports) {
      const moduleLower = imp.module.toLowerCase();
      if (moduleLower.includes('langchain')) return { framework: 'langchain' };
      if (moduleLower.includes('crewai')) return { framework: 'crewai' };
    }
  }

  return null;
}

/**
 * Detect if a call is a dangerous operation
 */
function detectDangerousOperation(call: CallSite): DangerousOperation | null {
  for (const pattern of DANGEROUS_OPERATION_PATTERNS) {
    if (pattern.pattern.test(call.callee)) {
      return {
        callee: call.callee,
        category: pattern.category,
        severity: pattern.severity,
        line: call.startLine,
        column: call.startColumn,
        codeSnippet: call.codeSnippet,
      };
    }
  }
  return null;
}

/**
 * Find all dangerous operation paths from a starting node
 */
function findDangerousPathsFromNode(
  node: CallGraphNode,
  allNodes: Map<string, CallGraphNode>,
  visited: Set<string>,
  currentPath: string[],
  foundPaths: { operation: DangerousOperation; path: string[]; hasGate: boolean }[]
): { operation: DangerousOperation; path: string[]; hasGate: boolean }[] {
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

  // Report dangerous operations in this node
  for (const op of node.dangerousOps) {
    foundPaths.push({
      operation: op,
      path: [...currentPath],
      hasGate: hasGateInPath || node.hasPolicyGate,
    });
  }

  // Recursively check callees (limit depth to prevent stack overflow)
  if (currentPath.length < 10) {
    for (const calleeId of node.callees) {
      const calleeNode = allNodes.get(calleeId);
      if (calleeNode) {
        findDangerousPathsFromNode(
          calleeNode,
          allNodes,
          new Set(visited),
          [...currentPath, calleeId],
          foundPaths
        );
      }
    }
  }

  return foundPaths;
}
