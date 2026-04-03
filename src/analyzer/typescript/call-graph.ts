/**
 * TypeScript/JavaScript Call Graph Builder
 *
 * Builds a call graph from parsed TypeScript files to trace:
 * 1. Tool registration points via semantic root extraction
 * 2. Execution paths from tools to dangerous operations
 * 3. Presence or absence of structural policy gates in call paths
 *
 * Mirrors Python call graph architecture but adapted for TypeScript/JavaScript.
 */

import {
  ParsedTypeScriptFile,
  FunctionDef,
  ClassDef,
  CallSite,
  ImportInfo,
  ControlFlowInfo,
  CallArgumentInfo,
} from './ast-parser';
import {
  TypeScriptSemanticIndex,
  extractSemanticInvocationRoots,
  SemanticInvocationRoot,
} from './semantic-index';
import { ExecutionCategory, Severity } from '../../types';
import * as path from 'path';

/**
 * Import resolution result
 */
export interface ResolvedImport {
  name: string;
  alias?: string;
  resolvedFile?: string;
  resolved: boolean;
  modulePath: string;
}

/**
 * A node in the call graph
 */
export interface CallGraphNode {
  id: string;
  name: string;
  className?: string;
  startLine: number;
  endLine: number;
  callees: Set<string>;
  callers: Set<string>;
  isToolRegistration: boolean;
  framework?: string;
  toolDetectionKind?: 'semantic' | 'heuristic';
  toolDetectionEvidence?: string;
  dangerousOps: DangerousOperation[];
  hasPolicyGate: boolean;
  hasHeuristicGateIndicator?: boolean;
  controlFlow?: ControlFlowInfo;
  sourceFile?: string;
  parameters?: string[];
  outgoingCalls: Array<{
    targetId?: string;
    call: CallSite;
  }>;
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
  nodes: Map<string, CallGraphNode>;
  toolRegistrations: CallGraphNode[];
  exposedPaths: ExposedPath[];
}

/**
 * An exposed execution path from tool to dangerous operation
 */
export interface ExposedPath {
  tool: CallGraphNode;
  operation: DangerousOperation;
  path: string[];
  hasGate: boolean;
  involvesCrossFile: boolean;
  unresolvedCalls: string[];
  depthLimitHit: boolean;
  inputFlowsToOperation: boolean;
  supportingEvidence: string[];
}

/**
 * Import resolution configuration
 */
export interface ImportResolutionConfig {
  searchPaths: string[];
  fileExtensions: string[];
  packageJsonLookup: boolean;
}

export const DEFAULT_IMPORT_CONFIG: ImportResolutionConfig = {
  searchPaths: ['src', 'lib', '.'],
  fileExtensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  packageJsonLookup: true,
};

/**
 * Dangerous operation patterns for Node.js/TypeScript
 *
 * These are semantic patterns that match qualified module names.
 * Example: child_process.exec, fs.unlink, eval
 */
interface DangerousOperationPattern {
  identity: RegExp;
  category: ExecutionCategory;
  severity: Severity;
  description: string;
  resourceHint?: string;
  changesState?: boolean;
}

const SEMANTIC_DANGEROUS_OPERATION_PATTERNS: DangerousOperationPattern[] = [
  // Shell/Process Execution (CRITICAL)
  { identity: /^child_process\.(exec|execSync)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell command execution', resourceHint: 'shell', changesState: true },
  { identity: /^child_process\.(spawn|spawnSync)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Process spawn', resourceHint: 'process', changesState: true },
  { identity: /^child_process\.(execFile|execFileSync)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'File execution', resourceHint: 'file', changesState: true },
  { identity: /^child_process\.fork$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Process fork', resourceHint: 'process', changesState: true },
  { identity: /^execa$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell execution via execa', resourceHint: 'shell', changesState: true },

  // Code Execution (CRITICAL)
  { identity: /^eval$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'JavaScript eval', changesState: true },
  { identity: /^Function$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic function creation', changesState: true },
  { identity: /^vm\.(runInContext|runInNewContext|runInThisContext)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'VM code execution', changesState: true },

  // File Deletion (CRITICAL)
  { identity: /^fs\.(unlink|unlinkSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(rm|rmSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File/directory deletion', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(rmdir|rmdirSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Directory deletion', resourceHint: 'directory', changesState: true },
  { identity: /^fs\/promises\.unlink$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Async file deletion', resourceHint: 'file', changesState: true },
  { identity: /^fs\/promises\.rm$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Async file/directory deletion', resourceHint: 'file', changesState: true },
  { identity: /^fse\.(remove|removeSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion via fs-extra', resourceHint: 'file', changesState: true },
  { identity: /^rimraf$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Recursive deletion', resourceHint: 'directory', changesState: true },

  // File Write (WARNING)
  { identity: /^fs\.(writeFile|writeFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(appendFile|appendFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File append', resourceHint: 'file', changesState: true },
  { identity: /^fs\.createWriteStream$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Write stream creation', resourceHint: 'file', changesState: true },
  { identity: /^fs\/promises\.(writeFile|appendFile)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Async file write', resourceHint: 'file', changesState: true },
  { identity: /^fse\.(writeFile|writeFileSync|outputFile|outputFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write via fs-extra', resourceHint: 'file', changesState: true },

  // HTTP Mutations (WARNING)
  { identity: /^fetch$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request', resourceHint: 'http', changesState: false }, // Severity adjusted based on method in detection
  { identity: /^axios\.(post|put|patch|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation', resourceHint: 'http', changesState: true },
  { identity: /^got\.(post|put|patch|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation via got', resourceHint: 'http', changesState: true },
  { identity: /^request\.(post|put|patch|delete)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation via request', resourceHint: 'http', changesState: true },

  // Database Operations (WARNING)
  { identity: /^.*\.(query|execute|run)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database operation', changesState: true },
  { identity: /^.*\.(insert|update|delete|drop|create|alter)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database mutation', changesState: true },

  // File Read (INFO)
  { identity: /^fs\.(readFile|readFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read', resourceHint: 'file', changesState: false },
  { identity: /^fs\.createReadStream$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Read stream creation', resourceHint: 'file', changesState: false },
  { identity: /^fs\/promises\.readFile$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Async file read', resourceHint: 'file', changesState: false },
];

/**
 * Pattern-based fallback for dangerous operations
 * Used when semantic resolution fails
 */
const DANGEROUS_OPERATION_PATTERNS: DangerousOperationPattern[] = [
  // Process/Shell
  { identity: /^(exec|spawn|execFile|fork)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Process execution', changesState: true },

  // Code execution
  { identity: /^(eval|Function)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Code execution', changesState: true },

  // File operations
  { identity: /^(unlink|rm|rmdir|remove)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion', changesState: true },
  { identity: /^(writeFile|appendFile|createWriteStream)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write', changesState: true },
  { identity: /^(readFile|createReadStream)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read', changesState: false },
];

/**
 * Determine if function is a structural policy gate
 */
function isStructuralPolicyGate(func: FunctionDef): boolean {
  if (!func.controlFlow) return false;

  const cf = func.controlFlow;

  // Must have conditional execution control
  if (!cf.hasConditionalRaise && !cf.hasConditionalReturn) {
    return false;
  }

  // Must check input parameters
  if (!cf.checksParameters) {
    return false;
  }

  // Must raise authorization-related exceptions
  const authExceptions = ['PermissionError', 'UnauthorizedError', 'ForbiddenError', 'AuthorizationError', 'Error'];
  const hasAuthException = cf.raiseTypes.some(t => authExceptions.some(ae => t.includes(ae)));

  return hasAuthException;
}

/**
 * Resolve call identity from imports and semantic resolution
 */
function resolveCallIdentity(
  call: CallSite,
  imports: ImportInfo[],
  files: Map<string, ParsedTypeScriptFile>,
  currentFile: string,
  config: ImportResolutionConfig
): string | null {
  // For member expressions like child_process.exec
  if (call.memberChain.length > 1) {
    const base = call.memberChain[0];
    const method = call.memberChain[call.memberChain.length - 1];

    // Check if base is an imported module
    const importInfo = imports.find(imp =>
      imp.names.includes(base) || imp.alias === base
    );

    if (importInfo) {
      return `${importInfo.module}.${method}`;
    }

    // Return as-is for semantic matching
    return call.memberChain.join('.');
  }

  // Simple identifier - check imports
  const callee = call.callee;
  const importInfo = imports.find(imp =>
    imp.names.includes(callee) || imp.alias === callee
  );

  if (importInfo) {
    return `${importInfo.module}.${callee}`;
  }

  return null;
}

/**
 * Match dangerous operation
 */
function matchDangerousOperation(
  call: CallSite,
  resolvedIdentity: string | null,
  sourceFile: string
): DangerousOperation | null {
  // Try semantic resolution first
  if (resolvedIdentity) {
    for (const pattern of SEMANTIC_DANGEROUS_OPERATION_PATTERNS) {
      if (pattern.identity.test(resolvedIdentity)) {
        return {
          callee: resolvedIdentity,
          category: pattern.category,
          severity: pattern.severity,
          line: call.line,
          column: call.column,
          codeSnippet: call.callee,
          sourceFile,
          argumentDetails: call.argumentDetails,
          resourceHint: pattern.resourceHint,
          changesState: pattern.changesState,
          detectionKind: 'semantic',
          detectionEvidence: `Resolved module identity: ${resolvedIdentity}`,
          resolvedIdentity,
        };
      }
    }
  }

  // Fallback to pattern matching on callee name
  for (const pattern of DANGEROUS_OPERATION_PATTERNS) {
    if (pattern.identity.test(call.callee)) {
      return {
        callee: call.callee,
        category: pattern.category,
        severity: pattern.severity,
        line: call.line,
        column: call.column,
        codeSnippet: call.callee,
        sourceFile,
        argumentDetails: call.argumentDetails,
        resourceHint: pattern.resourceHint,
        changesState: pattern.changesState,
        detectionKind: 'heuristic',
        detectionEvidence: `Pattern match on callee name`,
      };
    }
  }

  return null;
}

/**
 * Resolve module path to file
 */
function resolveModulePath(
  modulePath: string,
  currentFile: string,
  config: ImportResolutionConfig
): string | null {
  const currentDir = path.dirname(currentFile);

  // Relative import
  if (modulePath.startsWith('./') || modulePath.startsWith('../')) {
    const basePath = path.resolve(currentDir, modulePath);

    // Try with extensions
    for (const ext of config.fileExtensions) {
      const candidate = basePath + ext;
      // In real implementation, check if file exists
      // For now, just return the first possibility
      return candidate;
    }

    // Try index file
    for (const ext of config.fileExtensions) {
      const candidate = path.join(basePath, 'index' + ext);
      return candidate;
    }
  }

  // Absolute or package import - would need node_modules resolution
  // For now, return null (unresolved)
  return null;
}

/**
 * Build call graph from parsed files
 */
export function buildCallGraph(
  files: Map<string, ParsedTypeScriptFile>,
  semanticRoots?: Map<string, SemanticInvocationRoot>,
  config: ImportResolutionConfig = DEFAULT_IMPORT_CONFIG
): CallGraphAnalysis {
  const nodes = new Map<string, CallGraphNode>();
  const toolRegistrations: CallGraphNode[] = [];

  // Extract semantic roots if not provided
  if (!semanticRoots) {
    semanticRoots = extractSemanticInvocationRoots(files);
  }

  // Build nodes
  for (const [filePath, parsed] of files) {
    // Process functions
    for (const func of parsed.functions) {
      const nodeId = func.className
        ? `${filePath}:${func.className}.${func.name}`
        : `${filePath}:${func.name}`;

      // Check if this is a tool registration
      const semanticRoot = semanticRoots.get(nodeId);
      const isToolRegistration = !!semanticRoot;

      // Find dangerous operations in this function
      const dangerousOps: DangerousOperation[] = [];
      const outgoingCalls: Array<{ targetId?: string; call: CallSite }> = [];

      for (const call of parsed.calls) {
        if (call.enclosingFunction === func.name ||
            (func.className && call.enclosingClass === func.className && call.enclosingFunction === func.name)) {

          // Try to resolve call identity
          const resolvedIdentity = resolveCallIdentity(call, parsed.imports, files, filePath, config);

          // Check if dangerous
          const dangerousOp = matchDangerousOperation(call, resolvedIdentity, filePath);
          if (dangerousOp) {
            dangerousOp.enclosingNodeId = nodeId;
            dangerousOps.push(dangerousOp);
          }

          // Track outgoing call
          const targetId = call.enclosingClass
            ? `${filePath}:${call.enclosingClass}.${call.callee}`
            : `${filePath}:${call.callee}`;

          outgoingCalls.push({
            targetId: nodes.has(targetId) ? targetId : undefined,
            call,
          });
        }
      }

      // Check if structural policy gate
      const hasPolicyGate = isStructuralPolicyGate(func);

      const node: CallGraphNode = {
        id: nodeId,
        name: func.name,
        className: func.className,
        startLine: func.startLine,
        endLine: func.endLine,
        callees: new Set(),
        callers: new Set(),
        isToolRegistration,
        framework: semanticRoot?.framework,
        toolDetectionKind: semanticRoot ? 'semantic' : undefined,
        toolDetectionEvidence: semanticRoot?.evidence,
        dangerousOps,
        hasPolicyGate,
        controlFlow: func.controlFlow,
        sourceFile: filePath,
        parameters: func.parameters,
        outgoingCalls,
      };

      nodes.set(nodeId, node);

      if (isToolRegistration) {
        toolRegistrations.push(node);
      }
    }
  }

  // Build edges
  for (const node of nodes.values()) {
    for (const outgoing of node.outgoingCalls) {
      if (outgoing.targetId && nodes.has(outgoing.targetId)) {
        node.callees.add(outgoing.targetId);
        nodes.get(outgoing.targetId)!.callers.add(node.id);
      }
    }
  }

  // Find exposed paths
  const exposedPaths = findExposedPaths(nodes, toolRegistrations, files);

  return {
    nodes,
    toolRegistrations,
    exposedPaths,
  };
}

/**
 * Find exposed paths from tools to dangerous operations
 */
function findExposedPaths(
  nodes: Map<string, CallGraphNode>,
  toolRegistrations: CallGraphNode[],
  files: Map<string, ParsedTypeScriptFile>
): ExposedPath[] {
  const exposedPaths: ExposedPath[] = [];

  for (const tool of toolRegistrations) {
    const paths = findDangerousPathsFromNode(tool, nodes, 10);

    for (const pathInfo of paths) {
      const hasGate = pathInfo.path.some(nodeId => {
        const node = nodes.get(nodeId);
        return node?.hasPolicyGate || false;
      });

      exposedPaths.push({
        tool,
        operation: pathInfo.operation,
        path: pathInfo.path,
        hasGate,
        involvesCrossFile: pathInfo.involvesCrossFile,
        unresolvedCalls: pathInfo.unresolvedCalls,
        depthLimitHit: pathInfo.depthLimitHit,
        inputFlowsToOperation: pathInfo.inputFlowsToOperation,
        supportingEvidence: pathInfo.supportingEvidence,
      });
    }
  }

  return exposedPaths;
}

/**
 * Find paths from a node to dangerous operations (BFS)
 */
function findDangerousPathsFromNode(
  startNode: CallGraphNode,
  nodes: Map<string, CallGraphNode>,
  maxDepth: number
): Array<{
  operation: DangerousOperation;
  path: string[];
  involvesCrossFile: boolean;
  unresolvedCalls: string[];
  depthLimitHit: boolean;
  inputFlowsToOperation: boolean;
  supportingEvidence: string[];
}> {
  const results: Array<{
    operation: DangerousOperation;
    path: string[];
    involvesCrossFile: boolean;
    unresolvedCalls: string[];
    depthLimitHit: boolean;
    inputFlowsToOperation: boolean;
    supportingEvidence: string[];
  }> = [];

  const queue: Array<{ nodeId: string; path: string[]; depth: number }> = [
    { nodeId: startNode.id, path: [startNode.id], depth: 0 }
  ];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift()!;
    const node = nodes.get(current.nodeId);

    if (!node || visited.has(current.nodeId)) continue;
    visited.add(current.nodeId);

    // Check for dangerous operations in this node
    for (const op of node.dangerousOps) {
      const involvesCrossFile = current.path.some(id => {
        const n = nodes.get(id);
        return n?.sourceFile !== startNode.sourceFile;
      });

      results.push({
        operation: op,
        path: current.path,
        involvesCrossFile,
        unresolvedCalls: [],
        depthLimitHit: current.depth >= maxDepth,
        inputFlowsToOperation: false, // Would need taint analysis
        supportingEvidence: [],
      });
    }

    // Explore callees if not at depth limit
    if (current.depth < maxDepth) {
      for (const calleeId of node.callees) {
        if (!visited.has(calleeId)) {
          queue.push({
            nodeId: calleeId,
            path: [...current.path, calleeId],
            depth: current.depth + 1,
          });
        }
      }
    }
  }

  return results;
}
