/**
 * TypeScript/JavaScript AFB04 Detector
 *
 * Detects AFB04 (Unauthorized Action) boundaries in TypeScript/JavaScript codebases.
 * Uses proper AST parsing with tree-sitter and call graph analysis to find tool
 * definitions that can reach dangerous operations without policy gates.
 *
 * Detection approach (mirrors Python detector):
 * 1. Parse TypeScript/JavaScript AST using tree-sitter
 * 2. Identify tool registration points across frameworks
 * 3. Build call graph from tool definitions
 * 4. Trace paths to dangerous operations
 * 5. Check for policy gates in call paths
 * 6. Generate findings with severity based on exposure
 */

import {
  initParser,
  parseTypeScriptSource,
  ParsedTypeScriptFile,
} from './ast-parser';
import {
  buildCallGraph,
  ExposedPath,
  DangerousOperation,
} from './call-graph';
import {
  extractSemanticInvocationRoots,
} from './semantic-index';
import {
  AFBFinding,
  CEERecord,
  FileAnalysisResult,
  AFBType,
  ExecutionCategory,
  Severity,
} from '../../types';
import * as path from 'path';

interface TypeScriptSourceInput {
  filePath: string;
  sourceCode: string;
}

interface TypeScriptBatchDiagnostics {
  language: 'typescript';
  rootsByFramework: Record<string, number>;
  totalRoots: number;
  callGraphNodes: number;
  dangerousOperationsDiscovered: number;
  unresolvedCallEdges: number;
  crossFileResolvedEdges: number;
  traversalDepthBudget: number;
  depthLimitedExposedPaths: number;
  exposedPathsWithUnresolvedCalls: number;
  uniqueEntrypointsWithExposure: number;
  parseFailedFiles: Array<{ file: string; error: string }>;
}

/**
 * Irreversible operations (CRITICAL severity)
 */
const IRREVERSIBLE_OPS = new Set([
  'child_process.exec',
  'child_process.execSync',
  'child_process.spawn',
  'child_process.spawnSync',
  'Bun.spawn',
  'Bun.spawnSync',
  'Bun.shell',
  'Deno.run',
  'Deno.Command',
  'fs.unlink',
  'fs.unlinkSync',
  'fs.rm',
  'fs.rmSync',
  'fs.rmdir',
  'fs.rmdirSync',
  'eval',
  'Function',
]);

/**
 * Calculate final severity for an exposed path
 */
function calculateSeverity(
  baseSeverity: Severity,
  operation: DangerousOperation
): Severity {
  // Irreversible operations are always CRITICAL
  if (operation.resolvedIdentity && IRREVERSIBLE_OPS.has(operation.resolvedIdentity)) {
    return Severity.CRITICAL;
  }

  if (IRREVERSIBLE_OPS.has(operation.callee)) {
    return Severity.CRITICAL;
  }

  return baseSeverity;
}

function isIrreversibleOperation(callee: string): boolean {
  return IRREVERSIBLE_OPS.has(callee);
}

// Parser state
let parserInitialized = false;

/**
 * Ensure TypeScript parser is initialized
 */
export async function ensureTypeScriptParserInitialized(): Promise<void> {
  if (!parserInitialized) {
    await initParser();
    parserInitialized = true;
  }
}

/**
 * Analyze a single TypeScript/JavaScript file
 */
export function analyzeTypeScriptFile(
  filePath: string,
  sourceCode: string
): FileAnalysisResult {
  const startTime = Date.now();
  const ext = path.extname(filePath).toLowerCase();
  const language = ext === '.js' || ext === '.jsx' ? 'javascript' : 'typescript';
  const isTSX = ext === '.tsx';

  // Parse the file
  const parsed = parseTypeScriptSource(sourceCode, isTSX);

  if (!parsed.success) {
    return {
      file: filePath,
      language,
      findings: [],
      success: false,
      error: parsed.error,
      analysisTimeMs: Date.now() - startTime,
    };
  }

  // Build call graph from this single file
  const files = new Map([[filePath, parsed]]);
  const semanticRoots = extractSemanticInvocationRoots(files);
  const callGraph = buildCallGraph(files, semanticRoots);

  // Generate findings from exposed paths
  const findings: AFBFinding[] = [];
  const cees: CEERecord[] = [];

  for (const exposed of callGraph.exposedPaths) {
    const cee = createCEEFromPath(filePath, exposed, parsed);
    cees.push(cee);

    // Only emit AFBFinding for non-registration-only, non-gated paths
    if (!exposed.hasGate && !isRegistrationOnlyCEE(exposed) && cee.afbType) {
      const finding = createFindingFromCEE(cee, parsed);
      findings.push(finding);
    }
  }

  return {
    file: filePath,
    language,
    findings,
    cees,
    success: true,
    analysisTimeMs: Date.now() - startTime,
  };
}

/**
 * Analyze multiple TypeScript/JavaScript files together
 */
export function analyzeTypeScriptFiles(inputs: TypeScriptSourceInput[], onProgress?: (msg: string) => void): FileAnalysisResult[] {
  const tsTotal = inputs.length;
  let tsParsed = 0;
  const files = new Map<string, ParsedTypeScriptFile>();
  const parseFailedFiles: Array<{ filePath: string; language: 'typescript' | 'javascript'; error: string }> = [];

  // Parse all files
  for (const input of inputs) {
    const ext = path.extname(input.filePath).toLowerCase();
    const isTSX = ext === '.tsx';
    const language = ext === '.js' || ext === '.jsx' ? 'javascript' : 'typescript';
    const parsed = parseTypeScriptSource(input.sourceCode, isTSX);

    tsParsed++;
    if (onProgress && tsTotal > 100 && tsParsed % 100 === 0) onProgress(`  Parsing TypeScript/JS (${tsParsed}/${tsTotal})...`);
    if (parsed.success) {
      files.set(input.filePath, parsed);
    } else {
      parseFailedFiles.push({
        filePath: input.filePath,
        language,
        error: parsed.error || 'Unknown parse failure',
      });
    }
  }

  // Build call graph across all files
  if (onProgress) onProgress('  Building TypeScript/JS call graph...');
  const semanticRoots = extractSemanticInvocationRoots(files);
  const callGraph = buildCallGraph(files, semanticRoots);
  const rootsByFramework: Record<string, number> = {};
  for (const root of semanticRoots.values()) {
    rootsByFramework[root.framework] = (rootsByFramework[root.framework] || 0) + 1;
  }
  const batchDiagnostics: TypeScriptBatchDiagnostics = {
    language: 'typescript',
    rootsByFramework,
    totalRoots: semanticRoots.size,
    callGraphNodes: callGraph.diagnostics.totalNodes,
    dangerousOperationsDiscovered: callGraph.diagnostics.dangerousOperationsDiscovered,
    unresolvedCallEdges: callGraph.diagnostics.unresolvedCallEdges,
    crossFileResolvedEdges: callGraph.diagnostics.crossFileResolvedEdges,
    traversalDepthBudget: callGraph.diagnostics.traversalDepthBudget,
    depthLimitedExposedPaths: callGraph.diagnostics.depthLimitedExposedPaths,
    exposedPathsWithUnresolvedCalls: callGraph.diagnostics.exposedPathsWithUnresolvedCalls,
    uniqueEntrypointsWithExposure: callGraph.diagnostics.uniqueEntrypointsWithExposure,
    parseFailedFiles: parseFailedFiles.map((failed) => ({ file: failed.filePath, error: failed.error })),
  };

  // Generate findings per file
  const results: FileAnalysisResult[] = [];
  const tsFileTotal = files.size;
  let tsFileIdx = 0;
  if (onProgress && tsFileTotal > 0) onProgress(`  Classifying TypeScript/JS CEEs (0/${tsFileTotal} files)...`);

  for (const [filePath, parsed] of files) {
    tsFileIdx++;
    if (onProgress && tsFileTotal > 50 && tsFileIdx % 50 === 0) onProgress(`  Classifying TypeScript/JS CEEs (${tsFileIdx}/${tsFileTotal} files)...`);
    const startTime = Date.now();
    const ext = path.extname(filePath).toLowerCase();
    const language = ext === '.js' || ext === '.jsx' ? 'javascript' : 'typescript';

    const findings: AFBFinding[] = [];
    const cees: CEERecord[] = [];

    // Find exposed paths involving this file
    for (const exposed of callGraph.exposedPaths) {
      // For registration-only CEEs, attribute to the tool's source file
      const isRegOnly = isRegistrationOnlyCEE(exposed);
      const targetFile = isRegOnly ? (exposed.tool.sourceFile || filePath) : (exposed.operation.sourceFile || filePath);
      if (targetFile !== filePath) {
        continue;
      }

      const cee = createCEEFromPath(filePath, exposed, parsed);
      cees.push(cee);

      // Only emit AFBFinding for non-registration-only, non-gated paths
      if (!exposed.hasGate && !isRegOnly && cee.afbType) {
        const finding = createFindingFromCEE(cee, parsed);
        findings.push(finding);
      }
    }

    results.push({
      file: filePath,
      language,
      findings,
      cees,
      success: true,
      analysisTimeMs: Date.now() - startTime,
    });
  }

  for (const failed of parseFailedFiles) {
    results.push({
      file: failed.filePath,
      language: failed.language,
      findings: [],
      success: false,
      error: failed.error,
      analysisTimeMs: 0,
    });
  }

  if (results.length > 0) {
    results[0].analysisDiagnostics = Object.fromEntries(Object.entries(batchDiagnostics));
  }

  return results;
}

/**
 * Build unique CEE key
 */
function buildCEEKey(filePath: string, exposed: ExposedPath): string {
  return `${filePath}:${exposed.tool.name}:${exposed.operation.line}:${exposed.operation.callee}`;
}

/**
 * Determine if an exposed path is a registration-only entry (no real dangerous op traced).
 * These are emitted by Step 5 logic in findExposedPaths when no dangerous op is found.
 */
function isRegistrationOnlyCEE(exposed: ExposedPath): boolean {
  return exposed.operation.callee.startsWith('agent-tool-registration:');
}

/**
 * Create CEE from exposed path.
 *
 * For registration-only entries (callee starts with 'agent-tool-registration:'), the CEE
 * is INFO severity and has no AFB type. For all other entries, normal AFB04 logic applies.
 */
function createCEEFromPath(
  filePath: string,
  exposed: ExposedPath,
  parsed: ParsedTypeScriptFile
): CEERecord {
  const op = exposed.operation;
  const tool = exposed.tool;

  if (isRegistrationOnlyCEE(exposed)) {
    // Registration-only CEE: INFO severity, no AFB type
    return {
      file: tool.sourceFile || filePath,
      line: tool.startLine,
      column: 0,
      operation: `Agent tool registration: ${tool.name}`,
      tool: tool.name,
      framework: tool.framework,
      toolFile: tool.sourceFile,
      toolLine: tool.startLine,
      callPath: [tool.id],
      gateStatus: exposed.hasGate ? 'present' : 'absent',
      afbType: null,
      severity: Severity.INFO,
      category: ExecutionCategory.TOOL_CALL,
      classificationNote: `Tool registration detected. No external operations traced from this entry point.`,
      codeSnippet: tool.name,
      involvesCrossFile: false,
      unresolvedCalls: exposed.unresolvedCalls,
      depthLimitHit: false,
      evidenceKind: 'semantic',
      supportingEvidence: exposed.supportingEvidence,
      resource: undefined,
      changesState: false,
    };
  }

  const finalSeverity = calculateSeverity(op.severity, op);

  return {
    file: op.sourceFile || filePath,
    line: op.line,
    column: op.column,
    operation: `${getCategoryDescription(op.category)}: ${op.resolvedIdentity || op.callee}`,
    tool: tool.name,
    framework: tool.framework,
    toolFile: tool.sourceFile,
    toolLine: tool.startLine,
    callPath: exposed.path,
    gateStatus: exposed.hasGate ? 'present' : 'absent',
    afbType: exposed.hasGate ? null : AFBType.UNAUTHORIZED_ACTION,
    severity: finalSeverity,
    category: op.category,
    classificationNote: buildCEEClassificationNote(exposed),
    codeSnippet: op.codeSnippet,
    involvesCrossFile: exposed.involvesCrossFile,
    unresolvedCalls: exposed.unresolvedCalls,
    depthLimitHit: exposed.depthLimitHit,
    evidenceKind: op.detectionKind || 'heuristic',
    supportingEvidence: exposed.supportingEvidence,
    resource: op.resourceHint,
    changesState: op.changesState,
  };
}

/**
 * Create finding from CEE
 */
function createFindingFromCEE(cee: CEERecord, parsed: ParsedTypeScriptFile): AFBFinding {
  return {
    severity: cee.severity,
    type: cee.afbType || AFBType.UNAUTHORIZED_ACTION,
    file: cee.file,
    line: cee.line,
    column: cee.column,
    operation: cee.operation,
    explanation: cee.classificationNote,
    codeSnippet: cee.codeSnippet,
    category: cee.category,
    confidence: calculateConfidenceForCEE(cee),
    context: {
      toolName: cee.tool,
      framework: cee.framework,
      toolFile: cee.toolFile,
      toolLine: cee.toolLine,
      callPath: cee.callPath,
      involvesCrossFile: cee.involvesCrossFile,
      unresolvedCalls: cee.unresolvedCalls,
      depthLimitHit: cee.depthLimitHit,
      evidenceKind: cee.evidenceKind,
      supportingEvidence: cee.supportingEvidence,
      resource: cee.resource,
      changesState: cee.changesState,
    },
  };
}

/**
 * Calculate confidence for CEE
 */
function calculateConfidenceForCEE(cee: CEERecord): number {
  let confidence = 0.8; // Base confidence

  // Higher confidence for semantic detection
  if (cee.evidenceKind === 'semantic') {
    confidence += 0.1;
  }

  // Lower confidence if depth limit hit
  if (cee.depthLimitHit) {
    confidence -= 0.1;
  }

  // Lower confidence if unresolved calls
  if (cee.unresolvedCalls && cee.unresolvedCalls.length > 0) {
    confidence -= 0.05 * Math.min(cee.unresolvedCalls.length, 3);
  }

  // Higher confidence for direct paths
  if (cee.callPath && cee.callPath.length <= 2) {
    confidence += 0.05;
  }

  return Math.max(0.45, Math.min(0.98, Number(confidence.toFixed(2))));
}

/**
 * Build classification note for CEE
 */
function buildCEEClassificationNote(exposed: ExposedPath): string {
  const tool = exposed.tool;
  const op = exposed.operation;
  const framework = tool.framework || 'agent framework';
  const pathLen = exposed.path.length;

  let note = `Detected reachable call from tool "${tool.name}" (${framework}) to ${op.resolvedIdentity || op.callee}`;

  if (pathLen > 1) {
    note += ` through ${pathLen - 1} intermediate call(s)`;
  }

  note += `. No policy gate detected in the analyzed call path.`;

  if (exposed.inputFlowsToOperation) {
    note += ` Traced tool-controlled input into the matched operation arguments.`;
  }

  if (op.resourceHint) {
    note += ` Resource hint: ${op.resourceHint}.`;
  }

  return note;
}

/**
 * Get category description
 */
function getCategoryDescription(category: ExecutionCategory): string {
  switch (category) {
    case ExecutionCategory.SHELL_EXECUTION:
      return 'Shell command execution';
    case ExecutionCategory.CODE_EXECUTION:
      return 'Code execution';
    case ExecutionCategory.FILE_OPERATION:
      return 'File system operation';
    case ExecutionCategory.API_CALL:
      return 'HTTP operation';
    case ExecutionCategory.DATABASE_OPERATION:
      return 'Database operation';
    default:
      return 'Operation';
  }
}
