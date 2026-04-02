/**
 * Python AFB04 Detector
 *
 * Detects AFB04 (Unauthorized Action) boundaries in Python codebases.
 * Uses proper AST parsing with tree-sitter and call graph analysis
 * to find tool definitions that can reach dangerous operations
 * without policy gates.
 *
 * Detection approach:
 * 1. Parse Python AST using tree-sitter
 * 2. Identify tool registration points across frameworks
 * 3. Build call graph from tool definitions
 * 4. Trace paths to dangerous operations
 * 5. Check for policy gates in call paths
 * 6. Generate findings with severity based on exposure
 *
 * IMPORTANT: This detector requires tree-sitter for AST parsing.
 * If tree-sitter fails to initialize or parse a file, the scan FAILS.
 * We do NOT fall back to regex. A missed finding is acceptable.
 * A false finding from pattern matching is not.
 */

import {
  initParser,
  parsePythonSource,
  ParsedPythonFile,
} from './ast-parser';
import {
  buildCallGraph,
  ExposedPath,
  DangerousOperation,
} from './call-graph';
import {
  AFBFinding,
  CEERecord,
  FileAnalysisResult,
  AFBType,
  ExecutionCategory,
  Severity,
} from '../../types';

interface PythonSourceInput {
  filePath: string;
  sourceCode: string;
}

/**
 * SEVERITY MODEL (v1.2.2 - Simplified)
 *
 * Severity is determined by operation class only:
 *
 * CRITICAL: Irreversible operations
 *   - File deletion (rmtree, remove, unlink)
 *   - Code execution (eval, exec)
 *   - Shell execution (subprocess, os.system)
 *
 * WARNING: State modification
 *   - File writes
 *   - HTTP POST/PUT/PATCH/DELETE
 *   - Database writes
 *
 * INFO: Read-only operations
 *   - File reads
 *   - Database reads
 *
 * NOTE: Naming heuristics removed in v1.2.2 (SENSITIVE_DATA_PATTERNS,
 * VALIDATION_HELPER_PATTERNS). Severity is now deterministic from
 * operation taxonomy only.
 */

/** Irreversible operations that are always CRITICAL severity */
const IRREVERSIBLE_OPS = new Set([
  'shutil.rmtree',
  'os.remove',
  'os.unlink',
  'os.rmdir',
  'Path.unlink',
  'Path.rmdir',
  'pathlib.Path.unlink',
  'pathlib.Path.rmdir',
  'eval',
  'exec',
  'subprocess.run',
  'subprocess.Popen',
  'subprocess.call',
  'os.system',
  'os.popen',
  'asyncio.create_subprocess_exec',
  'asyncio.create_subprocess_shell',
]);

/**
 * Calculate the final severity for an exposed path.
 *
 * v1.2.2: Simplified to deterministic model based on operation class only.
 * 1. If operation is irreversible, return CRITICAL
 * 2. Otherwise, return base severity from operation category
 */
function calculateSeverity(
  baseSeverity: Severity,
  operation: DangerousOperation,
  exposed: ExposedPath
): Severity {
  // Irreversible operations are always CRITICAL
  if (isIrreversibleOperation(operation.callee)) {
    return Severity.CRITICAL;
  }

  // Return base severity from operation category
  return baseSeverity;
}

/** Check if an operation is irreversible */
function isIrreversibleOperation(callee: string): boolean {
  // Check exact match
  if (IRREVERSIBLE_OPS.has(callee)) {
    return true;
  }
  // Check if callee ends with a known irreversible operation
  for (const op of IRREVERSIBLE_OPS) {
    if (callee.endsWith(op) || callee.endsWith(op.split('.').pop() || '')) {
      return true;
    }
  }
  return false;
}

let parserInitialized = false;

/**
 * Ensure the AST parser is initialized.
 * Throws an error if initialization fails - we do NOT fall back to regex.
 */
export async function ensureParserInitialized(): Promise<void> {
  if (!parserInitialized) {
    await initParser();
    parserInitialized = true;
  }
}

/**
 * Analyze a single Python file for AFB04 boundaries.
 *
 * IMPORTANT: If parsing fails, this returns a failure result with an error
 * message. We do NOT fall back to regex-based detection.
 */
export function analyzePythonFile(
  filePath: string,
  sourceCode: string
): FileAnalysisResult {
  const startTime = Date.now();
  const findings: AFBFinding[] = [];
  const cees: CEERecord[] = [];

  // Parse the file using tree-sitter
  const parsed = parsePythonSource(sourceCode);

  if (!parsed.success) {
    // Hard fail - do not fall back to regex
    return {
      file: filePath,
      language: 'python',
      findings: [],
      success: false,
      error: `Tree-sitter parse failed: ${parsed.error || 'Parser not initialized. Call ensureParserInitialized() first.'}`,
      analysisTimeMs: Date.now() - startTime,
    };
  }

  // Build call graph for this single file
  const fileMap = new Map<string, ParsedPythonFile>();
  fileMap.set(filePath, parsed);
  const callGraph = buildCallGraph(fileMap);

  // Convert exposed paths to findings with deduplication
  // Key: tool:file:line:callee - same reachable tool event should only be reported once
  const seenEvents = new Set<string>();

  for (const exposed of callGraph.exposedPaths) {
    const eventKey = buildCEEKey(filePath, exposed);
    if (seenEvents.has(eventKey)) {
      continue;
    }
    seenEvents.add(eventKey);

    const cee = createCEEFromPath(filePath, exposed, parsed);
    cees.push(cee);

    if (cee.afbType === AFBType.UNAUTHORIZED_ACTION) {
      findings.push(createFindingFromCEE(cee, parsed));
    }
  }

  // NOTE: Removed tool-registration-only findings.
  // If a tool doesn't reach any dangerous operation, it's not a finding.
  // This avoids noise from tools that just return strings or do safe operations.

  // Sort findings by severity, then line
  findings.sort((a, b) => {
    const severityOrder = { critical: 0, warning: 1, info: 2, suppressed: 3 };
    const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.line - b.line;
  });

  return {
    file: filePath,
    language: 'python',
    findings,
    cees,
    success: true,
    analysisTimeMs: Date.now() - startTime,
  };
}

/**
 * Analyze multiple Python files as a single repository graph.
 *
 * This is the shipped path for directory-style scans. It parses all files first,
 * builds one call graph, then attributes findings back to the file where the
 * matched operation occurs.
 */
export function analyzePythonFiles(inputs: PythonSourceInput[]): FileAnalysisResult[] {
  const parsedByFile = new Map<string, ParsedPythonFile>();
  const parseResults = new Map<string, FileAnalysisResult>();

  for (const input of inputs) {
    const startTime = Date.now();
    const parsed = parsePythonSource(input.sourceCode);

    if (!parsed.success) {
      parseResults.set(input.filePath, {
        file: input.filePath,
        language: 'python',
        findings: [],
        cees: [],
        success: false,
        error: `Tree-sitter parse failed: ${parsed.error || 'Unknown parse failure.'}`,
        analysisTimeMs: Date.now() - startTime,
      });
      continue;
    }

    parsedByFile.set(input.filePath, parsed);
    parseResults.set(input.filePath, {
      file: input.filePath,
      language: 'python',
      findings: [],
      cees: [],
      success: true,
      analysisTimeMs: Date.now() - startTime,
    });
  }

  if (parsedByFile.size === 0) {
    return inputs.map((input) => parseResults.get(input.filePath) || {
      file: input.filePath,
      language: 'python',
      findings: [],
      cees: [],
      success: false,
      error: 'Python file was not analyzed.',
      analysisTimeMs: 0,
    });
  }

  const findingsByFile = new Map<string, AFBFinding[]>();
  const ceesByFile = new Map<string, CEERecord[]>();
  const seenEvents = new Set<string>();
  const callGraph = buildCallGraph(parsedByFile);

  for (const exposed of callGraph.exposedPaths) {
    const operationFile = exposed.file;
    const parsed = parsedByFile.get(operationFile);
    if (!parsed) {
      continue;
    }

    const eventKey = buildCEEKey(operationFile, exposed);
    if (seenEvents.has(eventKey)) {
      continue;
    }
    seenEvents.add(eventKey);

    const cee = createCEEFromPath(operationFile, exposed, parsed);
    const fileCEEs = ceesByFile.get(operationFile) || [];
    fileCEEs.push(cee);
    ceesByFile.set(operationFile, fileCEEs);

    if (cee.afbType === AFBType.UNAUTHORIZED_ACTION) {
      const fileFindings = findingsByFile.get(operationFile) || [];
      fileFindings.push(createFindingFromCEE(cee, parsed));
      findingsByFile.set(operationFile, fileFindings);
    }
  }

  for (const [filePath, fileCEEs] of ceesByFile) {
    fileCEEs.sort((a, b) => {
      const severityOrder = { critical: 0, warning: 1, info: 2, suppressed: 3 };
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.line - b.line;
    });

    const result = parseResults.get(filePath);
    if (result) {
      result.cees = fileCEEs;
    }
  }

  for (const [filePath, fileFindings] of findingsByFile) {
    fileFindings.sort((a, b) => {
      const severityOrder = { critical: 0, warning: 1, info: 2, suppressed: 3 };
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.line - b.line;
    });

    const result = parseResults.get(filePath);
    if (result) {
      result.findings = fileFindings;
    }
  }

  return inputs.map((input) => parseResults.get(input.filePath) || {
    file: input.filePath,
    language: 'python',
    findings: [],
    cees: [],
    success: false,
    error: 'Python file was not analyzed.',
    analysisTimeMs: 0,
  });
}

function buildCEEKey(filePath: string, exposed: ExposedPath): string {
  return [
    exposed.tool.sourceFile || filePath,
    exposed.tool.name,
    filePath,
    exposed.operation.line,
    exposed.operation.callee,
  ].join(':');
}

function createCEEFromPath(
  filePath: string,
  exposed: ExposedPath,
  parsed: ParsedPythonFile
): CEERecord {
  const op = exposed.operation;
  const severity = calculateSeverity(op.severity, op, exposed);
  const callPath = exposed.path.map((nodeId) => nodeId.includes(':') ? nodeId : `${filePath}:${nodeId}`);

  return {
    file: filePath,
    line: op.line,
    column: op.column,
    operation: `${getCategoryDescription(op.category)}: ${op.callee}`,
    codeSnippet: op.codeSnippet,
    category: op.category,
    severity,
    tool: exposed.tool.name,
    framework: exposed.tool.framework,
    toolFile: exposed.tool.sourceFile,
    toolLine: exposed.tool.startLine,
    callPath,
    gateStatus: exposed.hasGateInPath ? 'present' : 'absent',
    afbType: exposed.hasGateInPath ? null : AFBType.UNAUTHORIZED_ACTION,
    classificationNote: buildCEEClassificationNote(exposed),
    evidenceKind: exposed.evidenceKind,
    supportingEvidence: exposed.supportingEvidence,
    resource: exposed.resourceHint,
    changesState: exposed.changesState,
    involvesCrossFile: exposed.involvesCrossFile,
    unresolvedCalls: exposed.unresolvedCrossFileCalls,
    depthLimitHit: exposed.depthLimitHit,
  };
}

function createFindingFromCEE(cee: CEERecord, parsed: ParsedPythonFile): AFBFinding {
  const call = parsed.calls.find((c) => c.startLine === cee.line && cee.operation.endsWith(c.callee));

  return {
    type: AFBType.UNAUTHORIZED_ACTION,
    severity: cee.severity,
    category: cee.category,
    file: cee.file,
    line: cee.line,
    column: cee.column,
    codeSnippet: cee.codeSnippet,
    operation: cee.operation,
    explanation: cee.classificationNote,
    confidence: calculateConfidenceForCEE(cee),
    context: {
      enclosingFunction: call?.enclosingFunction,
      enclosingClass: call?.enclosingClass,
      isToolDefinition: true,
      framework: cee.framework,
      toolFile: cee.toolFile,
      toolLine: cee.toolLine,
      toolName: cee.tool,
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

function calculateConfidenceForCEE(cee: CEERecord): number {
  let confidence = 0.76;

  if (cee.evidenceKind === 'structural') {
    confidence += 0.18;
  } else if (cee.evidenceKind === 'semantic') {
    confidence += 0.12;
  } else if (cee.evidenceKind === 'heuristic') {
    confidence -= 0.04;
  }

  if (cee.supportingEvidence && cee.supportingEvidence.length > 0) {
    confidence += Math.min(0.08, cee.supportingEvidence.length * 0.02);
  }

  if (cee.unresolvedCalls && cee.unresolvedCalls.length > 0) {
    confidence -= 0.08;
  }

  if (cee.depthLimitHit) {
    confidence -= 0.1;
  }

  if (cee.gateStatus === 'present') {
    confidence -= 0.04;
  }

  return Math.max(0.45, Math.min(0.98, Number(confidence.toFixed(2))));
}

/**
 * Create a finding from an exposed path
 *
 * Applies the CEE (Comprehensive Exposure Evaluation) severity model:
 * - Starts with operation's base severity
 * - Adjusts based on reversibility, data sensitivity, and validation helpers
 */
function createFindingFromExposedPath(
  filePath: string,
  exposed: ExposedPath,
  parsed: ParsedPythonFile
): AFBFinding {
  return createFindingFromCEE(createCEEFromPath(filePath, exposed, parsed), parsed);
}

/**
 * Build explanation text for a finding
 */
function buildExplanation(exposed: ExposedPath, op: DangerousOperation): string {
  const toolName = exposed.tool.name;
  const framework = exposed.tool.framework || 'agent framework';
  const pathLen = exposed.path.length;

  let explanation = `Detected reachable call from tool "${toolName}" (${framework}) to ${op.callee}`;

  if (pathLen > 1) {
    explanation += ` through ${pathLen - 1} intermediate call(s)`;
  }

  explanation += '. ';

  if (exposed.involvesCrossFile) {
    explanation += 'The analyzed path crosses file boundaries. ';
  }

  if (!exposed.hasGateInPath) {
    explanation += 'No policy gate detected in the analyzed call path. ';

    if (exposed.hasHeuristicGateInPath) {
      explanation += 'Authorization-like decorator names were present, but the analyzed path did not provide structural gate evidence. ';
    }

    if (exposed.hasValidationHelperInPath) {
      explanation += 'The analyzed path includes a probable validation-helper name. This is heuristic evidence, not structural gate proof. ';
    }
  }

  if (exposed.inputFlowsToOperation) {
    explanation += 'Traced tool-controlled input into the matched operation arguments. ';
  }

  if (exposed.instructionLikeInput) {
    explanation += 'Instruction or context-like input is present in the analyzed path. ';
  }

  if (exposed.resourceHint) {
    explanation += `Resource hint: ${exposed.resourceHint}. `;
  }

  if (exposed.unresolvedCrossFileCalls && exposed.unresolvedCrossFileCalls.length > 0) {
    explanation += `Unresolved call targets while tracing: ${exposed.unresolvedCrossFileCalls.slice(0, 5).join(', ')}. `;
  }

  if (exposed.depthLimitHit) {
    explanation += 'Cross-file depth limit was reached while tracing this path. Manual review recommended. ';
  }

  return explanation.trim();
}

function buildCEEClassificationNote(exposed: ExposedPath): string {
  const op = exposed.operation;

  if (exposed.hasGateInPath) {
    let note = `Detected reachable call from tool "${exposed.tool.name}" (${exposed.tool.framework || 'agent framework'}) to ${op.callee}. Policy gate detected in the analyzed call path, so this event was not classified as AFB04.`;

    if (exposed.involvesCrossFile) {
      note += ' The analyzed path crosses file boundaries.';
    }

    if (exposed.inputFlowsToOperation) {
      note += ' Tool-controlled input was traced into the matched operation arguments.';
    }

    if (exposed.instructionLikeInput) {
      note += ' Instruction or context-like input is present in the analyzed path.';
    }

    if (exposed.unresolvedCrossFileCalls && exposed.unresolvedCrossFileCalls.length > 0) {
      note += ` Unresolved call targets while tracing: ${exposed.unresolvedCrossFileCalls.slice(0, 5).join(', ')}.`;
    }

    if (exposed.depthLimitHit) {
      note += ' Cross-file depth limit was reached while tracing this path. Manual review recommended.';
    }

    return note;
  }

  return buildExplanation(exposed, op);
}

/**
 * Get human-readable category description
 */
function getCategoryDescription(category: ExecutionCategory): string {
  const descriptions: Record<ExecutionCategory, string> = {
    [ExecutionCategory.TOOL_CALL]: 'Tool invocation',
    [ExecutionCategory.SHELL_EXECUTION]: 'Shell command execution',
    [ExecutionCategory.FILE_OPERATION]: 'File system operation',
    [ExecutionCategory.API_CALL]: 'External API call',
    [ExecutionCategory.DATABASE_OPERATION]: 'Database operation',
    [ExecutionCategory.CODE_EXECUTION]: 'Dynamic code execution',
  };
  return descriptions[category] || category;
}
