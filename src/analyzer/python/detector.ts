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
  FileAnalysisResult,
  AFBType,
  ExecutionCategory,
  Severity,
} from '../../types';

/**
 * SEVERITY MODEL (CEE - Comprehensive Exposure Evaluation)
 *
 * Severity is determined by three factors:
 *
 * 1. REVERSIBILITY
 *    - Irreversible operations (delete, rmtree, DROP TABLE, unlink) are always CRITICAL
 *    - Reversible mutations (write, POST, INSERT) stay WARNING unless other factors apply
 *
 * 2. DATA SENSITIVITY CONTEXT
 *    - If the dangerous operation is inside a function whose name or parameters
 *      suggest PII, auth tokens, credentials, secrets, or keys:
 *      elevate severity by one level
 *
 * 3. VALIDATION HELPER HEURISTIC
 *    - If a call path passes through a function named sanitize*, validate*,
 *      check*, verify*, etc.: downgrade severity by one level
 *    - This is a heuristic, not confirmation of a gate
 *
 * Severity cap: CRITICAL (cannot elevate beyond CRITICAL)
 * Severity floor: SUPPRESSED (cannot downgrade beyond SUPPRESSED)
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

/** Patterns that suggest sensitive data is involved */
const SENSITIVE_DATA_PATTERNS = [
  /password/i,
  /secret/i,
  /credential/i,
  /api[_-]?key/i,
  /token/i,
  /private[_-]?key/i,
  /pii/i,
  /ssn/i,
  /credit[_-]?card/i,
  /auth/i,
];

/**
 * Calculate the final severity for an exposed path.
 *
 * Applies the CEE (Comprehensive Exposure Evaluation) model:
 * 1. Start with operation's base severity
 * 2. Elevate to CRITICAL if operation is irreversible
 * 3. Elevate one level if sensitive data context detected
 * 4. Downgrade one level if validation helper in path
 */
function calculateSeverity(
  baseSeverity: Severity,
  operation: DangerousOperation,
  exposed: ExposedPath
): Severity {
  let severity = baseSeverity;

  // 1. Irreversibility: always CRITICAL
  if (isIrreversibleOperation(operation.callee)) {
    return Severity.CRITICAL;
  }

  // 2. Data sensitivity: elevate one level
  const enclosingFunc = exposed.tool.name;
  if (touchesSensitiveData(operation.codeSnippet, enclosingFunc)) {
    severity = elevateSeverity(severity);
  }

  // 3. Validation helper in path: downgrade one level
  if (exposed.hasValidationHelperInPath) {
    severity = downgradeSeverity(severity);
  }

  return severity;
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

/** Check if code or function name suggests sensitive data */
function touchesSensitiveData(codeSnippet: string, functionName: string): boolean {
  const combined = `${codeSnippet} ${functionName}`;
  return SENSITIVE_DATA_PATTERNS.some(pattern => pattern.test(combined));
}

/** Elevate severity by one level (cap at CRITICAL) */
function elevateSeverity(severity: Severity): Severity {
  switch (severity) {
    case Severity.SUPPRESSED:
      return Severity.INFO;
    case Severity.INFO:
      return Severity.WARNING;
    case Severity.WARNING:
      return Severity.CRITICAL;
    case Severity.CRITICAL:
      return Severity.CRITICAL;
    default:
      return severity;
  }
}

/** Downgrade severity by one level (floor at SUPPRESSED) */
function downgradeSeverity(severity: Severity): Severity {
  switch (severity) {
    case Severity.CRITICAL:
      return Severity.WARNING;
    case Severity.WARNING:
      return Severity.INFO;
    case Severity.INFO:
      return Severity.SUPPRESSED;
    case Severity.SUPPRESSED:
      return Severity.SUPPRESSED;
    default:
      return severity;
  }
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
 * This is the simplified single-file analysis for CLI use.
 * For full call graph analysis across multiple files, use analyzeProject().
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
  // Key: file:line:callee - same dangerous operation should only be reported once
  const seenOperations = new Set<string>();

  for (const exposed of callGraph.exposedPaths) {
    // Skip if there's a policy gate in the path
    if (exposed.hasGateInPath) {
      continue;
    }

    // Deduplicate: same file + line + callee = same finding
    const opKey = `${filePath}:${exposed.operation.line}:${exposed.operation.callee}`;
    if (seenOperations.has(opKey)) {
      continue;
    }
    seenOperations.add(opKey);

    const finding = createFindingFromExposedPath(filePath, exposed, parsed);
    findings.push(finding);
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
    success: true,
    analysisTimeMs: Date.now() - startTime,
  };
}

/**
 * Analyze multiple Python files with cross-file call graph analysis.
 *
 * IMPORTANT: If any file fails to parse, it is recorded as a failed file
 * in the results. We do NOT fall back to regex-based detection.
 */
export function analyzeProject(
  files: Map<string, string>
): Map<string, FileAnalysisResult> {
  const results = new Map<string, FileAnalysisResult>();
  const startTime = Date.now();

  // Parse all files - track failures separately
  const parsedFiles = new Map<string, ParsedPythonFile>();
  for (const [filePath, sourceCode] of files) {
    const parsed = parsePythonSource(sourceCode);
    if (parsed.success) {
      parsedFiles.set(filePath, parsed);
    } else {
      // Record the failure - do NOT fall back to regex
      results.set(filePath, {
        file: filePath,
        language: 'python',
        findings: [],
        success: false,
        error: `Tree-sitter parse failed: ${parsed.error || 'Unknown parse error'}`,
        analysisTimeMs: Date.now() - startTime,
      });
    }
  }

  // Build cross-file call graph from successfully parsed files
  const callGraph = buildCallGraph(parsedFiles);

  // Group exposed paths by file
  const pathsByFile = new Map<string, ExposedPath[]>();
  for (const exposed of callGraph.exposedPaths) {
    const existing = pathsByFile.get(exposed.file) || [];
    existing.push(exposed);
    pathsByFile.set(exposed.file, existing);
  }

  // Generate findings per file with deduplication
  for (const [filePath, parsed] of parsedFiles) {
    const findings: AFBFinding[] = [];
    const exposedPaths = pathsByFile.get(filePath) || [];

    // Deduplicate: same file + line + callee = same finding
    const seenOperations = new Set<string>();

    for (const exposed of exposedPaths) {
      if (exposed.hasGateInPath) continue;

      const opKey = `${filePath}:${exposed.operation.line}:${exposed.operation.callee}`;
      if (seenOperations.has(opKey)) {
        continue;
      }
      seenOperations.add(opKey);

      findings.push(createFindingFromExposedPath(filePath, exposed, parsed));
    }

    // NOTE: Removed tool-registration-only findings for project analysis too.
    // Tools without dangerous operations don't generate findings.

    findings.sort((a, b) => {
      const severityOrder = { critical: 0, warning: 1, info: 2, suppressed: 3 };
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.line - b.line;
    });

    results.set(filePath, {
      file: filePath,
      language: 'python',
      findings,
      success: true,
      analysisTimeMs: Date.now() - startTime,
    });
  }

  return results;
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
  const op = exposed.operation;

  // Apply CEE severity model
  const severity = calculateSeverity(op.severity, op, exposed);

  // Find the call that contains this operation
  const call = parsed.calls.find((c) => c.startLine === op.line && c.callee === op.callee);

  return {
    type: AFBType.UNAUTHORIZED_ACTION,
    severity,
    category: op.category,
    file: filePath,
    line: op.line,
    column: op.column,
    codeSnippet: op.codeSnippet,
    operation: `${getCategoryDescription(op.category)}: ${op.callee}`,
    explanation: buildExplanation(exposed, op),
    confidence: 0.95,
    context: {
      enclosingFunction: call?.enclosingFunction,
      enclosingClass: call?.enclosingClass,
      isToolDefinition: true,
      framework: exposed.tool.framework,
    },
  };
}

/**
 * Build explanation text for a finding
 */
function buildExplanation(exposed: ExposedPath, op: DangerousOperation): string {
  const toolName = exposed.tool.name;
  const framework = exposed.tool.framework || 'agent framework';
  const pathLen = exposed.path.length;

  let explanation = `Tool "${toolName}" (${framework}) can reach ${op.callee}`;

  if (pathLen > 1) {
    explanation += ` through ${pathLen - 1} call(s)`;
  }

  explanation += '. ';

  if (!exposed.hasGateInPath) {
    explanation += 'No policy gate or authorization check detected in call path. ';

    if (exposed.hasValidationHelperInPath) {
      explanation += 'Path includes probable validation helper (severity downgraded). ';
    }

    explanation += 'Agent can execute this operation without authorization basis.';
  }

  return explanation;
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

/**
 * Quick check if Python code likely contains agent-related patterns.
 */
export function likelyContainsAgentCode(sourceCode: string): boolean {
  const agentIndicators = [
    'langchain',
    'crewai',
    'autogen',
    'llama_index',
    'llamaindex',
    '@tool',
    '@task',
    '@agent',
    'BaseTool',
    'StructuredTool',
    'DynamicTool',
    'Agent',
    'AgentExecutor',
    'Tool(',
    'tools=',
    'FunctionTool',
    'register_function',
    'function_map',
    'mcp.server',
    '@server.tool',
    'openai.ChatCompletion',
    'tool_choice',
  ];

  const lowerCode = sourceCode.toLowerCase();
  return agentIndicators.some((indicator) =>
    lowerCode.includes(indicator.toLowerCase())
  );
}
