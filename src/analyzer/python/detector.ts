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

let parserInitialized = false;

/**
 * Ensure the AST parser is initialized
 */
export async function ensureParserInitialized(): Promise<void> {
  if (!parserInitialized) {
    try {
      await initParser();
      parserInitialized = true;
    } catch {
      // Fall back to regex-based parsing if tree-sitter fails
      console.warn('Tree-sitter initialization failed, using regex fallback');
    }
  }
}

/**
 * Analyze a single Python file for AFB04 boundaries.
 *
 * This is the simplified single-file analysis for CLI use.
 * For full call graph analysis across multiple files, use analyzeProject().
 */
export function analyzePythonFile(
  filePath: string,
  sourceCode: string
): FileAnalysisResult {
  const startTime = Date.now();
  const findings: AFBFinding[] = [];

  try {
    // Parse the file
    const parsed = parsePythonSource(sourceCode);

    if (!parsed.success) {
      // Fall back to regex-based detection
      return analyzeWithRegex(filePath, sourceCode, startTime);
    }

    // Build call graph for this single file
    const fileMap = new Map<string, ParsedPythonFile>();
    fileMap.set(filePath, parsed);
    const callGraph = buildCallGraph(fileMap);

    // Convert exposed paths to findings
    for (const exposed of callGraph.exposedPaths) {
      // Skip if there's a policy gate in the path
      if (exposed.hasGateInPath) {
        continue;
      }

      const finding = createFindingFromExposedPath(filePath, exposed, parsed);
      findings.push(finding);
    }

    // Also report tool definitions themselves (even if no dangerous ops found)
    for (const tool of callGraph.toolRegistrations) {
      // Only report if we haven't already reported it via exposed paths
      const alreadyReported = findings.some(
        (f) => f.line === tool.startLine && f.category === ExecutionCategory.TOOL_CALL
      );

      if (!alreadyReported) {
        findings.push(createToolDefinitionFinding(filePath, tool, parsed));
      }
    }

    // Sort findings by severity, then line
    findings.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2 };
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
  } catch (error) {
    // Fall back to regex analysis on any error
    return analyzeWithRegex(filePath, sourceCode, startTime);
  }
}

/**
 * Analyze multiple Python files with cross-file call graph analysis.
 */
export function analyzeProject(
  files: Map<string, string>
): Map<string, FileAnalysisResult> {
  const results = new Map<string, FileAnalysisResult>();
  const startTime = Date.now();

  // Parse all files
  const parsedFiles = new Map<string, ParsedPythonFile>();
  for (const [filePath, sourceCode] of files) {
    const parsed = parsePythonSource(sourceCode);
    if (parsed.success) {
      parsedFiles.set(filePath, parsed);
    } else {
      // Fall back to regex for this file
      const regexResult = analyzeWithRegex(filePath, sourceCode, Date.now());
      results.set(filePath, regexResult);
    }
  }

  // Build cross-file call graph
  const callGraph = buildCallGraph(parsedFiles);

  // Group exposed paths by file
  const pathsByFile = new Map<string, ExposedPath[]>();
  for (const exposed of callGraph.exposedPaths) {
    const existing = pathsByFile.get(exposed.file) || [];
    existing.push(exposed);
    pathsByFile.set(exposed.file, existing);
  }

  // Generate findings per file
  for (const [filePath, parsed] of parsedFiles) {
    const findings: AFBFinding[] = [];
    const exposedPaths = pathsByFile.get(filePath) || [];

    for (const exposed of exposedPaths) {
      if (exposed.hasGateInPath) continue;
      findings.push(createFindingFromExposedPath(filePath, exposed, parsed));
    }

    // Add tool definitions
    const toolsInFile = callGraph.toolRegistrations.filter((t) => {
      // Find tools defined in this file by checking line ranges
      for (const func of parsed.functions) {
        if (func.startLine === t.startLine && func.name === t.name) return true;
      }
      for (const cls of parsed.classes) {
        for (const method of cls.methods) {
          if (method.startLine === t.startLine && t.id === `${cls.name}.${method.name}`) return true;
        }
      }
      return false;
    });

    for (const tool of toolsInFile) {
      const alreadyReported = findings.some(
        (f) => f.line === tool.startLine && f.category === ExecutionCategory.TOOL_CALL
      );
      if (!alreadyReported) {
        findings.push(createToolDefinitionFinding(filePath, tool, parsed));
      }
    }

    findings.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2 };
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
 */
function createFindingFromExposedPath(
  filePath: string,
  exposed: ExposedPath,
  parsed: ParsedPythonFile
): AFBFinding {
  const op = exposed.operation;

  // Elevate severity if inside a tool with no policy gate
  let severity = op.severity;
  if (!exposed.hasGateInPath && severity !== Severity.CRITICAL) {
    severity = severity === Severity.MEDIUM ? Severity.HIGH : Severity.CRITICAL;
  }

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
 * Create a finding for a tool definition
 */
function createToolDefinitionFinding(
  filePath: string,
  tool: { id: string; name: string; className?: string; startLine: number; decorators: string[]; framework?: string },
  parsed: ParsedPythonFile
): AFBFinding {
  // Find the function definition
  const func = parsed.functions.find(
    (f) => f.startLine === tool.startLine || (f.className && `${f.className}.${f.name}` === tool.id)
  );

  const codeSnippet = func
    ? `@${tool.decorators[0] || 'tool'}\ndef ${func.name}(...)`
    : `${tool.className ? tool.className + '.' : ''}${tool.name}`;

  return {
    type: AFBType.UNAUTHORIZED_ACTION,
    severity: Severity.HIGH,
    category: ExecutionCategory.TOOL_CALL,
    file: filePath,
    line: tool.startLine,
    column: 1,
    codeSnippet,
    operation: `Tool registration: ${tool.name}`,
    explanation: `Tool "${tool.name}" is registered with ${tool.framework || 'agent framework'}, making it callable by agent reasoning. Review what this tool can do and ensure appropriate policy controls.`,
    confidence: 0.9,
    context: {
      enclosingFunction: tool.name,
      enclosingClass: tool.className,
      isToolDefinition: true,
      framework: tool.framework,
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
 * Fallback regex-based analysis when tree-sitter is unavailable
 */
function analyzeWithRegex(
  filePath: string,
  sourceCode: string,
  startTime: number
): FileAnalysisResult {
  const findings: AFBFinding[] = [];
  const lines = sourceCode.split('\n');

  // Tool decorator patterns
  const toolDecoratorPatterns = [
    { regex: /^\s*@tool\b/i, framework: 'langchain' },
    { regex: /^\s*@task\b/i, framework: 'crewai' },
    { regex: /^\s*@server\.tool\b/i, framework: 'mcp' },
    { regex: /^\s*@agent\b/i, framework: 'crewai' },
  ];

  // Class inheritance patterns for tools
  const toolClassPatterns = [
    { regex: /class\s+\w+\s*\(\s*BaseTool\s*\)/i, framework: 'langchain' },
    { regex: /class\s+\w+\s*\(\s*StructuredTool\s*\)/i, framework: 'langchain' },
    { regex: /class\s+\w+\s*\(\s*FunctionTool\s*\)/i, framework: 'llamaindex' },
  ];

  // Track if we're inside a tool definition
  let inToolDef = false;
  let toolStartLine = 0;
  let toolFramework: string | undefined;
  let toolIndent = 0;
  let defIndent = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const currentIndent = line.search(/\S/);

    // Check for tool decorator
    for (const pattern of toolDecoratorPatterns) {
      if (pattern.regex.test(line)) {
        inToolDef = true;
        toolStartLine = lineNum;
        toolFramework = pattern.framework;
        toolIndent = currentIndent;
        defIndent = -1;

        findings.push({
          type: AFBType.UNAUTHORIZED_ACTION,
          severity: Severity.HIGH,
          category: ExecutionCategory.TOOL_CALL,
          file: filePath,
          line: lineNum,
          column: 1,
          codeSnippet: line.trim(),
          operation: 'Tool definition',
          explanation: `Tool registered with ${pattern.framework}. Agent can invoke this tool. Review capabilities and add policy controls.`,
          confidence: 0.9,
          context: { isToolDefinition: true, framework: pattern.framework },
        });
        break;
      }
    }

    // Check for tool class definitions
    for (const pattern of toolClassPatterns) {
      if (pattern.regex.test(line)) {
        findings.push({
          type: AFBType.UNAUTHORIZED_ACTION,
          severity: Severity.HIGH,
          category: ExecutionCategory.TOOL_CALL,
          file: filePath,
          line: lineNum,
          column: 1,
          codeSnippet: line.trim(),
          operation: 'Tool class definition',
          explanation: `Tool class inherits from ${pattern.framework} tool base. Agent can invoke methods of this tool.`,
          confidence: 0.9,
          context: { isToolDefinition: true, framework: pattern.framework },
        });
      }
    }

    // Track function definition after decorator
    if (inToolDef && (line.match(/^\s*def\s+/) || line.match(/^\s*async\s+def\s+/))) {
      defIndent = currentIndent;
    }

    // Check if we've exited the tool definition (dedent after function def)
    if (inToolDef && defIndent >= 0 && currentIndent >= 0 && currentIndent <= defIndent && lineNum > toolStartLine + 2) {
      if (!line.trim().startsWith('@') && !line.trim().startsWith('def') && !line.trim().startsWith('async') && line.trim() !== '' && !line.trim().startsWith('#') && !line.trim().startsWith('"""') && !line.trim().startsWith("'''")) {
        inToolDef = false;
        defIndent = -1;
      }
    }

    // Check for dangerous operations
    const dangerousPatterns = [
      { regex: /subprocess\.(run|Popen|call|check_output|check_call)\s*\(/, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, desc: 'Subprocess execution' },
      { regex: /os\.(system|popen|exec\w*|spawn\w*)\s*\(/, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, desc: 'OS command execution' },
      { regex: /\beval\s*\(/, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, desc: 'Dynamic code evaluation' },
      { regex: /\bexec\s*\(/, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, desc: 'Dynamic code execution' },
      { regex: /requests\.(get|post|put|patch|delete|request)\s*\(/, category: ExecutionCategory.API_CALL, severity: Severity.HIGH, desc: 'HTTP request' },
      { regex: /httpx\.(get|post|put|patch|delete|request)\s*\(/, category: ExecutionCategory.API_CALL, severity: Severity.HIGH, desc: 'HTTP request' },
      { regex: /\.execute\s*\(/, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.HIGH, desc: 'SQL execution' },
      { regex: /\.executemany\s*\(/, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.HIGH, desc: 'SQL batch execution' },
      { regex: /\.write_text\s*\(/, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, desc: 'File write' },
      { regex: /\.write_bytes\s*\(/, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, desc: 'File write' },
      { regex: /shutil\.(rmtree|copy|copy2|copytree|move|remove)\s*\(/, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, desc: 'Bulk file operation' },
      { regex: /os\.(remove|unlink|rmdir|mkdir|makedirs|rename)\s*\(/, category: ExecutionCategory.FILE_OPERATION, severity: Severity.HIGH, desc: 'File system operation' },
    ];

    for (const pattern of dangerousPatterns) {
      const match = line.match(pattern.regex);
      if (match) {
        // Elevate severity if inside tool definition
        let severity = pattern.severity;
        if (inToolDef && severity !== Severity.CRITICAL) {
          severity = severity === Severity.MEDIUM ? Severity.HIGH : Severity.CRITICAL;
        }

        findings.push({
          type: AFBType.UNAUTHORIZED_ACTION,
          severity,
          category: pattern.category,
          file: filePath,
          line: lineNum,
          column: (match.index || 0) + 1,
          codeSnippet: line.trim(),
          operation: pattern.desc,
          explanation: inToolDef
            ? `${pattern.desc} inside tool definition. Agent can invoke this without authorization basis.`
            : `${pattern.desc} detected. Verify it is not reachable from agent tools without policy gates.`,
          confidence: inToolDef ? 0.95 : 0.7,
          context: {
            isToolDefinition: inToolDef,
            framework: inToolDef ? toolFramework : undefined,
          },
        });
      }
    }
  }

  // Sort by severity then line
  findings.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2 };
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
