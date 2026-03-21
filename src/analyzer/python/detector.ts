/**
 * Python AFB04 Detector
 *
 * Detects AFB04 (Unauthorized Action) boundaries in Python codebases.
 * Focuses on agent frameworks (LangChain, CrewAI) and dangerous operations
 * (shell commands, file operations, API calls, database operations).
 *
 * Detection approach:
 * 1. Walk the AST looking for function calls and decorators
 * 2. Match against known execution patterns
 * 3. Analyze context (is this inside a tool definition?)
 * 4. Generate findings with confidence scores
 */

import { ASTWalker, astWalker } from "../ast-walker";
import {
  AFBFinding,
  FileAnalysisResult,
} from "../../types";
import {
  PYTHON_PATTERNS,
  ExecutionPattern,
  createFinding,
} from "../../afb/afb04";

// Type alias for tree-sitter nodes (using any for web-tree-sitter compatibility)
type SyntaxNode = any;

/**
 * Detects if a call node matches a specific pattern.
 * Returns the pattern if matched, null otherwise.
 */
function matchCallPattern(
  node: SyntaxNode,
  sourceCode: string
): { pattern: ExecutionPattern; patternKey: string } | null {
  if (node.type !== "call") {
    return null;
  }

  const funcNode = node.childForFieldName?.("function");
  if (!funcNode) {
    return null;
  }

  const funcText = funcNode.text;

  // === TOOL CALL PATTERNS ===

  // Tool instantiation: Tool(...), StructuredTool(...), DynamicTool(...)
  if (
    funcText === "Tool" ||
    funcText === "StructuredTool" ||
    funcText === "DynamicTool" ||
    funcText === "BaseTool"
  ) {
    return { pattern: PYTHON_PATTERNS.tool_instantiation, patternKey: "tool_instantiation" };
  }

  // === SHELL EXECUTION PATTERNS ===

  // subprocess.run(), subprocess.Popen(), subprocess.call()
  if (
    funcText === "subprocess.run" ||
    funcText.endsWith(".run") && sourceCode.includes("import subprocess")
  ) {
    return { pattern: PYTHON_PATTERNS.subprocess_run, patternKey: "subprocess_run" };
  }

  if (
    funcText === "subprocess.Popen" ||
    funcText === "subprocess.call" ||
    funcText === "subprocess.check_output" ||
    funcText === "subprocess.check_call"
  ) {
    return { pattern: PYTHON_PATTERNS.subprocess_run, patternKey: "subprocess_run" };
  }

  // os.system(), os.popen()
  if (funcText === "os.system") {
    return { pattern: PYTHON_PATTERNS.os_system, patternKey: "os_system" };
  }

  if (funcText === "os.popen") {
    return { pattern: PYTHON_PATTERNS.os_popen, patternKey: "os_popen" };
  }

  // os.exec* family
  if (
    funcText.startsWith("os.exec") ||
    funcText.startsWith("os.spawn")
  ) {
    return { pattern: PYTHON_PATTERNS.os_system, patternKey: "os_system" };
  }

  // === FILE OPERATION PATTERNS ===

  // open() - builtin
  if (funcText === "open") {
    return { pattern: PYTHON_PATTERNS.file_open, patternKey: "file_open" };
  }

  // pathlib write operations
  if (
    funcText.endsWith(".write_text") ||
    funcText.endsWith(".write_bytes")
  ) {
    return { pattern: PYTHON_PATTERNS.pathlib_write, patternKey: "pathlib_write" };
  }

  // shutil operations
  if (
    funcText.startsWith("shutil.") &&
    (funcText.includes("copy") ||
      funcText.includes("move") ||
      funcText.includes("rmtree") ||
      funcText.includes("remove"))
  ) {
    return { pattern: PYTHON_PATTERNS.shutil_operation, patternKey: "shutil_operation" };
  }

  // os file operations
  if (
    funcText === "os.remove" ||
    funcText === "os.unlink" ||
    funcText === "os.rmdir" ||
    funcText === "os.mkdir" ||
    funcText === "os.makedirs"
  ) {
    return { pattern: PYTHON_PATTERNS.file_open, patternKey: "file_open" };
  }

  // === API/HTTP PATTERNS ===

  // requests library
  if (
    funcText.startsWith("requests.") &&
    (funcText.includes("get") ||
      funcText.includes("post") ||
      funcText.includes("put") ||
      funcText.includes("patch") ||
      funcText.includes("delete") ||
      funcText.includes("request"))
  ) {
    return { pattern: PYTHON_PATTERNS.requests_call, patternKey: "requests_call" };
  }

  // httpx library
  if (
    funcText.startsWith("httpx.") ||
    (funcText.endsWith(".get") && sourceCode.includes("import httpx")) ||
    (funcText.endsWith(".post") && sourceCode.includes("import httpx"))
  ) {
    return { pattern: PYTHON_PATTERNS.httpx_call, patternKey: "httpx_call" };
  }

  // aiohttp
  if (
    funcText.includes("aiohttp") ||
    (funcText.includes("session.") &&
      sourceCode.includes("aiohttp"))
  ) {
    return { pattern: PYTHON_PATTERNS.aiohttp_call, patternKey: "aiohttp_call" };
  }

  // urllib
  if (
    funcText.startsWith("urllib.request.") ||
    funcText === "urlopen"
  ) {
    return { pattern: PYTHON_PATTERNS.urllib_call, patternKey: "urllib_call" };
  }

  // === DATABASE PATTERNS ===

  // cursor.execute(), cursor.executemany()
  if (
    funcText.endsWith(".execute") ||
    funcText.endsWith(".executemany")
  ) {
    // Check if it looks like a database cursor context
    if (
      sourceCode.includes("cursor") ||
      sourceCode.includes("connection") ||
      sourceCode.includes("sqlite") ||
      sourceCode.includes("psycopg") ||
      sourceCode.includes("mysql")
    ) {
      return { pattern: PYTHON_PATTERNS.cursor_execute, patternKey: "cursor_execute" };
    }
  }

  // SQLAlchemy
  if (
    funcText.endsWith(".execute") &&
    (sourceCode.includes("sqlalchemy") || sourceCode.includes("Session"))
  ) {
    return { pattern: PYTHON_PATTERNS.sqlalchemy_execute, patternKey: "sqlalchemy_execute" };
  }

  // === CODE EXECUTION PATTERNS ===

  // eval()
  if (funcText === "eval") {
    return { pattern: PYTHON_PATTERNS.eval_call, patternKey: "eval_call" };
  }

  // exec()
  if (funcText === "exec") {
    return { pattern: PYTHON_PATTERNS.exec_call, patternKey: "exec_call" };
  }

  // compile()
  if (funcText === "compile") {
    return { pattern: PYTHON_PATTERNS.compile_call, patternKey: "compile_call" };
  }

  return null;
}

/**
 * Detects if a function is decorated with @tool or similar.
 */
function isToolDecoratedFunction(
  funcNode: SyntaxNode
): { isToolDef: boolean; framework?: string } {
  // Check if parent is decorated_definition
  if (funcNode.parent?.type !== "decorated_definition") {
    return { isToolDef: false };
  }

  // Get all decorators
  for (const child of funcNode.parent.children) {
    if (child.type === "decorator") {
      const decoratorText = child.text.toLowerCase();

      // LangChain @tool decorator
      if (decoratorText.includes("@tool")) {
        return { isToolDef: true, framework: "langchain" };
      }

      // CrewAI tool decorator
      if (decoratorText.includes("crewai") || decoratorText.includes("@agent")) {
        return { isToolDef: true, framework: "crewai" };
      }

      // Generic tool patterns
      if (
        decoratorText.includes("tool") ||
        decoratorText.includes("action") ||
        decoratorText.includes("capability")
      ) {
        return { isToolDef: true, framework: "custom" };
      }
    }
  }

  return { isToolDef: false };
}

/**
 * Detects if a class inherits from BaseTool or similar.
 */
function isToolClass(classNode: SyntaxNode): { isToolClass: boolean; framework?: string } {
  // Look for bases/superclasses
  const superclassNode = classNode.childForFieldName?.("superclasses");
  if (!superclassNode) {
    return { isToolClass: false };
  }

  const superclassText = superclassNode.text.toLowerCase();

  if (
    superclassText.includes("basetool") ||
    superclassText.includes("structuredtool") ||
    superclassText.includes("tool")
  ) {
    return { isToolClass: true, framework: "langchain" };
  }

  if (superclassText.includes("crewai")) {
    return { isToolClass: true, framework: "crewai" };
  }

  return { isToolClass: false };
}

/**
 * Analyze a single Python file for AFB04 boundaries.
 */
export function analyzePythonFile(
  filePath: string,
  sourceCode: string
): FileAnalysisResult {
  const startTime = Date.now();
  const findings: AFBFinding[] = [];

  try {
    const tree = astWalker.parse(sourceCode, "python");

    // Track which functions/classes are tool definitions
    const toolFunctions = new Set<SyntaxNode>();
    const toolClasses = new Set<SyntaxNode>();

    // First pass: identify tool definitions
    astWalker.walk(tree, (node) => {
      // Check function definitions for @tool decorator
      if (
        node.type === "function_definition" ||
        node.type === "async_function_definition"
      ) {
        const { isToolDef, framework } = isToolDecoratedFunction(node);
        if (isToolDef) {
          toolFunctions.add(node);

          // Report the tool definition itself as a finding
          const location = astWalker.getNodeLocation(node);
          const funcName = astWalker.getFunctionName(node, "python");

          findings.push(
            createFinding(
              filePath,
              location,
              node.text.split("\n").slice(0, 3).join("\n"),
              PYTHON_PATTERNS.tool_decorator,
              funcName || undefined,
              undefined,
              true,
              framework,
              0.95
            )
          );
        }
      }

      // Check class definitions for BaseTool inheritance
      if (node.type === "class_definition") {
        const { isToolClass: isTool, framework } = isToolClass(node);
        if (isTool) {
          toolClasses.add(node);

          const location = astWalker.getNodeLocation(node);
          const className = astWalker.getClassName(node, "python");

          findings.push(
            createFinding(
              filePath,
              location,
              node.text.split("\n").slice(0, 3).join("\n"),
              PYTHON_PATTERNS.tool_instantiation,
              undefined,
              className || undefined,
              true,
              framework,
              0.9
            )
          );
        }
      }
    });

    // Second pass: find all execution points
    astWalker.walk(tree, (node, ancestors) => {
      if (node.type !== "call") {
        return;
      }

      const match = matchCallPattern(node, sourceCode);
      if (!match) {
        return;
      }

      // Determine if this is inside a tool definition
      let isInToolDefinition = false;
      let framework: string | undefined;

      const enclosingFunc = astWalker.getEnclosingFunction(node, "python");
      if (enclosingFunc && toolFunctions.has(enclosingFunc)) {
        isInToolDefinition = true;
      }

      const enclosingClass = astWalker.getEnclosingClass(node, "python");
      if (enclosingClass && toolClasses.has(enclosingClass)) {
        isInToolDefinition = true;
      }

      // Also check ancestors for decorated_definition with @tool
      for (const ancestor of ancestors) {
        if (
          ancestor.type === "function_definition" ||
          ancestor.type === "async_function_definition"
        ) {
          const { isToolDef, framework: detectedFramework } =
            isToolDecoratedFunction(ancestor);
          if (isToolDef) {
            isInToolDefinition = true;
            framework = detectedFramework;
            break;
          }
        }
      }

      const location = astWalker.getNodeLocation(node);
      const funcName = enclosingFunc
        ? astWalker.getFunctionName(enclosingFunc, "python")
        : undefined;
      const className = enclosingClass
        ? astWalker.getClassName(enclosingClass, "python")
        : undefined;

      // Calculate confidence based on pattern and context
      let confidence = 0.8;
      if (isInToolDefinition) {
        confidence = 0.95; // Higher confidence when inside a tool
      }

      findings.push(
        createFinding(
          filePath,
          location,
          node.text,
          match.pattern,
          funcName || undefined,
          className || undefined,
          isInToolDefinition,
          framework,
          confidence
        )
      );
    });

    return {
      file: filePath,
      language: "python",
      findings,
      success: true,
      analysisTimeMs: Date.now() - startTime,
    };
  } catch (error) {
    return {
      file: filePath,
      language: "python",
      findings: [],
      success: false,
      error: error instanceof Error ? error.message : String(error),
      analysisTimeMs: Date.now() - startTime,
    };
  }
}

/**
 * Quick check if Python code likely contains agent-related patterns.
 * Used for pre-filtering before full analysis.
 */
export function likelyContainsAgentCode(sourceCode: string): boolean {
  const agentIndicators = [
    "langchain",
    "crewai",
    "@tool",
    "BaseTool",
    "StructuredTool",
    "DynamicTool",
    "Agent",
    "AgentExecutor",
    "Tool(",
    "tools=",
  ];

  const lowerCode = sourceCode.toLowerCase();
  return agentIndicators.some((indicator) =>
    lowerCode.includes(indicator.toLowerCase())
  );
}
