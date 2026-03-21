/**
 * TypeScript/JavaScript AFB04 Detector
 *
 * Detects AFB04 (Unauthorized Action) boundaries in TypeScript/JavaScript codebases.
 * Focuses on agent frameworks (LangChain.js) and dangerous operations
 * (shell commands, file operations, API calls, database operations).
 *
 * Detection approach:
 * 1. Walk the AST looking for function calls and class definitions
 * 2. Match against known execution patterns
 * 3. Analyze context (is this inside a tool definition?)
 * 4. Generate findings with confidence scores
 */

import Parser from "tree-sitter";
import { astWalker } from "../ast-walker";
import {
  AFBFinding,
  FileAnalysisResult,
} from "../../types";
import {
  TYPESCRIPT_PATTERNS,
  ExecutionPattern,
  createFinding,
} from "../../afb/afb04";

/**
 * Detects if a call node matches a specific pattern.
 * Returns the pattern if matched, null otherwise.
 */
function matchCallPattern(
  node: Parser.SyntaxNode,
  sourceCode: string
): { pattern: ExecutionPattern; patternKey: string } | null {
  if (node.type !== "call_expression") {
    return null;
  }

  const funcNode = node.childForFieldName("function");
  if (!funcNode) {
    return null;
  }

  const funcText = funcNode.text;

  // === TOOL CALL PATTERNS ===

  // LangChain tool() function
  if (funcText === "tool" || funcText === "DynamicTool" || funcText === "DynamicStructuredTool") {
    return { pattern: TYPESCRIPT_PATTERNS.tool_function, patternKey: "tool_function" };
  }

  // new DynamicTool(), new Tool()
  if (node.parent?.type === "new_expression") {
    const newText = node.parent.text;
    if (
      newText.includes("DynamicTool") ||
      newText.includes("DynamicStructuredTool") ||
      newText.includes("Tool(")
    ) {
      return { pattern: TYPESCRIPT_PATTERNS.dynamic_tool, patternKey: "dynamic_tool" };
    }
  }

  // === SHELL EXECUTION PATTERNS ===

  // child_process.exec, execSync, spawn, spawnSync, execFile, fork
  if (
    funcText === "exec" ||
    funcText === "execSync" ||
    funcText.endsWith(".exec") ||
    funcText.endsWith(".execSync")
  ) {
    if (sourceCode.includes("child_process") || sourceCode.includes("require('child_process')")) {
      return { pattern: TYPESCRIPT_PATTERNS.child_process_exec, patternKey: "child_process_exec" };
    }
  }

  if (
    funcText === "spawn" ||
    funcText === "spawnSync" ||
    funcText.endsWith(".spawn") ||
    funcText.endsWith(".spawnSync")
  ) {
    return { pattern: TYPESCRIPT_PATTERNS.child_process_spawn, patternKey: "child_process_spawn" };
  }

  if (
    funcText === "execFile" ||
    funcText === "execFileSync" ||
    funcText.endsWith(".execFile") ||
    funcText.endsWith(".execFileSync")
  ) {
    return { pattern: TYPESCRIPT_PATTERNS.child_process_exec, patternKey: "child_process_exec" };
  }

  if (funcText === "fork" || funcText.endsWith(".fork")) {
    return { pattern: TYPESCRIPT_PATTERNS.child_process_spawn, patternKey: "child_process_spawn" };
  }

  // === FILE OPERATION PATTERNS ===

  // fs.writeFile, writeFileSync, etc.
  if (
    funcText.includes("writeFile") ||
    funcText.includes("writeSync") ||
    funcText.endsWith(".write")
  ) {
    if (sourceCode.includes("fs") || sourceCode.includes("require('fs')")) {
      return { pattern: TYPESCRIPT_PATTERNS.fs_writeFile, patternKey: "fs_writeFile" };
    }
  }

  // fs.readFile, readFileSync
  if (funcText.includes("readFile") || funcText.includes("readSync")) {
    return { pattern: TYPESCRIPT_PATTERNS.fs_readFile, patternKey: "fs_readFile" };
  }

  // fs.unlink, unlinkSync
  if (funcText.includes("unlink")) {
    return { pattern: TYPESCRIPT_PATTERNS.fs_unlink, patternKey: "fs_unlink" };
  }

  // fs.rm, rmSync, rmdir, rmdirSync
  if (funcText.includes("rmSync") || funcText === "rm" || funcText.endsWith(".rm")) {
    return { pattern: TYPESCRIPT_PATTERNS.fs_rm, patternKey: "fs_rm" };
  }

  if (funcText.includes("rmdir")) {
    return { pattern: TYPESCRIPT_PATTERNS.fs_unlink, patternKey: "fs_unlink" };
  }

  // fs.mkdir, mkdirSync
  if (funcText.includes("mkdir")) {
    return { pattern: TYPESCRIPT_PATTERNS.fs_readFile, patternKey: "fs_readFile" };
  }

  // === API/HTTP PATTERNS ===

  // fetch()
  if (funcText === "fetch") {
    return { pattern: TYPESCRIPT_PATTERNS.fetch_call, patternKey: "fetch_call" };
  }

  // axios
  if (
    funcText.startsWith("axios") ||
    funcText === "axios" ||
    funcText.endsWith(".get") && sourceCode.includes("axios") ||
    funcText.endsWith(".post") && sourceCode.includes("axios")
  ) {
    return { pattern: TYPESCRIPT_PATTERNS.axios_call, patternKey: "axios_call" };
  }

  // http.request, https.request
  if (
    funcText.includes("http.request") ||
    funcText.includes("https.request") ||
    funcText.includes("http.get") ||
    funcText.includes("https.get")
  ) {
    return { pattern: TYPESCRIPT_PATTERNS.http_request, patternKey: "http_request" };
  }

  // === DATABASE PATTERNS ===

  // Prisma operations
  if (sourceCode.includes("prisma") || sourceCode.includes("PrismaClient")) {
    if (
      funcText.includes(".create") ||
      funcText.includes(".createMany")
    ) {
      return { pattern: TYPESCRIPT_PATTERNS.prisma_operation, patternKey: "prisma_operation" };
    }
    if (
      funcText.includes(".update") ||
      funcText.includes(".updateMany")
    ) {
      return { pattern: TYPESCRIPT_PATTERNS.prisma_operation, patternKey: "prisma_operation" };
    }
    if (
      funcText.includes(".delete") ||
      funcText.includes(".deleteMany")
    ) {
      return { pattern: TYPESCRIPT_PATTERNS.prisma_operation, patternKey: "prisma_operation" };
    }
    if (
      funcText.includes("$executeRaw") ||
      funcText.includes("$queryRaw")
    ) {
      return { pattern: TYPESCRIPT_PATTERNS.prisma_operation, patternKey: "prisma_operation" };
    }
  }

  // Generic query/execute
  if (
    funcText.endsWith(".query") ||
    funcText.endsWith(".execute")
  ) {
    if (
      sourceCode.includes("sql") ||
      sourceCode.includes("database") ||
      sourceCode.includes("db") ||
      sourceCode.includes("mysql") ||
      sourceCode.includes("postgres") ||
      sourceCode.includes("knex")
    ) {
      return { pattern: TYPESCRIPT_PATTERNS.query_execute, patternKey: "query_execute" };
    }
  }

  // === CODE EXECUTION PATTERNS ===

  // eval()
  if (funcText === "eval") {
    return { pattern: TYPESCRIPT_PATTERNS.eval_call, patternKey: "eval_call" };
  }

  // new Function()
  if (node.parent?.type === "new_expression" && funcText === "Function") {
    return { pattern: TYPESCRIPT_PATTERNS.function_constructor, patternKey: "function_constructor" };
  }

  return null;
}

/**
 * Detects if a node is inside a tool definition context.
 */
function isInsideToolDefinition(
  node: Parser.SyntaxNode,
  sourceCode: string
): { isToolDef: boolean; framework?: string } {
  let current: Parser.SyntaxNode | null = node.parent;

  while (current) {
    // Check for tool() call
    if (current.type === "call_expression") {
      const funcNode = current.childForFieldName("function");
      if (funcNode?.text === "tool" || funcNode?.text === "DynamicTool") {
        return { isToolDef: true, framework: "langchain" };
      }
    }

    // Check for variable declaration with tool pattern
    if (current.type === "variable_declarator") {
      const init = current.childForFieldName("value");
      if (init?.text.includes("tool(") || init?.text.includes("DynamicTool")) {
        return { isToolDef: true, framework: "langchain" };
      }
    }

    // Check for class extending Tool
    if (current.type === "class_declaration" || current.type === "class") {
      const heritage = current.descendantsOfType("extends_clause");
      if (heritage.length > 0) {
        const extendsText = heritage[0].text.toLowerCase();
        if (
          extendsText.includes("tool") ||
          extendsText.includes("basetool") ||
          extendsText.includes("structuredtool")
        ) {
          return { isToolDef: true, framework: "langchain" };
        }
      }
    }

    current = current.parent;
  }

  // Also check if the source contains tool-related imports near this code
  if (sourceCode.includes("@langchain/core/tools") || sourceCode.includes("langchain/tools")) {
    return { isToolDef: true, framework: "langchain" };
  }

  return { isToolDef: false };
}

/**
 * Find tool definitions in the AST.
 */
function findToolDefinitions(
  tree: Parser.Tree,
  sourceCode: string
): Parser.SyntaxNode[] {
  const toolDefs: Parser.SyntaxNode[] = [];

  astWalker.walk(tree, (node) => {
    // tool() calls
    if (node.type === "call_expression") {
      const funcNode = node.childForFieldName("function");
      if (
        funcNode?.text === "tool" ||
        funcNode?.text === "DynamicTool" ||
        funcNode?.text === "DynamicStructuredTool"
      ) {
        toolDefs.push(node);
      }
    }

    // new DynamicTool()
    if (node.type === "new_expression") {
      if (
        node.text.includes("DynamicTool") ||
        node.text.includes("DynamicStructuredTool")
      ) {
        toolDefs.push(node);
      }
    }

    // Classes extending Tool
    if (node.type === "class_declaration" || node.type === "class") {
      const heritage = node.descendantsOfType("extends_clause");
      if (heritage.length > 0) {
        const extendsText = heritage[0].text.toLowerCase();
        if (
          extendsText.includes("tool") ||
          extendsText.includes("basetool") ||
          extendsText.includes("structuredtool")
        ) {
          toolDefs.push(node);
        }
      }
    }
  });

  return toolDefs;
}

/**
 * Analyze a single TypeScript/JavaScript file for AFB04 boundaries.
 */
export function analyzeTypeScriptFile(
  filePath: string,
  sourceCode: string
): FileAnalysisResult {
  const startTime = Date.now();
  const findings: AFBFinding[] = [];

  try {
    const language = filePath.endsWith('.tsx') || filePath.endsWith('.jsx')
      ? 'typescript'
      : 'typescript';

    const tree = astWalker.parse(sourceCode, language, filePath);

    // First pass: find all tool definitions
    const toolDefs = findToolDefinitions(tree, sourceCode);

    // Report tool definitions as findings
    for (const toolDef of toolDefs) {
      const location = astWalker.getNodeLocation(toolDef);
      const enclosingFunc = astWalker.getEnclosingFunction(toolDef, "typescript");
      const funcName = enclosingFunc
        ? astWalker.getFunctionName(enclosingFunc, "typescript")
        : undefined;

      findings.push(
        createFinding(
          filePath,
          location,
          toolDef.text.split("\n").slice(0, 3).join("\n"),
          TYPESCRIPT_PATTERNS.tool_function,
          funcName || undefined,
          undefined,
          true,
          "langchain",
          0.9
        )
      );
    }

    // Second pass: find all execution points
    astWalker.walk(tree, (node, ancestors) => {
      if (node.type !== "call_expression") {
        return;
      }

      const match = matchCallPattern(node, sourceCode);
      if (!match) {
        return;
      }

      // Determine if this is inside a tool definition
      const { isToolDef, framework } = isInsideToolDefinition(node, sourceCode);

      // Also check if any ancestor is a tool definition
      let ancestorIsToolDef = false;
      for (const ancestor of ancestors) {
        if (toolDefs.includes(ancestor)) {
          ancestorIsToolDef = true;
          break;
        }
      }

      const isInToolDefinition = isToolDef || ancestorIsToolDef;

      const location = astWalker.getNodeLocation(node);
      const enclosingFunc = astWalker.getEnclosingFunction(node, "typescript");
      const enclosingClass = astWalker.getEnclosingClass(node, "typescript");

      const funcName = enclosingFunc
        ? astWalker.getFunctionName(enclosingFunc, "typescript")
        : undefined;
      const className = enclosingClass
        ? astWalker.getClassName(enclosingClass, "typescript")
        : undefined;

      // Calculate confidence
      let confidence = 0.8;
      if (isInToolDefinition) {
        confidence = 0.95;
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
      language: "typescript",
      findings,
      success: true,
      analysisTimeMs: Date.now() - startTime,
    };
  } catch (error) {
    return {
      file: filePath,
      language: "typescript",
      findings: [],
      success: false,
      error: error instanceof Error ? error.message : String(error),
      analysisTimeMs: Date.now() - startTime,
    };
  }
}

/**
 * Quick check if TypeScript code likely contains agent-related patterns.
 */
export function likelyContainsAgentCode(sourceCode: string): boolean {
  const agentIndicators = [
    "langchain",
    "@langchain",
    "DynamicTool",
    "DynamicStructuredTool",
    "tool(",
    "BaseTool",
    "StructuredTool",
    "AgentExecutor",
    "createAgent",
    "tools:",
  ];

  const lowerCode = sourceCode.toLowerCase();
  return agentIndicators.some((indicator) =>
    lowerCode.includes(indicator.toLowerCase())
  );
}
