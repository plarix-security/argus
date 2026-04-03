/**
 * TypeScript/JavaScript Semantic Index
 *
 * Extracts semantic invocation roots (tool registrations) from TypeScript/JavaScript
 * agentic frameworks.
 *
 * Supported frameworks:
 * - OpenAI SDK (tools parameter in chat.completions.create)
 * - LangChain.js (DynamicStructuredTool, @tool decorator)
 * - Vercel AI SDK (tool() definitions)
 * - Generic patterns (tools arrays passed to agent constructors)
 */

import {
  ParsedTypeScriptFile,
  FunctionDef,
  CallSite,
  AssignmentInfo,
  ImportInfo,
} from './ast-parser';

export interface SemanticInvocationRoot {
  /** Node ID (file:function or file:class.method) */
  nodeId: string;
  /** Tool name */
  toolName: string;
  /** Framework that registered this tool */
  framework: string;
  /** Evidence describing how registration was detected */
  evidence: string;
  /** Source file */
  sourceFile: string;
  /** Line number */
  line: number;
}

export class TypeScriptSemanticIndex {
  private files: Map<string, ParsedTypeScriptFile>;

  constructor(files: Map<string, ParsedTypeScriptFile>) {
    this.files = files;
  }

  /**
   * Extract all semantic invocation roots
   */
  extractRoots(): Map<string, SemanticInvocationRoot> {
    return extractSemanticInvocationRoots(this.files);
  }
}

/**
 * Extract semantic invocation roots from all files
 */
export function extractSemanticInvocationRoots(
  files: Map<string, ParsedTypeScriptFile>
): Map<string, SemanticInvocationRoot> {
  const roots = new Map<string, SemanticInvocationRoot>();

  for (const [filePath, parsed] of files) {
    // Check for OpenAI SDK usage
    const openaiRoots = extractOpenAITools(filePath, parsed);
    for (const root of openaiRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for LangChain.js usage
    const langchainRoots = extractLangChainTools(filePath, parsed);
    for (const root of langchainRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for Vercel AI SDK usage
    const vercelRoots = extractVercelAITools(filePath, parsed);
    for (const root of vercelRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for generic tool patterns
    const genericRoots = extractGenericTools(filePath, parsed);
    for (const root of genericRoots) {
      roots.set(root.nodeId, root);
    }
  }

  return roots;
}

/**
 * Extract OpenAI SDK tool registrations
 *
 * Pattern:
 * client.chat.completions.create({
 *   tools: [{ type: 'function', function: { name: 'myTool', ... } }]
 * })
 */
function extractOpenAITools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Check for openai import
  const hasOpenAI = parsed.imports.some(imp =>
    imp.module === 'openai' || imp.module.startsWith('@openai/')
  );

  if (!hasOpenAI) return roots;

  // Look for chat.completions.create calls with tools parameter
  for (const call of parsed.calls) {
    if (call.memberChain.join('.').includes('chat.completions.create') ||
        call.callee.includes('create')) {

      // Check if arguments contain 'tools'
      const hasTools = call.arguments.some(arg => arg.includes('tools:') || arg.includes('tools'));

      if (hasTools && call.enclosingFunction) {
        const nodeId = `${filePath}:${call.enclosingFunction}`;
        roots.push({
          nodeId,
          toolName: call.enclosingFunction,
          framework: 'openai',
          evidence: 'OpenAI chat.completions.create with tools parameter',
          sourceFile: filePath,
          line: call.line,
        });
      }
    }
  }

  return roots;
}

/**
 * Extract LangChain.js tool registrations
 *
 * Patterns:
 * - new DynamicStructuredTool({ func: myFunc, ... })
 * - @tool decorator on functions
 */
function extractLangChainTools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Check for langchain imports
  const hasLangChain = parsed.imports.some(imp =>
    imp.module.includes('langchain') || imp.module.includes('@langchain/')
  );

  if (!hasLangChain) return roots;

  // Look for DynamicStructuredTool constructor
  for (const call of parsed.calls) {
    if (call.callee.includes('DynamicStructuredTool') ||
        call.callee.includes('StructuredTool')) {

      // Find func parameter
      const funcArg = call.arguments.find(arg => arg.includes('func:'));

      if (funcArg && call.enclosingFunction) {
        // Extract function name from func: reference
        const funcMatch = funcArg.match(/func:\s*([a-zA-Z_][a-zA-Z0-9_]*)/);
        const toolName = funcMatch ? funcMatch[1] : call.enclosingFunction;

        const nodeId = `${filePath}:${toolName}`;
        roots.push({
          nodeId,
          toolName,
          framework: 'langchain',
          evidence: 'LangChain DynamicStructuredTool constructor',
          sourceFile: filePath,
          line: call.line,
        });
      }
    }
  }

  // Look for @tool decorator
  for (const func of parsed.functions) {
    if (func.decorators.some(d => d.includes('tool'))) {
      const nodeId = func.className
        ? `${filePath}:${func.className}.${func.name}`
        : `${filePath}:${func.name}`;

      roots.push({
        nodeId,
        toolName: func.name,
        framework: 'langchain',
        evidence: '@tool decorator from LangChain',
        sourceFile: filePath,
        line: func.startLine,
      });
    }
  }

  return roots;
}

/**
 * Extract Vercel AI SDK tool registrations
 *
 * Pattern:
 * const tools = {
 *   myTool: tool({ ... })
 * }
 * streamText({ model, tools })
 */
function extractVercelAITools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Check for ai import
  const hasAI = parsed.imports.some(imp => imp.module === 'ai' || imp.module === '@ai-sdk/core');

  if (!hasAI) return roots;

  // Look for tool() function calls in assignments
  for (const assignment of parsed.assignments) {
    if (assignment.value.includes('tool(') || assignment.value.includes('tool({')) {
      const nodeId = assignment.enclosingFunction
        ? `${filePath}:${assignment.enclosingFunction}`
        : `${filePath}:${assignment.target}`;

      roots.push({
        nodeId,
        toolName: assignment.target,
        framework: 'vercel-ai',
        evidence: 'Vercel AI SDK tool() definition',
        sourceFile: filePath,
        line: assignment.line,
      });
    }
  }

  // Look for streamText/generateText with tools
  for (const call of parsed.calls) {
    if ((call.callee === 'streamText' || call.callee === 'generateText') &&
        call.arguments.some(arg => arg.includes('tools'))) {

      if (call.enclosingFunction) {
        const nodeId = `${filePath}:${call.enclosingFunction}`;
        roots.push({
          nodeId,
          toolName: call.enclosingFunction,
          framework: 'vercel-ai',
          evidence: 'Vercel AI SDK streamText/generateText with tools',
          sourceFile: filePath,
          line: call.line,
        });
      }
    }
  }

  return roots;
}

/**
 * Extract generic tool patterns
 *
 * Pattern: Any function/method that contains 'tool' in name and appears
 * to be exported or assigned to a tools array
 */
function extractGenericTools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Look for assignments with 'tools' array
  for (const assignment of parsed.assignments) {
    if (assignment.target.toLowerCase().includes('tool') &&
        (assignment.value.includes('[') || assignment.value.includes('{'))) {

      // This might be a tools array/object
      // Check if any functions are referenced in the value
      for (const func of parsed.functions) {
        if (assignment.value.includes(func.name)) {
          const nodeId = func.className
            ? `${filePath}:${func.className}.${func.name}`
            : `${filePath}:${func.name}`;

          roots.push({
            nodeId,
            toolName: func.name,
            framework: 'generic',
            evidence: `Function referenced in ${assignment.target} tools collection`,
            sourceFile: filePath,
            line: func.startLine,
          });
        }
      }
    }
  }

  return roots;
}
