/**
 * TypeScript/JavaScript Semantic Index
 *
 * Extracts semantic invocation roots (tool registrations) from TypeScript/JavaScript
 * agentic frameworks.
 *
 * Supported frameworks:
 * - OpenAI SDK (tools parameter in chat.completions.create)
 * - LangChain.js (DynamicStructuredTool, @tool decorator)
 * - LangGraph.js (createReactAgent, StateGraph)
 * - Vercel AI SDK (tool() definitions)
 * - MCP SDK (server.tool() registrations)
 * - Mastra (tool definitions)
 * - Playwright (browser automation tools)
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

    // Check for LangChain.js/LangGraph.js usage
    const langchainRoots = extractLangChainTools(filePath, parsed);
    for (const root of langchainRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for Vercel AI SDK usage
    const vercelRoots = extractVercelAITools(filePath, parsed);
    for (const root of vercelRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for MCP SDK usage
    const mcpRoots = extractMCPTools(filePath, parsed);
    for (const root of mcpRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for Mastra usage
    const mastraRoots = extractMastraTools(filePath, parsed);
    for (const root of mastraRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for Playwright browser automation
    const playwrightRoots = extractPlaywrightTools(filePath, parsed);
    for (const root of playwrightRoots) {
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
 * const tools: OpenAI.ChatCompletionTool[] = [
 *   { type: 'function', function: { name: 'myTool', ... } }
 * ]
 *
 * Then we register the actual function 'myTool' as the tool root,
 * NOT the function that calls chat.completions.create.
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

  // Strategy: Find OpenAI tool schema definitions and extract the tool names
  // from `function: { name: 'toolName' }` patterns, then map to actual function definitions

  // Step 1: Find tool schema arrays/objects in assignments
  // Look for patterns like: const tools: OpenAI.ChatCompletionTool[] = [{ type: 'function', function: { name: 'query_orders' } }]
  for (const assignment of parsed.assignments) {
    // Check if this looks like an OpenAI tools array
    const isToolsArray = assignment.value.includes('ChatCompletionTool') ||
                          (assignment.target.toLowerCase().includes('tool') &&
                           assignment.value.includes("type:") &&
                           assignment.value.includes("'function'")) ||
                          (assignment.value.includes("type: 'function'") &&
                           assignment.value.includes("function: {"));

    if (isToolsArray) {
      // Extract tool names from function: { name: 'toolName' } patterns
      // Use [\s\S]*? to handle multiline schemas (non-greedy to avoid matching too much)
      const toolNameMatches = assignment.value.matchAll(/function:\s*\{[\s\S]*?name:\s*['"]([^'"]+)['"]/g);

      for (const match of toolNameMatches) {
        const toolName = match[1];

        // Find the corresponding function definition
        const toolFunc = parsed.functions.find(f => f.name === toolName);

        if (toolFunc) {
          const nodeId = toolFunc.className
            ? `${filePath}:${toolFunc.className}.${toolName}`
            : `${filePath}:${toolName}`;

          roots.push({
            nodeId,
            toolName,
            framework: 'openai',
            evidence: `OpenAI tool schema defines function "${toolName}"`,
            sourceFile: filePath,
            line: toolFunc.startLine,
          });
        }
      }
    }
  }

  // Step 2: Also look for inline tool definitions in chat.completions.create calls
  for (const call of parsed.calls) {
    const chainStr = call.memberChain.join('.');
    const isOpenAICompletions = chainStr.includes('chat.completions.create') ||
                                 chainStr.includes('completions.create') ||
                                 (chainStr.endsWith('.create') && chainStr.includes('chat'));

    if (isOpenAICompletions) {
      // Check arguments for inline tool definitions
      for (const arg of call.arguments) {
        if (arg.includes("function: {") && arg.includes("name:")) {
          // Extract inline tool names
          const inlineToolMatches = arg.matchAll(/function:\s*\{[^}]*name:\s*['"]([^'"]+)['"]/g);

          for (const match of inlineToolMatches) {
            const toolName = match[1];
            const toolFunc = parsed.functions.find(f => f.name === toolName);

            if (toolFunc) {
              const nodeId = toolFunc.className
                ? `${filePath}:${toolFunc.className}.${toolName}`
                : `${filePath}:${toolName}`;

              // Avoid duplicates
              if (!roots.some(r => r.nodeId === nodeId)) {
                roots.push({
                  nodeId,
                  toolName,
                  framework: 'openai',
                  evidence: `OpenAI inline tool schema defines function "${toolName}"`,
                  sourceFile: filePath,
                  line: toolFunc.startLine,
                });
              }
            }
          }
        }
      }
    }
  }

  return roots;
}

/**
 * Extract LangChain.js and LangGraph.js tool registrations
 *
 * Patterns:
 * - new DynamicStructuredTool({ func: myFunc, ... })
 * - @tool decorator on functions
 * - createReactAgent from @langchain/langgraph/prebuilt
 * - tools passed to agent constructors
 */
function extractLangChainTools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Check for langchain/langgraph imports
  const hasLangChain = parsed.imports.some(imp =>
    imp.module.includes('langchain') || imp.module.includes('@langchain/')
  );
  const hasLangGraph = parsed.imports.some(imp =>
    imp.module.includes('langgraph') || imp.module.includes('@langchain/langgraph')
  );

  if (!hasLangChain && !hasLangGraph) return roots;

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

    // LangGraph createReactAgent pattern
    if (call.callee === 'createReactAgent' || call.callee.endsWith('.createReactAgent')) {
      const toolsArg = call.arguments.find(arg => arg.includes('tools'));
      if (toolsArg && call.enclosingFunction) {
        const nodeId = `${filePath}:${call.enclosingFunction}`;
        roots.push({
          nodeId,
          toolName: call.enclosingFunction,
          framework: 'langgraph',
          evidence: 'LangGraph createReactAgent with tools',
          sourceFile: filePath,
          line: call.line,
        });
      }
    }

    // LangGraph StateGraph with tools
    if (call.callee === 'StateGraph' || call.callee.includes('StateGraph')) {
      if (call.enclosingFunction) {
        const nodeId = `${filePath}:${call.enclosingFunction}`;
        roots.push({
          nodeId,
          toolName: call.enclosingFunction,
          framework: 'langgraph',
          evidence: 'LangGraph StateGraph agent definition',
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
 * Pattern: Any function/method that is referenced in a tools array by name,
 * either directly or via function schema { name: 'funcName' }
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

      // Strategy 1: Direct function references in the value
      for (const func of parsed.functions) {
        // Check for direct reference: [myFunc, otherFunc] or { tool: myFunc }
        const directRef = new RegExp(`\\b${func.name}\\b(?!['":])`);
        if (directRef.test(assignment.value)) {
          const nodeId = func.className
            ? `${filePath}:${func.className}.${func.name}`
            : `${filePath}:${func.name}`;

          // Check we haven't already added this via OpenAI or other extractors
          if (!roots.some(r => r.nodeId === nodeId)) {
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

      // Strategy 2: Named tool schemas like { name: 'funcName' } or function: { name: 'funcName' }
      const schemaNameMatches = assignment.value.matchAll(/(?:name|function\.name|"name"):\s*['"]([^'"]+)['"]/g);
      for (const match of schemaNameMatches) {
        const toolName = match[1];
        const toolFunc = parsed.functions.find(f => f.name === toolName);

        if (toolFunc) {
          const nodeId = toolFunc.className
            ? `${filePath}:${toolFunc.className}.${toolName}`
            : `${filePath}:${toolName}`;

          // Avoid duplicates
          if (!roots.some(r => r.nodeId === nodeId)) {
            roots.push({
              nodeId,
              toolName,
              framework: 'generic',
              evidence: `Tool schema references function "${toolName}" in ${assignment.target}`,
              sourceFile: filePath,
              line: toolFunc.startLine,
            });
          }
        }
      }
    }
  }

  return roots;
}

/**
 * Extract MCP SDK tool registrations
 *
 * Pattern:
 * server.tool('toolName', schema, async (params) => { ... })
 * or
 * server.setRequestHandler(ListToolsRequestSchema, ...)
 */
function extractMCPTools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Check for MCP SDK import
  const hasMCP = parsed.imports.some(imp =>
    imp.module === '@modelcontextprotocol/sdk' ||
    imp.module.startsWith('@modelcontextprotocol/sdk/') ||
    imp.module.includes('mcp-server') ||
    imp.module.includes('@modelcontextprotocol')
  );

  if (!hasMCP) return roots;

  // Look for server.tool() calls
  for (const call of parsed.calls) {
    const chainStr = call.memberChain.join('.');

    // Match server.tool() pattern
    if (chainStr.endsWith('.tool') || call.callee === 'tool') {
      // First argument is typically the tool name
      const toolName = call.arguments[0]?.replace(/['"]/g, '') || call.enclosingFunction || 'mcpTool';

      const nodeId = call.enclosingFunction
        ? `${filePath}:${call.enclosingFunction}`
        : `${filePath}:${toolName}`;

      roots.push({
        nodeId,
        toolName,
        framework: 'mcp',
        evidence: 'MCP SDK server.tool() registration',
        sourceFile: filePath,
        line: call.line,
      });
    }

    // Match setRequestHandler for tools
    if (chainStr.includes('setRequestHandler') || call.callee === 'setRequestHandler') {
      if (call.arguments.some(arg => arg.includes('Tool') || arg.includes('tool'))) {
        const nodeId = call.enclosingFunction
          ? `${filePath}:${call.enclosingFunction}`
          : `${filePath}:mcpHandler`;

        roots.push({
          nodeId,
          toolName: call.enclosingFunction || 'mcpHandler',
          framework: 'mcp',
          evidence: 'MCP SDK setRequestHandler for tools',
          sourceFile: filePath,
          line: call.line,
        });
      }
    }
  }

  return roots;
}

/**
 * Extract Mastra tool registrations
 *
 * Pattern:
 * createTool({ ... })
 * or tool definitions in agents
 */
function extractMastraTools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Check for Mastra import
  const hasMastra = parsed.imports.some(imp =>
    imp.module === 'mastra' ||
    imp.module.startsWith('@mastra/') ||
    imp.module.includes('mastra')
  );

  if (!hasMastra) return roots;

  // Look for createTool calls
  for (const call of parsed.calls) {
    if (call.callee === 'createTool' || call.callee.includes('createTool')) {
      const nameArg = call.arguments.find(arg => arg.includes('name:'));
      const toolName = nameArg
        ? nameArg.match(/name:\s*['"]([^'"]+)['"]/)?.[1] || call.enclosingFunction || 'mastraTool'
        : call.enclosingFunction || 'mastraTool';

      const nodeId = call.enclosingFunction
        ? `${filePath}:${call.enclosingFunction}`
        : `${filePath}:${toolName}`;

      roots.push({
        nodeId,
        toolName,
        framework: 'mastra',
        evidence: 'Mastra createTool() definition',
        sourceFile: filePath,
        line: call.line,
      });
    }

    // Look for Agent constructor with tools
    if (call.callee === 'Agent' || call.callee.includes('Agent')) {
      const hasTools = call.arguments.some(arg => arg.includes('tools'));
      if (hasTools && call.enclosingFunction) {
        const nodeId = `${filePath}:${call.enclosingFunction}`;
        roots.push({
          nodeId,
          toolName: call.enclosingFunction,
          framework: 'mastra',
          evidence: 'Mastra Agent with tools',
          sourceFile: filePath,
          line: call.line,
        });
      }
    }
  }

  // Look for tool assignments
  for (const assignment of parsed.assignments) {
    if (assignment.value.includes('createTool(')) {
      const nodeId = assignment.enclosingFunction
        ? `${filePath}:${assignment.enclosingFunction}`
        : `${filePath}:${assignment.target}`;

      roots.push({
        nodeId,
        toolName: assignment.target,
        framework: 'mastra',
        evidence: 'Mastra tool assignment',
        sourceFile: filePath,
        line: assignment.line,
      });
    }
  }

  return roots;
}

/**
 * Extract Playwright browser automation tool patterns
 *
 * Pattern:
 * Functions that use page.evaluate, page.goto, etc.
 * Often used as tools in browser automation agents
 */
function extractPlaywrightTools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Check for Playwright import
  const hasPlaywright = parsed.imports.some(imp =>
    imp.module === 'playwright' ||
    imp.module === '@playwright/test' ||
    imp.module.startsWith('playwright-') ||
    imp.module === 'puppeteer' ||
    imp.module === 'puppeteer-core'
  );

  if (!hasPlaywright) return roots;

  // Track functions that contain dangerous browser operations
  const browserOpFunctions = new Set<string>();

  for (const call of parsed.calls) {
    const chainStr = call.memberChain.join('.');

    // Match page.evaluate, page.goto, etc.
    if (chainStr.includes('page.evaluate') ||
        chainStr.includes('page.evaluateHandle') ||
        chainStr.includes('page.goto') ||
        chainStr.includes('page.fill') ||
        chainStr.includes('page.type') ||
        chainStr.includes('page.click') ||
        chainStr.includes('page.addScriptTag') ||
        chainStr.includes('page.setContent')) {

      if (call.enclosingFunction) {
        browserOpFunctions.add(call.enclosingFunction);
      }
    }
  }

  // Create roots for functions containing browser operations
  for (const funcName of browserOpFunctions) {
    const func = parsed.functions.find(f => f.name === funcName);
    if (func) {
      const nodeId = func.className
        ? `${filePath}:${func.className}.${func.name}`
        : `${filePath}:${func.name}`;

      roots.push({
        nodeId,
        toolName: func.name,
        framework: 'playwright',
        evidence: 'Playwright browser automation function',
        sourceFile: filePath,
        line: func.startLine,
      });
    }
  }

  return roots;
}
