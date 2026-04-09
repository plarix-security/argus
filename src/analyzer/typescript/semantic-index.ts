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

    // Check for action object patterns (Eliza, custom frameworks)
    const actionRoots = extractActionObjectPatterns(filePath, parsed);
    for (const root of actionRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for plugin array patterns
    const pluginRoots = extractPluginArrayPatterns(filePath, parsed);
    for (const root of pluginRoots) {
      roots.set(root.nodeId, root);
    }

    // Check for registration call patterns
    const registrationRoots = extractRegistrationCallPatterns(filePath, parsed);
    for (const root of registrationRoots) {
      roots.set(root.nodeId, root);
    }
  }

  // If no roots found, try exported entry points as fallback
  if (roots.size === 0) {
    for (const [filePath, parsed] of files) {
      const exportRoots = extractExportedEntryPoints(filePath, parsed);
      for (const root of exportRoots) {
        roots.set(root.nodeId, root);
      }
    }
  }

  // Always add exported entry points that contain dangerous-looking patterns
  // This ensures files like plugin.ts get analyzed even when other files have framework patterns
  for (const [filePath, parsed] of files) {
    // Check if this file has dangerous calls but no roots yet
    const hasDangerousCalls = parsed.calls.some(call => {
      const callee = call.callee.toLowerCase();
      return callee.includes('spawn') ||
             callee.includes('exec') ||
             callee.includes('eval') ||
             callee.includes('unlink') ||
             callee.includes('rmdir') ||
             callee.includes('delete') ||
             callee.includes('read') ||
             callee.includes('write') ||
             callee.includes('mkdir') ||
             callee.includes('readdir') ||
             callee.includes('stat') ||
             callee.includes('open') ||
             callee.includes('fetch') ||
             callee.includes('request') ||
             callee.includes('post') ||
             callee.includes('put') ||
             callee.includes('patch') ||
             callee.includes('query') ||
             callee.includes('execute') ||
             callee.includes('shell') ||
             callee.includes('command');
    });

    if (hasDangerousCalls) {
      const fileHasRoots = [...roots.values()].some(r => r.sourceFile === filePath);
      if (!fileHasRoots) {
        // Add exported entry points for this file specifically
        const exportRoots = extractExportedEntryPoints(filePath, parsed);
        for (const root of exportRoots) {
          roots.set(root.nodeId, root);
        }
      }
    }
  }

  return roots;
}

/**
 * Extract OpenAI SDK tool registrations
 *
 * Uses pure AST-based analysis to find tool schemas and extract tool names.
 * No regex pattern matching - only structured AST traversal.
 *
 * Pattern:
 * const tools: OpenAI.ChatCompletionTool[] = [
 *   { type: 'function', function: { name: 'myTool', ... } }
 * ]
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

  // Find assignments that are OpenAI tool arrays
  for (const assignment of parsed.assignments) {
    if (!assignment.isArrayLiteral || !assignment.arrayElements) continue;
    if (!assignment.target.toLowerCase().includes('tool')) continue;

    // Each array element should be a tool schema object
    for (const element of assignment.arrayElements) {
      if (!element.objectProperties) continue;

      // Look for the 'function' property in the tool schema
      const functionProp = element.objectProperties.find(p => p.key === 'function');
      if (!functionProp || !functionProp.nestedProperties) continue;

      // Look for the 'name' property within the function object
      const nameProp = functionProp.nestedProperties.find(p => p.key === 'name');
      if (!nameProp || !nameProp.stringValue) continue;

      const toolName = nameProp.stringValue;

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
          evidence: `OpenAI tool schema array defines function "${toolName}" (AST-verified)`,
          sourceFile: filePath,
          line: toolFunc.startLine,
        });
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
 * Uses AST structure analysis to find functions referenced in tool arrays.
 * No regex pattern matching.
 *
 * Pattern: Any function referenced in a tools array by name,
 * either directly in the array or via tool schema objects.
 */
function extractGenericTools(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Look for assignments with 'tools' in the name that are arrays or objects
  for (const assignment of parsed.assignments) {
    if (!assignment.target.toLowerCase().includes('tool')) continue;

    // Strategy 1: Array of function references - [myFunc, otherFunc]
    if (assignment.isArrayLiteral && assignment.arrayElements) {
      for (const element of assignment.arrayElements) {
        // Check if element text is a simple identifier (function name)
        const trimmed = element.text.trim();

        // Find function with this name
        const toolFunc = parsed.functions.find(f => f.name === trimmed);

        if (toolFunc) {
          const nodeId = toolFunc.className
            ? `${filePath}:${toolFunc.className}.${toolFunc.name}`
            : `${filePath}:${toolFunc.name}`;

          if (!roots.some(r => r.nodeId === nodeId)) {
            roots.push({
              nodeId,
              toolName: toolFunc.name,
              framework: 'generic',
              evidence: `Function referenced in ${assignment.target} array`,
              sourceFile: filePath,
              line: toolFunc.startLine,
            });
          }
        }

        // Strategy 2: Array of tool schema objects with 'name' property
        if (element.objectProperties) {
          const nameProp = element.objectProperties.find(p => p.key === 'name');
          if (nameProp && nameProp.stringValue) {
            const toolName = nameProp.stringValue;
            const toolFunc = parsed.functions.find(f => f.name === toolName);

            if (toolFunc) {
              const nodeId = toolFunc.className
                ? `${filePath}:${toolFunc.className}.${toolName}`
                : `${filePath}:${toolName}`;

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
    }

    // Strategy 3: Object of tools - { myTool: tool(...), otherTool: func }
    if (assignment.isObjectLiteral && assignment.objectProperties) {
      for (const prop of assignment.objectProperties) {
        // Check if the value is a function identifier
        if (prop.valueType === 'identifier') {
          const toolFunc = parsed.functions.find(f => f.name === prop.value);

          if (toolFunc) {
            const nodeId = toolFunc.className
              ? `${filePath}:${toolFunc.className}.${toolFunc.name}`
              : `${filePath}:${toolFunc.name}`;

            if (!roots.some(r => r.nodeId === nodeId)) {
              roots.push({
                nodeId,
                toolName: toolFunc.name,
                framework: 'generic',
                evidence: `Function referenced as ${prop.key} in ${assignment.target}`,
                sourceFile: filePath,
                line: toolFunc.startLine,
              });
            }
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

/**
 * Extract action object patterns
 *
 * Detects objects with action-like callback properties:
 * - handler: async (runtime, message, state) => { ... }
 * - execute: async (context) => { ... }
 * - run: async (params) => { ... }
 * - action: async (...) => { ... }
 *
 * This pattern is used by Eliza, custom agent frameworks, and plugin systems.
 * Detects: { name: "myAction", handler: async () => { ... } }
 */
function extractActionObjectPatterns(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Action-like property names that indicate callback functions
  const actionPropertyNames = new Set(['handler', 'execute', 'run', 'action', 'handle', 'invoke', 'call', 'perform']);

  for (const assignment of parsed.assignments) {
    // Only check object literals
    if (!assignment.isObjectLiteral || !assignment.objectProperties) continue;

    // Look for action-like callback properties
    for (const prop of assignment.objectProperties) {
      if (!actionPropertyNames.has(prop.key)) continue;

      // Case 1: Inline function - { handler: async () => { ... } }
      if (prop.valueType === 'function') {
        // Try to get a name from the object
        const nameProp = assignment.objectProperties.find(p => p.key === 'name');
        const toolName = nameProp?.stringValue || assignment.target;

        const nodeId = assignment.enclosingFunction
          ? `${filePath}:${assignment.enclosingFunction}`
          : `${filePath}:${assignment.target}`;

        if (!roots.some(r => r.nodeId === nodeId)) {
          roots.push({
            nodeId,
            toolName,
            framework: 'action-object',
            evidence: `Action object "${assignment.target}" with inline ${prop.key} callback`,
            sourceFile: filePath,
            line: assignment.line,
          });
        }
        break; // Only add once per object
      }

      // Case 2: Function reference - { handler: myHandlerFunc }
      if (prop.valueType === 'identifier') {
        const funcName = prop.value;
        const func = parsed.functions.find(f => f.name === funcName);

        if (func) {
          const nameProp = assignment.objectProperties.find(p => p.key === 'name');
          const toolName = nameProp?.stringValue || funcName;

          const nodeId = func.className
            ? `${filePath}:${func.className}.${funcName}`
            : `${filePath}:${funcName}`;

          if (!roots.some(r => r.nodeId === nodeId)) {
            roots.push({
              nodeId,
              toolName,
              framework: 'action-object',
              evidence: `Action object "${assignment.target}" references ${prop.key} function "${funcName}"`,
              sourceFile: filePath,
              line: func.startLine,
            });
          }
          break; // Only add once per object
        }
      }
    }
  }

  return roots;
}

/**
 * Extract plugin array patterns
 *
 * Detects arrays named actions, plugins, handlers, commands containing
 * action objects or function references.
 *
 * Pattern: const myPlugin = { actions: [action1, action2] }
 * Pattern: const actions = [myAction, anotherAction]
 */
function extractPluginArrayPatterns(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Plugin array property names
  const pluginArrayNames = new Set(['actions', 'plugins', 'handlers', 'commands', 'evaluators', 'services', 'tools', 'capabilities']);

  for (const assignment of parsed.assignments) {
    // Case 1: Direct array assignment - const actions = [action1, action2]
    const targetLower = assignment.target.toLowerCase();
    const isPluginArray = Array.from(pluginArrayNames).some(name =>
      targetLower === name || targetLower.endsWith(name)
    );

    if (assignment.isArrayLiteral && assignment.arrayElements && isPluginArray) {
      for (const element of assignment.arrayElements) {
        const trimmed = element.text.trim();

        // Check if it's a function/variable reference
        const func = parsed.functions.find(f => f.name === trimmed);
        if (func) {
          const nodeId = func.className
            ? `${filePath}:${func.className}.${func.name}`
            : `${filePath}:${func.name}`;

          if (!roots.some(r => r.nodeId === nodeId)) {
            roots.push({
              nodeId,
              toolName: func.name,
              framework: 'plugin-array',
              evidence: `Function "${func.name}" in ${assignment.target} array`,
              sourceFile: filePath,
              line: func.startLine,
            });
          }
        }

        // Check if it's an object with a name property
        if (element.objectProperties) {
          const nameProp = element.objectProperties.find(p => p.key === 'name');
          const handlerProp = element.objectProperties.find(p =>
            p.key === 'handler' || p.key === 'execute' || p.key === 'run'
          );

          if (nameProp?.stringValue && handlerProp) {
            const toolName = nameProp.stringValue;

            // If handler is a function reference, find it
            if (handlerProp.valueType === 'identifier') {
              const func = parsed.functions.find(f => f.name === handlerProp.value);
              if (func) {
                const nodeId = func.className
                  ? `${filePath}:${func.className}.${func.name}`
                  : `${filePath}:${func.name}`;

                if (!roots.some(r => r.nodeId === nodeId)) {
                  roots.push({
                    nodeId,
                    toolName,
                    framework: 'plugin-array',
                    evidence: `Action "${toolName}" in ${assignment.target} with ${handlerProp.key} function`,
                    sourceFile: filePath,
                    line: func.startLine,
                  });
                }
              }
            } else if (handlerProp.valueType === 'function') {
              // Inline function in array element
              const nodeId = `${filePath}:${toolName}`;
              if (!roots.some(r => r.nodeId === nodeId)) {
                roots.push({
                  nodeId,
                  toolName,
                  framework: 'plugin-array',
                  evidence: `Action "${toolName}" in ${assignment.target} with inline ${handlerProp.key}`,
                  sourceFile: filePath,
                  line: assignment.line,
                });
              }
            }
          }
        }
      }
    }

    // Case 2: Object with plugin arrays - { name: "...", actions: [...] }
    if (assignment.isObjectLiteral && assignment.objectProperties) {
      for (const prop of assignment.objectProperties) {
        if (!pluginArrayNames.has(prop.key)) continue;
        if (prop.valueType !== 'array') continue;

        // This property is an array of actions/plugins
        // The array elements would be in the raw value, need to parse assignments that reference them
        // For now, mark the whole plugin object as a root
        const nameProp = assignment.objectProperties.find(p => p.key === 'name');
        const pluginName = nameProp?.stringValue || assignment.target;

        // Look for functions referenced in this file that might be handlers
        // We'll mark the plugin itself as needing analysis
        const nodeId = `${filePath}:${assignment.target}`;
        if (!roots.some(r => r.nodeId === nodeId)) {
          roots.push({
            nodeId,
            toolName: pluginName,
            framework: 'plugin-array',
            evidence: `Plugin "${pluginName}" exports ${prop.key} array`,
            sourceFile: filePath,
            line: assignment.line,
          });
        }
      }
    }
  }

  return roots;
}

/**
 * Extract registration call patterns
 *
 * Detects function calls that register actions/handlers:
 * - registerAction("name", handler)
 * - addPlugin(plugin)
 * - defineCommand("name", func)
 * - runtime.registerAction(action)
 */
function extractRegistrationCallPatterns(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Registration function patterns
  const registrationPatterns = [
    'register', 'add', 'define', 'use', 'install', 'mount', 'attach', 'bind'
  ];
  const registrationTargets = [
    'action', 'plugin', 'handler', 'command', 'tool', 'service', 'event', 'hook', 'capability'
  ];

  for (const call of parsed.calls) {
    const calleeLower = call.callee.toLowerCase();
    const lastMember = call.memberChain[call.memberChain.length - 1]?.toLowerCase() || calleeLower;

    // Check if this is a registration call
    const isRegistration = registrationPatterns.some(pattern =>
      lastMember.startsWith(pattern)
    );
    const targetType = registrationTargets.find(target =>
      lastMember.includes(target)
    );

    if (!isRegistration || !targetType) continue;

    // First argument is typically the name or the handler
    const firstArg = call.arguments[0];
    const secondArg = call.arguments[1];

    let toolName: string | undefined;
    let handlerName: string | undefined;

    // Pattern: registerAction("name", handler)
    if (firstArg && firstArg.startsWith('"') || firstArg?.startsWith("'")) {
      toolName = firstArg.replace(/['"]/g, '');
      handlerName = secondArg;
    }
    // Pattern: registerAction(actionObject)
    else if (firstArg && !firstArg.includes('(')) {
      toolName = firstArg;
      handlerName = firstArg;
    }

    if (toolName) {
      // Try to find the handler function
      const func = handlerName ? parsed.functions.find(f => f.name === handlerName) : undefined;

      const nodeId = func
        ? (func.className ? `${filePath}:${func.className}.${func.name}` : `${filePath}:${func.name}`)
        : (call.enclosingFunction ? `${filePath}:${call.enclosingFunction}` : `${filePath}:${toolName}`);

      if (!roots.some(r => r.nodeId === nodeId)) {
        roots.push({
          nodeId,
          toolName,
          framework: 'registration',
          evidence: `${call.callee}() registration call for "${toolName}"`,
          sourceFile: filePath,
          line: func?.startLine || call.line,
        });
      }
    }
  }

  return roots;
}

/**
 * Extract exported entry points as fallback
 *
 * When no framework-specific patterns are detected, treat exported
 * async functions with parameters as potential entry points.
 *
 * This is a lower-confidence fallback for custom/unknown frameworks.
 */
function extractExportedEntryPoints(
  filePath: string,
  parsed: ParsedTypeScriptFile
): SemanticInvocationRoot[] {
  const roots: SemanticInvocationRoot[] = [];

  // Entry point naming patterns
  const entryPointNames = [
    'execute', 'run', 'handle', 'process', 'action', 'handler',
    'invoke', 'call', 'perform', 'dispatch', 'trigger'
  ];

  for (const func of parsed.functions) {
    // Only consider exported functions
    if (!func.isExported) continue;

    // Skip methods (only top-level functions)
    if (func.isMethod) continue;

    // Check if name suggests it's an entry point or if it's async
    const nameLower = func.name.toLowerCase();
    const hasEntryPointName = entryPointNames.some(name => nameLower.includes(name));
    const isAsync = func.isAsync;
    const hasParameters = func.parameters.length > 0;
    const hasDangerousCallInFunction = parsed.calls.some((call) => {
      if (call.enclosingFunction !== func.name) {
        return false;
      }
      const callee = call.callee.toLowerCase();
      return callee.includes('exec') ||
             callee.includes('spawn') ||
             callee.includes('eval') ||
             callee.includes('write') ||
             callee.includes('read') ||
             callee.includes('delete') ||
             callee.includes('fetch') ||
             callee.includes('request');
    });

    // Include if it looks like an entry point or directly performs sensitive work.
    if (hasEntryPointName || (isAsync && hasParameters) || hasDangerousCallInFunction) {
      const nodeId = func.className
        ? `${filePath}:${func.className}.${func.name}`
        : `${filePath}:${func.name}`;

      if (!roots.some(r => r.nodeId === nodeId)) {
        roots.push({
          nodeId,
          toolName: func.name,
          framework: 'export-entry',
          evidence: `Exported ${isAsync ? 'async ' : ''}function "${func.name}" as potential entry point`,
          sourceFile: filePath,
          line: func.startLine,
        });
      }
    }
  }

  return roots;
}
