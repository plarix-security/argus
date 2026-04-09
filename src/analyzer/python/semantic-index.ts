import * as path from 'path';
import {
  AssignmentInfo,
  CallArgumentInfo,
  CallSite,
  FunctionDispatchMapping,
  OpenAIToolSchema,
  ParsedPythonFile,
  ReturnInfo,
  YieldInfo,
  WithBindingInfo,
} from './ast-parser';

export interface SemanticInvocationRoot {
  nodeId: string;
  framework: string;
  evidence: string;
}

export interface SemanticCallIdentity {
  identity: string;
  kind: 'structural' | 'semantic';
  evidence: string;
}

interface ImportBinding {
  alias: string;
  modulePath: string;
  importedName?: string;
  resolvedFile?: string;
}

interface ResolutionContext {
  filePath: string;
  className?: string;
  functionName?: string;
}

interface ConstructorBinding {
  modulePath?: string;
  importedName?: string;
  matchedReference?: string;
  identity?: string;
}

/**
 * Factory function return type mappings.
 * When a factory function is called, the result is an instance of the mapped type.
 * e.g., sqlite3.connect() returns sqlite3.Connection, not sqlite3.connect
 */
const FACTORY_RETURN_TYPES: Record<string, string> = {
  'sqlite3.connect': 'sqlite3.Connection',
  'psycopg2.connect': 'psycopg2.connection',
  'asyncpg.connect': 'asyncpg.Connection',
  'aiomysql.connect': 'aiomysql.Connection',
  'mysql.connector.connect': 'mysql.connector.connection',
  'pymysql.connect': 'pymysql.connections.Connection',
  'aiosqlite.connect': 'aiosqlite.Connection',
  'databases.Database': 'databases.Database',
  'redis.Redis': 'redis.Redis',
  'redis.StrictRedis': 'redis.StrictRedis',
  'aioredis.create_redis': 'aioredis.Redis',
  'boto3.client': 'boto3.client',
  'boto3.resource': 'boto3.resource',
  'httpx.Client': 'httpx.Client',
  'httpx.AsyncClient': 'httpx.AsyncClient',
  'requests.Session': 'requests.Session',
  'aiohttp.ClientSession': 'aiohttp.ClientSession',
};

function makeNodeId(filePath: string, localName: string): string {
  return `${filePath}:${localName}`;
}

/**
 * Flexible module matching for framework detection.
 * Handles wrapped/re-exported imports like my_utils.langgraph.prebuilt.
 *
 * @param modulePath The imported module path
 * @param targetModule The framework module to match
 * @returns true if the module matches (exact or suffix)
 */
function matchesFrameworkModule(modulePath: string, targetModule: string): boolean {
  // Exact match
  if (modulePath === targetModule) return true;

  // Suffix match for wrappers: my_utils.langgraph.prebuilt matches langgraph.prebuilt
  if (modulePath.endsWith('.' + targetModule)) return true;

  // Handle re-exports where final segments match
  // e.g., company.agents.create_react_agent for langgraph.prebuilt
  const modParts = modulePath.split('.');
  const targetParts = targetModule.split('.');

  // Check if module ends with target segments
  if (modParts.length >= targetParts.length) {
    const modSuffix = modParts.slice(-targetParts.length);
    if (modSuffix.every((part, i) => part === targetParts[i])) {
      return true;
    }
  }

  return false;
}

function resolveModulePath(modulePath: string, currentFilePath: string, allFilePaths: string[]): string | undefined {
  const currentDir = path.dirname(currentFilePath);

  if (modulePath.startsWith('.')) {
    const dots = modulePath.match(/^\.+/)?.[0].length || 0;
    let baseDir = currentDir;
    for (let i = 1; i < dots; i++) {
      baseDir = path.dirname(baseDir);
    }

    const relativeModule = modulePath.slice(dots).replace(/\./g, path.sep);
    const candidates = [
      path.join(baseDir, relativeModule + '.py'),
      path.join(baseDir, relativeModule, '__init__.py'),
    ];

    for (const candidate of candidates) {
      const normalized = path.normalize(candidate);
      if (allFilePaths.includes(normalized)) {
        return normalized;
      }
    }
  }

  const moduleAsPath = modulePath.replace(/\./g, path.sep);
  const possibleRoots = new Set<string>();
  for (const filePath of allFilePaths) {
    const parts = filePath.split(path.sep);
    for (let i = 0; i < parts.length - 1; i++) {
      if (parts[i] === 'src' || parts[i] === 'lib' || parts[i] === 'packages' || parts[i] === 'backend') {
        possibleRoots.add(parts.slice(0, i + 1).join(path.sep));
      }
    }
    possibleRoots.add(path.dirname(filePath));
  }

  for (const root of possibleRoots) {
    const candidates = [
      path.join(root, moduleAsPath + '.py'),
      path.join(root, moduleAsPath, '__init__.py'),
    ];

    for (const candidate of candidates) {
      const normalized = path.normalize(candidate);
      if (allFilePaths.includes(normalized)) {
        return normalized;
      }
    }
  }

  return undefined;
}

function getCallArgument(call: CallSite, keywordName: string, positionalIndex?: number): CallArgumentInfo | undefined {
  const keywordArgument = call.argumentDetails.find((arg) => arg.name === keywordName);
  if (keywordArgument) {
    return keywordArgument;
  }

  if (positionalIndex === undefined) {
    return undefined;
  }

  return call.argumentDetails.filter((arg) => !arg.name)[positionalIndex];
}

export class PythonSemanticIndex {
  private readonly allFilePaths: string[];
  private readonly importBindings = new Map<string, Map<string, ImportBinding>>();
  private readonly functionsByFile = new Map<string, Map<string, string>>();
  private readonly assignmentsByFile = new Map<string, AssignmentInfo[]>();
  private readonly returnsByFile = new Map<string, ReturnInfo[]>();
  private readonly yieldsByFile = new Map<string, YieldInfo[]>();
  private readonly withBindingsByFile = new Map<string, WithBindingInfo[]>();
  private readonly openAIToolSchemasByFile = new Map<string, OpenAIToolSchema[]>();
  private readonly dispatchMappingsByFile = new Map<string, FunctionDispatchMapping[]>();
  /** Maps function name -> whether it has @contextmanager decorator */
  private readonly contextManagerFunctions = new Map<string, Set<string>>();

  constructor(private readonly files: Map<string, ParsedPythonFile>) {
    this.allFilePaths = Array.from(files.keys());
    this.buildIndex();
  }

  extractInvocationRoots(): Map<string, SemanticInvocationRoot> {
    const roots = new Map<string, SemanticInvocationRoot>();

    for (const [filePath, parsed] of this.files) {
      for (const call of parsed.calls) {
        const context: ResolutionContext = {
          filePath,
          className: call.enclosingClass,
          functionName: call.enclosingFunction,
        };

        this.extractFrameworkCallRoots(call, context, roots);
      }
    }

    for (const [filePath, parsed] of this.files) {
      for (const func of parsed.functions) {
        const root = this.extractDecoratorRoot(func.decorators, filePath, func.className, func.name);
        if (!root || roots.has(root.nodeId)) {
          continue;
        }

        roots.set(root.nodeId, root);
      }
    }

    return roots;
  }

  resolveCallableNodeIds(reference: string, filePath: string, className?: string, functionName?: string): string[] {
    return Array.from(this.resolveReferenceToFunctionNodes(reference, { filePath, className, functionName }, new Set<string>()));
  }

  resolveCallIdentity(call: CallSite, filePath: string, className?: string): SemanticCallIdentity | undefined {
    const context: ResolutionContext = { filePath, className, functionName: call.enclosingFunction };
    const memberChain = call.memberChain || [];

    if (call.callee === 'open') {
      return {
        identity: 'builtins.open',
        kind: 'structural',
        evidence: 'built-in open call',
      };
    }

    if (call.callee === 'eval' || call.callee === 'exec') {
      return {
        identity: `builtins.${call.callee}`,
        kind: 'structural',
        evidence: `built-in ${call.callee} call`,
      };
    }

    const directImport = this.resolveImportedSymbol(call.callee, filePath);
    if (directImport?.modulePath && directImport.importedName) {
      return {
        identity: `${directImport.modulePath}.${directImport.importedName}`,
        kind: 'semantic',
        evidence: `resolved imported callable ${call.callee}`,
      };
    }

    // Derive baseExpression from callee when not explicitly provided.
    // Real AST parser always sets baseExpression for attribute calls, but
    // test data and some edge cases may omit it. Handle: "conn.execute" with
    // no baseExpression by splitting on the first dot.
    const effectiveBase = call.baseExpression ?? (call.callee.includes('.') ? call.callee.split('.')[0] : undefined);
    const effectiveMemberChain = call.baseExpression
      ? memberChain
      : (call.callee.includes('.') ? call.callee.split('.').slice(1) : memberChain);

    if (effectiveBase) {
      const moduleBinding = this.resolveImportedSymbol(effectiveBase, filePath);
      if (moduleBinding?.modulePath && effectiveMemberChain.length > 0) {
        return {
          identity: `${moduleBinding.modulePath}.${effectiveMemberChain.join('.')}`,
          kind: 'semantic',
          evidence: `resolved module alias ${effectiveBase}`,
        };
      }

      // Build a synthetic call for receiver resolution when baseExpression is derived
      const syntheticCall = call.baseExpression ? call : { ...call, baseExpression: effectiveBase, memberChain: effectiveMemberChain };
      const receiverReference = this.buildReceiverReference(syntheticCall, 1);
      const constructor = this.resolveAssignedConstructor(receiverReference, context);
      if (constructor.identity) {
        const receiverSegments = splitReferenceSegments(receiverReference);
        const matchedSegments = splitReferenceSegments(constructor.matchedReference);
        const trailingSegments = receiverSegments.slice(matchedSegments.length);
        const lastMember = effectiveMemberChain[effectiveMemberChain.length - 1];

        return {
          identity: [constructor.identity, ...trailingSegments, lastMember].filter(Boolean).join('.'),
          kind: 'semantic',
          evidence: `resolved receiver constructor ${constructor.identity} from ${constructor.matchedReference}`,
        };
      }

      const inlineConstructor = this.resolveInlineConstructor(effectiveBase, filePath);
      if (inlineConstructor.identity) {
        const lastMember = effectiveMemberChain[effectiveMemberChain.length - 1];
        return {
          identity: `${inlineConstructor.identity}.${lastMember}`,
          kind: 'semantic',
          evidence: `resolved inline constructor ${inlineConstructor.identity}`,
        };
      }
    }

    return undefined;
  }

  private buildIndex(): void {
    for (const [filePath, parsed] of this.files) {
      const localFunctions = new Map<string, string>();
      const contextManagers = new Set<string>();

      for (const func of parsed.functions) {
        const localId = func.className ? `${func.className}.${func.name}` : func.name;
        localFunctions.set(func.name, makeNodeId(filePath, localId));

        // Track context manager functions (decorated with @contextmanager)
        for (const decorator of func.decorators) {
          const baseName = decorator.split('(')[0].trim();
          if (baseName === 'contextmanager') {
            contextManagers.add(func.name);
          } else {
            // Check if contextmanager was imported with alias
            const imported = this.resolveImportedSymbol(baseName, filePath);
            if (imported?.importedName === 'contextmanager' &&
                imported.modulePath === 'contextlib') {
              contextManagers.add(func.name);
            }
          }
        }
      }

      this.functionsByFile.set(filePath, localFunctions);
      this.assignmentsByFile.set(filePath, parsed.assignments);
      this.returnsByFile.set(filePath, parsed.returns);
      this.yieldsByFile.set(filePath, parsed.yields || []);
      this.withBindingsByFile.set(filePath, parsed.withBindings || []);
      this.contextManagerFunctions.set(filePath, contextManagers);
      this.openAIToolSchemasByFile.set(filePath, parsed.openaiToolSchemas);
      this.dispatchMappingsByFile.set(filePath, parsed.dispatchMappings);

      const bindings = new Map<string, ImportBinding>();
      for (const imp of parsed.imports) {
        const resolvedFile = resolveModulePath(imp.module, filePath, this.allFilePaths);
        if (imp.isFrom) {
          for (const name of imp.names) {
            bindings.set(name.alias || name.name, {
              alias: name.alias || name.name,
              modulePath: imp.module,
              importedName: name.name,
              resolvedFile,
            });
          }
        } else {
          const alias = imp.names[0]?.alias || imp.module;
          bindings.set(alias, {
            alias,
            modulePath: imp.module,
            resolvedFile,
          });
        }
      }

      this.importBindings.set(filePath, bindings);
    }
  }

  private extractFrameworkCallRoots(call: CallSite, context: ResolutionContext, roots: Map<string, SemanticInvocationRoot>): void {
    const directImport = this.resolveImportedSymbol(call.callee, context.filePath);
    const modulePath = directImport?.modulePath || '';

    // LangGraph create_react_agent
    if (matchesFrameworkModule(modulePath, 'langgraph.prebuilt') && directImport?.importedName === 'create_react_agent') {
      const toolArg = getCallArgument(call, 'tools', 1);
      this.addRootsFromArgument(toolArg, context, 'langgraph', `create_react_agent at line ${call.startLine}`, roots);
      return;
    }

    // LangChain create_tool_calling_agent
    if (matchesFrameworkModule(modulePath, 'langchain.agents') && directImport?.importedName === 'create_tool_calling_agent') {
      const toolArg = getCallArgument(call, 'tools', 1);
      this.addRootsFromArgument(toolArg, context, 'langchain', `create_tool_calling_agent at line ${call.startLine}`, roots);
      return;
    }

    // LangChain AgentExecutor
    if (matchesFrameworkModule(modulePath, 'langchain.agents') && directImport?.importedName === 'AgentExecutor') {
      const toolArg = getCallArgument(call, 'tools', 1);
      this.addRootsFromArgument(toolArg, context, 'langchain', `AgentExecutor tools at line ${call.startLine}`, roots);
      return;
    }

    // SmolagentsCodeAgent/ToolCallingAgent
    if (matchesFrameworkModule(modulePath, 'smolagents') && ['CodeAgent', 'ToolCallingAgent'].includes(directImport?.importedName || '')) {
      const toolArg = getCallArgument(call, 'tools', 0);
      this.addRootsFromArgument(toolArg, context, 'smolagents', `${directImport?.importedName} tools at line ${call.startLine}`, roots);
      return;
    }

    // CrewAI Agent
    if (matchesFrameworkModule(modulePath, 'crewai') && directImport?.importedName === 'Agent') {
      const toolArg = getCallArgument(call, 'tools');
      this.addRootsFromArgument(toolArg, context, 'crewai', `CrewAI Agent tools at line ${call.startLine}`, roots);
      return;
    }

    // AutoGen UserProxyAgent
    if (matchesFrameworkModule(modulePath, 'autogen') && directImport?.importedName === 'UserProxyAgent') {
      const toolArg = getCallArgument(call, 'function_map');
      this.addRootsFromMappingArgument(toolArg, context, 'autogen', `UserProxyAgent function_map at line ${call.startLine}`, roots);
      return;
    }

    // AutoGen register_function
    if (call.memberChain?.[call.memberChain.length - 1] === 'register_function') {
      const receiver = this.resolveAssignedConstructor(this.buildReceiverReference(call, 1), context);
      if (matchesFrameworkModule(receiver.modulePath || '', 'autogen') && receiver.importedName === 'UserProxyAgent') {
        const toolArg = getCallArgument(call, 'function_map');
        this.addRootsFromMappingArgument(toolArg, context, 'autogen', `register_function at line ${call.startLine}`, roots);
      }
      return;
    }

    // LangChain bind_tools
    if (call.memberChain?.[call.memberChain.length - 1] === 'bind_tools') {
      const receiver = this.resolveAssignedConstructor(this.buildReceiverReference(call, 1), context);
      if (matchesFrameworkModule(receiver.modulePath || '', 'langchain_openai')) {
        const toolArg = getCallArgument(call, 'tools', 0);
        this.addRootsFromArgument(toolArg, context, 'langgraph', `bind_tools at line ${call.startLine}`, roots);
      }
      return;
    }

    // OpenAI chat.completions.create
    if (this.isOpenAIChatCompletionCreate(call, context)) {
      const toolArg = getCallArgument(call, 'tools');
      this.addRootsFromOpenAITools(toolArg, context, `chat.completions.create at line ${call.startLine}`, roots);
    }
  }

  private extractDecoratorRoot(decorators: string[], filePath: string, className: string | undefined, functionName: string): SemanticInvocationRoot | null {
    let heuristicResult: SemanticInvocationRoot | null = null;

    for (const decorator of decorators) {
      const baseName = decorator.split('(')[0].trim();
      const imported = this.resolveImportedSymbol(baseName, filePath);

      if (imported?.importedName) {
        if (
          imported.importedName === 'tool' &&
          (imported.modulePath === 'langchain_core.tools' || imported.modulePath === 'langchain.tools')
        ) {
          const localId = className ? `${className}.${functionName}` : functionName;
          return {
            nodeId: makeNodeId(filePath, localId),
            framework: 'langchain',
            evidence: `decorator ${baseName} imported from ${imported.modulePath}`,
          };
        }

        if (imported.importedName === 'tool' && imported.modulePath === 'crewai.tools') {
          const localId = className ? `${className}.${functionName}` : functionName;
          return {
            nodeId: makeNodeId(filePath, localId),
            framework: 'crewai',
            evidence: `decorator ${baseName} imported from ${imported.modulePath}`,
          };
        }

        if (imported.importedName === 'tool' && matchesFrameworkModule(imported.modulePath, 'smolagents')) {
          const localId = className ? `${className}.${functionName}` : functionName;
          return {
            nodeId: makeNodeId(filePath, localId),
            framework: 'smolagents',
            evidence: `decorator ${baseName} imported from ${imported.modulePath}`,
          };
        }

        // Any resolved 'tool' import from any framework module
        if (imported.importedName === 'tool') {
          const localId = className ? `${className}.${functionName}` : functionName;
          return {
            nodeId: makeNodeId(filePath, localId),
            framework: imported.modulePath.split('.')[0] || 'unknown',
            evidence: `decorator ${baseName} imported from ${imported.modulePath}`,
          };
        }
      }

      // Heuristic: bare @tool, @function_tool, or @tool_call decorators that are not imported
      // from any resolvable module are common in many agent frameworks and custom wrappers.
      // Record as heuristic fallback but keep looking for a structural match.
      if (
        !heuristicResult &&
        (baseName === 'tool' || baseName === 'function_tool' || baseName === 'tool_call' ||
         baseName === 'mcp_tool' || baseName === 'agent_tool' || baseName === 'register_tool')
      ) {
        const localId = className ? `${className}.${functionName}` : functionName;
        heuristicResult = {
          nodeId: makeNodeId(filePath, localId),
          framework: 'unknown',
          evidence: `heuristic: @${baseName} decorator (unresolved import)`,
        };
      }
    }

    return heuristicResult;
  }

  private addRootsFromArgument(
    argument: CallArgumentInfo | undefined,
    context: ResolutionContext,
    framework: string,
    evidence: string,
    roots: Map<string, SemanticInvocationRoot>
  ): void {
    if (!argument) {
      return;
    }

    const nodeIds = this.expandExpressionToFunctionNodes(argument.value, context, new Set<string>());

    if (nodeIds.size > 0) {
      for (const nodeId of nodeIds) {
        if (!roots.has(nodeId)) {
          roots.set(nodeId, { nodeId, framework, evidence });
        }
      }
      return;
    }

    // Fallback: when tool references cannot be resolved to known function nodes
    // (e.g., tools defined in external packages not yet in the analysis corpus),
    // create synthetic roots so the framework is still detected.
    for (const ref of argument.value.references) {
      const syntheticNodeId = makeNodeId(context.filePath, ref);
      if (!roots.has(syntheticNodeId)) {
        roots.set(syntheticNodeId, {
          nodeId: syntheticNodeId,
          framework,
          evidence: `${evidence} (unresolved reference: ${ref})`,
        });
      }
    }
  }

  private addRootsFromMappingArgument(
    argument: CallArgumentInfo | undefined,
    context: ResolutionContext,
    framework: string,
    evidence: string,
    roots: Map<string, SemanticInvocationRoot>
  ): void {
    if (!argument) {
      return;
    }

    const nodeIds = this.expandMappingToFunctionNodes(argument.value, context, new Set<string>());
    for (const nodeId of nodeIds) {
      if (!roots.has(nodeId)) {
        roots.set(nodeId, { nodeId, framework, evidence });
      }
    }
  }

  private addRootsFromOpenAITools(
    argument: CallArgumentInfo | undefined,
    context: ResolutionContext,
    evidence: string,
    roots: Map<string, SemanticInvocationRoot>
  ): void {
    if (!argument) {
      return;
    }

    const toolNames = this.resolveOpenAIToolNames(argument.value, context, new Set<string>());
    if (toolNames.size === 0) {
      return;
    }

    const dispatchMappings = this.dispatchMappingsByFile.get(context.filePath) || [];
    for (const dispatchMapping of dispatchMappings) {
      for (const toolName of toolNames) {
        const functionReference = dispatchMapping.mappings.get(toolName);
        if (!functionReference) {
          continue;
        }

        for (const nodeId of this.resolveReferenceToFunctionNodes(functionReference, context, new Set<string>())) {
          if (!roots.has(nodeId)) {
            roots.set(nodeId, {
              nodeId,
              framework: 'openai',
              evidence: `${evidence} via dispatch mapping ${dispatchMapping.variableName}`,
            });
          }
        }
      }
    }
  }

  private resolveOpenAIToolNames(
    expression: { references: string[]; callCallee?: string },
    context: ResolutionContext,
    visited: Set<string>
  ): Set<string> {
    const result = new Set<string>();

    for (const reference of expression.references) {
      const visitKey = `${context.filePath}:${reference}`;
      if (visited.has(visitKey)) {
        continue;
      }

      visited.add(visitKey);

      for (const schema of this.openAIToolSchemasByFile.get(context.filePath) || []) {
        if (schema.variableName === reference) {
          for (const toolName of schema.toolNames) {
            result.add(toolName);
          }
        }
      }

      for (const assignment of this.findAssignments(reference, context)) {
        for (const toolName of this.resolveOpenAIToolNames(assignment.value, { filePath: context.filePath, className: assignment.enclosingClass, functionName: assignment.enclosingFunction }, visited)) {
          result.add(toolName);
        }
      }

      const imported = this.resolveImportedSymbol(reference, context.filePath);
      if (imported?.resolvedFile) {
        for (const schema of this.openAIToolSchemasByFile.get(imported.resolvedFile) || []) {
          if (schema.variableName === (imported.importedName || reference)) {
            for (const toolName of schema.toolNames) {
              result.add(toolName);
            }
          }
        }
      }
    }

    if (expression.callCallee) {
      for (const returnInfo of this.resolveFunctionReturns(expression.callCallee, context)) {
        for (const toolName of this.resolveOpenAIToolNames(returnInfo.value, {
          filePath: returnInfo.filePath,
          className: returnInfo.enclosingClass,
          functionName: returnInfo.enclosingFunction,
        }, visited)) {
          result.add(toolName);
        }
      }
    }

    return result;
  }

  private expandMappingToFunctionNodes(
    expression: {
      references: string[];
      mappingReferences: Array<{ key: string; reference: string }>;
      subscriptReferences?: Array<{ base: string; keyReference?: string; keyString?: string }>;
      callCallee?: string;
    },
    context: ResolutionContext,
    visited: Set<string>
  ): Set<string> {
    const result = new Set<string>();

    for (const mapping of expression.mappingReferences) {
      for (const nodeId of this.resolveReferenceToFunctionNodes(mapping.reference, context, visited)) {
        result.add(nodeId);
      }
    }

    for (const reference of expression.references) {
      for (const assignment of this.findAssignments(reference, context)) {
        for (const mapping of assignment.value.mappingReferences) {
          for (const nodeId of this.resolveReferenceToFunctionNodes(mapping.reference, { filePath: context.filePath, className: assignment.enclosingClass, functionName: assignment.enclosingFunction }, visited)) {
            result.add(nodeId);
          }
        }
      }
    }

    for (const subscriptReference of expression.subscriptReferences || []) {
      for (const nodeId of this.resolveDispatchReferenceToFunctionNodes(subscriptReference.base, subscriptReference.keyString, subscriptReference.keyReference, context, visited)) {
        result.add(nodeId);
      }
    }

    if (expression.callCallee) {
      for (const returnInfo of this.resolveFunctionReturns(expression.callCallee, context)) {
        for (const nodeId of this.expandMappingToFunctionNodes(returnInfo.value, {
          filePath: returnInfo.filePath,
          className: returnInfo.enclosingClass,
          functionName: returnInfo.enclosingFunction,
        }, visited)) {
          result.add(nodeId);
        }
      }
    }

    return result;
  }

  private expandExpressionToFunctionNodes(
    expression: {
      references: string[];
      subscriptReferences?: Array<{ base: string; keyReference?: string; keyString?: string }>;
      callCallee?: string;
    },
    context: ResolutionContext,
    visited: Set<string>
  ): Set<string> {
    const result = new Set<string>();

    for (const reference of expression.references) {
      for (const nodeId of this.resolveReferenceToFunctionNodes(reference, context, visited)) {
        result.add(nodeId);
      }
    }

    for (const subscriptReference of expression.subscriptReferences || []) {
      for (const nodeId of this.resolveDispatchReferenceToFunctionNodes(subscriptReference.base, subscriptReference.keyString, subscriptReference.keyReference, context, visited)) {
        result.add(nodeId);
      }
    }

    if (expression.callCallee) {
      for (const returnInfo of this.resolveFunctionReturns(expression.callCallee, context)) {
        for (const nodeId of this.expandExpressionToFunctionNodes(returnInfo.value, {
          filePath: returnInfo.filePath,
          className: returnInfo.enclosingClass,
          functionName: returnInfo.enclosingFunction,
        }, visited)) {
          result.add(nodeId);
        }
      }
    }

    return result;
  }

  private resolveReferenceToFunctionNodes(reference: string, context: ResolutionContext, visited: Set<string>): Set<string> {
    const visitKey = `${context.filePath}:${context.className || ''}:${context.functionName || ''}:${reference}`;
    if (visited.has(visitKey)) {
      return new Set<string>();
    }

    visited.add(visitKey);
    const result = new Set<string>();
    const localFunctions = this.functionsByFile.get(context.filePath) || new Map<string, string>();

    const subscriptReference = parseSubscriptReference(reference);
    if (subscriptReference) {
      for (const nodeId of this.resolveDispatchReferenceToFunctionNodes(subscriptReference.base, subscriptReference.keyString, subscriptReference.keyReference, context, visited)) {
        result.add(nodeId);
      }

      if (result.size > 0) {
        return result;
      }
    }

    if (reference.includes('.')) {
      const parts = reference.split('.');
      const lastPart = parts[parts.length - 1];
      if (['invoke', 'ainvoke', 'run', 'arun', 'execute', '_run', '_execute', '__call__'].includes(lastPart)) {
        const receiverReference = parts.slice(0, -1).join('.');
        for (const nodeId of this.resolveReferenceToFunctionNodes(receiverReference, context, visited)) {
          result.add(nodeId);
        }
        if (result.size > 0) {
          return result;
        }
      }
    }

    if (reference.startsWith('self.') && context.className) {
      const methodName = reference.slice('self.'.length);
      const selfNodeId = makeNodeId(context.filePath, `${context.className}.${methodName}`);
      if (this.files.has(context.filePath) && Array.from(localFunctions.values()).includes(selfNodeId)) {
        result.add(selfNodeId);
        return result;
      }
    }

    if (localFunctions.has(reference)) {
      result.add(localFunctions.get(reference)!);
      return result;
    }

    const assignments = this.findAssignments(reference, context);
    if (assignments.length > 0) {
      for (const assignment of assignments) {
        for (const nodeId of this.expandExpressionToFunctionNodes(assignment.value, { filePath: context.filePath, className: assignment.enclosingClass, functionName: assignment.enclosingFunction }, visited)) {
          result.add(nodeId);
        }
      }
      if (result.size > 0) {
        return result;
      }
    }

    const imported = this.resolveImportedSymbol(reference, context.filePath);
    if (imported?.resolvedFile && imported.importedName) {
      const targetFunctions = this.functionsByFile.get(imported.resolvedFile) || new Map<string, string>();
      if (targetFunctions.has(imported.importedName)) {
        result.add(targetFunctions.get(imported.importedName)!);
        return result;
      }

      for (const importedAssignment of this.findAssignments(imported.importedName, { filePath: imported.resolvedFile })) {
        for (const nodeId of this.expandExpressionToFunctionNodes(importedAssignment.value, { filePath: imported.resolvedFile, className: importedAssignment.enclosingClass, functionName: importedAssignment.enclosingFunction }, visited)) {
          result.add(nodeId);
        }
      }
    }

    if (reference.includes('.')) {
      const [base, member] = reference.split('.', 2);
      const importedBase = this.resolveImportedSymbol(base, context.filePath);
      if (importedBase?.resolvedFile) {
        const targetFunctions = this.functionsByFile.get(importedBase.resolvedFile) || new Map<string, string>();
        if (targetFunctions.has(member)) {
          result.add(targetFunctions.get(member)!);
        }

        for (const importedAssignment of this.findAssignments(member, { filePath: importedBase.resolvedFile })) {
          for (const nodeId of this.expandExpressionToFunctionNodes(importedAssignment.value, { filePath: importedBase.resolvedFile, className: importedAssignment.enclosingClass, functionName: importedAssignment.enclosingFunction }, visited)) {
            result.add(nodeId);
          }
        }
      }
    }

    return result;
  }

  private resolveDispatchReferenceToFunctionNodes(
    baseReference: string,
    keyString: string | undefined,
    keyReference: string | undefined,
    context: ResolutionContext,
    visited: Set<string>
  ): Set<string> {
    const mappings = this.collectDispatchMappings(baseReference, context);
    const keys = keyString ? [keyString] : Array.from(this.resolvePossibleStringKeys(keyReference, context, visited));
    const result = new Set<string>();

    if (mappings.size === 0) {
      return result;
    }

    if (keys.length === 0) {
      for (const reference of mappings.values()) {
        for (const nodeId of this.resolveReferenceToFunctionNodes(reference, context, visited)) {
          result.add(nodeId);
        }
      }

      return result;
    }

    for (const key of keys) {
      const reference = mappings.get(key);
      if (!reference) {
        continue;
      }

      for (const nodeId of this.resolveReferenceToFunctionNodes(reference, context, visited)) {
        result.add(nodeId);
      }
    }

    return result;
  }

  private collectDispatchMappings(baseReference: string, context: ResolutionContext): Map<string, string> {
    const mappings = new Map<string, string>();

    for (const dispatchMapping of this.dispatchMappingsByFile.get(context.filePath) || []) {
      if (dispatchMapping.variableName !== baseReference) {
        continue;
      }

      for (const [key, reference] of dispatchMapping.mappings) {
        mappings.set(key, reference);
      }
    }

    for (const assignment of this.findAssignments(baseReference, context)) {
      for (const mappingReference of assignment.value.mappingReferences) {
        mappings.set(mappingReference.key, mappingReference.reference);
      }
    }

    const imported = this.resolveImportedSymbol(baseReference, context.filePath);
    if (imported?.resolvedFile) {
      for (const dispatchMapping of this.dispatchMappingsByFile.get(imported.resolvedFile) || []) {
        if (dispatchMapping.variableName !== (imported.importedName || baseReference)) {
          continue;
        }

        for (const [key, reference] of dispatchMapping.mappings) {
          mappings.set(key, reference);
        }
      }
    }

    return mappings;
  }

  private resolvePossibleStringKeys(reference: string | undefined, context: ResolutionContext, visited: Set<string>): Set<string> {
    const result = new Set<string>();
    if (!reference) {
      return result;
    }

    if ((reference.startsWith('"') && reference.endsWith('"')) || (reference.startsWith("'") && reference.endsWith("'"))) {
      result.add(reference.slice(1, -1));
      return result;
    }

    const visitKey = `${context.filePath}:${context.className || ''}:${context.functionName || ''}:str:${reference}`;
    if (visited.has(visitKey)) {
      return result;
    }

    visited.add(visitKey);
    for (const assignment of this.findAssignments(reference, context)) {
      for (const literal of assignment.value.stringLiterals) {
        result.add(literal);
      }
    }

    return result;
  }

  private resolveAssignedConstructor(
    baseExpression: string | undefined,
    context: ResolutionContext,
    visited = new Set<string>()
  ): ConstructorBinding {
    if (!baseExpression) {
      return {};
    }

    // First check if this is a with-bound variable (e.g., `with foo() as x`)
    const withBinding = this.resolveWithBoundVariable(baseExpression, context, visited);
    if (withBinding?.identity) {
      return withBinding;
    }

    for (const candidateReference of iterateReferenceCandidates(baseExpression)) {
      const visitKey = `${context.filePath}:${context.className || ''}:${context.functionName || ''}:ctor:${candidateReference}`;
      if (visited.has(visitKey)) {
        continue;
      }

      visited.add(visitKey);

      const assignment = this.findAssignments(candidateReference, context)
        .slice()
        .reverse()
        .find((candidate) => candidate.value.callCallee || candidate.value.references.length > 0);
      if (!assignment) {
        continue;
      }

      const assignmentContext: ResolutionContext = {
        filePath: context.filePath,
        className: assignment.enclosingClass,
        functionName: assignment.enclosingFunction,
      };

      if (assignment.value.callCallee) {
        const binding = this.resolveCallResultBinding(assignment.value.callCallee, assignmentContext, visited);
        if (binding.identity) {
          return {
            ...binding,
            matchedReference: candidateReference,
          };
        }
      }

      for (const reference of assignment.value.references) {
        const aliasBinding = this.resolveAssignedConstructor(reference, assignmentContext, visited);
        if (aliasBinding.identity) {
          return {
            ...aliasBinding,
            matchedReference: candidateReference,
          };
        }
      }
    }

    return this.resolveInlineConstructor(baseExpression, context.filePath);
  }

  private buildReceiverReference(call: CallSite, trailingMemberCount: number): string | undefined {
    if (!call.baseExpression) {
      return undefined;
    }

    const memberChain = call.memberChain || [];
    const receiverSegments = memberChain.slice(0, Math.max(0, memberChain.length - trailingMemberCount));
    const parts = [call.baseExpression, ...receiverSegments].filter(Boolean);
    return parts.length > 0 ? parts.join('.') : undefined;
  }

  private findAssignments(reference: string, context: ResolutionContext): AssignmentInfo[] {
    const assignments = this.assignmentsByFile.get(context.filePath) || [];

    if (reference.startsWith('self.') && context.className) {
      return assignments.filter((assignment) => assignment.target === reference && assignment.enclosingClass === context.className);
    }

    return assignments.filter((assignment) => {
      if (assignment.target !== reference) {
        return false;
      }

      if ((assignment.enclosingClass || undefined) !== (context.className || undefined)) {
        return false;
      }

      if (!assignment.enclosingFunction) {
        return true;
      }

      return assignment.enclosingFunction === context.functionName;
    });
  }

  /**
   * Check if a reference is a with-bound variable and resolve its identity
   * from the context manager's yield type.
   *
   * Example: `with sqlite_connection() as conn:` -> conn has type sqlite3.Connection
   */
  private resolveWithBoundVariable(
    reference: string,
    context: ResolutionContext,
    visited: Set<string>
  ): ConstructorBinding | undefined {
    const withBindings = this.withBindingsByFile.get(context.filePath) || [];

    for (const binding of withBindings) {
      // Must match target, enclosing function and class
      if (binding.target !== reference) continue;
      if ((binding.enclosingFunction || undefined) !== (context.functionName || undefined)) continue;
      if ((binding.enclosingClass || undefined) !== (context.className || undefined)) continue;

      // Found a with binding for this reference
      // Now resolve what the context manager yields
      const contextManagerExpr = binding.contextManager;

      // The context manager is typically a call like sqlite_connection()
      if (contextManagerExpr.callCallee) {
        const cmIdentity = this.resolveContextManagerYieldType(
          contextManagerExpr.callCallee,
          context,
          visited
        );
        if (cmIdentity) {
          return {
            identity: cmIdentity,
            matchedReference: reference,
          };
        }
      }

      // Handle reference to a context manager variable
      for (const ref of contextManagerExpr.references) {
        const cmIdentity = this.resolveContextManagerYieldType(ref, context, visited);
        if (cmIdentity) {
          return {
            identity: cmIdentity,
            matchedReference: reference,
          };
        }
      }
    }

    return undefined;
  }

  /**
   * Resolve what type a context manager function yields.
   *
   * For known stdlib context managers, return hardcoded types.
   * For @contextmanager decorated functions, trace the yield statement.
   */
  private resolveContextManagerYieldType(
    calleeReference: string,
    context: ResolutionContext,
    visited: Set<string>
  ): string | undefined {
    const visitKey = `${context.filePath}:cm:${calleeReference}`;
    if (visited.has(visitKey)) return undefined;
    visited.add(visitKey);

    // Check if it's a local function with @contextmanager decorator
    const localFunctions = this.functionsByFile.get(context.filePath);
    const contextManagers = this.contextManagerFunctions.get(context.filePath) || new Set();

    if (localFunctions?.has(calleeReference) && contextManagers.has(calleeReference)) {
      // Find the yield statement in this function
      const yields = this.yieldsByFile.get(context.filePath) || [];
      for (const yieldInfo of yields) {
        if (yieldInfo.enclosingFunction === calleeReference) {
          // The yield value tells us what type is produced
          // Check if it's a call result
          if (yieldInfo.value.callCallee) {
            const binding = this.resolveCallResultBinding(yieldInfo.value.callCallee, {
              filePath: context.filePath,
              functionName: calleeReference,
            }, visited);
            if (binding.identity) {
              return binding.identity;
            }
          }

          // Check if it's a reference to a variable
          for (const ref of yieldInfo.value.references) {
            // Try to resolve the reference
            const binding = this.resolveAssignedConstructor(ref, {
              filePath: context.filePath,
              functionName: calleeReference,
            }, visited);
            if (binding.identity) {
              return binding.identity;
            }
          }
        }
      }
    }

    // Check imported context managers
    const imported = this.resolveImportedSymbol(calleeReference, context.filePath);
    if (imported?.resolvedFile && imported.importedName) {
      const targetContextManagers = this.contextManagerFunctions.get(imported.resolvedFile) || new Set();
      if (targetContextManagers.has(imported.importedName)) {
        const yields = this.yieldsByFile.get(imported.resolvedFile) || [];
        for (const yieldInfo of yields) {
          if (yieldInfo.enclosingFunction === imported.importedName) {
            if (yieldInfo.value.callCallee) {
              const binding = this.resolveCallResultBinding(yieldInfo.value.callCallee, {
                filePath: imported.resolvedFile,
                functionName: imported.importedName,
              }, visited);
              if (binding.identity) {
                return binding.identity;
              }
            }

            for (const ref of yieldInfo.value.references) {
              const binding = this.resolveAssignedConstructor(ref, {
                filePath: imported.resolvedFile,
                functionName: imported.importedName,
              }, visited);
              if (binding.identity) {
                return binding.identity;
              }
            }
          }
        }
      }
    }

    // Known stdlib context managers with their yield types
    // These are hardcoded because we can't trace into stdlib
    const knownContextManagers: Record<string, string> = {
      'sqlite3.connect': 'sqlite3.Connection',
      'psycopg2.connect': 'psycopg2.connection',
      'asyncpg.connect': 'asyncpg.Connection',
      'aiomysql.connect': 'aiomysql.Connection',
      'motor.motor_asyncio.AsyncIOMotorClient': 'motor.motor_asyncio.AsyncIOMotorDatabase',
    };

    for (const [pattern, yieldType] of Object.entries(knownContextManagers)) {
      if (calleeReference === pattern || calleeReference.endsWith('.' + pattern.split('.').pop())) {
        return yieldType;
      }
    }

    return undefined;
  }

  private resolveImportedSymbol(reference: string, filePath: string): ImportBinding | undefined {
    const baseName = reference.split('.')[0];
    return this.importBindings.get(filePath)?.get(baseName);
  }

  private resolveCallResultBinding(
    callCallee: string,
    context: ResolutionContext,
    visited: Set<string>
  ): ConstructorBinding {
    if (callCallee === 'open' || callCallee === 'eval' || callCallee === 'exec') {
      return {
        modulePath: 'builtins',
        importedName: callCallee,
        matchedReference: callCallee,
        identity: `builtins.${callCallee}`,
      };
    }

    const imported = this.resolveImportedSymbol(callCallee, context.filePath);
    if (imported?.modulePath) {
      const rawIdentity = imported.importedName ? `${imported.modulePath}.${imported.importedName}` : callCallee;
      // Apply factory return type mapping: sqlite3.connect() returns sqlite3.Connection
      const mappedIdentity = FACTORY_RETURN_TYPES[rawIdentity] || rawIdentity;
      return {
        modulePath: imported.modulePath,
        importedName: imported.importedName,
        matchedReference: callCallee,
        identity: mappedIdentity,
      };
    }

    if (callCallee.includes('.')) {
      const parts = callCallee.split('.');
      const lastMember = parts.pop()!;
      const receiverReference = parts.join('.');
      const receiverBinding = this.resolveAssignedConstructor(receiverReference, context, visited);
      if (receiverBinding.identity) {
        const resolvedIdentity = this.resolveMethodResultIdentity(receiverBinding.identity, lastMember);
        // Apply factory return type mapping
        const mappedIdentity = FACTORY_RETURN_TYPES[resolvedIdentity] || resolvedIdentity;
        return {
          ...receiverBinding,
          matchedReference: receiverReference,
          importedName: lastMember,
          identity: mappedIdentity,
        };
      }
    }

    const functionBinding = this.resolveFunctionReturnBinding(callCallee, context, visited);
    // Apply factory return type mapping to function return results
    if (functionBinding.identity && FACTORY_RETURN_TYPES[functionBinding.identity]) {
      return {
        ...functionBinding,
        identity: FACTORY_RETURN_TYPES[functionBinding.identity],
      };
    }
    return functionBinding;
  }

  private resolveFunctionReturnBinding(
    reference: string,
    context: ResolutionContext,
    visited: Set<string>
  ): ConstructorBinding {
    const target = this.resolveFunctionReference(reference, context);
    if (!target) {
      return {};
    }

    const targetContext: ResolutionContext = {
      filePath: target.filePath,
      className: target.className,
      functionName: target.functionName,
    };

    for (const returnInfo of this.findReturns(target.functionName, targetContext)) {
      if (returnInfo.value.callCallee) {
        const binding = this.resolveCallResultBinding(returnInfo.value.callCallee, {
          filePath: target.filePath,
          className: returnInfo.enclosingClass,
          functionName: returnInfo.enclosingFunction,
        }, visited);
        if (binding.identity) {
          return binding;
        }
      }

      for (const returnReference of returnInfo.value.references) {
        const binding = this.resolveAssignedConstructor(returnReference, {
          filePath: target.filePath,
          className: returnInfo.enclosingClass,
          functionName: returnInfo.enclosingFunction,
        }, visited);
        if (binding.identity) {
          return binding;
        }
      }
    }

    return {};
  }

  private resolveFunctionReturns(
    reference: string,
    context: ResolutionContext
  ): Array<ReturnInfo & { filePath: string }> {
    const target = this.resolveFunctionReference(reference, context);
    if (!target) {
      return [];
    }

    return this.findReturns(target.functionName, {
      filePath: target.filePath,
      className: target.className,
      functionName: target.functionName,
    }).map((returnInfo) => ({
      ...returnInfo,
      filePath: target.filePath,
    }));
  }

  private resolveFunctionReference(
    reference: string,
    context: ResolutionContext
  ): { filePath: string; functionName: string; className?: string } | undefined {
    const localFunctions = this.functionsByFile.get(context.filePath) || new Map<string, string>();
    if (reference.startsWith('self.') && context.className) {
      const methodName = reference.slice('self.'.length);
      const selfNodeId = makeNodeId(context.filePath, `${context.className}.${methodName}`);
      if (Array.from(localFunctions.values()).includes(selfNodeId)) {
        return { filePath: context.filePath, functionName: methodName, className: context.className };
      }
    }

    if (localFunctions.has(reference)) {
      return { filePath: context.filePath, functionName: reference };
    }

    const imported = this.resolveImportedSymbol(reference, context.filePath);
    if (imported?.resolvedFile && imported.importedName) {
      const targetFunctions = this.functionsByFile.get(imported.resolvedFile) || new Map<string, string>();
      if (targetFunctions.has(imported.importedName)) {
        return { filePath: imported.resolvedFile, functionName: imported.importedName };
      }
    }

    return undefined;
  }

  private findReturns(functionName: string, context: ResolutionContext): ReturnInfo[] {
    const returns = this.returnsByFile.get(context.filePath) || [];
    return returns.filter((entry) => {
      if (entry.enclosingFunction !== functionName) {
        return false;
      }

      return (entry.enclosingClass || undefined) === (context.className || undefined);
    });
  }

  private resolveMethodResultIdentity(receiverIdentity: string, methodName: string): string {
    // Database connection type mappings
    // When calling .cursor() on a connection, return the Cursor type
    const cursorMappings: Record<string, string> = {
      'sqlite3.connect': 'sqlite3.Cursor',
      'sqlite3.Connection': 'sqlite3.Cursor',
      'psycopg2.connect': 'psycopg2.cursor',
      'psycopg2.connection': 'psycopg2.cursor',
      'asyncpg.connect': 'asyncpg.Cursor',
      'asyncpg.Connection': 'asyncpg.Cursor',
      'aiomysql.connect': 'aiomysql.Cursor',
      'aiomysql.Connection': 'aiomysql.Cursor',
      'mysql.connector.connect': 'mysql.connector.cursor',
      'pymysql.connect': 'pymysql.cursors.Cursor',
    };

    if (methodName === 'cursor') {
      // Check for exact or prefix match in cursor mappings
      for (const [connType, cursorType] of Object.entries(cursorMappings)) {
        if (receiverIdentity === connType || receiverIdentity.startsWith(connType + '.')) {
          return cursorType;
        }
      }
    }

    // Connection factory mappings - when calling connect(), return Connection type
    const connectMappings: Record<string, string> = {
      'sqlite3': 'sqlite3.Connection',
      'psycopg2': 'psycopg2.connection',
      'asyncpg': 'asyncpg.Connection',
      'aiomysql': 'aiomysql.Connection',
      'mysql.connector': 'mysql.connector.connection',
      'pymysql': 'pymysql.connections.Connection',
    };

    if (methodName === 'connect') {
      for (const [module, connType] of Object.entries(connectMappings)) {
        if (receiverIdentity === module) {
          return connType;
        }
      }
    }

    return `${receiverIdentity}.${methodName}`;
  }

  private resolveInlineConstructor(baseExpression: string | undefined, filePath: string): ConstructorBinding {
    if (!baseExpression) {
      return {};
    }

    const constructorMatch = baseExpression.match(/^([A-Za-z_][A-Za-z0-9_\.]*)\(/);
    if (!constructorMatch) {
      return {};
    }

    const constructorReference = constructorMatch[1];
    const imported = this.resolveImportedSymbol(constructorReference, filePath);
    if (!imported?.modulePath) {
      return {};
    }

    return {
      modulePath: imported.modulePath,
      importedName: imported.importedName,
      matchedReference: constructorReference,
      identity: imported.importedName ? `${imported.modulePath}.${imported.importedName}` : constructorReference,
    };
  }

  private isOpenAIChatCompletionCreate(call: CallSite, context: ResolutionContext): boolean {
    if (!call.memberChain || call.memberChain.length < 3) {
      return false;
    }

    const memberChain = call.memberChain.slice(-3).join('.');
    if (memberChain !== 'chat.completions.create') {
      return false;
    }

    const receiver = this.resolveAssignedConstructor(this.buildReceiverReference(call, 3), context);
    return receiver.modulePath === 'openai' && ['OpenAI', 'AsyncOpenAI'].includes(receiver.importedName || '');
  }
}

function splitReferenceSegments(reference: string | undefined): string[] {
  return (reference || '').split('.').filter(Boolean);
}

function parseSubscriptReference(reference: string): { base: string; keyReference?: string; keyString?: string } | undefined {
  const match = reference.match(/^(.+)\[([^\]]+)\]$/);
  if (!match) {
    return undefined;
  }

  const base = match[1].trim();
  const rawKey = match[2].trim();
  if (!base || !rawKey) {
    return undefined;
  }

  if ((rawKey.startsWith('"') && rawKey.endsWith('"')) || (rawKey.startsWith("'") && rawKey.endsWith("'"))) {
    return {
      base,
      keyString: rawKey.slice(1, -1),
    };
  }

  return {
    base,
    keyReference: rawKey,
  };
}

function* iterateReferenceCandidates(reference: string): Generator<string> {
  const segments = splitReferenceSegments(reference);
  for (let index = segments.length; index >= 1; index--) {
    yield segments.slice(0, index).join('.');
  }
}

export function extractSemanticInvocationRoots(files: Map<string, ParsedPythonFile>): Map<string, SemanticInvocationRoot> {
  return new PythonSemanticIndex(files).extractInvocationRoots();
}
