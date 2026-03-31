import * as path from 'path';
import {
  AssignmentInfo,
  CallArgumentInfo,
  CallSite,
  ParsedPythonFile,
} from './ast-parser';

export interface SemanticInvocationRoot {
  nodeId: string;
  framework: string;
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
}

interface ConstructorBinding {
  modulePath?: string;
  importedName?: string;
}

function makeNodeId(filePath: string, localName: string): string {
  return `${filePath}:${localName}`;
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

  resolveCallableNodeIds(reference: string, filePath: string, className?: string): string[] {
    return Array.from(this.resolveReferenceToFunctionNodes(reference, { filePath, className }, new Set<string>()));
  }

  private buildIndex(): void {
    for (const [filePath, parsed] of this.files) {
      const localFunctions = new Map<string, string>();
      for (const func of parsed.functions) {
        const localId = func.className ? `${func.className}.${func.name}` : func.name;
        localFunctions.set(func.name, makeNodeId(filePath, localId));
      }

      this.functionsByFile.set(filePath, localFunctions);
      this.assignmentsByFile.set(filePath, parsed.assignments);

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

    if (directImport?.modulePath === 'langgraph.prebuilt' && directImport.importedName === 'create_react_agent') {
      const toolArg = getCallArgument(call, 'tools', 1);
      this.addRootsFromArgument(toolArg, context, 'langgraph', `create_react_agent at line ${call.startLine}`, roots);
      return;
    }

    if (directImport?.modulePath === 'smolagents' && ['CodeAgent', 'ToolCallingAgent'].includes(directImport.importedName || '')) {
      const toolArg = getCallArgument(call, 'tools', 0);
      this.addRootsFromArgument(toolArg, context, 'smolagents', `${directImport.importedName} tools at line ${call.startLine}`, roots);
      return;
    }

    if (directImport?.modulePath === 'crewai' && directImport.importedName === 'Agent') {
      const toolArg = getCallArgument(call, 'tools');
      this.addRootsFromArgument(toolArg, context, 'crewai', `CrewAI Agent tools at line ${call.startLine}`, roots);
      return;
    }

    if (directImport?.modulePath === 'autogen' && directImport.importedName === 'UserProxyAgent') {
      const toolArg = getCallArgument(call, 'function_map');
      this.addRootsFromMappingArgument(toolArg, context, 'autogen', `UserProxyAgent function_map at line ${call.startLine}`, roots);
      return;
    }

    if (call.memberChain?.[call.memberChain.length - 1] === 'register_function') {
      const receiver = this.resolveAssignedConstructor(call.baseExpression, context);
      if (receiver.modulePath === 'autogen' && receiver.importedName === 'UserProxyAgent') {
        const toolArg = getCallArgument(call, 'function_map');
        this.addRootsFromMappingArgument(toolArg, context, 'autogen', `register_function at line ${call.startLine}`, roots);
      }
      return;
    }

    if (call.memberChain?.[call.memberChain.length - 1] === 'bind_tools') {
      const receiver = this.resolveAssignedConstructor(call.baseExpression, context);
      if (receiver.modulePath === 'langchain_openai') {
        const toolArg = getCallArgument(call, 'tools', 0);
        this.addRootsFromArgument(toolArg, context, 'langgraph', `bind_tools at line ${call.startLine}`, roots);
      }
    }
  }

  private extractDecoratorRoot(decorators: string[], filePath: string, className: string | undefined, functionName: string): SemanticInvocationRoot | null {
    for (const decorator of decorators) {
      const baseName = decorator.split('(')[0].trim();
      const imported = this.resolveImportedSymbol(baseName, filePath);
      if (!imported?.importedName) {
        continue;
      }

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
    }

    return null;
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

    for (const nodeId of this.expandExpressionToFunctionNodes(argument.value, context, new Set<string>())) {
      if (!roots.has(nodeId)) {
        roots.set(nodeId, { nodeId, framework, evidence });
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

  private expandMappingToFunctionNodes(expression: { references: string[]; mappingReferences: Array<{ key: string; reference: string }> }, context: ResolutionContext, visited: Set<string>): Set<string> {
    const result = new Set<string>();

    for (const mapping of expression.mappingReferences) {
      for (const nodeId of this.resolveReferenceToFunctionNodes(mapping.reference, context, visited)) {
        result.add(nodeId);
      }
    }

    for (const reference of expression.references) {
      const assignment = this.findAssignment(reference, context);
      if (!assignment) {
        continue;
      }

      for (const mapping of assignment.value.mappingReferences) {
        for (const nodeId of this.resolveReferenceToFunctionNodes(mapping.reference, { filePath: context.filePath, className: assignment.enclosingClass }, visited)) {
          result.add(nodeId);
        }
      }
    }

    return result;
  }

  private expandExpressionToFunctionNodes(expression: { references: string[] }, context: ResolutionContext, visited: Set<string>): Set<string> {
    const result = new Set<string>();

    for (const reference of expression.references) {
      for (const nodeId of this.resolveReferenceToFunctionNodes(reference, context, visited)) {
        result.add(nodeId);
      }
    }

    return result;
  }

  private resolveReferenceToFunctionNodes(reference: string, context: ResolutionContext, visited: Set<string>): Set<string> {
    const visitKey = `${context.filePath}:${context.className || ''}:${reference}`;
    if (visited.has(visitKey)) {
      return new Set<string>();
    }

    visited.add(visitKey);
    const result = new Set<string>();
    const localFunctions = this.functionsByFile.get(context.filePath) || new Map<string, string>();

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

    const assignment = this.findAssignment(reference, context);
    if (assignment) {
      for (const nodeId of this.expandExpressionToFunctionNodes(assignment.value, { filePath: context.filePath, className: assignment.enclosingClass }, visited)) {
        result.add(nodeId);
      }
      return result;
    }

    const imported = this.resolveImportedSymbol(reference, context.filePath);
    if (imported?.resolvedFile && imported.importedName) {
      const targetFunctions = this.functionsByFile.get(imported.resolvedFile) || new Map<string, string>();
      if (targetFunctions.has(imported.importedName)) {
        result.add(targetFunctions.get(imported.importedName)!);
        return result;
      }

      const importedAssignment = this.findAssignment(imported.importedName, { filePath: imported.resolvedFile });
      if (importedAssignment) {
        for (const nodeId of this.expandExpressionToFunctionNodes(importedAssignment.value, { filePath: imported.resolvedFile, className: importedAssignment.enclosingClass }, visited)) {
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

        const importedAssignment = this.findAssignment(member, { filePath: importedBase.resolvedFile });
        if (importedAssignment) {
          for (const nodeId of this.expandExpressionToFunctionNodes(importedAssignment.value, { filePath: importedBase.resolvedFile, className: importedAssignment.enclosingClass }, visited)) {
            result.add(nodeId);
          }
        }
      }
    }

    return result;
  }

  private resolveAssignedConstructor(baseExpression: string | undefined, context: ResolutionContext): ConstructorBinding {
    if (!baseExpression) {
      return {};
    }

    const assignment = this.findAssignment(baseExpression, context);
    if (!assignment?.value.callCallee) {
      return {};
    }

    const imported = this.resolveImportedSymbol(assignment.value.callCallee, context.filePath);
    if (!imported) {
      return {};
    }

    return {
      modulePath: imported.modulePath,
      importedName: imported.importedName,
    };
  }

  private findAssignment(reference: string, context: ResolutionContext): AssignmentInfo | undefined {
    const assignments = this.assignmentsByFile.get(context.filePath) || [];

    if (reference.startsWith('self.') && context.className) {
      return assignments.find((assignment) => assignment.target === reference && assignment.enclosingClass === context.className);
    }

    return assignments.find((assignment) => assignment.target === reference && !assignment.enclosingFunction);
  }

  private resolveImportedSymbol(reference: string, filePath: string): ImportBinding | undefined {
    const baseName = reference.split('.')[0];
    return this.importBindings.get(filePath)?.get(baseName);
  }
}

export function extractSemanticInvocationRoots(files: Map<string, ParsedPythonFile>): Map<string, SemanticInvocationRoot> {
  return new PythonSemanticIndex(files).extractInvocationRoots();
}
