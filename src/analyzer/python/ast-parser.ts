/**
 * Python AST Parser using tree-sitter
 *
 * Provides proper AST parsing for Python code with support for:
 * - Function definitions and decorators
 * - Class definitions and inheritance
 * - Function calls with argument tracking
 * - Import statements
 * - Call graph construction
 */

import Parser from 'web-tree-sitter';
import * as path from 'path';
import * as fs from 'fs';

let parser: Parser | null = null;
let pythonLanguage: Parser.Language | null = null;

/**
 * AST node wrapper for consistent interface
 */
export interface ASTNode {
  type: string;
  text: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  children: ASTNode[];
  parent: ASTNode | null;
}

/**
 * Control flow information for structural policy gate detection
 */
export interface ControlFlowInfo {
  /** Whether the function contains any raise statements */
  hasRaise: boolean;
  /** Whether raises are inside conditional branches (can prevent execution) */
  hasConditionalRaise: boolean;
  /** Whether the function has early returns that can prevent execution */
  hasConditionalReturn: boolean;
  /** Types of exceptions raised (e.g., PermissionError, ValueError) */
  raiseTypes: string[];
  /** Whether the function has conditional branches (if statements) */
  hasConditionalBranches: boolean;
  /** Whether function parameters are used in conditions */
  checksParameters: boolean;
}

/**
 * Function definition with metadata
 */
export interface FunctionDef {
  name: string;
  decorators: string[];
  startLine: number;
  endLine: number;
  body: ASTNode[];
  isAsync: boolean;
  isMethod: boolean;
  className?: string;
  /** Parameter names in declaration order */
  parameters?: string[];
  /** Control flow information for policy gate detection */
  controlFlow?: ControlFlowInfo;
  /** Whether any decorator structurally acts as a gate */
  hasDecoratorGate?: boolean;
  /** Names of decorators that act as structural gates */
  gateDecorators?: string[];
}

/**
 * Decorator definition info for structural gate detection
 */
export interface DecoratorDef {
  /** Name of the decorator function */
  name: string;
  /** Line where defined */
  startLine: number;
  /** Whether this decorator structurally acts as a gate */
  isStructuralGate: boolean;
  /** Control flow info of the decorator (or inner wrapper) */
  controlFlow?: ControlFlowInfo;
}

/**
 * OpenAI tool schema extracted from dictionary definitions
 * Detects patterns like: TOOLS = [{"type": "function", "function": {"name": "calculate"}}]
 */
export interface OpenAIToolSchema {
  /** Variable name holding the tool definitions (e.g., "CALCULATOR_TOOLS") */
  variableName: string;
  /** Line where defined */
  startLine: number;
  /** Tool names extracted from the schema */
  toolNames: string[];
}

/**
 * Function dispatch mapping (string -> function reference)
 * Detects patterns like: tool_functions = {"calculate": calculate, "delete": delete_file}
 */
export interface FunctionDispatchMapping {
  /** Variable name holding the mapping (e.g., "tool_functions") */
  variableName: string;
  /** Line where defined */
  startLine: number;
  /** Map of tool name strings to function identifiers */
  mappings: Map<string, string>;
}

/**
 * Class definition with metadata
 */
export interface ClassDef {
  name: string;
  bases: string[];
  startLine: number;
  endLine: number;
  methods: FunctionDef[];
  decorators: string[];
}

/**
 * Function call with context
 */
export interface CallSite {
  callee: string;
  startLine: number;
  startColumn: number;
  codeSnippet: string;
  enclosingFunction?: string;
  enclosingClass?: string;
  arguments: string[];
  argumentDetails: CallArgumentInfo[];
  baseExpression?: string;
  memberChain?: string[];
}

export interface ExpressionSummary {
  text: string;
  references: string[];
  stringLiterals: string[];
  mappingReferences: Array<{
    key: string;
    reference: string;
  }>;
  callCallee?: string;
}

export interface CallArgumentInfo {
  name?: string;
  value: ExpressionSummary;
}

export interface AssignmentInfo {
  target: string;
  value: ExpressionSummary;
  startLine: number;
  enclosingFunction?: string;
  enclosingClass?: string;
}

/**
 * Import statement
 */
export interface ImportInfo {
  module: string;
  names: { name: string; alias?: string }[];
  isFrom: boolean;
}

/**
 * Parsed Python file result
 */
export interface ParsedPythonFile {
  functions: FunctionDef[];
  classes: ClassDef[];
  calls: CallSite[];
  imports: ImportInfo[];
  assignments: AssignmentInfo[];
  /** Decorator functions defined in this file (for cross-file resolution) */
  decoratorDefs: DecoratorDef[];
  /** OpenAI tool schemas extracted from list/dict literals */
  openaiToolSchemas: OpenAIToolSchema[];
  /** Function dispatch mappings (string -> function) */
  dispatchMappings: FunctionDispatchMapping[];
  success: boolean;
  error?: string;
}

/**
 * Initialize the tree-sitter parser with Python language
 */
export async function initParser(): Promise<void> {
  if (parser) return;

  await Parser.init();
  parser = new Parser();

  // WASM loading paths in order of preference:
  // 1. dist/wasm (built/deployed)
  // 2. wasm (source directory)
  // 3. node_modules/tree-sitter-wasms/out (npm package)
  const wasmCandidates = [
    path.join(__dirname, '../../../wasm/tree-sitter-python.wasm'),     // from dist/analyzer/python
    path.join(__dirname, '../../wasm/tree-sitter-python.wasm'),        // from src/analyzer/python (dev)
    path.join(process.cwd(), 'dist/wasm/tree-sitter-python.wasm'),
    path.join(process.cwd(), 'wasm/tree-sitter-python.wasm'),
    path.join(process.cwd(), 'node_modules/tree-sitter-wasms/out/tree-sitter-python.wasm'),
  ];

  let wasmPath: string | undefined;
  let validationError: string | undefined;

  for (const candidate of wasmCandidates) {
    if (fs.existsSync(candidate)) {
      // Validate it's actually a WASM file by checking magic bytes
      try {
        const fd = fs.openSync(candidate, 'r');
        const buffer = Buffer.alloc(4);
        fs.readSync(fd, buffer, 0, 4, 0);
        fs.closeSync(fd);

        // WASM magic number: 0x00 0x61 0x73 0x6D (null + 'asm')
        if (buffer[0] === 0x00 && buffer[1] === 0x61 && buffer[2] === 0x73 && buffer[3] === 0x6d) {
          wasmPath = candidate;
          break;
        } else {
          validationError = `${candidate} is not a valid WASM file (wrong magic number)`;
        }
      } catch (err) {
        validationError = `Failed to validate ${candidate}: ${err}`;
      }
    }
  }

  if (!wasmPath) {
    const triedPaths = wasmCandidates.join('\n  - ');
    throw new Error(
      `Python WASM not found. Tried:\n  - ${triedPaths}\n` +
      (validationError ? `Last validation error: ${validationError}\n` : '') +
      `Install with: npm install tree-sitter-wasms`
    );
  }

  pythonLanguage = await Parser.Language.load(wasmPath);
  parser.setLanguage(pythonLanguage);
}

/**
 * Convert tree-sitter node to our AST node format
 */
function convertNode(node: Parser.SyntaxNode): ASTNode {
  return {
    type: node.type,
    text: node.text,
    startLine: node.startPosition.row + 1,
    startColumn: node.startPosition.column + 1,
    endLine: node.endPosition.row + 1,
    endColumn: node.endPosition.column + 1,
    children: node.children.map(convertNode),
    parent: null,
  };
}

/**
 * Extract decorator names from a decorated definition
 */
function extractDecorators(node: Parser.SyntaxNode): string[] {
  const decorators: string[] = [];

  for (const child of node.children) {
    if (child.type === 'decorator') {
      // Get the decorator content after @
      const atSign = child.children.find((c) => c.type === '@');
      if (atSign && atSign.nextSibling) {
        let decoratorText = '';
        let current = atSign.nextSibling;
        while (current) {
          decoratorText += current.text;
          current = current.nextSibling as Parser.SyntaxNode;
        }
        decorators.push(decoratorText.trim());
      } else {
        // Fallback: extract text after @
        const text = child.text;
        if (text.startsWith('@')) {
          decorators.push(text.slice(1).split('(')[0].trim());
        }
      }
    }
  }

  return decorators;
}

/**
 * Extract base class names from class definition
 */
function extractBases(node: Parser.SyntaxNode): string[] {
  const bases: string[] = [];

  const argList = node.childForFieldName('superclasses');
  if (argList) {
    for (const child of argList.children) {
      if (child.type === 'identifier' || child.type === 'attribute') {
        bases.push(child.text);
      }
    }
  }

  return bases;
}

/**
 * Extract function name from function definition
 */
function extractFunctionName(node: Parser.SyntaxNode): string {
  const nameNode = node.childForFieldName('name');
  return nameNode?.text || '';
}

/**
 * Extract class name from class definition
 */
function extractClassName(node: Parser.SyntaxNode): string {
  const nameNode = node.childForFieldName('name');
  return nameNode?.text || '';
}

/**
 * Get the callee string from a call expression
 */
function extractCallee(callNode: Parser.SyntaxNode): string {
  return extractCalleeInfo(callNode).callee;
}

function extractCalleeInfo(callNode: Parser.SyntaxNode): { callee: string; baseExpression?: string; memberChain: string[] } {
  const funcNode = callNode.childForFieldName('function');
  if (!funcNode) {
    return { callee: '', memberChain: [] };
  }

  const parts = extractMemberChain(funcNode);
  return {
    callee: funcNode.text,
    baseExpression: parts.baseExpression,
    memberChain: parts.memberChain,
  };
}

function extractMemberChain(node: Parser.SyntaxNode): { baseExpression?: string; memberChain: string[] } {
  if (node.type === 'attribute') {
    const objectNode = node.childForFieldName('object');
    const attributeNode = node.childForFieldName('attribute');

    if (objectNode && attributeNode) {
      const inner = extractMemberChain(objectNode);
      if (inner.baseExpression) {
        return {
          baseExpression: inner.baseExpression,
          memberChain: [...inner.memberChain, attributeNode.text],
        };
      }

      return {
        baseExpression: objectNode.text,
        memberChain: [attributeNode.text],
      };
    }
  }

  return {
    baseExpression: node.text,
    memberChain: [],
  };
}

/**
 * Extract call arguments
 */
function extractArguments(callNode: Parser.SyntaxNode): string[] {
  return extractArgumentDetails(callNode).map((arg) => arg.name ? `${arg.name}=${arg.value.text}` : arg.value.text);
}

function extractArgumentDetails(callNode: Parser.SyntaxNode): CallArgumentInfo[] {
  const args: CallArgumentInfo[] = [];
  const argList = callNode.childForFieldName('arguments');

  if (argList) {
    for (const child of argList.children) {
      if (
        child.type !== '(' &&
        child.type !== ')' &&
        child.type !== ',' &&
        child.type !== 'comment'
      ) {
        if (child.type === 'keyword_argument') {
          const nameNode = child.childForFieldName('name');
          const valueNode = child.childForFieldName('value');

          if (valueNode) {
            args.push({
              name: nameNode?.text,
              value: summarizeExpression(valueNode),
            });
          }

          continue;
        }

        args.push({ value: summarizeExpression(child) });
      }
    }
  }

  return args;
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function uniqueMappingReferences(values: Array<{ key: string; reference: string }>): Array<{ key: string; reference: string }> {
  const seen = new Set<string>();
  const result: Array<{ key: string; reference: string }> = [];

  for (const value of values) {
    const key = `${value.key}:${value.reference}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push(value);
  }

  return result;
}

function summarizeExpression(node: Parser.SyntaxNode): ExpressionSummary {
  const empty = (): ExpressionSummary => ({
    text: node.text,
    references: [],
    stringLiterals: [],
    mappingReferences: [],
  });

  if (node.type === 'identifier' || node.type === 'attribute') {
    return {
      text: node.text,
      references: [node.text],
      stringLiterals: [],
      mappingReferences: [],
    };
  }

  if (node.type === 'string') {
    return {
      text: node.text,
      references: [],
      stringLiterals: [extractStringValue(node) || node.text],
      mappingReferences: [],
    };
  }

  if (node.type === 'call') {
    const calleeInfo = extractCalleeInfo(node);
    const argumentDetails = extractArgumentDetails(node);

    return {
      text: node.text,
      references: uniqueStrings(argumentDetails.flatMap((arg) => arg.value.references)),
      stringLiterals: uniqueStrings(argumentDetails.flatMap((arg) => arg.value.stringLiterals)),
      mappingReferences: uniqueMappingReferences(argumentDetails.flatMap((arg) => arg.value.mappingReferences)),
      callCallee: calleeInfo.callee,
    };
  }

  if (
    node.type === 'list' ||
    node.type === 'tuple' ||
    node.type === 'set' ||
    node.type === 'parenthesized_expression'
  ) {
    const childSummaries = node.children
      .filter((child) => !['[', ']', '(', ')', '{', '}', ',', 'comment'].includes(child.type))
      .map((child) => summarizeExpression(child));

    return {
      text: node.text,
      references: uniqueStrings(childSummaries.flatMap((child) => child.references)),
      stringLiterals: uniqueStrings(childSummaries.flatMap((child) => child.stringLiterals)),
      mappingReferences: uniqueMappingReferences(childSummaries.flatMap((child) => child.mappingReferences)),
      callCallee: childSummaries.find((child) => child.callCallee)?.callCallee,
    };
  }

  if (node.type === 'dictionary') {
    const summary = empty();

    for (const child of node.children) {
      if (child.type !== 'pair') {
        continue;
      }

      const pairChildren = child.children.filter((pairChild) => pairChild.type !== ':');
      if (pairChildren.length < 2) {
        continue;
      }

      const keyNode = pairChildren[0];
      const valueNode = pairChildren[1];
      const valueSummary = summarizeExpression(valueNode);

      summary.references.push(...valueSummary.references);
      summary.stringLiterals.push(...valueSummary.stringLiterals);
      summary.mappingReferences.push(...valueSummary.mappingReferences);

      const key = extractStringValue(keyNode);
      if (key && valueSummary.references.length === 1) {
        summary.mappingReferences.push({
          key,
          reference: valueSummary.references[0],
        });
      }
    }

    summary.references = uniqueStrings(summary.references);
    summary.stringLiterals = uniqueStrings(summary.stringLiterals);
    summary.mappingReferences = uniqueMappingReferences(summary.mappingReferences);
    return summary;
  }

  if (node.type === 'binary_operator') {
    const childSummaries = node.children
      .filter((child) => child.type !== '+' && child.type !== 'comment')
      .map((child) => summarizeExpression(child));

    return {
      text: node.text,
      references: uniqueStrings(childSummaries.flatMap((child) => child.references)),
      stringLiterals: uniqueStrings(childSummaries.flatMap((child) => child.stringLiterals)),
      mappingReferences: uniqueMappingReferences(childSummaries.flatMap((child) => child.mappingReferences)),
      callCallee: childSummaries.find((child) => child.callCallee)?.callCallee,
    };
  }

  const nestedChildren = node.children.filter((child) => child.type !== 'comment');
  if (nestedChildren.length === 0) {
    return empty();
  }

  const nestedSummaries = nestedChildren.map((child) => summarizeExpression(child));
  return {
    text: node.text,
    references: uniqueStrings(nestedSummaries.flatMap((child) => child.references)),
    stringLiterals: uniqueStrings(nestedSummaries.flatMap((child) => child.stringLiterals)),
    mappingReferences: uniqueMappingReferences(nestedSummaries.flatMap((child) => child.mappingReferences)),
    callCallee: nestedSummaries.find((child) => child.callCallee)?.callCallee,
  };
}

function extractAssignmentTarget(node: Parser.SyntaxNode | null): string | null {
  if (!node) {
    return null;
  }

  if (node.type === 'identifier' || node.type === 'attribute') {
    return node.text;
  }

  return null;
}

/**
 * Find enclosing function for a node
 */
function findEnclosingFunction(
  node: Parser.SyntaxNode
): Parser.SyntaxNode | null {
  let current = node.parent;
  while (current) {
    if (
      current.type === 'function_definition' ||
      current.type === 'async_function_definition'
    ) {
      return current;
    }
    current = current.parent;
  }
  return null;
}

/**
 * Find enclosing class for a node
 */
function findEnclosingClass(
  node: Parser.SyntaxNode
): Parser.SyntaxNode | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'class_definition') {
      return current;
    }
    current = current.parent;
  }
  return null;
}

/**
 * Recursively find all nodes of given types
 */
function findAllNodes(
  node: Parser.SyntaxNode,
  types: Set<string>
): Parser.SyntaxNode[] {
  const results: Parser.SyntaxNode[] = [];

  if (types.has(node.type)) {
    results.push(node);
  }

  for (const child of node.children) {
    results.push(...findAllNodes(child, types));
  }

  return results;
}

/**
 * Check if a node is inside a conditional branch that can PREVENT execution.
 *
 * IMPORTANT: try/except is NOT a gate mechanism!
 * A try/except doesn't prevent the dangerous operation from running - it handles
 * exceptions AFTER the operation fails. Per the AFB specification:
 * "A try/except around the dangerous operation is NOT a gate."
 *
 * Only if statements and early returns can actually prevent execution.
 */
function isInsideConditional(node: Parser.SyntaxNode): boolean {
  let current = node.parent;
  while (current) {
    // Only if/elif branches can actually prevent execution
    // try/except/with do NOT prevent execution - they handle it afterwards
    if (
      current.type === 'if_statement' ||
      current.type === 'elif_clause'
    ) {
      return true;
    }
    // Note: else_clause removed - an else branch always runs when condition is false,
    // it doesn't conditionally prevent execution based on input
    // Note: try_statement/except_clause/with_statement removed - they don't prevent execution

    // Stop at function boundary
    if (
      current.type === 'function_definition' ||
      current.type === 'async_function_definition'
    ) {
      break;
    }
    current = current.parent;
  }
  return false;
}

/**
 * Extract exception type from a raise statement
 */
function extractRaiseType(raiseNode: Parser.SyntaxNode): string | null {
  // raise ExceptionType(...) or raise ExceptionType
  for (const child of raiseNode.children) {
    if (child.type === 'call') {
      const funcNode = child.childForFieldName('function');
      if (funcNode) {
        return funcNode.text;
      }
    }
    if (child.type === 'identifier') {
      return child.text;
    }
    if (child.type === 'attribute') {
      return child.text;
    }
  }
  return null;
}

/**
 * Check if an if statement condition uses function parameters
 */
function conditionUsesParameters(
  ifNode: Parser.SyntaxNode,
  paramNames: Set<string>
): boolean {
  const condition = ifNode.childForFieldName('condition');
  if (!condition) return false;

  // Find all identifiers in the condition
  const identifiers = findAllNodes(condition, new Set(['identifier']));
  for (const id of identifiers) {
    if (paramNames.has(id.text)) {
      return true;
    }
  }
  return false;
}

/**
 * Extract parameter names from a function definition
 */
function extractParameterNames(funcNode: Parser.SyntaxNode): Set<string> {
  const params = new Set<string>();
  const parameters = funcNode.childForFieldName('parameters');
  if (!parameters) return params;

  for (const child of parameters.children) {
    if (child.type === 'identifier') {
      params.add(child.text);
    } else if (child.type === 'typed_parameter' || child.type === 'default_parameter') {
      const nameNode = child.childForFieldName('name');
      if (nameNode) {
        params.add(nameNode.text);
      }
    }
  }
  return params;
}

/**
 * Analyze a function body for control flow patterns that indicate policy gate behavior.
 *
 * A policy gate is STRUCTURAL, not nominal. It must have:
 * 1. Conditional branches that can prevent execution from continuing
 * 2. These branches should be able to raise exceptions or return early
 * 3. The conditions should be based on the input (parameters)
 *
 * A function named "check_permission" that always returns True is NOT a gate.
 * A function named "process_data" that raises PermissionError conditionally IS a gate.
 */
function analyzeControlFlow(funcNode: Parser.SyntaxNode): ControlFlowInfo {
  const body = funcNode.childForFieldName('body');
  if (!body) {
    return {
      hasRaise: false,
      hasConditionalRaise: false,
      hasConditionalReturn: false,
      raiseTypes: [],
      hasConditionalBranches: false,
      checksParameters: false,
    };
  }

  // Get function parameters
  const paramNames = extractParameterNames(funcNode);

  // Find all raise statements in the function body
  const raiseNodes = findAllNodes(body, new Set(['raise_statement']));
  const hasRaise = raiseNodes.length > 0;

  // Check if any raises are inside conditional branches
  let hasConditionalRaise = false;
  const raiseTypes: string[] = [];
  for (const raise of raiseNodes) {
    const type = extractRaiseType(raise);
    if (type && !raiseTypes.includes(type)) {
      raiseTypes.push(type);
    }
    if (isInsideConditional(raise)) {
      hasConditionalRaise = true;
    }
  }

  // Find all return statements and check if any are conditional
  const returnNodes = findAllNodes(body, new Set(['return_statement']));
  let hasConditionalReturn = false;
  for (const ret of returnNodes) {
    if (isInsideConditional(ret)) {
      hasConditionalReturn = true;
      break;
    }
  }

  // Find all if statements
  const ifNodes = findAllNodes(body, new Set(['if_statement']));
  const hasConditionalBranches = ifNodes.length > 0;

  // Check if any conditions use parameters
  let checksParameters = false;
  for (const ifNode of ifNodes) {
    if (conditionUsesParameters(ifNode, paramNames)) {
      checksParameters = true;
      break;
    }
  }

  return {
    hasRaise,
    hasConditionalRaise,
    hasConditionalReturn,
    raiseTypes,
    hasConditionalBranches,
    checksParameters,
  };
}

/**
 * Detect if a function is a decorator and analyze its gate behavior.
 *
 * A decorator is identified by:
 * 1. It returns a function (wrapper pattern)
 * 2. The wrapper wraps the original function
 *
 * A decorator is a STRUCTURAL GATE if the wrapper function:
 * 1. Has conditional paths that can raise exceptions
 * 2. Has conditional paths that can return early (before calling the wrapped function)
 * 3. Checks some condition (like permissions) before proceeding
 */
function analyzeDecoratorFunction(funcNode: Parser.SyntaxNode): DecoratorDef | null {
  const name = funcNode.childForFieldName('name')?.text || '';
  const body = funcNode.childForFieldName('body');
  if (!body) return null;

  // Look for a nested function definition (the wrapper)
  const nestedFuncs = findAllNodes(body, new Set(['function_definition', 'async_function_definition']));

  // A decorator typically has one inner wrapper function
  if (nestedFuncs.length === 0) return null;

  // Check if the function returns the wrapper
  const returnStmts = findAllNodes(body, new Set(['return_statement']));
  let returnsWrapper = false;
  for (const ret of returnStmts) {
    const returnValue = ret.children.find(c => c.type !== 'return');
    if (returnValue) {
      // Check if it returns one of the nested function names
      for (const nestedFunc of nestedFuncs) {
        const nestedName = nestedFunc.childForFieldName('name')?.text;
        if (nestedName && returnValue.text.includes(nestedName)) {
          returnsWrapper = true;
          break;
        }
      }
    }
  }

  if (!returnsWrapper) return null;

  // This looks like a decorator! Now analyze the wrapper for gate behavior
  // The wrapper is the innermost function that gets executed when the decorated function is called
  const wrapperFunc = nestedFuncs[nestedFuncs.length - 1]; // Usually the last/deepest one is the actual wrapper
  const wrapperControlFlow = analyzeControlFlow(wrapperFunc);

  // A decorator is a structural gate if the wrapper can prevent execution
  const isStructuralGate = (
    wrapperControlFlow.hasConditionalRaise ||
    wrapperControlFlow.hasConditionalReturn
  ) && wrapperControlFlow.hasConditionalBranches;

  return {
    name,
    startLine: funcNode.startPosition.row + 1,
    isStructuralGate,
    controlFlow: wrapperControlFlow,
  };
}

/**
 * Check if decorators on a function include any structural gates.
 *
 * Uses a map of decorator definitions from the same file
 * to determine if decorators structurally act as gates.
 */
function checkDecoratorGates(
  decorators: string[],
  decoratorDefs: Map<string, DecoratorDef>
): { hasGate: boolean; gateDecorators: string[] } {
  const gateDecorators: string[] = [];

  for (const dec of decorators) {
    // Extract the decorator name (without arguments)
    const decoratorName = dec.split('(')[0].trim();

    // Check if we have the decorator definition and it's a gate
    const def = decoratorDefs.get(decoratorName);
    if (def?.isStructuralGate) {
      gateDecorators.push(decoratorName);
    }
  }

  return {
    hasGate: gateDecorators.length > 0,
    gateDecorators,
  };
}

/**
 * Extract string value from a string literal node.
 * Handles both single and double quoted strings.
 */
function extractStringValue(node: Parser.SyntaxNode): string | null {
  if (node.type === 'string') {
    const text = node.text;
    // Handle various string formats: "str", 'str', """str""", '''str'''
    if (text.startsWith('"""') && text.endsWith('"""')) {
      return text.slice(3, -3);
    }
    if (text.startsWith("'''") && text.endsWith("'''")) {
      return text.slice(3, -3);
    }
    if ((text.startsWith('"') && text.endsWith('"')) ||
        (text.startsWith("'") && text.endsWith("'"))) {
      return text.slice(1, -1);
    }
  }
  return null;
}

/**
 * Extract a nested string value from a dictionary for a specific key.
 * Used to find "name" inside {"function": {"name": "..."}}
 */
function extractNestedDictStringValue(dictNode: Parser.SyntaxNode, targetKey: string): string | null {
  for (const child of dictNode.children) {
    if (child.type === 'pair') {
      const keyNode = child.children.find(c => c.type === 'string');
      const valueNode = child.children.find(c => c.type === 'string' && c !== keyNode);

      if (keyNode && extractStringValue(keyNode) === targetKey && valueNode) {
        return extractStringValue(valueNode);
      }
    }
  }
  return null;
}

/**
 * Check if a dictionary node matches OpenAI tool schema pattern:
 * {"type": "function", "function": {"name": "tool_name", ...}}
 * Returns the tool name if found, null otherwise.
 */
function extractToolNameFromOpenAISchema(dictNode: Parser.SyntaxNode): string | null {
  let hasTypeFunctionPair = false;
  let toolName: string | null = null;

  for (const child of dictNode.children) {
    if (child.type === 'pair') {
      // Get key and value - pair structure: key, ':', value
      const children = child.children.filter(c => c.type !== ':');
      if (children.length < 2) continue;

      const keyNode = children[0];
      const valueNode = children[1];

      const keyText = extractStringValue(keyNode);

      // Check for "type": "function"
      if (keyText === 'type') {
        const valueText = extractStringValue(valueNode);
        if (valueText === 'function') {
          hasTypeFunctionPair = true;
        }
      }

      // Check for "function": {...} containing "name"
      if (keyText === 'function' && valueNode.type === 'dictionary') {
        toolName = extractNestedDictStringValue(valueNode, 'name');
      }
    }
  }

  return hasTypeFunctionPair && toolName ? toolName : null;
}

/**
 * Extract OpenAI tool schemas from an assignment node.
 * Detects: TOOLS = [{"type": "function", "function": {"name": "calculate"}}]
 */
function extractOpenAIToolSchema(assignmentNode: Parser.SyntaxNode): OpenAIToolSchema | null {
  // Handle both simple assignment and augmented assignment
  let leftNode: Parser.SyntaxNode | null = null;
  let rightNode: Parser.SyntaxNode | null = null;

  if (assignmentNode.type === 'assignment') {
    leftNode = assignmentNode.childForFieldName('left');
    rightNode = assignmentNode.childForFieldName('right');
  } else if (assignmentNode.type === 'expression_statement') {
    // Find assignment within expression statement
    const assignment = assignmentNode.children.find(c => c.type === 'assignment');
    if (assignment) {
      leftNode = assignment.childForFieldName('left');
      rightNode = assignment.childForFieldName('right');
    }
  }

  if (!leftNode || !rightNode) return null;

  // Get variable name - handle both identifier and attribute (e.g., self.tools)
  let variableName = '';
  if (leftNode.type === 'identifier') {
    variableName = leftNode.text;
  } else if (leftNode.type === 'attribute') {
    variableName = leftNode.text;
  } else {
    return null;
  }

  // Check if right side is a list
  if (rightNode.type !== 'list') return null;

  const toolNames: string[] = [];

  // Iterate through list items looking for OpenAI schema dicts
  for (const item of rightNode.children) {
    if (item.type === 'dictionary') {
      const toolName = extractToolNameFromOpenAISchema(item);
      if (toolName) {
        toolNames.push(toolName);
      }
    }
  }

  if (toolNames.length === 0) return null;

  return {
    variableName,
    startLine: assignmentNode.startPosition.row + 1,
    toolNames,
  };
}

/**
 * Extract function dispatch mapping from an assignment node.
 * Detects: tool_functions = {"calculate": calculate, "delete": delete_file}
 */
function extractDispatchMapping(assignmentNode: Parser.SyntaxNode): FunctionDispatchMapping | null {
  let leftNode: Parser.SyntaxNode | null = null;
  let rightNode: Parser.SyntaxNode | null = null;

  if (assignmentNode.type === 'assignment') {
    leftNode = assignmentNode.childForFieldName('left');
    rightNode = assignmentNode.childForFieldName('right');
  } else if (assignmentNode.type === 'expression_statement') {
    const assignment = assignmentNode.children.find(c => c.type === 'assignment');
    if (assignment) {
      leftNode = assignment.childForFieldName('left');
      rightNode = assignment.childForFieldName('right');
    }
  }

  if (!leftNode || !rightNode) return null;

  // Get variable name
  let variableName = '';
  if (leftNode.type === 'identifier') {
    variableName = leftNode.text;
  } else if (leftNode.type === 'attribute') {
    variableName = leftNode.text;
  } else {
    return null;
  }

  // Check if right side is a dictionary
  if (rightNode.type !== 'dictionary') return null;

  const mappings = new Map<string, string>();

  for (const child of rightNode.children) {
    if (child.type === 'pair') {
      // Get key and value
      const children = child.children.filter(c => c.type !== ':');
      if (children.length < 2) continue;

      const keyNode = children[0];
      const valueNode = children[1];

      // Key must be a string literal
      const keyStr = extractStringValue(keyNode);
      if (!keyStr) continue;

      // Value must be an identifier (function reference)
      if (valueNode.type === 'identifier') {
        mappings.set(keyStr, valueNode.text);
      }
    }
  }

  if (mappings.size === 0) return null;

  return {
    variableName,
    startLine: assignmentNode.startPosition.row + 1,
    mappings,
  };
}

/**
 * Parse a Python source file and extract structural information
 */
export function parsePythonSource(sourceCode: string): ParsedPythonFile {
  if (!parser || !pythonLanguage) {
    return {
      functions: [],
      classes: [],
      calls: [],
      imports: [],
      assignments: [],
      decoratorDefs: [],
      openaiToolSchemas: [],
      dispatchMappings: [],
      success: false,
      error: 'Parser not initialized. Call initParser() first.',
    };
  }

  try {
    const tree = parser.parse(sourceCode);
    const root = tree.rootNode;

    if (root.hasError) {
      return {
        functions: [],
        classes: [],
        calls: [],
        imports: [],
        assignments: [],
        decoratorDefs: [],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: false,
        error: 'Tree-sitter produced a syntax-error parse tree.',
      };
    }

    const lines = sourceCode.split('\n');

    const functions: FunctionDef[] = [];
    const classes: ClassDef[] = [];
    const calls: CallSite[] = [];
    const imports: ImportInfo[] = [];
    const assignments: AssignmentInfo[] = [];
    const decoratorDefs: DecoratorDef[] = [];

    // Find all decorated definitions, function definitions, and class definitions
    const decoratedDefs = findAllNodes(root, new Set(['decorated_definition']));
    const funcDefs = findAllNodes(
      root,
      new Set(['function_definition', 'async_function_definition'])
    );
    const classDefs = findAllNodes(root, new Set(['class_definition']));
    const callNodes = findAllNodes(root, new Set(['call']));
    const importNodes = findAllNodes(
      root,
      new Set(['import_statement', 'import_from_statement'])
    );
    const assignmentNodes = findAllNodes(root, new Set(['assignment']));

    // First pass: identify decorator definitions
    // A decorator is a function that returns a wrapper function
    const decoratorDefMap = new Map<string, DecoratorDef>();
    for (const funcDef of funcDefs) {
      const decDef = analyzeDecoratorFunction(funcDef);
      if (decDef) {
        decoratorDefs.push(decDef);
        decoratorDefMap.set(decDef.name, decDef);
      }
    }

    // Process decorated definitions
    for (const decDef of decoratedDefs) {
      const decorators = extractDecorators(decDef);
      const innerDef = decDef.children.find(
        (c) =>
          c.type === 'function_definition' ||
          c.type === 'async_function_definition' ||
          c.type === 'class_definition'
      );

      if (!innerDef) continue;

      // Check for decorator-based gates
      const decoratorGateInfo = checkDecoratorGates(decorators, decoratorDefMap);

      if (
        innerDef.type === 'function_definition' ||
        innerDef.type === 'async_function_definition'
      ) {
        const enclosingClass = findEnclosingClass(decDef);
        functions.push({
          name: extractFunctionName(innerDef),
          decorators,
          startLine: decDef.startPosition.row + 1,
          endLine: decDef.endPosition.row + 1,
          body: [],
          isAsync: innerDef.type === 'async_function_definition',
          isMethod: !!enclosingClass,
          className: enclosingClass
            ? extractClassName(enclosingClass)
            : undefined,
          parameters: Array.from(extractParameterNames(innerDef)),
          controlFlow: analyzeControlFlow(innerDef),
          hasDecoratorGate: decoratorGateInfo.hasGate,
          gateDecorators: decoratorGateInfo.gateDecorators,
        });
      } else if (innerDef.type === 'class_definition') {
        const classDef: ClassDef = {
          name: extractClassName(innerDef),
          bases: extractBases(innerDef),
          startLine: decDef.startPosition.row + 1,
          endLine: decDef.endPosition.row + 1,
          methods: [],
          decorators,
        };

        // Extract methods from class body
        const body = innerDef.childForFieldName('body');
        if (body) {
          const methodNodes = findAllNodes(
            body,
            new Set(['function_definition', 'async_function_definition'])
          );
          for (const method of methodNodes) {
            const methodEnclosingClass = findEnclosingClass(method);
            if (
              methodEnclosingClass &&
              extractClassName(methodEnclosingClass) === classDef.name
            ) {
              classDef.methods.push({
                name: extractFunctionName(method),
                decorators: [],
                startLine: method.startPosition.row + 1,
                endLine: method.endPosition.row + 1,
                body: [],
                isAsync: method.type === 'async_function_definition',
                isMethod: true,
                className: classDef.name,
                parameters: Array.from(extractParameterNames(method)),
                controlFlow: analyzeControlFlow(method),
              });
            }
          }
        }

        classes.push(classDef);
      }
    }

    // Process standalone function definitions (not already captured via decorators)
    const decoratedFuncLines = new Set(functions.map((f) => f.startLine));
    for (const funcDef of funcDefs) {
      const line = funcDef.startPosition.row + 1;
      // Skip if this function is part of a decorated definition we already processed
      if (decoratedFuncLines.has(line) || decoratedFuncLines.has(line - 1)) {
        continue;
      }

      // Skip if parent is decorated_definition
      if (funcDef.parent?.type === 'decorated_definition') {
        continue;
      }

      const enclosingClass = findEnclosingClass(funcDef);
      functions.push({
        name: extractFunctionName(funcDef),
        decorators: [],
        startLine: line,
        endLine: funcDef.endPosition.row + 1,
        body: [],
        isAsync: funcDef.type === 'async_function_definition',
        isMethod: !!enclosingClass,
        className: enclosingClass ? extractClassName(enclosingClass) : undefined,
        parameters: Array.from(extractParameterNames(funcDef)),
        controlFlow: analyzeControlFlow(funcDef),
      });
    }

    // Process standalone class definitions
    const decoratedClassLines = new Set(classes.map((c) => c.startLine));
    for (const classDef of classDefs) {
      const line = classDef.startPosition.row + 1;
      if (decoratedClassLines.has(line) || decoratedClassLines.has(line - 1)) {
        continue;
      }

      if (classDef.parent?.type === 'decorated_definition') {
        continue;
      }

      const def: ClassDef = {
        name: extractClassName(classDef),
        bases: extractBases(classDef),
        startLine: line,
        endLine: classDef.endPosition.row + 1,
        methods: [],
        decorators: [],
      };

      const body = classDef.childForFieldName('body');
      if (body) {
        const methodNodes = findAllNodes(
          body,
          new Set(['function_definition', 'async_function_definition'])
        );
        for (const method of methodNodes) {
          def.methods.push({
            name: extractFunctionName(method),
            decorators: [],
            startLine: method.startPosition.row + 1,
            endLine: method.endPosition.row + 1,
            body: [],
            isAsync: method.type === 'async_function_definition',
            isMethod: true,
            className: def.name,
            parameters: Array.from(extractParameterNames(method)),
            controlFlow: analyzeControlFlow(method),
          });
        }
      }

      classes.push(def);
    }

    // Process all function calls
    for (const callNode of callNodes) {
      const calleeInfo = extractCalleeInfo(callNode);
      const callee = calleeInfo.callee;
      if (!callee) continue;

      const enclosingFunc = findEnclosingFunction(callNode);
      const enclosingClass = findEnclosingClass(callNode);

      const startLine = callNode.startPosition.row + 1;
      const snippet = lines[startLine - 1]?.trim() || callNode.text;

      calls.push({
        callee,
        startLine,
        startColumn: callNode.startPosition.column + 1,
        codeSnippet: snippet.length > 100 ? snippet.slice(0, 100) + '...' : snippet,
        enclosingFunction: enclosingFunc
          ? extractFunctionName(enclosingFunc)
          : undefined,
        enclosingClass: enclosingClass
          ? extractClassName(enclosingClass)
          : undefined,
        arguments: extractArguments(callNode),
        argumentDetails: extractArgumentDetails(callNode),
        baseExpression: calleeInfo.baseExpression,
        memberChain: calleeInfo.memberChain,
      });
    }

    for (const assignmentNode of assignmentNodes) {
      const leftNode = assignmentNode.childForFieldName('left');
      const rightNode = assignmentNode.childForFieldName('right');
      const target = extractAssignmentTarget(leftNode);

      if (!target || !rightNode) {
        continue;
      }

      const enclosingFunc = findEnclosingFunction(assignmentNode);
      const enclosingClass = findEnclosingClass(assignmentNode);

      assignments.push({
        target,
        value: summarizeExpression(rightNode),
        startLine: assignmentNode.startPosition.row + 1,
        enclosingFunction: enclosingFunc ? extractFunctionName(enclosingFunc) : undefined,
        enclosingClass: enclosingClass ? extractClassName(enclosingClass) : undefined,
      });
    }

    // Process imports
    for (const importNode of importNodes) {
      if (importNode.type === 'import_statement') {
        // import module
        const nameNode = importNode.childForFieldName('name');
        if (nameNode) {
          imports.push({
            module: nameNode.text,
            names: [{ name: nameNode.text }],
            isFrom: false,
          });
        }
      } else if (importNode.type === 'import_from_statement') {
        // from module import name
        const moduleNode = importNode.childForFieldName('module_name');
        const names: { name: string; alias?: string }[] = [];

        for (const child of importNode.children) {
          if (child.type === 'dotted_name' && child !== moduleNode) {
            names.push({ name: child.text });
          } else if (child.type === 'aliased_import') {
            const nameChild = child.childForFieldName('name');
            const aliasChild = child.childForFieldName('alias');
            if (nameChild) {
              names.push({
                name: nameChild.text,
                alias: aliasChild?.text,
              });
            }
          }
        }

        imports.push({
          module: moduleNode?.text || '',
          names,
          isFrom: true,
        });
      }
    }

    // Process assignments for OpenAI tool schema detection
    // Find all expression_statement nodes that contain assignments
    const expressionStatements = findAllNodes(root, new Set(['expression_statement']));
    const openaiToolSchemas: OpenAIToolSchema[] = [];
    const dispatchMappings: FunctionDispatchMapping[] = [];

    for (const exprStmt of expressionStatements) {
      // Try to extract OpenAI tool schema
      const schema = extractOpenAIToolSchema(exprStmt);
      if (schema) {
        openaiToolSchemas.push(schema);
      }

      // Try to extract dispatch mapping
      const mapping = extractDispatchMapping(exprStmt);
      if (mapping) {
        dispatchMappings.push(mapping);
      }
    }

    return {
      functions,
      classes,
      calls,
      imports,
      assignments,
      decoratorDefs,
      openaiToolSchemas,
      dispatchMappings,
      success: true,
    };
  } catch (error) {
    return {
      functions: [],
      classes: [],
      calls: [],
      imports: [],
      assignments: [],
      decoratorDefs: [],
      openaiToolSchemas: [],
      dispatchMappings: [],
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
