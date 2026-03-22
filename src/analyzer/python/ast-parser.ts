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
  /** Decorator functions defined in this file (for cross-file resolution) */
  decoratorDefs: DecoratorDef[];
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

  // Try dist first, then fall back to source wasm
  let wasmPath = path.join(__dirname, '../../../wasm/tree-sitter-python.wasm');
  if (!fs.existsSync(wasmPath)) {
    wasmPath = path.join(process.cwd(), 'wasm/tree-sitter-python.wasm');
  }
  if (!fs.existsSync(wasmPath)) {
    throw new Error(`Python WASM not found at ${wasmPath}`);
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
  const funcNode = callNode.childForFieldName('function');
  if (!funcNode) return '';

  // Handle attribute access: obj.method()
  if (funcNode.type === 'attribute') {
    return funcNode.text;
  }

  // Handle simple identifier: func()
  if (funcNode.type === 'identifier') {
    return funcNode.text;
  }

  // Handle subscript: arr[0]()
  if (funcNode.type === 'subscript') {
    return funcNode.text;
  }

  return funcNode.text;
}

/**
 * Extract call arguments
 */
function extractArguments(callNode: Parser.SyntaxNode): string[] {
  const args: string[] = [];
  const argList = callNode.childForFieldName('arguments');

  if (argList) {
    for (const child of argList.children) {
      if (
        child.type !== '(' &&
        child.type !== ')' &&
        child.type !== ',' &&
        child.type !== 'comment'
      ) {
        args.push(child.text);
      }
    }
  }

  return args;
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
 * Check if a node is inside a conditional branch (if statement, try block, etc.)
 */
function isInsideConditional(node: Parser.SyntaxNode): boolean {
  let current = node.parent;
  while (current) {
    if (
      current.type === 'if_statement' ||
      current.type === 'elif_clause' ||
      current.type === 'else_clause' ||
      current.type === 'try_statement' ||
      current.type === 'except_clause' ||
      current.type === 'with_statement'
    ) {
      return true;
    }
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
 * Parse a Python source file and extract structural information
 */
export function parsePythonSource(sourceCode: string): ParsedPythonFile {
  if (!parser || !pythonLanguage) {
    return {
      functions: [],
      classes: [],
      calls: [],
      imports: [],
      decoratorDefs: [],
      success: false,
      error: 'Parser not initialized. Call initParser() first.',
    };
  }

  try {
    const tree = parser.parse(sourceCode);
    const root = tree.rootNode;
    const lines = sourceCode.split('\n');

    const functions: FunctionDef[] = [];
    const classes: ClassDef[] = [];
    const calls: CallSite[] = [];
    const imports: ImportInfo[] = [];
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
            controlFlow: analyzeControlFlow(method),
          });
        }
      }

      classes.push(def);
    }

    // Process all function calls
    for (const callNode of callNodes) {
      const callee = extractCallee(callNode);
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

    return {
      functions,
      classes,
      calls,
      imports,
      decoratorDefs,
      success: true,
    };
  } catch (error) {
    return {
      functions: [],
      classes: [],
      calls: [],
      imports: [],
      decoratorDefs: [],
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
