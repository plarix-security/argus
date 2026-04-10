/**
 * TypeScript/JavaScript AST Parser
 *
 * Parses TypeScript and JavaScript source code using tree-sitter to extract:
 * - Function and method definitions
 * - Class definitions
 * - Function calls and method invocations
 * - Import/require statements
 * - Variable assignments
 * - Return statements
 *
 * This parser mirrors the Python AST parser but adapted for TS/JS syntax.
 */

import Parser from 'web-tree-sitter';
import * as path from 'path';

// Shared types matching Python parser interface
export interface ASTNode {
  type: string;
  startLine: number;
  endLine: number;
  text: string;
}

export interface ControlFlowInfo {
  hasRaise: boolean;
  hasConditionalRaise: boolean;
  hasConditionalReturn: boolean;
  checksParameters: boolean;
  raiseTypes: string[];
}

export interface FunctionDef {
  name: string;
  parameters: string[];
  decorators: string[];
  isAsync: boolean;
  isArrow: boolean;
  isMethod: boolean;
  className?: string;
  startLine: number;
  endLine: number;
  bodyNode?: ASTNode;
  controlFlow?: ControlFlowInfo;
  /** Whether this function is exported */
  isExported?: boolean;
  /** How this function is exported */
  exportKind?: 'named' | 'default' | 'commonjs';
}

export interface ClassDef {
  name: string;
  extends: string[];
  methods: string[];
  startLine: number;
  endLine: number;
}

export interface CallSite {
  callee: string;
  line: number;
  column: number;
  enclosingFunction?: string;
  enclosingClass?: string;
  memberChain: string[];
  baseExpression?: string;
  arguments: string[];
  argumentDetails: CallArgumentInfo[];
}

export interface CallArgumentInfo {
  value: string;
  isSpread: boolean;
  isIdentifier: boolean;
  identifierName?: string;
}

export interface ArrayElement {
  text: string;
  objectProperties?: ObjectProperty[];
}

export interface ObjectProperty {
  key: string;
  value: string;
  valueType: 'string' | 'number' | 'boolean' | 'identifier' | 'object' | 'array' | 'function' | 'unknown';
  stringValue?: string; // For string literals, the unquoted value
  nestedProperties?: ObjectProperty[]; // For nested objects
}

export interface AssignmentInfo {
  target: string;
  value: string;
  line: number;
  enclosingFunction?: string;
  typeAnnotation?: string;
  assertedType?: string;
  // Structured data extracted from AST (not regex)
  isObjectLiteral?: boolean;
  isArrayLiteral?: boolean;
  objectProperties?: ObjectProperty[];
  arrayElements?: ArrayElement[];
}

export interface ReturnInfo {
  value: string;
  line: number;
  enclosingFunction?: string;
}

export interface ImportInfo {
  module: string;
  names: string[];
  isDefault: boolean;
  isNamespace: boolean;
  alias?: string;
  line: number;
}

export interface ParsedTypeScriptFile {
  success: boolean;
  error?: string;
  functions: FunctionDef[];
  classes: ClassDef[];
  calls: CallSite[];
  imports: ImportInfo[];
  assignments: AssignmentInfo[];
  returns: ReturnInfo[];
  /** Map of exported symbol names to their export kind */
  exports?: Map<string, 'named' | 'default' | 'commonjs'>;
}

// Parser state
let parser: Parser | null = null;
let tsParser: Parser | null = null;
let tsxParser: Parser | null = null;

/**
 * Initialize tree-sitter parsers for TypeScript and TSX
 */
export async function initParser(): Promise<void> {
  if (parser !== null) {
    return; // Already initialized
  }

  try {
    await Parser.init();

    // TypeScript WASM candidates
    const tsCandidates = [
      path.join(__dirname, '../../../wasm/tree-sitter-typescript.wasm'),     // from dist/analyzer/typescript
      path.join(__dirname, '../../wasm/tree-sitter-typescript.wasm'),        // from src/analyzer/typescript (dev)
      path.join(process.cwd(), 'wasm/tree-sitter-typescript.wasm'),
      path.join(process.cwd(), 'node_modules/tree-sitter-wasms/out/tree-sitter-typescript.wasm'),
    ];

    // TSX WASM candidates
    const tsxCandidates = [
      path.join(__dirname, '../../../wasm/tree-sitter-tsx.wasm'),
      path.join(__dirname, '../../wasm/tree-sitter-tsx.wasm'),
      path.join(process.cwd(), 'wasm/tree-sitter-tsx.wasm'),
      path.join(process.cwd(), 'node_modules/tree-sitter-wasms/out/tree-sitter-tsx.wasm'),
    ];

    // Find TypeScript WASM
    let tsWasmPath: string | null = null;
    for (const candidate of tsCandidates) {
      try {
        const fs = await import('fs');
        if (fs.existsSync(candidate)) {
          tsWasmPath = candidate;
          break;
        }
      } catch {
        continue;
      }
    }

    if (!tsWasmPath) {
      throw new Error('Could not find tree-sitter-typescript.wasm');
    }

    // Find TSX WASM
    let tsxWasmPath: string | null = null;
    for (const candidate of tsxCandidates) {
      try {
        const fs = await import('fs');
        if (fs.existsSync(candidate)) {
          tsxWasmPath = candidate;
          break;
        }
      } catch {
        continue;
      }
    }

    if (!tsxWasmPath) {
      throw new Error('Could not find tree-sitter-tsx.wasm');
    }

    // Initialize TypeScript parser
    tsParser = new Parser();
    const tsLang = await Parser.Language.load(tsWasmPath);
    tsParser.setLanguage(tsLang);

    // Initialize TSX parser
    tsxParser = new Parser();
    const tsxLang = await Parser.Language.load(tsxWasmPath);
    tsxParser.setLanguage(tsxLang);

    parser = tsParser; // Default to TS parser
  } catch (error) {
    throw new Error(`Failed to initialize TypeScript parser: ${error}`);
  }
}

/**
 * Convert tree-sitter node to AST node
 */
function convertNode(node: Parser.SyntaxNode): ASTNode {
  return {
    type: node.type,
    startLine: node.startPosition.row + 1,
    endLine: node.endPosition.row + 1,
    text: node.text,
  };
}

/**
 * Extract decorators from function/class node (TypeScript)
 */
function extractDecorators(node: Parser.SyntaxNode): string[] {
  const decorators: string[] = [];

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === 'decorator') {
      const decoratorText = child.text.replace(/^@/, '');
      decorators.push(decoratorText);
    }
  }

  return decorators;
}

/**
 * Extract function name from function declaration
 */
function extractFunctionName(node: Parser.SyntaxNode): string {
  const nameNode = node.childForFieldName('name');
  return nameNode?.text || '<anonymous>';
}

/**
 * Extract class name
 */
function extractClassName(node: Parser.SyntaxNode): string {
  const nameNode = node.childForFieldName('name');
  return nameNode?.text || '<anonymous>';
}

/**
 * Extract extends/implements from class
 */
function extractExtends(node: Parser.SyntaxNode): string[] {
  const extends_: string[] = [];

  let heritage = node.childForFieldName('heritage');
  if (!heritage) {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child?.type === 'class_heritage') {
        heritage = child;
        break;
      }
    }
  }

  if (heritage) {
    for (let i = 0; i < heritage.childCount; i++) {
      const child = heritage.child(i);
      if (child?.type !== 'extends_clause') continue;

      for (let j = 0; j < child.childCount; j++) {
        const typeNode = child.child(j);
        if (!typeNode || typeNode.type === 'extends') continue;
        extends_.push(typeNode.text);
      }
    }
  }

  return extends_;
}

/**
 * Extract parameter names from function
 */
function extractParameters(node: Parser.SyntaxNode): string[] {
  const params: string[] = [];
  const paramsNode = node.childForFieldName('parameters');

  if (!paramsNode) return params;

  for (let i = 0; i < paramsNode.childCount; i++) {
    const child = paramsNode.child(i);
    if (!child) continue;

    if (child.type === 'required_parameter' || child.type === 'optional_parameter') {
      const pattern = child.childForFieldName('pattern');
      if (pattern) {
        params.push(pattern.text);
      }
    } else if (child.type === 'rest_parameter') {
      const pattern = child.childForFieldName('pattern');
      if (pattern) {
        params.push(`...${pattern.text}`);
      }
    }
  }

  return params;
}

/**
 * Extract callee information from call expression
 */
function extractCalleeInfo(callNode: Parser.SyntaxNode): { callee: string; baseExpression?: string; memberChain: string[] } {
  const functionNode = callNode.childForFieldName('function');

  if (!functionNode) {
    return { callee: '<unknown>', memberChain: [] };
  }

  if (functionNode.type === 'member_expression') {
    const chain = extractMemberChain(functionNode);
    const callee = chain.memberChain.join('.');
    return {
      callee,
      baseExpression: chain.baseExpression,
      memberChain: chain.memberChain,
    };
  }

  return {
    callee: functionNode.text,
    memberChain: [functionNode.text],
  };
}

/**
 * Extract member chain from member expression (e.g., client.chat.completions.create)
 */
function extractMemberChain(node: Parser.SyntaxNode): { baseExpression?: string; memberChain: string[] } {
  const chain: string[] = [];
  let current: Parser.SyntaxNode | null = node;
  let baseExpression: string | undefined;

  while (current && current.type === 'member_expression') {
    const property = current.childForFieldName('property');
    if (property) {
      chain.unshift(property.text);
    }

    const object = current.childForFieldName('object');
    if (!object) break;

    if (object.type === 'member_expression') {
      current = object;
    } else {
      baseExpression = object.text;
      chain.unshift(baseExpression ?? '');
      break;
    }
  }

  return { baseExpression, memberChain: chain };
}

/**
 * Extract call arguments
 */
function extractArguments(callNode: Parser.SyntaxNode): string[] {
  const args: string[] = [];
  const argsNode = callNode.childForFieldName('arguments');

  if (!argsNode) return args;

  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (child && child.type !== '(' && child.type !== ')' && child.type !== ',') {
      args.push(child.text);
    }
  }

  return args;
}

/**
 * Extract detailed argument information
 */
function extractArgumentDetails(callNode: Parser.SyntaxNode): CallArgumentInfo[] {
  const details: CallArgumentInfo[] = [];
  const argsNode = callNode.childForFieldName('arguments');

  if (!argsNode) return details;

  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (!child || child.type === '(' || child.type === ')' || child.type === ',') continue;

    const isSpread = child.type === 'spread_element';
    const isIdentifier = child.type === 'identifier';

    details.push({
      value: child.text,
      isSpread,
      isIdentifier,
      identifierName: isIdentifier ? child.text : undefined,
    });
  }

  return details;
}

/**
 * Find enclosing function for a node
 */
function findEnclosingFunction(node: Parser.SyntaxNode): string | undefined {
  let current: Parser.SyntaxNode | null = node.parent;

  while (current) {
    if (current.type === 'function_declaration' ||
        current.type === 'function' ||
        current.type === 'method_definition' ||
        current.type === 'arrow_function') {
      const nameNode = current.childForFieldName('name');
      if (nameNode) {
        return nameNode.text;
      }

      const parent = current.parent;

      // For arrow functions assigned to object properties:
      // const action = { handler: async () => { ... } }
      // Walk up: arrow_function -> pair -> object -> variable_declarator
      if (parent?.type === 'pair') {
        const keyNode = parent.childForFieldName('key');
        const propName = keyNode?.text?.replace(/['"]/g, '');
        const objectNode = parent.parent; // object
        if (objectNode && (objectNode.type === 'object' || objectNode.type === 'object_pattern')) {
          const varDecl = objectNode.parent; // variable_declarator (or may have 'as' expression)
          const actualVarDecl = varDecl?.type === 'as_expression' ? varDecl.parent : varDecl;
          if (actualVarDecl?.type === 'variable_declarator') {
            const varName = actualVarDecl.childForFieldName('name');
            if (varName && propName) {
              return `${varName.text}.${propName}`;
            }
          }
        }
      }

      // For arrow functions assigned to variables
      if (parent?.type === 'variable_declarator') {
        const varName = parent.childForFieldName('name');
        if (varName) {
          return varName.text;
        }
      }

      // For arrow functions inside variable declarations (const/let/var)
      if (parent?.type === 'lexical_declaration' || parent?.type === 'variable_declaration') {
        // walk siblings to find variable_declarator
        for (let i = 0; i < (parent?.childCount ?? 0); i++) {
          const child = parent?.child(i);
          if (child?.type === 'variable_declarator') {
            const varName = child.childForFieldName('name');
            if (varName) return varName.text;
          }
        }
      }

      return '<anonymous>';
    }
    current = current.parent;
  }

  return undefined;
}

/**
 * Find enclosing class for a node
 */
function findEnclosingClass(node: Parser.SyntaxNode): string | undefined {
  let current: Parser.SyntaxNode | null = node.parent;

  while (current) {
    if (current.type === 'class_declaration' || current.type === 'class') {
      const nameNode = current.childForFieldName('name');
      return nameNode?.text || '<anonymous>';
    }
    current = current.parent;
  }

  return undefined;
}

/**
 * Find all nodes of given types
 */
function findAllNodes(rootNode: Parser.SyntaxNode, types: string[]): Parser.SyntaxNode[] {
  const results: Parser.SyntaxNode[] = [];
  const typeSet = new Set(types);

  function visit(node: Parser.SyntaxNode) {
    if (typeSet.has(node.type)) {
      results.push(node);
    }

    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) visit(child);
    }
  }

  visit(rootNode);
  return results;
}

function normalizeTypeText(raw: string): string {
  return raw.replace(/^:\s*/, '').replace(/^<\s*|\s*>$/g, '').trim();
}

function extractAssertedType(node: Parser.SyntaxNode): string | undefined {
  if (node.type === 'as_expression' || node.type === 'satisfies_expression') {
    const lastChild = node.child(node.childCount - 1);
    if (lastChild) {
      return normalizeTypeText(lastChild.text);
    }
  }

  if (node.type === 'type_assertion') {
    const firstChild = node.child(0);
    if (firstChild) {
      return normalizeTypeText(firstChild.text);
    }
  }

  return undefined;
}

function unwrapExpressionNode(node: Parser.SyntaxNode): Parser.SyntaxNode {
  let current = node;

  while (true) {
    if (current.type === 'parenthesized_expression') {
      let inner: Parser.SyntaxNode | null = null;
      for (let i = 0; i < current.childCount; i++) {
        const child = current.child(i);
        if (!child || child.type === '(' || child.type === ')') continue;
        inner = child;
        break;
      }
      if (!inner) return current;
      current = inner;
      continue;
    }

    if (current.type === 'as_expression' || current.type === 'satisfies_expression') {
      const exprChild = current.child(0);
      if (!exprChild) return current;
      current = exprChild;
      continue;
    }

    if (current.type === 'type_assertion') {
      const exprChild = current.child(current.childCount - 1);
      if (!exprChild) return current;
      current = exprChild;
      continue;
    }

    return current;
  }
}

function extractInlineObjectFunctions(
  objectNode: Parser.SyntaxNode,
  objectName: string,
  exports: Map<string, 'named' | 'default' | 'commonjs'>
): FunctionDef[] {
  const extracted: FunctionDef[] = [];
  const actionPropertyNames = new Set(['handler', 'execute', 'run', 'action', 'handle', 'invoke', 'call', 'perform', 'get', 'validate', 'init', 'dispose']);

  const visitObject = (node: Parser.SyntaxNode, prefix: string) => {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (!child || child.type !== 'pair') continue;

      const keyNode = child.childForFieldName('key');
      const rawValueNode = child.childForFieldName('value');
      if (!keyNode || !rawValueNode) continue;

      const key = keyNode.text.replace(/['"]/g, '');
      const valueNode = unwrapExpressionNode(rawValueNode);
      const exportKind = exports.get(objectName);

      if ((valueNode.type === 'arrow_function' || valueNode.type === 'function_expression' || valueNode.type === 'function') &&
          (actionPropertyNames.has(key) || key.startsWith('['))) {
        const syntheticName = `${prefix}.${key}`;
        extracted.push({
          name: syntheticName,
          parameters: extractParameters(valueNode),
          decorators: [],
          isAsync: valueNode.text.startsWith('async '),
          isArrow: valueNode.type === 'arrow_function',
          isMethod: false,
          startLine: valueNode.startPosition.row + 1,
          endLine: valueNode.endPosition.row + 1,
          bodyNode: convertNode(valueNode),
          controlFlow: analyzeControlFlow(valueNode),
          isExported: !!exportKind,
          exportKind,
        });
        continue;
      }

      if (valueNode.type === 'array' || valueNode.type === 'array_pattern') {
        let fnIndex = 0;
        for (let j = 0; j < valueNode.childCount; j++) {
          const arrChild = valueNode.child(j);
          if (!arrChild || arrChild.type === ',' || arrChild.type === '[' || arrChild.type === ']') continue;
          const elementNode = unwrapExpressionNode(arrChild);
          if (elementNode.type !== 'arrow_function' && elementNode.type !== 'function_expression' && elementNode.type !== 'function') continue;
          const syntheticName = `${prefix}.${key}[${fnIndex}]`;
          extracted.push({
            name: syntheticName,
            parameters: extractParameters(elementNode),
            decorators: [],
            isAsync: elementNode.text.startsWith('async '),
            isArrow: elementNode.type === 'arrow_function',
            isMethod: false,
            startLine: elementNode.startPosition.row + 1,
            endLine: elementNode.endPosition.row + 1,
            bodyNode: convertNode(elementNode),
            controlFlow: analyzeControlFlow(elementNode),
            isExported: !!exportKind,
            exportKind,
          });
          fnIndex++;
        }
        continue;
      }

      if (valueNode.type === 'object' || valueNode.type === 'object_pattern') {
        visitObject(valueNode, `${prefix}.${key}`);
      }
    }
  };

  visitObject(objectNode, objectName);
  return extracted;
}

/**
 * Check if node is inside a conditional
 */
function isInsideConditional(node: Parser.SyntaxNode): boolean {
  let current: Parser.SyntaxNode | null = node.parent;

  while (current) {
    if (current.type === 'if_statement' ||
        current.type === 'switch_statement' ||
        current.type === 'ternary_expression') {
      return true;
    }
    current = current.parent;
  }

  return false;
}

/**
 * Analyze control flow of a function
 */
function analyzeControlFlow(funcNode: Parser.SyntaxNode): ControlFlowInfo {
  const bodyNode = funcNode.childForFieldName('body');
  if (!bodyNode) {
    return {
      hasRaise: false,
      hasConditionalRaise: false,
      hasConditionalReturn: false,
      checksParameters: false,
      raiseTypes: [],
    };
  }

  const throwNodes = findAllNodes(bodyNode, ['throw_statement']);
  const returnNodes = findAllNodes(bodyNode, ['return_statement']);
  const ifNodes = findAllNodes(bodyNode, ['if_statement']);

  const hasRaise = throwNodes.length > 0;
  const hasConditionalRaise = throwNodes.some(n => isInsideConditional(n));
  const hasConditionalReturn = returnNodes.some(n => isInsideConditional(n));

  const params = extractParameters(funcNode);
  const paramSet = new Set(params.map(p => p.replace(/^\.\.\./, '')));

  // Check if any if-statement condition references parameters
  let checksParameters = false;
  for (const ifNode of ifNodes) {
    const condition = ifNode.childForFieldName('condition');
    if (condition && Array.from(paramSet).some(p => condition.text.includes(p))) {
      checksParameters = true;
      break;
    }
  }

  // Extract exception types from throw statements
  const raiseTypes: string[] = [];
  for (const throwNode of throwNodes) {
    const valueNode = throwNode.childForFieldName('value');
    if (valueNode?.type === 'new_expression') {
      const constructorNode = valueNode.childForFieldName('constructor');
      if (constructorNode) {
        raiseTypes.push(constructorNode.text);
      }
    }
  }

  return {
    hasRaise,
    hasConditionalRaise,
    hasConditionalReturn,
    checksParameters,
    raiseTypes,
  };
}

/**
 * Extract exported symbol names from AST
 * Detects: export function foo(), export const foo, export default, export { foo }, module.exports
 */
function extractExports(rootNode: Parser.SyntaxNode): Map<string, 'named' | 'default' | 'commonjs'> {
  const exports = new Map<string, 'named' | 'default' | 'commonjs'>();

  // Find all export_statement nodes
  const exportStatements = findAllNodes(rootNode, ['export_statement']);

  for (const node of exportStatements) {
    const text = node.text;

    // export default function/class/expression
    if (text.startsWith('export default')) {
      // Try to find the name of what's being exported
      const declaration = node.childForFieldName('declaration');
      const value = node.childForFieldName('value');

      if (declaration) {
        // export default function foo() or export default class Foo
        const nameNode = declaration.childForFieldName('name');
        if (nameNode) {
          exports.set(nameNode.text, 'default');
        } else {
          exports.set('default', 'default');
        }
      } else if (value) {
        // export default identifier or export default expression
        if (value.type === 'identifier') {
          exports.set(value.text, 'default');
        } else {
          exports.set('default', 'default');
        }
      }
      continue;
    }

    // export function foo() {}
    const funcDecl = node.children.find(c => c.type === 'function_declaration');
    if (funcDecl) {
      const nameNode = funcDecl.childForFieldName('name');
      if (nameNode) {
        exports.set(nameNode.text, 'named');
      }
      continue;
    }

    // export class Foo {}
    const classDecl = node.children.find(c => c.type === 'class_declaration');
    if (classDecl) {
      const nameNode = classDecl.childForFieldName('name');
      if (nameNode) {
        exports.set(nameNode.text, 'named');
      }
      continue;
    }

    // export const/let/var foo = ...
    const lexicalDecl = node.children.find(c => c.type === 'lexical_declaration');
    const varDecl = node.children.find(c => c.type === 'variable_declaration');
    const decl = lexicalDecl || varDecl;
    if (decl) {
      const declarators = findAllNodes(decl, ['variable_declarator']);
      for (const declarator of declarators) {
        const nameNode = declarator.childForFieldName('name');
        if (nameNode) {
          exports.set(nameNode.text, 'named');
        }
      }
      continue;
    }

    // export { foo, bar as baz }
    const exportClause = node.children.find(c => c.type === 'export_clause');
    if (exportClause) {
      for (let i = 0; i < exportClause.childCount; i++) {
        const child = exportClause.child(i);
        if (child?.type === 'export_specifier') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) {
            exports.set(nameNode.text, 'named');
          }
        }
      }
      continue;
    }
  }

  // Handle CommonJS: module.exports = ... or exports.foo = ...
  const assignExprs = findAllNodes(rootNode, ['assignment_expression']);
  for (const node of assignExprs) {
    const left = node.childForFieldName('left');
    if (!left) continue;

    const leftText = left.text;

    // module.exports = something
    if (leftText === 'module.exports') {
      const right = node.childForFieldName('right');
      if (right?.type === 'identifier') {
        exports.set(right.text, 'commonjs');
      } else if (right?.type === 'object') {
        // module.exports = { foo, bar }
        const props = extractObjectProperties(right);
        for (const prop of props) {
          exports.set(prop.key, 'commonjs');
        }
      }
      continue;
    }

    // exports.foo = something
    if (leftText.startsWith('exports.')) {
      const name = leftText.replace('exports.', '');
      exports.set(name, 'commonjs');
      continue;
    }

    // module.exports.foo = something
    if (leftText.startsWith('module.exports.')) {
      const name = leftText.replace('module.exports.', '');
      exports.set(name, 'commonjs');
      continue;
    }
  }

  return exports;
}

/**
 * Extract functions from AST
 */
function extractFunctions(rootNode: Parser.SyntaxNode, exports: Map<string, 'named' | 'default' | 'commonjs'>): FunctionDef[] {
  const functions: FunctionDef[] = [];

  // Function declarations
  const funcDecls = findAllNodes(rootNode, ['function_declaration']);
  for (const node of funcDecls) {
    const name = extractFunctionName(node);
    const parameters = extractParameters(node);
    const decorators = extractDecorators(node);
    const isAsync = node.text.startsWith('async ');
    const controlFlow = analyzeControlFlow(node);
    const exportKind = exports.get(name);

    functions.push({
      name,
      parameters,
      decorators,
      isAsync,
      isArrow: false,
      isMethod: false,
      startLine: node.startPosition.row + 1,
      endLine: node.endPosition.row + 1,
      bodyNode: convertNode(node),
      controlFlow,
      isExported: !!exportKind,
      exportKind,
    });
  }

  // Arrow functions assigned to variables
  const varDecls = findAllNodes(rootNode, ['variable_declarator']);
  for (const node of varDecls) {
    const nameNode = node.childForFieldName('name');
    const rawValueNode = node.childForFieldName('value');
    const valueNode = rawValueNode ? unwrapExpressionNode(rawValueNode) : undefined;

    if (valueNode && (valueNode.type === 'arrow_function' || valueNode.type === 'function')) {
      const name = nameNode?.text || '<anonymous>';
      const parameters = extractParameters(valueNode);
      const isAsync = valueNode.text.startsWith('async ');
      const controlFlow = analyzeControlFlow(valueNode);
      const exportKind = exports.get(name);

      functions.push({
        name,
        parameters,
        decorators: [],
        isAsync,
        isArrow: valueNode.type === 'arrow_function',
        isMethod: false,
        startLine: valueNode.startPosition.row + 1,
        endLine: valueNode.endPosition.row + 1,
        bodyNode: convertNode(valueNode),
        controlFlow,
        isExported: !!exportKind,
        exportKind,
      });
    }

    // Extract inline handler functions inside action objects
    // Pattern: const action = { handler: async () => {}, execute: () => {} }
    if (valueNode && (valueNode.type === 'object' || valueNode.type === 'object_pattern')) {
      const objectName = nameNode?.text || '<anonymous>';
      functions.push(...extractInlineObjectFunctions(valueNode, objectName, exports));
    }
  }

  // Method definitions
  const methodDefs = findAllNodes(rootNode, ['method_definition']);
  for (const node of methodDefs) {
    const nameNode = node.childForFieldName('name');
    const name = nameNode?.text || '<anonymous>';
    const parameters = extractParameters(node);
    const decorators = extractDecorators(node);
    const isAsync = node.text.includes('async ');
    const className = findEnclosingClass(node);
    const controlFlow = analyzeControlFlow(node);

    functions.push({
      name,
      parameters,
      decorators,
      isAsync,
      isArrow: false,
      isMethod: true,
      className,
      startLine: node.startPosition.row + 1,
      endLine: node.endPosition.row + 1,
      bodyNode: convertNode(node),
      controlFlow,
    });
  }

  return functions;
}

/**
 * Extract classes from AST
 */
function extractClasses(rootNode: Parser.SyntaxNode): ClassDef[] {
  const classes: ClassDef[] = [];
  const classDecls = findAllNodes(rootNode, ['class_declaration', 'class_expression']);

  for (const node of classDecls) {
    const name = extractClassName(node);
    const extends_ = extractExtends(node);

    // Extract method names
    const methods: string[] = [];
    const methodNodes = findAllNodes(node, ['method_definition']);
    for (const methodNode of methodNodes) {
      const nameNode = methodNode.childForFieldName('name');
      if (nameNode) {
        methods.push(nameNode.text);
      }
    }

    classes.push({
      name,
      extends: extends_,
      methods,
      startLine: node.startPosition.row + 1,
      endLine: node.endPosition.row + 1,
    });
  }

  return classes;
}

/**
 * Extract call sites from AST
 */
function extractCalls(rootNode: Parser.SyntaxNode): CallSite[] {
  const calls: CallSite[] = [];
  const callNodes = findAllNodes(rootNode, ['call_expression', 'new_expression']);

  for (const node of callNodes) {
    const callInfo = extractCalleeInfo(node);
    const enclosingFunction = findEnclosingFunction(node);
    const enclosingClass = findEnclosingClass(node);
    const args = extractArguments(node);
    const argDetails = extractArgumentDetails(node);

    calls.push({
      callee: callInfo.callee,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
      enclosingFunction,
      enclosingClass,
      memberChain: callInfo.memberChain,
      baseExpression: callInfo.baseExpression,
      arguments: args,
      argumentDetails: argDetails,
    });
  }

  return calls;
}

/**
 * Extract import statements
 */
function extractImports(rootNode: Parser.SyntaxNode): ImportInfo[] {
  const imports: ImportInfo[] = [];

  // ES6 imports
  const importDecls = findAllNodes(rootNode, ['import_statement']);
  for (const node of importDecls) {
    const sourceNode = node.childForFieldName('source');
    if (!sourceNode) continue;

    const module = sourceNode.text.replace(/['"]/g, '');
    const names: string[] = [];
    let isDefault = false;
    let isNamespace = false;
    let alias: string | undefined;

    const clauseNode = node.childForFieldName('import_clause') || node.child(1);
    if (clauseNode) {
      const parseNamedImports = (namedImportsNode: Parser.SyntaxNode) => {
        for (let i = 0; i < namedImportsNode.childCount; i++) {
          const child = namedImportsNode.child(i);
          if (child?.type === 'import_specifier') {
            const nameNode = child.childForFieldName('name');
            if (nameNode) {
              names.push(nameNode.text);
            }
          }
        }
      };

      const parseNamespaceImport = (namespaceNode: Parser.SyntaxNode) => {
        isNamespace = true;
        const nameNode = namespaceNode.childForFieldName('name');
        if (nameNode) {
          alias = nameNode.text;
        }
      };

      // Handle direct clause forms
      if (clauseNode.type === 'identifier') {
        isDefault = true;
        names.push(clauseNode.text);
      } else if (clauseNode.type === 'namespace_import') {
        parseNamespaceImport(clauseNode);
      } else if (clauseNode.type === 'named_imports') {
        parseNamedImports(clauseNode);
      } else if (clauseNode.type === 'import_clause') {
        // Handle "import foo, { bar } from '...'" and similar forms
        for (let i = 0; i < clauseNode.childCount; i++) {
          const child = clauseNode.child(i);
          if (!child) continue;

          if (child.type === 'identifier') {
            isDefault = true;
            names.push(child.text);
          } else if (child.type === 'named_imports') {
            parseNamedImports(child);
          } else if (child.type === 'namespace_import') {
            parseNamespaceImport(child);
          }
        }
      }
    }

    imports.push({
      module,
      names,
      isDefault,
      isNamespace,
      alias,
      line: node.startPosition.row + 1,
    });
  }

  // CommonJS requires
  const varDecls = findAllNodes(rootNode, ['variable_declarator']);
  for (const node of varDecls) {
    const valueNode = node.childForFieldName('value');
    if (valueNode?.type === 'call_expression') {
      const funcNode = valueNode.childForFieldName('function');
      if (funcNode?.text === 'require') {
        const argsNode = valueNode.childForFieldName('arguments');
        if (argsNode && argsNode.childCount > 1) {
          const moduleNode = argsNode.child(1);
          if (moduleNode) {
            const module = moduleNode.text.replace(/['"]/g, '');
            const nameNode = node.childForFieldName('name');
            const names = nameNode ? [nameNode.text] : [];

            imports.push({
              module,
              names,
              isDefault: true,
              isNamespace: false,
              line: node.startPosition.row + 1,
            });
          }
        }
      }
    }
  }

  return imports;
}

/**
 * Extract structured properties from an object literal AST node
 * Uses AST traversal instead of regex pattern matching
 */
function extractObjectProperties(node: Parser.SyntaxNode): ObjectProperty[] {
  const properties: ObjectProperty[] = [];

  // Object literals have type 'object' or 'object_pattern'
  if (node.type !== 'object' && node.type !== 'object_pattern') {
    return properties;
  }

  // Find all pair nodes (key-value pairs)
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child || child.type !== 'pair') continue;

    const keyNode = child.childForFieldName('key');
    const valueNode = child.childForFieldName('value');

    if (!keyNode || !valueNode) continue;

    const key = keyNode.text.replace(/['"]/g, ''); // Remove quotes if string key
    const value = valueNode.text;

    let valueType: ObjectProperty['valueType'] = 'unknown';
    let stringValue: string | undefined;
    let nestedProperties: ObjectProperty[] | undefined;

    // Determine value type from AST node type
    switch (valueNode.type) {
      case 'string':
      case 'template_string':
        valueType = 'string';
        stringValue = valueNode.text.replace(/^['"`]|['"`]$/g, ''); // Remove quotes
        break;
      case 'number':
        valueType = 'number';
        break;
      case 'true':
      case 'false':
        valueType = 'boolean';
        break;
      case 'identifier':
        valueType = 'identifier';
        break;
      case 'object':
      case 'object_pattern':
        valueType = 'object';
        nestedProperties = extractObjectProperties(valueNode);
        break;
      case 'array':
      case 'array_pattern':
        valueType = 'array';
        break;
      case 'arrow_function':
      case 'function_expression':
      case 'function':
        valueType = 'function';
        break;
    }

    properties.push({
      key,
      value,
      valueType,
      stringValue,
      nestedProperties,
    });
  }

  return properties;
}

/**
 * Extract array elements from an array literal AST node
 * Returns structured objects for object literal elements
 */
function extractArrayElements(node: Parser.SyntaxNode): Array<{text: string, objectProperties?: ObjectProperty[]}> {
  const elements: Array<{text: string, objectProperties?: ObjectProperty[]}> = [];

  if (node.type !== 'array' && node.type !== 'array_pattern') {
    return elements;
  }

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child || child.type === ',' || child.type === '[' || child.type === ']') continue;

    // Check if element is an object literal
    const isObject = child.type === 'object' || child.type === 'object_pattern';

    elements.push({
      text: child.text,
      objectProperties: isObject ? extractObjectProperties(child) : undefined,
    });
  }

  return elements;
}

/**
 * Extract assignments
 */
function extractAssignments(rootNode: Parser.SyntaxNode): AssignmentInfo[] {
  const assignments: AssignmentInfo[] = [];

  // Variable declarations
  const varDecls = findAllNodes(rootNode, ['variable_declarator']);
  for (const node of varDecls) {
    const nameNode = node.childForFieldName('name');
    const rawValueNode = node.childForFieldName('value');
    const valueNode = rawValueNode ? unwrapExpressionNode(rawValueNode) : undefined;

    if (nameNode && rawValueNode && valueNode) {
      const enclosingFunction = findEnclosingFunction(node);
      const typeNode = node.childForFieldName('type');
      const isObjectLiteral = valueNode.type === 'object' || valueNode.type === 'object_pattern';
      const isArrayLiteral = valueNode.type === 'array' || valueNode.type === 'array_pattern';

      assignments.push({
        target: nameNode.text,
        value: rawValueNode.text,
        line: node.startPosition.row + 1,
        enclosingFunction,
        typeAnnotation: typeNode ? normalizeTypeText(typeNode.text) : undefined,
        assertedType: extractAssertedType(rawValueNode),
        isObjectLiteral,
        isArrayLiteral,
        objectProperties: isObjectLiteral ? extractObjectProperties(valueNode) : undefined,
        arrayElements: isArrayLiteral ? extractArrayElements(valueNode) : undefined,
      });
    }
  }

  // Assignment expressions
  const assignExprs = findAllNodes(rootNode, ['assignment_expression']);
  for (const node of assignExprs) {
    const leftNode = node.childForFieldName('left');
    const rawRightNode = node.childForFieldName('right');
    const rightNode = rawRightNode ? unwrapExpressionNode(rawRightNode) : undefined;

    if (leftNode && rawRightNode && rightNode) {
      const enclosingFunction = findEnclosingFunction(node);
      const isObjectLiteral = rightNode.type === 'object' || rightNode.type === 'object_pattern';
      const isArrayLiteral = rightNode.type === 'array' || rightNode.type === 'array_pattern';

      assignments.push({
        target: leftNode.text,
        value: rawRightNode.text,
        line: node.startPosition.row + 1,
        enclosingFunction,
        assertedType: extractAssertedType(rawRightNode),
        isObjectLiteral,
        isArrayLiteral,
        objectProperties: isObjectLiteral ? extractObjectProperties(rightNode) : undefined,
        arrayElements: isArrayLiteral ? extractArrayElements(rightNode) : undefined,
      });
    }
  }

  return assignments;
}

/**
 * Extract return statements
 */
function extractReturns(rootNode: Parser.SyntaxNode): ReturnInfo[] {
  const returns: ReturnInfo[] = [];
  const returnNodes = findAllNodes(rootNode, ['return_statement']);

  for (const node of returnNodes) {
    const valueNode = node.child(1); // First child is 'return' keyword
    const enclosingFunction = findEnclosingFunction(node);

    returns.push({
      value: valueNode?.text || '',
      line: node.startPosition.row + 1,
      enclosingFunction,
    });
  }

  return returns;
}

/**
 * Parse TypeScript/JavaScript source code
 */
export function parseTypeScriptSource(sourceCode: string, isTSX: boolean = false): ParsedTypeScriptFile {
  if (!parser) {
    return {
      success: false,
      error: 'Parser not initialized. Call initParser() first.',
      functions: [],
      classes: [],
      calls: [],
      imports: [],
      assignments: [],
      returns: [],
    };
  }

  try {
    const activeParser = isTSX ? tsxParser : tsParser;
    if (!activeParser) {
      return {
        success: false,
        error: `${isTSX ? 'TSX' : 'TypeScript'} parser not initialized`,
        functions: [],
        classes: [],
        calls: [],
        imports: [],
        assignments: [],
        returns: [],
      };
    }

    const tree = activeParser.parse(sourceCode);
    const rootNode = tree.rootNode;

    const exports = extractExports(rootNode);
    const functions = extractFunctions(rootNode, exports);
    const classes = extractClasses(rootNode);
    const calls = extractCalls(rootNode);
    const imports = extractImports(rootNode);
    const assignments = extractAssignments(rootNode);
    const returns = extractReturns(rootNode);

    return {
      success: true,
      functions,
      classes,
      calls,
      imports,
      assignments,
      returns,
      exports,
    };
  } catch (error) {
    return {
      success: false,
      error: `Parse error: ${error}`,
      functions: [],
      classes: [],
      calls: [],
      imports: [],
      assignments: [],
      returns: [],
    };
  }
}
