/**
 * AST Walker Module
 * 
 * Provides tree-sitter based AST walking capabilities for Python and TypeScript.
 * This is the foundation for all static analysis in AFB Scanner.
 */

import Parser from 'tree-sitter';
import Python from 'tree-sitter-python';
import TypeScript from 'tree-sitter-typescript';
import * as fs from 'fs';
import * as path from 'path';
import { SupportedLanguage, NodeLocation } from '../types';

/**
 * Tree-sitter syntax node with location information.
 */
export interface ASTNode {
  type: string;
  text: string;
  location: NodeLocation;
  children: ASTNode[];
  parent?: ASTNode;
  fieldName?: string;
}

/**
 * Callback function for AST traversal.
 */
export type ASTVisitor = (node: Parser.SyntaxNode, ancestors: Parser.SyntaxNode[]) => void;

/**
 * AST Walker class for parsing and traversing source code.
 */
export class ASTWalker {
  private pythonParser: Parser;
  private typescriptParser: Parser;
  private tsxParser: Parser;

  constructor() {
    this.pythonParser = new Parser();
    this.pythonParser.setLanguage(Python);

    this.typescriptParser = new Parser();
    this.typescriptParser.setLanguage(TypeScript.typescript);

    this.tsxParser = new Parser();
    this.tsxParser.setLanguage(TypeScript.tsx);
  }

  /**
   * Determine the language of a file based on its extension.
   */
  getLanguage(filePath: string): SupportedLanguage | null {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
      case '.py':
        return 'python';
      case '.ts':
      case '.tsx':
      case '.js':
      case '.jsx':
        return 'typescript'; // tree-sitter-typescript handles JS too
      default:
        return null;
    }
  }

  /**
   * Check if a file should be analyzed based on extension.
   */
  isAnalyzable(filePath: string): boolean {
    return this.getLanguage(filePath) !== null;
  }

  /**
   * Parse source code into an AST.
   */
  parse(sourceCode: string, language: SupportedLanguage, filePath?: string): Parser.Tree {
    const isTsx = filePath?.endsWith('.tsx') || filePath?.endsWith('.jsx');
    
    switch (language) {
      case 'python':
        return this.pythonParser.parse(sourceCode);
      case 'typescript':
      case 'javascript':
        return isTsx 
          ? this.tsxParser.parse(sourceCode)
          : this.typescriptParser.parse(sourceCode);
      default:
        throw new Error(`Unsupported language: ${language}`);
    }
  }

  /**
   * Parse a file and return its AST.
   */
  parseFile(filePath: string): Parser.Tree | null {
    const language = this.getLanguage(filePath);
    if (!language) {
      return null;
    }

    const sourceCode = fs.readFileSync(filePath, 'utf-8');
    return this.parse(sourceCode, language, filePath);
  }

  /**
   * Walk the AST and call the visitor for each node.
   * Performs depth-first traversal.
   */
  walk(tree: Parser.Tree, visitor: ASTVisitor): void {
    const walkNode = (node: Parser.SyntaxNode, ancestors: Parser.SyntaxNode[]): void => {
      visitor(node, ancestors);
      
      for (const child of node.children) {
        walkNode(child, [...ancestors, node]);
      }
    };

    walkNode(tree.rootNode, []);
  }

  /**
   * Find all nodes matching a specific type.
   */
  findNodesByType(tree: Parser.Tree, nodeType: string): Parser.SyntaxNode[] {
    const matches: Parser.SyntaxNode[] = [];
    
    this.walk(tree, (node) => {
      if (node.type === nodeType) {
        matches.push(node);
      }
    });

    return matches;
  }

  /**
   * Find all nodes matching any of the specified types.
   */
  findNodesByTypes(tree: Parser.Tree, nodeTypes: string[]): Parser.SyntaxNode[] {
    const typeSet = new Set(nodeTypes);
    const matches: Parser.SyntaxNode[] = [];
    
    this.walk(tree, (node) => {
      if (typeSet.has(node.type)) {
        matches.push(node);
      }
    });

    return matches;
  }

  /**
   * Get the enclosing function/method for a node.
   */
  getEnclosingFunction(node: Parser.SyntaxNode, language: SupportedLanguage): Parser.SyntaxNode | null {
    const functionTypes = language === 'python'
      ? ['function_definition', 'async_function_definition']
      : ['function_declaration', 'method_definition', 'arrow_function', 'function_expression'];

    let current: Parser.SyntaxNode | null = node.parent;
    while (current) {
      if (functionTypes.includes(current.type)) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  /**
   * Get the enclosing class for a node.
   */
  getEnclosingClass(node: Parser.SyntaxNode, language: SupportedLanguage): Parser.SyntaxNode | null {
    const classTypes = language === 'python'
      ? ['class_definition']
      : ['class_declaration', 'class'];

    let current: Parser.SyntaxNode | null = node.parent;
    while (current) {
      if (classTypes.includes(current.type)) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  /**
   * Get function name from a function node.
   */
  getFunctionName(funcNode: Parser.SyntaxNode, language: SupportedLanguage): string | null {
    if (language === 'python') {
      const nameNode = funcNode.childForFieldName('name');
      return nameNode?.text || null;
    } else {
      // TypeScript/JavaScript
      const nameNode = funcNode.childForFieldName('name');
      return nameNode?.text || null;
    }
  }

  /**
   * Get class name from a class node.
   */
  getClassName(classNode: Parser.SyntaxNode, language: SupportedLanguage): string | null {
    if (language === 'python') {
      const nameNode = classNode.childForFieldName('name');
      return nameNode?.text || null;
    } else {
      const nameNode = classNode.childForFieldName('name');
      return nameNode?.text || null;
    }
  }

  /**
   * Extract location information from a syntax node.
   */
  getNodeLocation(node: Parser.SyntaxNode): NodeLocation {
    return {
      startLine: node.startPosition.row + 1, // Convert to 1-indexed
      startColumn: node.startPosition.column + 1,
      endLine: node.endPosition.row + 1,
      endColumn: node.endPosition.column + 1,
    };
  }

  /**
   * Get the source text for a specific line range.
   */
  getSourceLines(sourceCode: string, startLine: number, endLine: number): string {
    const lines = sourceCode.split('\n');
    return lines.slice(startLine - 1, endLine).join('\n');
  }

  /**
   * Check if a node is inside a decorator.
   */
  isInsideDecorator(node: Parser.SyntaxNode): boolean {
    let current: Parser.SyntaxNode | null = node.parent;
    while (current) {
      if (current.type === 'decorator' || current.type === 'decorated_definition') {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Get decorators for a function in Python.
   */
  getPythonDecorators(funcNode: Parser.SyntaxNode): string[] {
    const decorators: string[] = [];
    
    // In Python, decorators are part of decorated_definition
    if (funcNode.parent?.type === 'decorated_definition') {
      for (const child of funcNode.parent.children) {
        if (child.type === 'decorator') {
          // Extract decorator name
          const attrAccess = child.descendantsOfType('attribute');
          const identifiers = child.descendantsOfType('identifier');
          
          if (attrAccess.length > 0) {
            decorators.push(attrAccess[0].text);
          } else if (identifiers.length > 0) {
            decorators.push(identifiers[0].text);
          }
        }
      }
    }
    
    return decorators;
  }
}

// Export singleton instance for convenience
export const astWalker = new ASTWalker();
