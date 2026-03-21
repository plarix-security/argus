import * as fs from 'fs';
import * as path from 'path';
import { SupportedLanguage, NodeLocation } from '../types';

type Tree = any;
type SyntaxNode = any;

export type ASTVisitor = (node: SyntaxNode, ancestors: SyntaxNode[]) => void;

export class ASTWalker {
  async initialize(): Promise<void> { }
  
  getLanguage(filePath: string): SupportedLanguage | null {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.py' ? 'python' : ['.ts', '.tsx', '.js', '.jsx'].includes(ext) ? 'typescript' : null;
  }
  
  isAnalyzable(filePath: string): boolean { return this.getLanguage(filePath) !== null; }
  
  parse(sourceCode: string, language: SupportedLanguage): Tree | null {
    const lines = sourceCode.split('\n');
    const nodes: SyntaxNode[] = [];
    lines.forEach((line, i) => {
      const callMatch = line.match(/(\w+(?:\.\w+)*)\s*\(/);
      if (callMatch) {
        const funcName = callMatch[1];
        const col = line.indexOf(callMatch[0]);
        nodes.push({ type: language === 'python' ? 'call' : 'call_expression', text: line.trim(), startPosition: { row: i, column: col }, endPosition: { row: i, column: line.length }, children: [], parent: null, childForFieldName: (name: string) => name === 'function' ? { text: funcName, type: 'identifier' } : null, descendantsOfType: () => [] });
      }
      if (line.trim().startsWith('@tool')) nodes.push({ type: 'decorator', text: line.trim(), startPosition: { row: i, column: 0 }, endPosition: { row: i, column: line.length }, children: [], parent: null });
    });
    return { rootNode: { type: 'module', text: sourceCode, children: nodes, startPosition: { row: 0, column: 0 }, endPosition: { row: lines.length, column: 0 } } };
  }
  
  parseFile(filePath: string): Tree | null {
    const language = this.getLanguage(filePath);
    if (!language) return null;
    return this.parse(fs.readFileSync(filePath, 'utf-8'), language);
  }
  
  walk(tree: Tree, visitor: ASTVisitor): void {
    const walkNode = (node: SyntaxNode, ancestors: SyntaxNode[]): void => {
      visitor(node, ancestors);
      for (const child of (node.children || [])) walkNode(child, [...ancestors, node]);
    };
    if (tree?.rootNode) walkNode(tree.rootNode, []);
  }
  
  findNodesByType(tree: Tree, nodeType: string): SyntaxNode[] {
    const matches: SyntaxNode[] = [];
    this.walk(tree, (node) => { if (node.type === nodeType) matches.push(node); });
    return matches;
  }
  
  findNodesByTypes(tree: Tree, nodeTypes: string[]): SyntaxNode[] {
    const matches: SyntaxNode[] = [];
    const typeSet = new Set(nodeTypes);
    this.walk(tree, (node) => { if (typeSet.has(node.type)) matches.push(node); });
    return matches;
  }
  
  getEnclosingFunction(node: SyntaxNode, language: SupportedLanguage): SyntaxNode | null { return null; }
  getEnclosingClass(node: SyntaxNode, language: SupportedLanguage): SyntaxNode | null { return null; }
  getFunctionName(funcNode: SyntaxNode, language: SupportedLanguage): string |  null { return funcNode.childForFieldName?.('name')?.text || null; }
  getClassName(classNode: SyntaxNode, language: SupportedLanguage): string | null { return classNode.childForFieldName?.('name')?.text || null; }
  
  getNodeLocation(node: SyntaxNode): NodeLocation {
    return { startLine: (node.startPosition?.row || 0) + 1, startColumn: (node.startPosition?.column || 0) + 1, endLine: (node.endPosition?.row || 0) + 1, endColumn: (node.endPosition?.column || 0) + 1 };
  }
  
  getSourceLines(sourceCode: string, startLine: number, endLine: number): string {
    return sourceCode.split('\n').slice(startLine - 1, endLine).join('\n');
  }
  
  isInsideDecorator(node: SyntaxNode): boolean { return false; }
  getPythonDecorators(funcNode: SyntaxNode): string[] { return []; }
}

export const astWalker = new ASTWalker();
