/**
 * TypeScript/JavaScript AFB04 Detector
 *
 * Detects AFB04 (Unauthorized Action) execution points in TypeScript/JavaScript
 * code through AST analysis. Specifically targets:
 *
 * 1. Tool definitions (LangChain tool(), DynamicTool)
 * 2. Shell command execution (child_process)
 * 3. File operations (fs module)
 * 4. API calls (fetch, axios, http)
 * 5. Database operations (query, Prisma)
 * 6. Code execution (eval, Function constructor)
 */

import Parser from 'tree-sitter';
import { ASTWalker } from '../ast-walker';
import {
  AFBFinding,
  FileAnalysisResult,
} from '../../types';
import {
  TYPESCRIPT_PATTERNS,
  ExecutionPattern,
  createFinding,
} from '../../afb/afb04';

/**
 * TypeScript/JavaScript-specific detector for AFB04 execution points.
 */
export class TypeScriptDetector {
  private walker: ASTWalker;

  constructor(walker: ASTWalker) {
    this.walker = walker;
  }

  /**
   * Analyze a TypeScript/JavaScript file for AFB04 execution points.
   */
  analyzeFile(filePath: string, sourceCode: string): FileAnalysisResult {
    const startTime = Date.now();
    const findings: AFBFinding[] = [];

    try {
      const tree = this.walker.parse(sourceCode, 'typescript', filePath);
      
      // Collect all findings
      findings.push(...this.detectToolDefinitions(tree, filePath, sourceCode));
      findings.push(...this.detectShellExecution(tree, filePath, sourceCode));
      findings.push(...this.detectFileOperations(tree, filePath, sourceCode));
      findings.push(...this.detectApiCalls(tree, filePath, sourceCode));
      findings.push(...this.detectDatabaseOperations(tree, filePath, sourceCode));
      findings.push(...this.detectCodeExecution(tree, filePath, sourceCode));

      return {
        file: filePath,
        language: 'typescript',
        findings,
        success: true,
        analysisTimeMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        file: filePath,
        language: 'typescript',
        findings: [],
        success: false,
        error: error instanceof Error ? error.message : String(error),
        analysisTimeMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Detect LangChain.js tool definitions.
   * Patterns:
   * - tool() function call
   * - new DynamicTool()
   * - new StructuredTool()
   * - DynamicStructuredTool.fromFunction()
   */
  private detectToolDefinitions(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];

    // Find call expressions
    const callExpressions = this.walker.findNodesByType(tree, 'call_expression');
    
    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;
      let framework = 'langchain';

      // tool() function call
      if (funcText === 'tool' || funcText.endsWith('.tool')) {
        pattern = TYPESCRIPT_PATTERNS.tool_function;
      }
      // DynamicTool.fromFunction() or similar factory methods
      else if (this.matchesPattern(funcText, ['DynamicTool.from', 
          'StructuredTool.from', 'DynamicStructuredTool.from'])) {
        pattern = TYPESCRIPT_PATTERNS.dynamic_tool;
      }

      if (pattern) {
        const { enclosingFunc, enclosingClass } = this.getCallContext(call);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(call),
          call.text,
          pattern,
          enclosingFunc,
          enclosingClass,
          true, // Tool definitions
          framework,
          0.9
        ));
      }
    }

    // Find new expressions for tool classes
    const newExpressions = this.walker.findNodesByType(tree, 'new_expression');
    
    for (const newExpr of newExpressions) {
      const constructorNode = newExpr.childForFieldName('constructor');
      if (!constructorNode) continue;

      const constructorText = constructorNode.text;
      
      if (this.isToolClass(constructorText)) {
        const { enclosingFunc, enclosingClass } = this.getCallContext(newExpr);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(newExpr),
          newExpr.text,
          TYPESCRIPT_PATTERNS.dynamic_tool,
          enclosingFunc,
          enclosingClass,
          true,
          'langchain',
          0.9
        ));
      }
    }

    return findings;
  }

  /**
   * Detect shell command execution.
   * Patterns:
   * - exec(), execSync()
   * - spawn(), spawnSync()
   * - execFile(), execFileSync()
   * - child_process module imports/requires
   */
  private detectShellExecution(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call_expression');

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      // exec functions
      if (this.matchesPattern(funcText, ['exec', 'execSync', 
          'child_process.exec', 'child_process.execSync'])) {
        pattern = funcText.includes('Sync') ? 
          TYPESCRIPT_PATTERNS.child_process_execSync : 
          TYPESCRIPT_PATTERNS.child_process_exec;
      }
      // spawn functions
      else if (this.matchesPattern(funcText, ['spawn', 'spawnSync',
          'child_process.spawn', 'child_process.spawnSync'])) {
        pattern = TYPESCRIPT_PATTERNS.child_process_spawn;
      }
      // execFile functions
      else if (this.matchesPattern(funcText, ['execFile', 'execFileSync',
          'child_process.execFile', 'child_process.execFileSync'])) {
        pattern = TYPESCRIPT_PATTERNS.child_process_exec;
      }

      if (pattern) {
        const { enclosingFunc, enclosingClass, isInTool } = 
          this.getCallContext(call, tree);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(call),
          call.text,
          pattern,
          enclosingFunc,
          enclosingClass,
          isInTool,
          undefined,
          0.95
        ));
      }
    }

    return findings;
  }

  /**
   * Detect file operations.
   * Patterns:
   * - fs.writeFile(), fs.writeFileSync()
   * - fs.readFile(), fs.readFileSync()
   * - fs.unlink(), fs.rm(), fs.rmdir()
   * - fs.promises.* methods
   */
  private detectFileOperations(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call_expression');

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      // Write operations
      if (this.matchesPattern(funcText, ['writeFile', 'writeFileSync',
          'fs.writeFile', 'fs.writeFileSync', 'fs.promises.writeFile',
          'appendFile', 'appendFileSync', 'fs.appendFile'])) {
        pattern = TYPESCRIPT_PATTERNS.fs_writeFile;
      }
      // Read operations
      else if (this.matchesPattern(funcText, ['readFile', 'readFileSync',
          'fs.readFile', 'fs.readFileSync', 'fs.promises.readFile'])) {
        pattern = TYPESCRIPT_PATTERNS.fs_readFile;
      }
      // Delete operations
      else if (this.matchesPattern(funcText, ['unlink', 'unlinkSync',
          'fs.unlink', 'fs.unlinkSync', 'fs.promises.unlink'])) {
        pattern = TYPESCRIPT_PATTERNS.fs_unlink;
      }
      // Recursive removal
      else if (this.matchesPattern(funcText, ['rm', 'rmSync', 'rmdir',
          'fs.rm', 'fs.rmSync', 'fs.rmdir', 'fs.promises.rm'])) {
        pattern = TYPESCRIPT_PATTERNS.fs_rm;
      }

      if (pattern) {
        const { enclosingFunc, enclosingClass, isInTool } = 
          this.getCallContext(call, tree);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(call),
          call.text,
          pattern,
          enclosingFunc,
          enclosingClass,
          isInTool,
          undefined,
          0.9
        ));
      }
    }

    return findings;
  }

  /**
   * Detect HTTP/API calls.
   * Patterns:
   * - fetch()
   * - axios.get(), axios.post(), etc.
   * - http.request(), https.request()
   */
  private detectApiCalls(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call_expression');
    const httpMethods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      // fetch API
      if (funcText === 'fetch' || funcText.endsWith('.fetch')) {
        pattern = TYPESCRIPT_PATTERNS.fetch_call;
      }
      // axios
      else if (httpMethods.some(m => this.matchesPattern(funcText, 
          [`axios.${m}`, `axios`])) || funcText === 'axios') {
        pattern = TYPESCRIPT_PATTERNS.axios_call;
      }
      // http/https modules
      else if (this.matchesPattern(funcText, ['http.request', 'https.request',
          'http.get', 'https.get'])) {
        pattern = TYPESCRIPT_PATTERNS.http_request;
      }

      if (pattern) {
        const { enclosingFunc, enclosingClass, isInTool } = 
          this.getCallContext(call, tree);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(call),
          call.text,
          pattern,
          enclosingFunc,
          enclosingClass,
          isInTool,
          undefined,
          0.85
        ));
      }
    }

    return findings;
  }

  /**
   * Detect database operations.
   * Patterns:
   * - .query(), .execute()
   * - Prisma client methods
   * - TypeORM operations
   */
  private detectDatabaseOperations(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call_expression');

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      // Generic query/execute methods
      if (funcText.endsWith('.query') || funcText.endsWith('.execute')) {
        // Check for database-related context
        if (this.isDatabaseContext(funcText, call, tree)) {
          pattern = TYPESCRIPT_PATTERNS.query_execute;
        }
      }
      // Prisma operations
      else if (this.isPrismaOperation(funcText)) {
        pattern = TYPESCRIPT_PATTERNS.prisma_operation;
      }

      if (pattern) {
        const { enclosingFunc, enclosingClass, isInTool } = 
          this.getCallContext(call, tree);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(call),
          call.text,
          pattern,
          enclosingFunc,
          enclosingClass,
          isInTool,
          undefined,
          0.8
        ));
      }
    }

    return findings;
  }

  /**
   * Detect code execution.
   * Patterns:
   * - eval()
   * - new Function()
   * - vm.runInContext(), vm.runInNewContext()
   */
  private detectCodeExecution(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];

    // Check call expressions for eval
    const callExpressions = this.walker.findNodesByType(tree, 'call_expression');
    
    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      if (funcText === 'eval') {
        pattern = TYPESCRIPT_PATTERNS.eval_call;
      }
      // vm module
      else if (this.matchesPattern(funcText, ['vm.runInContext', 
          'vm.runInNewContext', 'vm.runInThisContext', 'vm.compileFunction'])) {
        pattern = TYPESCRIPT_PATTERNS.eval_call;
      }

      if (pattern) {
        const { enclosingFunc, enclosingClass, isInTool } = 
          this.getCallContext(call, tree);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(call),
          call.text,
          pattern,
          enclosingFunc,
          enclosingClass,
          isInTool,
          undefined,
          0.95
        ));
      }
    }

    // Check new expressions for Function constructor
    const newExpressions = this.walker.findNodesByType(tree, 'new_expression');
    
    for (const newExpr of newExpressions) {
      const constructorNode = newExpr.childForFieldName('constructor');
      if (!constructorNode) continue;

      if (constructorNode.text === 'Function') {
        const { enclosingFunc, enclosingClass, isInTool } = 
          this.getCallContext(newExpr, tree);
        
        findings.push(createFinding(
          filePath,
          this.walker.getNodeLocation(newExpr),
          newExpr.text,
          TYPESCRIPT_PATTERNS.function_constructor,
          enclosingFunc,
          enclosingClass,
          isInTool,
          undefined,
          0.95
        ));
      }
    }

    return findings;
  }

  // --- Helper methods ---

  private isToolClass(text: string): boolean {
    const patterns = [
      'DynamicTool', 'StructuredTool', 'DynamicStructuredTool',
      'Tool', 'BaseTool'
    ];
    return patterns.some(p => text === p || text.endsWith('.' + p));
  }

  private matchesPattern(text: string, patterns: string[]): boolean {
    return patterns.some(pattern => 
      text === pattern || text.endsWith(pattern) || text.includes(pattern)
    );
  }

  private isPrismaOperation(funcText: string): boolean {
    // Prisma patterns: prisma.user.create, prisma.post.findMany, etc.
    const prismaOperations = [
      'create', 'createMany', 'update', 'updateMany', 'upsert',
      'delete', 'deleteMany', 'findUnique', 'findFirst', 'findMany',
      'aggregate', 'groupBy', 'count'
    ];
    
    // Check if it looks like prisma.model.operation
    if (funcText.includes('prisma.') || funcText.includes('$transaction')) {
      return prismaOperations.some(op => funcText.endsWith('.' + op));
    }
    return false;
  }

  private isDatabaseContext(
    funcText: string,
    call: Parser.SyntaxNode,
    tree: Parser.Tree
  ): boolean {
    // Heuristics for database context:
    // 1. Variable name contains db, database, pool, connection, client
    // 2. Part of a chain that includes common DB patterns
    const dbIndicators = ['db', 'database', 'pool', 'connection', 'client', 
      'mysql', 'postgres', 'pg', 'mongo', 'sqlite', 'knex', 'sequelize'];
    
    const lowerText = funcText.toLowerCase();
    return dbIndicators.some(indicator => lowerText.includes(indicator));
  }

  private getFunctionName(funcNode: Parser.SyntaxNode): string | undefined {
    const nameNode = funcNode.childForFieldName('name');
    return nameNode?.text;
  }

  private getClassName(classNode: Parser.SyntaxNode): string | undefined {
    const nameNode = classNode.childForFieldName('name');
    return nameNode?.text;
  }

  private getCallContext(
    call: Parser.SyntaxNode,
    tree?: Parser.Tree
  ): { enclosingFunc?: string; enclosingClass?: string; isInTool: boolean } {
    const enclosingFuncNode = this.walker.getEnclosingFunction(call, 'typescript');
    const enclosingClassNode = this.walker.getEnclosingClass(call, 'typescript');
    
    const enclosingFunc = enclosingFuncNode ? 
      this.getFunctionName(enclosingFuncNode) : undefined;
    const enclosingClass = enclosingClassNode ? 
      this.getClassName(enclosingClassNode) : undefined;

    // Heuristic: check if we're inside a tool-related context
    let isInTool = false;
    let current: Parser.SyntaxNode | null = call.parent;
    
    while (current) {
      // Check for tool-related patterns in ancestor nodes
      if (current.type === 'call_expression') {
        const func = current.childForFieldName('function');
        if (func && (func.text === 'tool' || this.isToolClass(func.text))) {
          isInTool = true;
          break;
        }
      }
      // Check variable declarations with tool-related names
      if (current.type === 'variable_declarator') {
        const name = current.childForFieldName('name');
        if (name && /tool/i.test(name.text)) {
          isInTool = true;
          break;
        }
      }
      current = current.parent;
    }

    return { enclosingFunc, enclosingClass, isInTool };
  }
}
