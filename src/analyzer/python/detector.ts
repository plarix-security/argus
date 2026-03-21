/**
 * Python AFB04 Detector
 *
 * Detects AFB04 (Unauthorized Action) execution points in Python code
 * through AST analysis. Specifically targets:
 *
 * 1. Tool definitions (LangChain @tool, CrewAI tools)
 * 2. Shell command execution (subprocess, os.system)
 * 3. File operations (open, pathlib, shutil)
 * 4. API calls (requests, httpx, aiohttp, urllib)
 * 5. Database operations (cursor.execute, SQLAlchemy)
 * 6. Code execution (eval, exec)
 */

import Parser from 'tree-sitter';
import { ASTWalker } from '../ast-walker';
import {
  AFBFinding,
  FileAnalysisResult,
  NodeLocation,
} from '../../types';
import {
  PYTHON_PATTERNS,
  ExecutionPattern,
  createFinding,
} from '../../afb/afb04';

/**
 * Python-specific detector for AFB04 execution points.
 */
export class PythonDetector {
  private walker: ASTWalker;

  constructor(walker: ASTWalker) {
    this.walker = walker;
  }

  /**
   * Analyze a Python file for AFB04 execution points.
   */
  analyzeFile(filePath: string, sourceCode: string): FileAnalysisResult {
    const startTime = Date.now();
    const findings: AFBFinding[] = [];

    try {
      const tree = this.walker.parse(sourceCode, 'python', filePath);
      
      // Collect all findings
      findings.push(...this.detectToolDefinitions(tree, filePath, sourceCode));
      findings.push(...this.detectShellExecution(tree, filePath, sourceCode));
      findings.push(...this.detectFileOperations(tree, filePath, sourceCode));
      findings.push(...this.detectApiCalls(tree, filePath, sourceCode));
      findings.push(...this.detectDatabaseOperations(tree, filePath, sourceCode));
      findings.push(...this.detectCodeExecution(tree, filePath, sourceCode));

      return {
        file: filePath,
        language: 'python',
        findings,
        success: true,
        analysisTimeMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        file: filePath,
        language: 'python',
        findings: [],
        success: false,
        error: error instanceof Error ? error.message : String(error),
        analysisTimeMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Detect LangChain/CrewAI tool definitions.
   * Patterns:
   * - @tool decorator
   * - Tool() class instantiation
   * - BaseTool subclass
   * - StructuredTool, DynamicTool
   */
  private detectToolDefinitions(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];

    // Find decorated functions (looking for @tool)
    const decoratedDefs = this.walker.findNodesByType(tree, 'decorated_definition');
    
    for (const decorated of decoratedDefs) {
      const decorators = decorated.descendantsOfType('decorator');
      
      for (const decorator of decorators) {
        const decoratorText = decorator.text;
        
        // Check for @tool decorator (LangChain)
        if (this.isToolDecorator(decoratorText)) {
          const funcDef = decorated.descendantsOfType('function_definition')[0] ||
                          decorated.descendantsOfType('async_function_definition')[0];
          
          if (funcDef) {
            const funcName = this.getFunctionName(funcDef);
            findings.push(this.createToolFinding(
              filePath,
              decorator,
              sourceCode,
              PYTHON_PATTERNS.tool_decorator,
              funcName,
              undefined,
              'langchain'
            ));
          }
        }
      }
    }

    // Find Tool instantiations
    const callExpressions = this.walker.findNodesByType(tree, 'call');
    
    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      
      // Check for Tool(), DynamicTool(), StructuredTool() instantiation
      if (this.isToolInstantiation(funcText)) {
        const enclosingFunc = this.walker.getEnclosingFunction(call, 'python');
        const enclosingClass = this.walker.getEnclosingClass(call, 'python');
        
        findings.push(this.createToolFinding(
          filePath,
          call,
          sourceCode,
          PYTHON_PATTERNS.tool_instantiation,
          enclosingFunc ? this.getFunctionName(enclosingFunc) : undefined,
          enclosingClass ? this.getClassName(enclosingClass) : undefined,
          this.detectToolFramework(funcText)
        ));
      }
    }

    // Find BaseTool subclasses
    const classDefs = this.walker.findNodesByType(tree, 'class_definition');
    
    for (const classDef of classDefs) {
      const superclasses = classDef.childForFieldName('superclasses');
      if (superclasses && this.isToolBaseClass(superclasses.text)) {
        const className = this.getClassName(classDef);
        findings.push(this.createToolFinding(
          filePath,
          classDef,
          sourceCode,
          PYTHON_PATTERNS.tool_instantiation,
          undefined,
          className,
          'langchain'
        ));
      }
    }

    return findings;
  }

  /**
   * Detect shell command execution.
   * Patterns:
   * - subprocess.run(), subprocess.Popen(), subprocess.call()
   * - os.system(), os.popen()
   */
  private detectShellExecution(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call');

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      // subprocess module calls
      if (this.matchesPattern(funcText, ['subprocess.run', 'subprocess.Popen', 
          'subprocess.call', 'subprocess.check_output', 'subprocess.check_call'])) {
        pattern = PYTHON_PATTERNS.subprocess_run;
      }
      // os.system
      else if (this.matchesPattern(funcText, ['os.system'])) {
        pattern = PYTHON_PATTERNS.os_system;
      }
      // os.popen
      else if (this.matchesPattern(funcText, ['os.popen'])) {
        pattern = PYTHON_PATTERNS.os_popen;
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
          0.95 // High confidence for these patterns
        ));
      }
    }

    return findings;
  }

  /**
   * Detect file operations.
   * Patterns:
   * - open() with write modes
   * - pathlib.Path.write_text(), write_bytes()
   * - shutil.copy(), shutil.move(), shutil.rmtree()
   */
  private detectFileOperations(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call');

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;
      let confidence = 0.8;

      // Built-in open()
      if (funcText === 'open') {
        pattern = PYTHON_PATTERNS.file_open;
        // Check mode argument for write operations
        const args = call.childForFieldName('arguments');
        if (args && this.hasWriteMode(args.text)) {
          pattern = { ...PYTHON_PATTERNS.file_open };
          confidence = 0.9;
        }
      }
      // pathlib write operations
      else if (this.matchesPattern(funcText, ['.write_text', '.write_bytes', 
          'Path.write_text', 'Path.write_bytes'])) {
        pattern = PYTHON_PATTERNS.pathlib_write;
        confidence = 0.9;
      }
      // shutil operations
      else if (this.matchesPattern(funcText, ['shutil.copy', 'shutil.copy2',
          'shutil.move', 'shutil.rmtree', 'shutil.copytree'])) {
        pattern = PYTHON_PATTERNS.shutil_operation;
        confidence = 0.95;
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
          confidence
        ));
      }
    }

    return findings;
  }

  /**
   * Detect HTTP/API calls.
   * Patterns:
   * - requests.get(), requests.post(), etc.
   * - httpx.get(), httpx.post(), etc.
   * - aiohttp.ClientSession
   * - urllib.request.urlopen()
   */
  private detectApiCalls(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call');

    const httpMethods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      // requests library
      if (httpMethods.some(m => this.matchesPattern(funcText, [`requests.${m}`]))) {
        pattern = PYTHON_PATTERNS.requests_call;
      }
      // httpx library
      else if (httpMethods.some(m => this.matchesPattern(funcText, [`httpx.${m}`])) ||
               this.matchesPattern(funcText, ['httpx.AsyncClient', 'httpx.Client'])) {
        pattern = PYTHON_PATTERNS.httpx_call;
      }
      // aiohttp
      else if (this.matchesPattern(funcText, ['aiohttp.ClientSession', 
          'session.get', 'session.post', 'client.get', 'client.post'])) {
        pattern = PYTHON_PATTERNS.aiohttp_call;
      }
      // urllib
      else if (this.matchesPattern(funcText, ['urllib.request.urlopen', 'urlopen'])) {
        pattern = PYTHON_PATTERNS.urllib_call;
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
   * - cursor.execute()
   * - session.execute(), session.commit()
   * - engine.execute()
   */
  private detectDatabaseOperations(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call');

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      // Raw cursor execute
      if (funcText.endsWith('.execute') && 
          (funcText.includes('cursor') || funcText.includes('conn'))) {
        pattern = PYTHON_PATTERNS.cursor_execute;
      }
      // SQLAlchemy session operations
      else if (this.matchesPattern(funcText, ['session.execute', 'session.commit',
          'session.add', 'session.delete', 'session.merge'])) {
        pattern = PYTHON_PATTERNS.sqlalchemy_execute;
      }
      // Engine execute
      else if (funcText.endsWith('.execute') && 
               (funcText.includes('engine') || funcText.includes('connection'))) {
        pattern = PYTHON_PATTERNS.sqlalchemy_execute;
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
   * - exec()
   * - compile()
   */
  private detectCodeExecution(
    tree: Parser.Tree,
    filePath: string,
    sourceCode: string
  ): AFBFinding[] {
    const findings: AFBFinding[] = [];
    const callExpressions = this.walker.findNodesByType(tree, 'call');

    for (const call of callExpressions) {
      const funcNode = call.childForFieldName('function');
      if (!funcNode) continue;

      const funcText = funcNode.text;
      let pattern: ExecutionPattern | null = null;

      if (funcText === 'eval') {
        pattern = PYTHON_PATTERNS.eval_call;
      } else if (funcText === 'exec') {
        pattern = PYTHON_PATTERNS.exec_call;
      } else if (funcText === 'compile') {
        pattern = PYTHON_PATTERNS.compile_call;
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
          0.95 // High confidence for these builtins
        ));
      }
    }

    return findings;
  }

  // --- Helper methods ---

  private isToolDecorator(text: string): boolean {
    // Match @tool, @tool(), @langchain.tools.tool, etc.
    return /^@(tool|langchain[.\w]*tool|crewai[.\w]*tool)/i.test(text);
  }

  private isToolInstantiation(text: string): boolean {
    const patterns = [
      'Tool', 'DynamicTool', 'StructuredTool', 'BaseTool',
      'create_tool', 'tool_from_function'
    ];
    return patterns.some(p => text === p || text.endsWith('.' + p));
  }

  private isToolBaseClass(superclassText: string): boolean {
    const patterns = ['BaseTool', 'StructuredTool', 'Tool'];
    return patterns.some(p => superclassText.includes(p));
  }

  private detectToolFramework(funcText: string): string {
    if (funcText.includes('crewai') || funcText.includes('CrewAI')) {
      return 'crewai';
    }
    if (funcText.includes('langchain') || funcText.includes('LangChain')) {
      return 'langchain';
    }
    return 'custom';
  }

  private matchesPattern(text: string, patterns: string[]): boolean {
    return patterns.some(pattern => 
      text === pattern || text.endsWith(pattern) || text.includes(pattern)
    );
  }

  private hasWriteMode(argsText: string): boolean {
    // Check for write modes: 'w', 'a', 'x', 'r+', 'w+', 'a+', 'wb', etc.
    return /['"]([wax]|r\+|w\+|a\+)[b]?['"]/.test(argsText);
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
    tree: Parser.Tree
  ): { enclosingFunc?: string; enclosingClass?: string; isInTool: boolean } {
    const enclosingFuncNode = this.walker.getEnclosingFunction(call, 'python');
    const enclosingClassNode = this.walker.getEnclosingClass(call, 'python');
    
    const enclosingFunc = enclosingFuncNode ? 
      this.getFunctionName(enclosingFuncNode) : undefined;
    const enclosingClass = enclosingClassNode ? 
      this.getClassName(enclosingClassNode) : undefined;

    // Check if inside a tool definition
    let isInTool = false;
    if (enclosingFuncNode) {
      const decorators = this.walker.getPythonDecorators(enclosingFuncNode);
      isInTool = decorators.some(d => this.isToolDecorator('@' + d));
    }
    if (enclosingClassNode && !isInTool) {
      const superclasses = enclosingClassNode.childForFieldName('superclasses');
      isInTool = superclasses ? this.isToolBaseClass(superclasses.text) : false;
    }

    return { enclosingFunc, enclosingClass, isInTool };
  }

  private createToolFinding(
    filePath: string,
    node: Parser.SyntaxNode,
    sourceCode: string,
    pattern: ExecutionPattern,
    enclosingFunc?: string,
    enclosingClass?: string,
    framework?: string
  ): AFBFinding {
    return createFinding(
      filePath,
      this.walker.getNodeLocation(node),
      node.text,
      pattern,
      enclosingFunc,
      enclosingClass,
      true, // Tool definitions are inherently tool-related
      framework,
      0.9 // High confidence for tool definitions
    );
  }
}
