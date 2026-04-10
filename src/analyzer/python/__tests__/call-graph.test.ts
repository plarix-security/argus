import { buildCallGraph } from '../call-graph';
import { ParsedPythonFile } from '../ast-parser';

describe('Python Call Graph - Dangerous Operation Detection', () => {
  describe('HTTP Client Detection', () => {
    it('should detect requests.get as dangerous HTTP operation', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [
          {
            module: 'requests',
            names: [{ name: 'get' }],
            isFrom: true,
          },
          {
            module: 'langchain_core.tools',
            names: [{ name: 'tool' }],
            isFrom: true,
          },
        ],
        functions: [{
          name: 'make_request',
          decorators: ['tool'],
          startLine: 3,
          endLine: 5,
          body: [],
          isAsync: false,
          isMethod: false,
        }],
        classes: [],
        calls: [{
          callee: 'get',
          startLine: 4,
          startColumn: 0,
          codeSnippet: 'get("https://api.example.com")',
          enclosingFunction: 'make_request',
          arguments: ['"https://api.example.com"'],
          argumentDetails: [{
            value: {
              text: '"https://api.example.com"',
              references: [],
              stringLiterals: ['https://api.example.com'],
              mappingReferences: [],
              subscriptReferences: [],
            },
          }],
        }],
        assignments: [],
        returns: [],
        yields: [],
        withBindings: [],
        decoratorDefs: [],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: true,
      };

      const files = new Map([
        ['/test/http.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);
      const operations = graph.exposedPaths.map(p => p.operation);

      expect(operations.length).toBeGreaterThan(0);
      const httpOps = operations.filter(op => op.callee.includes('requests') || op.callee.includes('get'));
      expect(httpOps.length).toBeGreaterThan(0);
    });
  });

  describe('Database Client Detection', () => {
    it('should detect sqlite3.Connection.execute as dangerous SQL operation', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [
          {
            module: 'sqlite3',
            names: [{ name: 'connect' }],
            isFrom: true,
          },
          {
            module: 'langchain_core.tools',
            names: [{ name: 'tool' }],
            isFrom: true,
          },
        ],
        functions: [{
          name: 'run_query',
          decorators: ['tool'],
          startLine: 3,
          endLine: 6,
          body: [],
          isAsync: false,
          isMethod: false,
        }],
        classes: [],
        calls: [
          {
            callee: 'connect',
            startLine: 4,
            startColumn: 0,
            codeSnippet: 'connect("db.sqlite")',
            enclosingFunction: 'run_query',
            arguments: ['"db.sqlite"'],
            argumentDetails: [{
              value: {
                text: '"db.sqlite"',
                references: [],
                stringLiterals: ['db.sqlite'],
                mappingReferences: [],
                subscriptReferences: [],
              },
            }],
          },
          {
            callee: 'conn.execute',
            startLine: 5,
            startColumn: 0,
            codeSnippet: 'conn.execute(query)',
            enclosingFunction: 'run_query',
            arguments: ['query'],
            argumentDetails: [{
              value: {
                text: 'query',
                references: ['query'],
                stringLiterals: [],
                mappingReferences: [],
                subscriptReferences: [],
              },
            }],
            memberChain: ['conn', 'execute'],
          },
        ],
        assignments: [{
          target: 'conn',
          value: {
            text: 'connect("db.sqlite")',
            references: [],
            stringLiterals: ['db.sqlite'],
            mappingReferences: [],
            subscriptReferences: [],
            callCallee: 'connect',
          },
          startLine: 4,
          enclosingFunction: 'run_query',
        }],
        returns: [],
        yields: [],
        withBindings: [],
        decoratorDefs: [],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: true,
      };

      const files = new Map([
        ['/test/db.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);
      const operations = graph.exposedPaths.map(p => p.operation);

      expect(operations.length).toBeGreaterThan(0);
      const sqlOps = operations.filter(op => op.callee.includes('sqlite3') || op.callee.includes('execute'));
      expect(sqlOps.length).toBeGreaterThan(0);
    });
  });

  describe('Shell Execution Detection', () => {
    it('should detect subprocess.run as dangerous shell operation', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [
          {
            module: 'subprocess',
            names: [{ name: 'run' }],
            isFrom: true,
          },
          {
            module: 'langchain_core.tools',
            names: [{ name: 'tool' }],
            isFrom: true,
          },
        ],
        functions: [{
          name: 'run_command',
          decorators: ['tool'],
          startLine: 3,
          endLine: 5,
          body: [],
          isAsync: false,
          isMethod: false,
        }],
        classes: [],
        calls: [{
          callee: 'run',
          startLine: 4,
          startColumn: 0,
          codeSnippet: 'run(cmd)',
          enclosingFunction: 'run_command',
          arguments: ['cmd'],
          argumentDetails: [{
            value: {
              text: 'cmd',
              references: ['cmd'],
              stringLiterals: [],
              mappingReferences: [],
              subscriptReferences: [],
            },
          }],
        }],
        assignments: [],
        returns: [],
        yields: [],
        withBindings: [],
        decoratorDefs: [],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: true,
      };

      const files = new Map([
        ['/test/shell.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);
      const operations = graph.exposedPaths.map(p => p.operation);

      expect(operations.length).toBeGreaterThan(0);
      const shellOps = operations.filter(op => op.callee.includes('subprocess') || op.callee.includes('run'));
      expect(shellOps.length).toBeGreaterThan(0);
    });
  });

  describe('Call Graph Construction', () => {
    it('should build a valid call graph', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [{
          module: 'langchain_core.tools',
          names: [{ name: 'tool' }],
          isFrom: true,
        }],
        functions: [{
          name: 'check_access',
          decorators: ['tool'],
          startLine: 1,
          endLine: 5,
          body: [],
          isAsync: false,
          isMethod: false,
        }],
        classes: [],
        calls: [{
          callee: 'risky_call',
          startLine: 3,
          startColumn: 0,
          codeSnippet: 'risky_call()',
          enclosingFunction: 'check_access',
          arguments: [],
          argumentDetails: [],
        }],
        assignments: [],
        returns: [],
        yields: [],
        withBindings: [],
        decoratorDefs: [],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: true,
      };

      const files = new Map([
        ['/test/auth.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);

      // Graph should be built successfully
      expect(graph.nodes).toBeDefined();
      expect(graph.toolRegistrations).toBeDefined();
      expect(graph.exposedPaths).toBeDefined();
    });
  });
});
