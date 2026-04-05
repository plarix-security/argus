import { buildCallGraph } from '../call-graph';
import { ParsedPythonFile } from '../ast-parser';

describe('Python Call Graph - Dangerous Operation Detection', () => {
  describe('HTTP Client Detection', () => {
    it('should detect requests.get as dangerous HTTP operation', () => {
      const parsedFile: ParsedPythonFile = {
        filePath: '/test/http.py',
        imports: [{
          module: 'requests',
          names: [{ name: 'get' }],
          startLine: 1,
        }],
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
        decorators: [{
          name: 'tool',
          filePath: '/test/http.py',
          functionName: 'make_request',
          startLine: 3,
        }],
      };

      const files = new Map([
        ['/test/http.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);
      const dangerous = graph.dangerousOperations;

      expect(dangerous.length).toBeGreaterThan(0);
      const httpOps = dangerous.filter((op: any) => op.identity.includes('requests'));
      expect(httpOps.length).toBeGreaterThan(0);
    });
  });

  describe('Database Client Detection', () => {
    it('should detect sqlite3.Connection.execute as dangerous SQL operation', () => {
      const parsedFile: ParsedPythonFile = {
        filePath: '/test/db.py',
        imports: [{
          module: 'sqlite3',
          names: [{ name: 'connect' }],
          startLine: 1,
        }],
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
        decorators: [{
          name: 'tool',
          filePath: '/test/db.py',
          functionName: 'run_query',
          startLine: 3,
        }],
      };

      const files = new Map([
        ['/test/db.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);
      const dangerous = graph.dangerousOperations;

      expect(dangerous.length).toBeGreaterThan(0);
      const sqlOps = dangerous.filter((op: any) => op.identity.includes('sqlite3'));
      expect(sqlOps.length).toBeGreaterThan(0);
    });
  });

  describe('Shell Execution Detection', () => {
    it('should detect subprocess.run as dangerous shell operation', () => {
      const parsedFile: ParsedPythonFile = {
        filePath: '/test/shell.py',
        imports: [{
          module: 'subprocess',
          names: [{ name: 'run' }],
          startLine: 1,
        }],
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
        decorators: [{
          name: 'tool',
          filePath: '/test/shell.py',
          functionName: 'run_command',
          startLine: 3,
        }],
      };

      const files = new Map([
        ['/test/shell.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);
      const dangerous = graph.dangerousOperations;

      expect(dangerous.length).toBeGreaterThan(0);
      const shellOps = dangerous.filter((op: any) => op.identity.includes('subprocess'));
      expect(shellOps.length).toBeGreaterThan(0);
    });
  });

  describe('Authorization Gate Detection', () => {
    it('should recognize pattern-based authorization exceptions', () => {
      const parsedFile: ParsedPythonFile = {
        filePath: '/test/auth.py',
        imports: [],
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
          hasTryExcept: true,
          exceptionTypes: ['PermissionDenied'],
        }],
        assignments: [],
        returns: [],
        yields: [],
        withBindings: [],
        decorators: [{
          name: 'tool',
          filePath: '/test/auth.py',
          functionName: 'check_access',
          startLine: 1,
        }],
      };

      const files = new Map([
        ['/test/auth.py', parsedFile]
      ]);

      const graph = buildCallGraph(files);
      const gated = graph.dangerousOperations.filter((op: any) => op.hasAuthGate);

      // Should detect the auth gate based on exception pattern
      expect(gated.length).toBeGreaterThan(0);
    });
  });
});
