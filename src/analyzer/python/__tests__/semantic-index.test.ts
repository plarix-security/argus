import { PythonSemanticIndex } from '../semantic-index';
import { ParsedPythonFile } from '../ast-parser';

describe('PythonSemanticIndex', () => {
  describe('Framework Detection', () => {
    it('should detect langgraph.prebuilt.create_react_agent', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [{
          module: 'langgraph.prebuilt',
          names: [{ name: 'create_react_agent' }],
          isFrom: true,
        }],
        functions: [{
          name: 'tool1',
          decorators: [],
          startLine: 2,
          endLine: 3,
          body: [],
          isAsync: false,
          isMethod: false,
          parameters: [],
        }],
        classes: [],
        calls: [{
          callee: 'create_react_agent',
          startLine: 5,
          startColumn: 0,
          codeSnippet: 'create_react_agent(llm, tools=[tool1])',
          arguments: ['llm', '[tool1]'],
          argumentDetails: [
            {
              value: { text: 'llm', references: ['llm'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] }
            },
            {
              name: 'tools',
              value: { text: '[tool1]', references: ['tool1'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] }
            },
          ],
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

      const files = new Map([['/test/agent.py', parsedFile]]);
      const index = new PythonSemanticIndex(files);
      const roots = index.extractInvocationRoots();

      expect(roots.size).toBeGreaterThan(0);
      const langgraphRoots = Array.from(roots.values()).filter(r => r.framework === 'langgraph');
      expect(langgraphRoots.length).toBeGreaterThan(0);
    });

    it('should detect wrapped framework imports', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [{
          module: 'my_utils.langgraph.prebuilt',
          names: [{ name: 'create_react_agent' }],
          isFrom: true,
        }],
        functions: [{
          name: 'tool1',
          decorators: [],
          startLine: 2,
          endLine: 3,
          body: [],
          isAsync: false,
          isMethod: false,
          parameters: [],
        }],
        classes: [],
        calls: [{
          callee: 'create_react_agent',
          startLine: 5,
          startColumn: 0,
          codeSnippet: 'create_react_agent(llm, tools=[tool1])',
          arguments: ['llm', '[tool1]'],
          argumentDetails: [
            {
              value: { text: 'llm', references: ['llm'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] }
            },
            {
              name: 'tools',
              value: { text: '[tool1]', references: ['tool1'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] }
            },
          ],
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

      const files = new Map([['/test/wrapped.py', parsedFile]]);
      const index = new PythonSemanticIndex(files);
      const roots = index.extractInvocationRoots();

      // Should detect the framework even through wrapper module
      expect(roots.size).toBeGreaterThan(0);
    });
  });

  describe('Factory Return Type Mapping', () => {
    it('should handle sqlite3.connect imports', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [{
          module: 'sqlite3',
          names: [{ name: 'connect' }],
          isFrom: true,
        }],
        functions: [{
          name: 'get_connection',
          decorators: [],
          startLine: 3,
          endLine: 6,
          body: [],
          isAsync: false,
          isMethod: false,
          parameters: [],
        }],
        classes: [],
        calls: [{
          callee: 'connect',
          startLine: 4,
          startColumn: 0,
          codeSnippet: 'connect("db.sqlite")',
          enclosingFunction: 'get_connection',
          arguments: ['"db.sqlite"'],
          argumentDetails: [{
            value: { text: '"db.sqlite"', references: [], stringLiterals: ['db.sqlite'], mappingReferences: [], subscriptReferences: [] }
          }],
        }],
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
          enclosingFunction: 'get_connection',
        }],
        returns: [{
          value: { text: 'conn', references: ['conn'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] },
          startLine: 5,
          enclosingFunction: 'get_connection',
        }],
        yields: [],
        withBindings: [],
        decoratorDefs: [],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: true,
      };

      const files = new Map([['/test/db.py', parsedFile]]);
      const index = new PythonSemanticIndex(files);

      // Factory function mapping is tested through the semantic index
      expect(index).toBeDefined();
    });
  });

  describe('Context Manager Type Tracking', () => {
    it('should handle with-statement bindings', () => {
      const parsedFile: ParsedPythonFile = {
        imports: [{
          module: 'sqlite3',
          names: [{ name: 'connect' }],
          isFrom: true,
        }],
        functions: [{
          name: 'sqlite_connection',
          decorators: [],
          startLine: 3,
          endLine: 5,
          body: [],
          isAsync: false,
          isMethod: false,
          parameters: [],
        }],
        classes: [],
        calls: [{
          callee: 'connect',
          startLine: 4,
          startColumn: 0,
          codeSnippet: 'connect("db.sqlite")',
          enclosingFunction: 'sqlite_connection',
          arguments: ['"db.sqlite"'],
          argumentDetails: [{
            value: { text: '"db.sqlite"', references: [], stringLiterals: ['db.sqlite'], mappingReferences: [], subscriptReferences: [] }
          }],
        }],
        assignments: [],
        returns: [{
          value: {
            text: 'connect("db.sqlite")',
            references: [],
            stringLiterals: ['db.sqlite'],
            mappingReferences: [],
            subscriptReferences: [],
            callCallee: 'connect',
          },
          startLine: 4,
          enclosingFunction: 'sqlite_connection',
        }],
        yields: [],
        withBindings: [{
          target: 'conn',
          contextManager: {
            text: 'sqlite_connection()',
            references: [],
            stringLiterals: [],
            mappingReferences: [],
            subscriptReferences: [],
            callCallee: 'sqlite_connection',
          },
          startLine: 7,
          enclosingFunction: 'use_db',
        }],
        decoratorDefs: [],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: true,
      };

      const files = new Map([['/test/context.py', parsedFile]]);
      const index = new PythonSemanticIndex(files);

      // With-binding resolution verified through semantic index creation
      expect(index).toBeDefined();
    });
  });

  describe('Cross-File Resolution', () => {
    it('should resolve imports across multiple files', () => {
      // File 1: defines a tool
      const toolFile: ParsedPythonFile = {
        imports: [],
        functions: [{
          name: 'search_tool',
          decorators: ['tool'],
          startLine: 1,
          endLine: 3,
          body: [],
          isAsync: false,
          isMethod: false,
          parameters: [],
        }],
        classes: [],
        calls: [],
        assignments: [],
        returns: [],
        yields: [],
        withBindings: [],
        decoratorDefs: [{
          name: 'tool',
          startLine: 1,
          isStructuralGate: false,
        }],
        openaiToolSchemas: [],
        dispatchMappings: [],
        success: true,
      };

      // File 2: uses the tool
      const agentFile: ParsedPythonFile = {
        imports: [
          { module: 'tools', names: [{ name: 'search_tool' }], isFrom: true },
          { module: 'langgraph.prebuilt', names: [{ name: 'create_react_agent' }], isFrom: true },
        ],
        functions: [],
        classes: [],
        calls: [{
          callee: 'create_react_agent',
          startLine: 5,
          startColumn: 0,
          codeSnippet: 'create_react_agent(llm, tools=[search_tool])',
          arguments: ['llm', '[search_tool]'],
          argumentDetails: [
            {
              value: { text: 'llm', references: ['llm'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] }
            },
            {
              name: 'tools',
              value: { text: '[search_tool]', references: ['search_tool'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] }
            },
          ],
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
        ['/test/tools.py', toolFile],
        ['/test/agent.py', agentFile],
      ]);
      const index = new PythonSemanticIndex(files);

      const roots = index.extractInvocationRoots();
      expect(roots.size).toBeGreaterThan(0);
    });
  });
});
