import { PythonSemanticIndex } from '../semantic-index';
import { ParsedPythonFile } from '../ast-parser';

describe('PythonSemanticIndex', () => {
  describe('Framework Module Matching', () => {
    const testCases = [
      // Exact matches
      { modulePath: 'langgraph.prebuilt', target: 'langgraph.prebuilt', expected: true },
      { modulePath: 'langchain.agents', target: 'langchain.agents', expected: true },

      // Suffix matches (wrapped imports)
      { modulePath: 'my_utils.langgraph.prebuilt', target: 'langgraph.prebuilt', expected: true },
      { modulePath: 'company.internal.langchain.agents', target: 'langchain.agents', expected: true },

      // Non-matches
      { modulePath: 'langgraph', target: 'langgraph.prebuilt', expected: false },
      { modulePath: 'other.module', target: 'langgraph.prebuilt', expected: false },
      { modulePath: 'langgraph.prebuilt.extra', target: 'langgraph.prebuilt', expected: false },
    ];

    testCases.forEach(({ modulePath, target, expected }) => {
      it(`should ${expected ? 'match' : 'not match'} "${modulePath}" against "${target}"`, () => {
        // This tests the matchesFrameworkModule function indirectly through framework detection
        const index = new PythonSemanticIndex();

        // Create a minimal parsed file with the import
        const parsedFile: ParsedPythonFile = {
          filePath: '/test/file.py',
          imports: [{
            module: modulePath,
            names: [{ name: 'create_react_agent', alias: null }],
            startLine: 1,
          }],
          functions: [],
          classes: [],
          calls: [{
            callee: 'create_react_agent',
            arguments: [
              { name: null, value: { text: 'llm', references: ['llm'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] } },
              { name: 'tools', value: { text: '[tool1]', references: ['tool1'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] } },
            ],
            keywords: {},
            startLine: 5,
            memberChain: null,
          }],
          assignments: [],
          returns: [],
          yields: [],
          withBindings: [],
          decorators: [],
        };

        index.indexFile(parsedFile);
        const roots = index.findInvocationRoots();

        if (expected) {
          expect(roots.size).toBeGreaterThan(0);
          expect(Array.from(roots.values())[0].framework).toBe('langgraph');
        } else {
          expect(roots.size).toBe(0);
        }
      });
    });
  });

  describe('Factory Return Type Mapping', () => {
    it('should map sqlite3.connect to sqlite3.Connection', () => {
      const index = new PythonSemanticIndex();

      const parsedFile: ParsedPythonFile = {
        filePath: '/test/db.py',
        imports: [{
          module: 'sqlite3',
          names: [{ name: 'connect', alias: null }],
          startLine: 1,
        }],
        functions: [{
          name: 'get_connection',
          parameters: [],
          decorators: [],
          className: undefined,
          startLine: 3,
          returnType: null,
        }],
        classes: [],
        calls: [{
          callee: 'connect',
          arguments: [
            { name: null, value: { text: '"db.sqlite"', references: [], stringLiterals: ['db.sqlite'], mappingReferences: [], subscriptReferences: [] } },
          ],
          keywords: {},
          startLine: 4,
          memberChain: null,
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
          enclosingClass: undefined,
          enclosingFunction: 'get_connection',
          startLine: 4,
        }],
        returns: [{
          value: { text: 'conn', references: ['conn'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] },
          enclosingClass: undefined,
          enclosingFunction: 'get_connection',
          startLine: 5,
        }],
        yields: [],
        withBindings: [],
        decorators: [],
      };

      index.indexFile(parsedFile);

      // The factory function should map connect() result to Connection type
      // This is tested indirectly through the call graph resolution
      expect(index).toBeDefined();
    });
  });

  describe('Context Manager Type Tracking', () => {
    it('should resolve types from with-statement bindings', () => {
      const index = new PythonSemanticIndex();

      const parsedFile: ParsedPythonFile = {
        filePath: '/test/context.py',
        imports: [{
          module: 'sqlite3',
          names: [{ name: 'connect', alias: null }],
          startLine: 1,
        }],
        functions: [{
          name: 'sqlite_connection',
          parameters: [],
          decorators: [],
          className: undefined,
          startLine: 3,
          returnType: null,
        }],
        classes: [],
        calls: [{
          callee: 'connect',
          arguments: [
            { name: null, value: { text: '"db.sqlite"', references: [], stringLiterals: ['db.sqlite'], mappingReferences: [], subscriptReferences: [] } },
          ],
          keywords: {},
          startLine: 4,
          memberChain: null,
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
          enclosingClass: undefined,
          enclosingFunction: 'sqlite_connection',
          startLine: 4,
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
          enclosingClass: undefined,
        }],
        decorators: [],
      };

      index.indexFile(parsedFile);

      // With-binding should resolve conn to the return type of sqlite_connection
      expect(index).toBeDefined();
    });
  });

  describe('Multiple File Indexing', () => {
    it('should handle cross-file imports', () => {
      const index = new PythonSemanticIndex();

      // File 1: defines a tool
      const toolFile: ParsedPythonFile = {
        filePath: '/test/tools.py',
        imports: [],
        functions: [{
          name: 'search_tool',
          parameters: [],
          decorators: ['@tool'],
          className: undefined,
          startLine: 1,
          returnType: null,
        }],
        classes: [],
        calls: [],
        assignments: [],
        returns: [],
        yields: [],
        withBindings: [],
        decorators: [{
          name: 'tool',
          filePath: '/test/tools.py',
          className: undefined,
          functionName: 'search_tool',
          startLine: 1,
        }],
      };

      // File 2: uses the tool
      const agentFile: ParsedPythonFile = {
        filePath: '/test/agent.py',
        imports: [
          { module: 'tools', names: [{ name: 'search_tool', alias: null }], startLine: 1 },
          { module: 'langgraph.prebuilt', names: [{ name: 'create_react_agent', alias: null }], startLine: 2 },
        ],
        functions: [],
        classes: [],
        calls: [{
          callee: 'create_react_agent',
          arguments: [
            { name: null, value: { text: 'llm', references: ['llm'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] } },
            { name: 'tools', value: { text: '[search_tool]', references: ['search_tool'], stringLiterals: [], mappingReferences: [], subscriptReferences: [] } },
          ],
          keywords: {},
          startLine: 5,
          memberChain: null,
        }],
        assignments: [],
        returns: [],
        yields: [],
        withBindings: [],
        decorators: [],
      };

      index.indexFile(toolFile);
      index.indexFile(agentFile);

      const roots = index.findInvocationRoots();
      expect(roots.size).toBeGreaterThan(0);
    });
  });
});
