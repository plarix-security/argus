const {initParser, parseTypeScriptSource} = require('./dist/analyzer/typescript/ast-parser.js');
const fs = require('fs');

(async () => {
  await initParser();

  const code = fs.readFileSync('test-action.ts', 'utf8');
  const parsed = parseTypeScriptSource(code);

  console.log('Parse Success:', parsed.success);
  console.log('Functions:', parsed.functions.map(f => ({
    name: f.name,
    startLine: f.startLine,
    endLine: f.endLine
  })));

  console.log('\nCalls:', parsed.calls.map(c => ({
    callee: c.callee,
    line: c.line,
    enclosingFunction: c.enclosingFunction
  })));

  console.log('\nImports:', parsed.imports.map(i => ({
    names: i.names,
    module: i.module
  })));
})();
