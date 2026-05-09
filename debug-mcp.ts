import { initParser, parseTypeScriptSource } from './src/analyzer/typescript/ast-parser';
import { extractSemanticInvocationRoots } from './src/analyzer/typescript/semantic-index';
import { buildCallGraph } from './src/analyzer/typescript/call-graph';
import * as fs from 'fs';

async function main() {
  await initParser();
  const source = fs.readFileSync('./test-fixtures/langchain-agent.ts', 'utf-8');
  const parsed = parseTypeScriptSource(source, false);
  
  console.log('=== IMPORTS ===');
  for (const imp of parsed.imports) {
    console.log(`  ${imp.module} -> [${imp.names.join(', ')}]`);
  }
  
  console.log('\n=== FUNCTIONS ===');
  for (const func of parsed.functions) {
    console.log(`  ${func.name} (line ${func.startLine}-${func.endLine})`);
  }
  
  console.log('\n=== CALLS ===');
  for (const call of parsed.calls) {
    console.log(`  ${call.callee} (chain: ${call.memberChain.join('.')}) @ line ${call.line} | enclosing: ${call.enclosingFunction || 'module-level'}`);
    if (call.arguments.length > 0) {
      console.log(`    args: ${call.arguments.slice(0, 3).map(a => a.slice(0, 60)).join(' | ')}`);
    }
  }
  
  const files = new Map([['test.ts', parsed]]);
  const roots = extractSemanticInvocationRoots(files);
  console.log('\n=== SEMANTIC ROOTS ===');
  for (const [id, root] of roots) {
    console.log(`  ${id} -> ${root.toolName} (${root.framework}) @ line ${root.line}`);
    console.log(`    evidence: ${root.evidence}`);
  }
  
  const callGraph = buildCallGraph(files, roots);
  console.log('\n=== EXPOSED PATHS ===');
  for (const exposed of callGraph.exposedPaths) {
    console.log(`  tool: ${exposed.tool.name} -> op: ${exposed.operation.callee} @ line ${exposed.operation.line}`);
    console.log(`    path: ${exposed.path.join(' -> ')}`);
    console.log(`    hasGate: ${exposed.hasGate}`);
  }
  
  console.log('\n=== DIAGNOSTICS ===');
  console.log(`  total nodes: ${callGraph.diagnostics.totalNodes}`);
  console.log(`  tool registrations: ${callGraph.diagnostics.totalToolRegistrations}`);
  console.log(`  dangerous ops: ${callGraph.diagnostics.dangerousOperationsDiscovered}`);
  console.log(`  unresolved edges: ${callGraph.diagnostics.unresolvedCallEdges}`);
}

main().catch(console.error);
