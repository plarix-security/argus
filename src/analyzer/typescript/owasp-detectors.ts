import { ParsedTypeScriptFile, CallSite } from './ast-parser';
import { AFBFinding, CEERecord, ExecutionCategory, Severity, OWASPLabel, AFBType } from '../../types';

export function runOWASPDetectors(parsed: ParsedTypeScriptFile, filePath: string): AFBFinding[] {
  const findings: AFBFinding[] = [];

  // Helper to identify if a call is an LLM call
  function isLLMCall(call: CallSite): boolean {
    const callee = call.callee || '';
    if (callee.match(/^(openai|client)\.(chat\.completions\.create|completions\.create)/)) return true;
    if (callee.match(/^(anthropic|client)\.messages\.create/)) return true;
    if (callee.match(/^(agent|chain|model|llm)\.(invoke|ainvoke|call|acall)/)) return true;
    if (callee.match(/^llm\.(complete|acomplete|chat|achat)/)) return true;
    return false;
  }

  // Helper to identify if a call is a RAG retrieval
  function isRAGCall(call: CallSite): boolean {
    const callee = call.callee || '';
    if (callee.match(/^(vectorStore|index|retriever)\.(similaritySearch|query|retrieve|search)/)) return true;
    return false;
  }

  // LLM01: Prompt Injection
  // LLM02: Sensitive Data in Prompts
  // LLM08: RAG without Source Validation

  for (const func of parsed.functions) {
    const callsInFunc = parsed.calls.filter(c => c.enclosingFunction === func.name);
    
    // Check for LLM08 (RAG)
    const ragCalls = callsInFunc.filter(isRAGCall);
    const llmCalls = callsInFunc.filter(isLLMCall);
    
    if (ragCalls.length > 0 && llmCalls.length > 0) {
      // Check for source validation (simple heuristic: if statement checking domain/source/metadata)
      const hasValidation = func.controlFlow?.checksParameters || func.controlFlow?.hasConditionalRaise || func.controlFlow?.hasConditionalReturn;
      // Also look for specific variable checks in if statements?
      // Since we don't have deep AST for if conditions, we can rely on `func.controlFlow` or just check if `hasConditionalRaise` or `hasConditionalReturn` is present.
      // A strict LLM08 detector might check if there's any conditional before the LLM call.
      // Let's do a basic heuristic: if there's no conditional return/raise, or no 'filter'/'validate' calls.
      const hasFilterCall = callsInFunc.some(c => c.callee.includes('filter') || c.callee.includes('validate') || c.callee.includes('check'));
      
      if (!hasValidation && !hasFilterCall) {
        // Flag LLM08
        const ragCall = ragCalls[0];
        findings.push({
          severity: Severity.WARNING,
          type: AFBType.UNAUTHORIZED_ACTION, // Not strictly AFB04, but we need a type. Or we can just use the OWASP label.
          file: filePath,
          line: llmCalls[0].line,
          column: llmCalls[0].column,
          operation: 'LLM Call with unvalidated RAG retrieval',
          explanation: 'Detected vector store retrieval flowing into an LLM call without explicit source validation or filtering.',
          codeSnippet: llmCalls[0].callee,
          category: ExecutionCategory.TOOL_CALL,
          confidence: 0.7,
          owasp: OWASPLabel.L8,
          remediation: 'Validate source domain or metadata before passing retrieved content to LLM. Example: if (!ALLOWED_DOMAINS.includes(source.domain)) filter out.',
        });
      }
    }

    // Build tainted variables for this function
    const taintedVars = new Set<string>();
    // Add parameters
    for (const param of func.parameters) {
      taintedVars.add(param.split(':')[0].trim());
    }
    // Add assignments from req.body, req.query, etc.
    for (const assign of parsed.assignments) {
      if (assign.enclosingFunction === func.name) {
        if (assign.value.includes('req.body') || assign.value.includes('req.query') || assign.value.includes('process.argv')) {
          taintedVars.add(assign.target);
        }
      }
    }

    // Process LLM calls for LLM01 and LLM02
    for (const llmCall of llmCalls) {
      const allArgsString = llmCall.arguments.join(' ');

      // LLM01: Prompt injection from external input
      const usesExternalInput = allArgsString.includes('req.body') || allArgsString.includes('req.query') || allArgsString.includes('process.argv');
      
      let usesTaintedVar = false;
      for (const tVar of taintedVars) {
        if (allArgsString.match(new RegExp(`\\b${tVar}\\b`))) {
          usesTaintedVar = true;
          break;
        }
      }

      if (usesExternalInput || usesTaintedVar) {
        // Is there sanitization?
        const hasSanitization = callsInFunc.some(c => c.callee.includes('sanitize') || c.callee.includes('validate') || c.callee.includes('escape'));
        if (!hasSanitization) {
          findings.push({
            severity: usesExternalInput ? Severity.CRITICAL : Severity.WARNING,
            type: AFBType.UNAUTHORIZED_ACTION,
            file: filePath,
            line: llmCall.line,
            column: llmCall.column,
            operation: 'LLM Call with unsanitized input',
            explanation: 'User-controlled input flows into an LLM call without apparent sanitization or validation.',
            codeSnippet: llmCall.callee,
            category: ExecutionCategory.TOOL_CALL,
            confidence: 0.7,
            owasp: OWASPLabel.L1,
            remediation: 'Implement a sanitization gate or input validation schema before passing external input to the LLM.',
          });
        }
      }

      // LLM02: Sensitive Data in Prompts
      const funcBodyText = func.bodyNode ? func.bodyNode.text : '';
      const hasHardcodedKey = funcBodyText.match(/['"`](sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xoxb-[a-zA-Z0-9-]{20,})['"`]/);
      const usesEnvUnmasked = allArgsString.includes('process.env.') && !allArgsString.includes('.slice(') && !allArgsString.includes('mask');
      const usesSecretVar = allArgsString.match(/\b(apiKey|api_key|secret|password|token|credential|auth)\b/i);

      if (hasHardcodedKey || usesEnvUnmasked || usesSecretVar) {
        const isCritical = !!hasHardcodedKey;
        findings.push({
          severity: isCritical ? Severity.CRITICAL : Severity.WARNING,
          type: AFBType.UNAUTHORIZED_ACTION,
          file: filePath,
          line: llmCall.line,
          column: llmCall.column,
          operation: 'LLM Call with sensitive data',
          explanation: 'Sensitive data (credentials, keys, or raw env vars) detected in prompt construction path.',
          codeSnippet: llmCall.callee,
          category: ExecutionCategory.TOOL_CALL,
          confidence: 0.8,
          owasp: OWASPLabel.L2,
          remediation: hasHardcodedKey 
            ? "Remove hardcoded credentials. Move to environment variable." 
            : "Mask sensitive variables with process.env.API_KEY.slice(0,4) + '...' in logging/prompt paths.",
        });
      }
    }
  }

  return findings;
}
