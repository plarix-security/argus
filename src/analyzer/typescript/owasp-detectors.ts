import { ParsedTypeScriptFile, CallSite, AssignmentInfo, FunctionDef } from './ast-parser';
import { AFBFinding, CEERecord, ExecutionCategory, Severity, OWASPLabel, AFBType } from '../../types';

// ============================================================================
// Taint Tracking Engine
// ============================================================================

/**
 * A taint source describes where untrusted data enters the program.
 */
interface TaintSource {
  kind: 'external-input' | 'rag-retrieval' | 'parameter' | 'env';
  variable: string;
  line: number;
  /** Original expression that introduced the taint (e.g. "req.body.prompt") */
  origin: string;
}

/**
 * External input patterns that introduce taint.
 * These represent data from HTTP requests, CLI args, event payloads, etc.
 */
const EXTERNAL_INPUT_PATTERNS: readonly RegExp[] = [
  /\breq\.body\b/,
  /\breq\.query\b/,
  /\breq\.params\b/,
  /\breq\.headers\b/,
  /\brequest\.body\b/,
  /\brequest\.query\b/,
  /\bevent\.body\b/,
  /\bevent\.queryStringParameters\b/,
  /\bevent\.pathParameters\b/,
  /\bctx\.request\.body\b/,
  /\bctx\.query\b/,
  /\bprocess\.argv\b/,
  /\bDeno\.args\b/,
  /\bBun\.argv\b/,
];

/**
 * RAG retrieval patterns — vector store lookups that return unvalidated content.
 */
const RAG_RETRIEVAL_PATTERNS: readonly RegExp[] = [
  /\bvectorStore\.similaritySearch\b/,
  /\bvectorStore\.asRetriever\b/,
  /\bindex\.query\b/,
  /\bretriever\.retrieve\b/,
  /\bretriever\.getRelevantDocuments\b/,
  /\bretriever\.invoke\b/,
  /\bsimilaritySearch\b/,
  /\bmmr\b/,
  /\bsimilaritySearchWithScore\b/,
];

/**
 * LLM sink patterns — calls that consume prompts/content.
 */
const LLM_SINK_PATTERNS: readonly RegExp[] = [
  // OpenAI
  /^(openai|client)\.chat\.completions\.create$/,
  /^(openai|client)\.completions\.create$/,
  // Anthropic
  /^(anthropic|client)\.messages\.create$/,
  // LangChain / generic agent
  /^(agent|chain|model|llm)\.(invoke|ainvoke|call|acall|run|arun|predict|apredict)$/,
  // LlamaIndex
  /^llm\.(complete|acomplete|chat|achat)$/,
  // Vercel AI
  /^(generateText|streamText)$/,
];

function matchesAny(text: string, patterns: readonly RegExp[]): boolean {
  return patterns.some(p => p.test(text));
}

function isLLMSink(call: CallSite): boolean {
  return matchesAny(call.callee, LLM_SINK_PATTERNS);
}

function isRAGRetrieval(call: CallSite): boolean {
  return matchesAny(call.callee, RAG_RETRIEVAL_PATTERNS);
}

// ============================================================================
// Intra-Procedural Taint Propagation
// ============================================================================

/**
 * Build the set of tainted variables for a given function.
 *
 * The algorithm:
 * 1. Seed with function parameters (they come from outside).
 * 2. Seed with assignments from external input expressions.
 * 3. Seed with assignments from RAG retrieval results.
 * 4. Propagate: if an assignment RHS mentions a tainted variable, the LHS becomes tainted.
 * 5. Iterate until fixpoint.
 */
function buildTaintSet(
  func: FunctionDef,
  parsed: ParsedTypeScriptFile,
): { taintedVars: Map<string, TaintSource>; ragTaintedVars: Set<string> } {
  const taintedVars = new Map<string, TaintSource>();
  const ragTaintedVars = new Set<string>();

  // Collect assignments scoped to this function
  const funcAssignments = parsed.assignments.filter(
    a => a.enclosingFunction === func.name
  );

  // Collect calls scoped to this function
  const funcCalls = parsed.calls.filter(
    c => c.enclosingFunction === func.name
  );

  // 1. Seed: function parameters
  for (const param of func.parameters) {
    const paramName = param.split(':')[0].replace(/^\.\.\./,'').trim();
    if (paramName) {
      taintedVars.set(paramName, {
        kind: 'parameter',
        variable: paramName,
        line: func.startLine,
        origin: `parameter "${paramName}"`,
      });
    }
  }

  // 2. Seed: assignments from external input
  for (const assign of funcAssignments) {
    for (const pattern of EXTERNAL_INPUT_PATTERNS) {
      if (pattern.test(assign.value)) {
        taintedVars.set(assign.target, {
          kind: 'external-input',
          variable: assign.target,
          line: assign.line,
          origin: assign.value.substring(0, 80),
        });
        break;
      }
    }
  }

  // 3. Seed: assignments from RAG retrieval
  for (const assign of funcAssignments) {
    for (const pattern of RAG_RETRIEVAL_PATTERNS) {
      if (pattern.test(assign.value)) {
        taintedVars.set(assign.target, {
          kind: 'rag-retrieval',
          variable: assign.target,
          line: assign.line,
          origin: assign.value.substring(0, 80),
        });
        ragTaintedVars.add(assign.target);
        break;
      }
    }
  }

  // Also seed from call results assigned to variables (e.g. const docs = await vectorStore.similaritySearch(...))
  for (const call of funcCalls) {
    if (isRAGRetrieval(call)) {
      // Find assignment on the same line or enclosing the call
      const assignOnLine = funcAssignments.find(a => a.line === call.line);
      if (assignOnLine) {
        taintedVars.set(assignOnLine.target, {
          kind: 'rag-retrieval',
          variable: assignOnLine.target,
          line: call.line,
          origin: call.callee,
        });
        ragTaintedVars.add(assignOnLine.target);
      }
    }
  }

  // 4. Propagate taint through assignments (fixpoint iteration)
  let changed = true;
  let iterations = 0;
  const MAX_ITERATIONS = 20;

  while (changed && iterations < MAX_ITERATIONS) {
    changed = false;
    iterations++;

    for (const assign of funcAssignments) {
      if (taintedVars.has(assign.target)) continue;

      // Check if any tainted variable appears in the RHS
      for (const [tVar, tSource] of taintedVars) {
        const varPattern = new RegExp(`\\b${escapeRegex(tVar)}\\b`);
        if (varPattern.test(assign.value)) {
          taintedVars.set(assign.target, {
            kind: tSource.kind,
            variable: assign.target,
            line: assign.line,
            origin: `propagated from "${tVar}"`,
          });

          if (ragTaintedVars.has(tVar)) {
            ragTaintedVars.add(assign.target);
          }
          changed = true;
          break;
        }
      }
    }
  }

  return { taintedVars, ragTaintedVars };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Check if any tainted variable flows into a call's arguments.
 */
function taintFlowsIntoCall(
  call: CallSite,
  taintedVars: Map<string, TaintSource>,
): TaintSource | null {
  const allArgsText = call.arguments.join(' ');

  // Direct reference to external input in args
  for (const pattern of EXTERNAL_INPUT_PATTERNS) {
    if (pattern.test(allArgsText)) {
      return {
        kind: 'external-input',
        variable: '<direct>',
        line: call.line,
        origin: allArgsText.substring(0, 80),
      };
    }
  }

  // Check tainted variable references in args
  for (const [tVar, tSource] of taintedVars) {
    const varPattern = new RegExp(`\\b${escapeRegex(tVar)}\\b`);
    if (varPattern.test(allArgsText)) {
      return tSource;
    }
  }

  return null;
}

/**
 * Check if a function contains sanitization/validation calls before the given line.
 */
function hasSanitizationBefore(
  funcCalls: CallSite[],
  beforeLine: number,
): boolean {
  const sanitizationPatterns = [
    'sanitize', 'validate', 'escape', 'filter',
    'clean', 'purify', 'strip', 'encode',
    'DOMPurify', 'xss', 'htmlEscape',
  ];

  return funcCalls.some(c => {
    if (c.line >= beforeLine) return false;
    const calleeLower = c.callee.toLowerCase();
    return sanitizationPatterns.some(p => calleeLower.includes(p));
  });
}

/**
 * Check if a function contains source validation for RAG content before the given line.
 */
function hasSourceValidationBefore(
  funcCalls: CallSite[],
  func: FunctionDef,
  beforeLine: number,
): boolean {
  const validationPatterns = [
    'filter', 'validate', 'check', 'verify',
    'includes', 'startsWith', 'indexOf',
  ];

  // Check for filter/validate calls
  const hasValidationCall = funcCalls.some(c => {
    if (c.line >= beforeLine) return false;
    const calleeLower = c.callee.toLowerCase();
    return validationPatterns.some(p => calleeLower.includes(p));
  });

  // Check for conditional returns/raises (structural validation)
  const hasControlFlowValidation =
    func.controlFlow?.checksParameters ||
    func.controlFlow?.hasConditionalRaise ||
    func.controlFlow?.hasConditionalReturn;

  return hasValidationCall || !!hasControlFlowValidation;
}

// ============================================================================
// OWASP Detector Entry Point
// ============================================================================

export function runOWASPDetectors(parsed: ParsedTypeScriptFile, filePath: string): AFBFinding[] {
  const findings: AFBFinding[] = [];

  for (const func of parsed.functions) {
    const funcCalls = parsed.calls.filter(c => c.enclosingFunction === func.name);
    const llmCalls = funcCalls.filter(isLLMSink);
    const ragCalls = funcCalls.filter(isRAGRetrieval);

    // Skip functions with no LLM calls — nothing to detect
    if (llmCalls.length === 0) continue;

    // Build taint set for this function
    const { taintedVars, ragTaintedVars } = buildTaintSet(func, parsed);

    // ----- LLM08: RAG without Source Validation -----
    if (ragCalls.length > 0) {
      for (const llmCall of llmCalls) {
        // Check if RAG-tainted data flows into this LLM call
        const ragTaintInArgs = taintFlowsIntoCall(llmCall, new Map(
          [...taintedVars].filter(([k]) => ragTaintedVars.has(k))
        ));

        if (ragTaintInArgs) {
          // Is there source validation before the LLM call?
          if (!hasSourceValidationBefore(funcCalls, func, llmCall.line)) {
            findings.push({
              severity: Severity.WARNING,
              type: AFBType.UNAUTHORIZED_ACTION,
              file: filePath,
              line: llmCall.line,
              column: llmCall.column,
              operation: 'LLM call with unvalidated RAG retrieval',
              explanation: `Unvalidated vector store content flows from "${ragTaintInArgs.origin}" into LLM call "${llmCall.callee}" without source domain or metadata filtering.`,
              codeSnippet: llmCall.callee,
              category: ExecutionCategory.TOOL_CALL,
              confidence: 0.78,
              owasp: OWASPLabel.L8,
              remediation: 'Validate source domain or metadata before passing retrieved content to LLM. Example: if (!ALLOWED_DOMAINS.includes(doc.metadata.source)) filter out.',
            });
          }
        }
      }
    }

    // ----- LLM01: Prompt Injection -----
    for (const llmCall of llmCalls) {
      const taintSource = taintFlowsIntoCall(llmCall, taintedVars);
      if (!taintSource) continue;

      // Only flag external-input and parameter taint (not RAG — that's L8)
      if (taintSource.kind === 'rag-retrieval') continue;

      // Check for sanitization before this call
      if (hasSanitizationBefore(funcCalls, llmCall.line)) continue;

      const isDirect = taintSource.kind === 'external-input';
      findings.push({
        severity: isDirect ? Severity.CRITICAL : Severity.WARNING,
        type: AFBType.UNAUTHORIZED_ACTION,
        file: filePath,
        line: llmCall.line,
        column: llmCall.column,
        operation: 'LLM call with unsanitized external input',
        explanation: `User-controlled input from ${taintSource.origin} flows into LLM call "${llmCall.callee}" without sanitization or validation gate.`,
        codeSnippet: llmCall.callee,
        category: ExecutionCategory.TOOL_CALL,
        confidence: isDirect ? 0.88 : 0.72,
        owasp: OWASPLabel.L1,
        remediation: 'Implement a sanitization gate or input validation schema before passing external input to the LLM.',
      });
    }

    // ----- LLM02: Sensitive Data in Prompts -----
    const funcBodyText = func.bodyNode ? func.bodyNode.text : '';

    for (const llmCall of llmCalls) {
      const allArgsString = llmCall.arguments.join(' ');

      // Hardcoded credentials in function body
      const hasHardcodedKey = funcBodyText.match(
        /['"`](sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xoxb-[a-zA-Z0-9-]{20,}|AKIA[A-Z0-9]{16}|glpat-[a-zA-Z0-9-]{20,})['"`]/
      );

      // Raw env vars flowing into LLM without masking
      const usesEnvUnmasked =
        allArgsString.includes('process.env.') &&
        !allArgsString.includes('.slice(') &&
        !allArgsString.includes('mask') &&
        !allArgsString.includes('redact');

      // Secret-named variables in LLM args
      const usesSecretVar = allArgsString.match(
        /\b(apiKey|api_key|secret|password|token|credential|auth|private_key|privateKey)\b/i
      );

      if (hasHardcodedKey || usesEnvUnmasked || usesSecretVar) {
        const isCritical = !!hasHardcodedKey;
        findings.push({
          severity: isCritical ? Severity.CRITICAL : Severity.WARNING,
          type: AFBType.UNAUTHORIZED_ACTION,
          file: filePath,
          line: llmCall.line,
          column: llmCall.column,
          operation: 'LLM call with sensitive data',
          explanation: 'Sensitive data (credentials, keys, or raw env vars) detected in prompt construction path.',
          codeSnippet: llmCall.callee,
          category: ExecutionCategory.TOOL_CALL,
          confidence: isCritical ? 0.92 : 0.75,
          owasp: OWASPLabel.L2,
          remediation: hasHardcodedKey
            ? "Remove hardcoded credentials. Move to environment variable and never include in prompts."
            : "Mask sensitive variables with process.env.API_KEY.slice(0,4) + '...' in logging/prompt paths.",
        });
      }
    }
  }

  return findings;
}
