import { astWalker } from "../ast-walker";
import { AFBFinding, FileAnalysisResult } from "../../types";
import { TYPESCRIPT_PATTERNS, ExecutionPattern, createFinding } from "../../afb/afb04";

type SyntaxNode = any;

function matchCallPattern(node: SyntaxNode, sourceCode: string): { pattern: ExecutionPattern; patternKey: string } | null {
  if (node.type !== "call_expression") return null;
  const funcNode = node.childForFieldName?.("function");
  if (!funcNode) return null;
  const funcText = funcNode.text;

  if (funcText === "tool") return { pattern: TYPESCRIPT_PATTERNS.tool_function, patternKey: "tool_function" };
  if (funcText.includes("exec")) return { pattern: TYPESCRIPT_PATTERNS.child_process_exec, patternKey: "child_process_exec" };
  if (funcText.includes("spawn")) return { pattern: TYPESCRIPT_PATTERNS.child_process_spawn, patternKey: "child_process_spawn" };
  if (funcText.includes("writeFile")) return { pattern: TYPESCRIPT_PATTERNS.fs_writeFile, patternKey: "fs_writeFile" };
  if (funcText.includes("readFile")) return { pattern: TYPESCRIPT_PATTERNS.fs_readFile, patternKey: "fs_readFile" };
  if (funcText.includes("unlink")) return { pattern: TYPESCRIPT_PATTERNS.fs_unlink, patternKey: "fs_unlink" };
  if (funcText.includes("rm")) return { pattern: TYPESCRIPT_PATTERNS.fs_rm, patternKey: "fs_rm" };
  if (funcText === "fetch") return { pattern: TYPESCRIPT_PATTERNS.fetch_call, patternKey: "fetch_call" };
  if (funcText.includes("axios")) return { pattern: TYPESCRIPT_PATTERNS.axios_call, patternKey: "axios_call" };
  if (funcText.includes("http")) return { pattern: TYPESCRIPT_PATTERNS.http_request, patternKey: "http_request" };
  if (funcText.includes("query") || funcText.includes("execute")) return { pattern: TYPESCRIPT_PATTERNS.query_execute, patternKey: "query_execute" };
  if (funcText.includes("prisma")) return { pattern: TYPESCRIPT_PATTERNS.prisma_operation, patternKey: "prisma_operation" };
  if (funcText === "eval") return { pattern: TYPESCRIPT_PATTERNS.eval_call, patternKey: "eval_call" };
  return null;
}

export function analyzeTypeScriptFile(filePath: string, sourceCode: string): FileAnalysisResult {
  const startTime = Date.now();
  const findings: AFBFinding[] = [];
  try {
    const tree = astWalker.parse(sourceCode, "typescript");
    astWalker.walk(tree, (node: SyntaxNode) => {
      const match = matchCallPattern(node, sourceCode);
      if (match) {
        const location = astWalker.getNodeLocation(node);
        findings.push(createFinding(filePath, location, node.text, match.pattern, undefined, undefined, false, undefined, 0.8));
      }
    });
    return { file: filePath, language: "typescript", findings, success: true, analysisTimeMs: Date.now() - startTime };
  } catch (error) {
    return { file: filePath, language: "typescript", findings: [], success: false, error: String(error), analysisTimeMs: Date.now() - startTime };
  }
}
