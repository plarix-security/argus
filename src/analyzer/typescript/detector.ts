/**
 * TypeScript/JavaScript AFB04 Detector
 *
 * IMPORTANT: AFB04 is about AGENT failure boundaries - operations reachable
 * from tools that an AI agent can call. Regular application code that uses
 * fetch() or query() is NOT an AFB04 issue.
 *
 * Without full call graph analysis (not yet implemented for TS), we can only
 * report findings if the file clearly contains agent tool patterns.
 *
 * Current approach: Return empty findings for TypeScript/JavaScript.
 * This is intentional - we follow the principle:
 * "A missed finding is acceptable. A false finding from pattern matching is not."
 *
 * Future iteration: Implement call graph analysis for TypeScript to properly
 * trace from tool registrations to dangerous operations.
 */

import { FileAnalysisResult } from "../../types";

export function analyzeTypeScriptFile(filePath: string, sourceCode: string): FileAnalysisResult {
  const startTime = Date.now();

  // TypeScript/JavaScript AFB04 detection is disabled until proper
  // call graph analysis is implemented. Returning empty findings to
  // avoid false positives from pattern matching regular application code.
  //
  // The Python detector has proper call graph analysis and should be
  // the primary detection mechanism for now.

  return {
    file: filePath,
    language: "typescript",
    findings: [],
    success: true,
    analysisTimeMs: Date.now() - startTime,
  };
}
