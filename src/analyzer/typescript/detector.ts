/**
 * TypeScript/JavaScript AFB04 Detector
 *
 * IMPORTANT: AFB04 is about AGENT failure boundaries - operations reachable
 * from tools that an AI agent can call. Regular application code that uses
 * fetch() or query() is NOT an AFB04 issue.
 *
 * Current status: TypeScript/JavaScript support is in progress.
 * This detector returns empty findings and logs an INFO message.
 *
 * The principle we follow:
 * "A missed finding is acceptable. A false finding from pattern matching is not."
 *
 * Full implementation requires call graph analysis for TypeScript, which is
 * planned for a future release.
 */

import { FileAnalysisResult } from "../../types";

/**
 * Analyzes a TypeScript/JavaScript file for AFB04 boundaries.
 *
 * Currently returns empty findings with an explicit notice that TypeScript
 * support is in progress. This avoids false positives from pattern matching
 * that cannot trace from tool registrations to dangerous operations.
 */
export function analyzeTypeScriptFile(filePath: string, sourceCode: string): FileAnalysisResult {
  const startTime = Date.now();

  // Emit INFO-level message to stderr (not a finding, just notification)
  // Only emit once per file, and only if the file is not empty
  if (sourceCode.trim().length > 0) {
    console.error(`INFO: TypeScript support is in progress. No findings will be reported for: ${filePath}`);
  }

  return {
    file: filePath,
    language: "typescript",
    findings: [],
    success: true,
    analysisTimeMs: Date.now() - startTime,
    skipped: true,
    skipReason: "TypeScript/JavaScript detection not yet implemented. Full call graph analysis required.",
  };
}
