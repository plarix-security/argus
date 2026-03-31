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

import * as path from 'path';
import { FileAnalysisResult } from '../../types';

/**
 * Analyzes a TypeScript/JavaScript file for AFB04 boundaries.
 *
 * Currently returns empty findings with an explicit notice that TypeScript
 * support is in progress. This avoids false positives from pattern matching
 * that cannot trace from tool registrations to dangerous operations.
 */
export function analyzeTypeScriptFile(filePath: string, sourceCode: string): FileAnalysisResult {
  const startTime = Date.now();
  const ext = path.extname(filePath).toLowerCase();
  const language = ext === '.js' || ext === '.jsx' ? 'javascript' : 'typescript';
  const displayLanguage = language === 'javascript' ? 'JavaScript' : 'TypeScript';

  if (sourceCode.trim().length > 0) {
    console.error(`INFO: Skipping unsupported ${displayLanguage} file: ${filePath}`);
  }

  return {
    file: filePath,
    language,
    findings: [],
    success: true,
    analysisTimeMs: Date.now() - startTime,
    skipped: true,
    skipReason: `${displayLanguage} scanning is not implemented in this version. File skipped.`,
  };
}
