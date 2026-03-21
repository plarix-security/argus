/**
 * AFB Scanner - Main Analyzer
 *
 * Orchestrates static analysis across multiple files and languages.
 * Coordinates Python and TypeScript detectors to produce a unified report.
 */

import * as fs from "fs";
import * as path from "path";
import { astWalker } from "./ast-walker";
import { analyzePythonFile } from "./python/detector";
import { analyzeTypeScriptFile } from "./typescript/detector";
import {
  AFBFinding,
  FileAnalysisResult,
  AnalysisReport,
  AnalyzerConfig,
  Severity,
} from "../types";

/** Scanner version */
export const SCANNER_VERSION = "1.0.0";

/** Default directories to exclude */
const DEFAULT_EXCLUDE_DIRS = [
  "node_modules",
  ".git",
  "__pycache__",
  ".venv",
  "venv",
  "env",
  ".env",
  "dist",
  "build",
  ".next",
  "coverage",
  ".tox",
  ".pytest_cache",
  ".mypy_cache",
  "vendor",
  "third_party",
];

/** Default file patterns to exclude */
const DEFAULT_EXCLUDE_PATTERNS = [
  "*.min.js",
  "*.bundle.js",
  "*.d.ts",
  "*.map",
  "*.lock",
  "*.log",
];

/**
 * Check if a path should be excluded from analysis.
 */
function shouldExclude(
  filePath: string,
  excludeDirs: string[],
  excludePatterns: string[]
): boolean {
  const parts = filePath.split(path.sep);

  // Check if any directory in the path is excluded
  for (const part of parts) {
    if (excludeDirs.includes(part)) {
      return true;
    }
  }

  // Check file patterns
  const fileName = path.basename(filePath);
  for (const pattern of excludePatterns) {
    // Simple glob matching for *.ext patterns
    if (pattern.startsWith("*")) {
      const ext = pattern.slice(1);
      if (fileName.endsWith(ext)) {
        return true;
      }
    } else if (pattern === fileName) {
      return true;
    }
  }

  return false;
}

/**
 * Recursively find all analyzable files in a directory.
 */
function findAnalyzableFiles(
  dirPath: string,
  excludeDirs: string[],
  excludePatterns: string[],
  maxFiles: number = 1000
): string[] {
  const files: string[] = [];

  function walkDir(currentPath: string): void {
    if (files.length >= maxFiles) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= maxFiles) break;

      const fullPath = path.join(currentPath, entry.name);
      const relativePath = path.relative(dirPath, fullPath);

      if (entry.isDirectory()) {
        if (!excludeDirs.includes(entry.name)) {
          walkDir(fullPath);
        }
      } else if (entry.isFile()) {
        if (
          !shouldExclude(relativePath, excludeDirs, excludePatterns) &&
          astWalker.isAnalyzable(fullPath)
        ) {
          files.push(fullPath);
        }
      }
    }
  }

  walkDir(dirPath);
  return files;
}

/**
 * Analyze a single file based on its language.
 */
export function analyzeFile(filePath: string): FileAnalysisResult {
  const language = astWalker.getLanguage(filePath);

  if (!language) {
    return {
      file: filePath,
      language: "python", // Default, won't matter
      findings: [],
      success: false,
      error: `Unsupported file type: ${path.extname(filePath)}`,
      analysisTimeMs: 0,
    };
  }

  let sourceCode: string;
  try {
    sourceCode = fs.readFileSync(filePath, "utf-8");
  } catch (error) {
    return {
      file: filePath,
      language,
      findings: [],
      success: false,
      error: `Failed to read file: ${error instanceof Error ? error.message : String(error)}`,
      analysisTimeMs: 0,
    };
  }

  if (language === "python") {
    return analyzePythonFile(filePath, sourceCode);
  } else {
    return analyzeTypeScriptFile(filePath, sourceCode);
  }
}

/**
 * Analyze multiple files.
 */
export function analyzeFiles(filePaths: string[]): FileAnalysisResult[] {
  return filePaths.map((filePath) => analyzeFile(filePath));
}

/**
 * Analyze a directory recursively.
 */
export function analyzeDirectory(
  dirPath: string,
  config: AnalyzerConfig = {}
): AnalysisReport {
  const startTime = Date.now();
  const {
    exclude = [],
    minConfidence = 0.5,
    maxFiles = 1000,
  } = config;

  const excludeDirs = [...DEFAULT_EXCLUDE_DIRS, ...exclude];
  const excludePatterns = DEFAULT_EXCLUDE_PATTERNS;

  // Find all analyzable files
  const filePaths = findAnalyzableFiles(
    dirPath,
    excludeDirs,
    excludePatterns,
    maxFiles
  );

  // Analyze each file
  const results = analyzeFiles(filePaths);

  // Aggregate findings
  const allFindings: AFBFinding[] = [];
  const failedFiles: string[] = [];

  for (const result of results) {
    if (result.success) {
      // Filter by confidence threshold
      const filteredFindings = result.findings.filter(
        (f) => f.confidence >= minConfidence
      );
      allFindings.push(...filteredFindings);
    } else {
      failedFiles.push(result.file);
    }
  }

  // Calculate summary statistics
  const findingsBySeverity = {
    critical: allFindings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: allFindings.filter((f) => f.severity === Severity.HIGH).length,
    medium: allFindings.filter((f) => f.severity === Severity.MEDIUM).length,
  };

  return {
    repository: path.basename(dirPath),
    filesAnalyzed: filePaths.map((p) => path.relative(dirPath, p)),
    totalFindings: allFindings.length,
    findingsBySeverity,
    findings: allFindings,
    metadata: {
      scannerVersion: SCANNER_VERSION,
      timestamp: new Date().toISOString(),
      totalTimeMs: Date.now() - startTime,
      failedFiles,
    },
  };
}

/**
 * Analyze only specific files (useful for PR analysis).
 */
export function analyzeSpecificFiles(
  basePath: string,
  relativePaths: string[],
  config: AnalyzerConfig = {}
): AnalysisReport {
  const startTime = Date.now();
  const { minConfidence = 0.5 } = config;

  // Convert relative paths to absolute and filter analyzable files
  const filePaths = relativePaths
    .map((p) => path.join(basePath, p))
    .filter((p) => {
      try {
        return fs.existsSync(p) && astWalker.isAnalyzable(p);
      } catch {
        return false;
      }
    });

  // Analyze each file
  const results = analyzeFiles(filePaths);

  // Aggregate findings
  const allFindings: AFBFinding[] = [];
  const failedFiles: string[] = [];

  for (const result of results) {
    if (result.success) {
      const filteredFindings = result.findings.filter(
        (f) => f.confidence >= minConfidence
      );
      allFindings.push(...filteredFindings);
    } else {
      failedFiles.push(result.file);
    }
  }

  const findingsBySeverity = {
    critical: allFindings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: allFindings.filter((f) => f.severity === Severity.HIGH).length,
    medium: allFindings.filter((f) => f.severity === Severity.MEDIUM).length,
  };

  return {
    repository: path.basename(basePath),
    filesAnalyzed: relativePaths,
    totalFindings: allFindings.length,
    findingsBySeverity,
    findings: allFindings,
    metadata: {
      scannerVersion: SCANNER_VERSION,
      timestamp: new Date().toISOString(),
      totalTimeMs: Date.now() - startTime,
      failedFiles,
    },
  };
}

// Re-export for convenience
export { astWalker } from "./ast-walker";
export { analyzePythonFile } from "./python/detector";
export { analyzeTypeScriptFile } from "./typescript/detector";
