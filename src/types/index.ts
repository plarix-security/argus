/**
 * AFB Scanner Type Definitions
 * 
 * Core types for Agent Failure Boundary detection through static analysis.
 * Based on the AFB Taxonomy v2.0 specification.
 */

/**
 * Supported programming languages for analysis.
 */
export type SupportedLanguage = 'python' | 'typescript' | 'javascript';

/**
 * AFB boundary types as defined in the AFB Taxonomy.
 * MVP focuses on AFB04 only.
 */
export enum AFBType {
  /** AFB01: Instruction Boundary - delineates system instructions from user input */
  INSTRUCTION = 'AFB01',
  /** AFB02: Context Boundary - separates trustworthy vs untrusted retrieved context */
  CONTEXT = 'AFB02',
  /** AFB03: Constraint Boundary - enforces operational limits and guardrails */
  CONSTRAINT = 'AFB03',
  /** AFB04: Unauthorized Action - controls what operations the agent can perform */
  UNAUTHORIZED_ACTION = 'AFB04',
}

/**
 * Severity levels for detected boundaries.
 *
 * Four-level model based on blast radius and reversibility:
 *
 * CRITICAL: Irreversible destruction, exfiltration, or arbitrary execution.
 *   No gate anywhere in call path. Examples: delete files/directories,
 *   execute shell commands, send data to external endpoints, write to
 *   system paths, eval/exec arbitrary code.
 *
 * WARNING: Recoverable but consequential state modification or data transmission.
 *   Gate detection is uncertain or partial. Examples: write files in user
 *   directories, POST to external APIs, database writes, email sending.
 *
 * INFO: Read-only access to sensitive data or external systems. Not immediately
 *   dangerous but worth knowing about. Examples: read files outside working
 *   directory, GET requests to external APIs, environment variable access,
 *   credential file reads.
 *
 * SUPPRESSED: Everything else. Low-confidence detections, internal operations,
 *   operations on clearly safe targets. These do not appear in PR reports,
 *   logged internally only.
 */
export enum Severity {
  /** Critical: Irreversible operations with no gate */
  CRITICAL = 'critical',
  /** Warning: Consequential operations with uncertain gate detection */
  WARNING = 'warning',
  /** Info: Read-only access to sensitive data or external systems */
  INFO = 'info',
  /** Suppressed: Low-confidence or safe operations (not reported) */
  SUPPRESSED = 'suppressed',
}

/**
 * Categories of execution points that represent AFB04 boundaries.
 */
export enum ExecutionCategory {
  /** Tool calls in agent frameworks (LangChain, CrewAI, etc.) */
  TOOL_CALL = 'tool_call',
  /** Shell command execution */
  SHELL_EXECUTION = 'shell_execution',
  /** File system operations */
  FILE_OPERATION = 'file_operation',
  /** HTTP/API calls */
  API_CALL = 'api_call',
  /** Database operations */
  DATABASE_OPERATION = 'database_operation',
  /** Code execution (eval, exec) */
  CODE_EXECUTION = 'code_execution',
}

/**
 * A detected AFB04 execution point in the codebase.
 */
export interface AFBFinding {
  /** The AFB type (always AFB04 for MVP) */
  type: AFBType;
  /** Severity of the finding */
  severity: Severity;
  /** Category of execution point */
  category: ExecutionCategory;
  /** File path relative to repository root */
  file: string;
  /** Line number (1-indexed) */
  line: number;
  /** Column number (1-indexed) */
  column: number;
  /** The code snippet containing the execution point */
  codeSnippet: string;
  /** What operation is being performed */
  operation: string;
  /** Why this represents an AFB04 boundary exposure */
  explanation: string;
  /** Confidence level of the detection (0.0 - 1.0) */
  confidence: number;
  /** Additional context about the finding */
  context?: {
    /** Function/method name containing this code */
    enclosingFunction?: string;
    /** Class name if applicable */
    enclosingClass?: string;
    /** Whether this is inside a tool definition */
    isToolDefinition?: boolean;
    /** The framework detected (langchain, crewai, custom) */
    framework?: string;
  };
}

/**
 * Result of analyzing a single file.
 */
export interface FileAnalysisResult {
  /** File path relative to repository root */
  file: string;
  /** Programming language of the file */
  language: SupportedLanguage;
  /** All AFB findings in this file */
  findings: AFBFinding[];
  /** Whether analysis completed successfully */
  success: boolean;
  /** Error message if analysis failed */
  error?: string;
  /** Time taken to analyze in milliseconds */
  analysisTimeMs: number;
  /** Whether this file was skipped (e.g., unsupported language) */
  skipped?: boolean;
  /** Reason for skipping this file */
  skipReason?: string;
}

/**
 * Complete analysis report for a repository or set of files.
 */
export interface AnalysisReport {
  /** Repository name or identifier */
  repository: string;
  /** Commit SHA if applicable */
  commitSha?: string;
  /** Pull request number if applicable */
  pullRequest?: number;
  /** List of files that were analyzed */
  filesAnalyzed: string[];
  /** Total number of findings */
  totalFindings: number;
  /** Findings grouped by severity */
  findingsBySeverity: {
    critical: number;
    warning: number;
    info: number;
    suppressed: number;
  };
  /** All individual findings */
  findings: AFBFinding[];
  /** Analysis metadata */
  metadata: {
    /** Scanner version */
    scannerVersion: string;
    /** Timestamp of analysis */
    timestamp: string;
    /** Total analysis time in milliseconds */
    totalTimeMs: number;
    /** Files that failed to analyze */
    failedFiles: string[];
  };
}

/**
 * Configuration for the analyzer.
 */
export interface AnalyzerConfig {
  /** Files/patterns to include in analysis */
  include?: string[];
  /** Files/patterns to exclude from analysis */
  exclude?: string[];
  /** Minimum confidence threshold for reporting (0.0 - 1.0) */
  minConfidence?: number;
  /** Maximum files to analyze (for performance) */
  maxFiles?: number;
  /** Whether to analyze only changed files (for PRs) */
  changedFilesOnly?: boolean;
}

/**
 * GitHub webhook event context.
 */
export interface WebhookContext {
  /** Event type (push, pull_request) */
  event: 'push' | 'pull_request';
  /** Repository owner */
  owner: string;
  /** Repository name */
  repo: string;
  /** Commit SHA */
  sha: string;
  /** Pull request number (if PR event) */
  pullNumber?: number;
  /** Branch name */
  branch: string;
  /** List of changed files (for PRs) */
  changedFiles?: string[];
  /** Installation ID for GitHub App */
  installationId: number;
}

/**
 * AST node location information.
 */
export interface NodeLocation {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

/**
 * Pattern matcher result from AST analysis.
 */
export interface PatternMatch {
  /** The pattern that matched */
  pattern: string;
  /** Node location in source */
  location: NodeLocation;
  /** The matched source code */
  sourceText: string;
  /** Additional captured data */
  captures?: Record<string, string>;
}
