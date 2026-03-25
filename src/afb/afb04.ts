/**
 * AFB04 - Unauthorized Action Detection
 *
 * This module contains the classification logic for AFB04 boundaries.
 * AFB04 represents the Agent → Act transition where an agent attempts
 * to perform an action that may not be authorized.
 *
 * Key insight from the AFB specification:
 * - AFB04 is the most detectable boundary through static analysis
 * - It involves concrete execution points: tool calls, API calls,
 *   file operations, shell commands, database operations
 * - Even if upstream boundaries (AFB01-03) are compromised,
 *   proper AFB04 enforcement can contain the blast radius
 */

import {
  ExecutionCategory,
  Severity,
} from '../types';

/**
 * Pattern definition for detecting execution points.
 */
export interface ExecutionPattern {
  /** Pattern identifier */
  id: string;
  /** Category of execution */
  category: ExecutionCategory;
  /** Base severity (may be elevated based on context) */
  baseSeverity: Severity;
  /** Human-readable description of what this pattern detects */
  description: string;
  /** Why this represents a boundary exposure */
  rationale: string;
}

// Note: Execution patterns and finding creation are implemented in
// analyzer/python/call-graph.ts and analyzer/python/detector.ts
// This file retains only the interface definition for documentation.
