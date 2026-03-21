import { AFBType, ExecutionCategory, ScannerSanityCheck } from '../types';

export const CANONICAL_CEE_CATEGORIES: ExecutionCategory[] = [
  ExecutionCategory.TOOL_CALL,
  ExecutionCategory.SHELL_EXECUTION,
  ExecutionCategory.FILE_OPERATION,
  ExecutionCategory.API_CALL,
  ExecutionCategory.DATABASE_OPERATION,
  ExecutionCategory.CODE_EXECUTION,
];

export function buildScannerSanityCheck(
  observedCEECategories: ExecutionCategory[]
): ScannerSanityCheck {
  return {
    isComprehensiveCoverageScanner: false,
    supportedAFBs: [AFBType.UNAUTHORIZED_ACTION],
    unsupportedAFBs: [AFBType.INSTRUCTION, AFBType.CONTEXT, AFBType.CONSTRAINT],
    canonicalCEECategories: CANONICAL_CEE_CATEGORIES,
    observedCEECategories,
    missingObservedCEECategories: CANONICAL_CEE_CATEGORIES.filter(
      (category) => !observedCEECategories.includes(category)
    ),
    verdict:
      'No. This scanner only statically detects AFB04-style execution patterns and cannot guarantee detection of all canonical execution events or all AFB boundaries in production.',
  };
}
