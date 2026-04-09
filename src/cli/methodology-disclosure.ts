import { AnalysisReport } from '../types';

export interface MethodologyDisclosure {
  short_answer: string;
  regex_main_method: boolean;
  primary_method: string;
  large_scale_agentic_readiness: {
    ready: boolean;
    verdict: string;
  };
  plan_for_large_scale_cee_coverage: string[];
}

export function buildMethodologyDisclosure(report: AnalysisReport): MethodologyDisclosure {
  const hasPartialCoverage = report.metadata.skippedFiles.length > 0 || report.metadata.failedFiles.length > 0;
  const coverageWarning = hasPartialCoverage
    ? 'No. This scan was partial, so readiness for full-system CEE coverage is not established.'
    : 'No. WyScan is on the right track, but it is not yet ready to guarantee full CEE coverage for large-scale agentic systems such as Eliza.';

  return {
    short_answer: coverageWarning,
    regex_main_method: false,
    primary_method: 'Tree-sitter AST parsing plus semantic tool-registration and call-path analysis.',
    large_scale_agentic_readiness: {
      ready: false,
      verdict: 'Not nearly ready for complete coverage of all CEEs in large-scale agentic systems.',
    },
    plan_for_large_scale_cee_coverage: [
      'Build and maintain a versioned large-scale benchmark corpus (including Eliza-style repositories) with hand-labeled CEEs.',
      'Add whole-repository symbol and module resolution for dynamic exports/imports and cross-file indirection.',
      'Add deeper interprocedural dataflow and alias tracking from tool inputs to execution sinks.',
      'Improve dynamic registration recovery (config-driven/plugin-based/runtime-composed tools) with explicit uncertainty reporting.',
      'Replace remaining regex sink matching paths with typed semantic sink models where possible; keep regex as fallback only.',
      'Gate releases on benchmark precision/recall targets and publish those metrics in CI artifacts and release notes.',
    ],
  };
}
