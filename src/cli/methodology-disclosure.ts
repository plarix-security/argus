import { AnalysisReport } from '../types';

export interface MethodologyDisclosure {
  runtime_surfaces: Array<'cli_only' | 'github_app_backend'>;
  regex_main_method: boolean;
  primary_method: string;
  anti_overfit_policy: {
    hardcoded_agent_schema_rules: boolean;
    memorized_framework_schema_rules: boolean;
    note: string;
  };
  evidence_integrity_policy: string[];
  coverage_note: string;
}

export function buildMethodologyDisclosure(report: AnalysisReport): MethodologyDisclosure {
  const hasPartialCoverage = report.metadata.skippedFiles.length > 0 || report.metadata.failedFiles.length > 0;
  const coverageNote = hasPartialCoverage
    ? 'Scan was partial. Coverage is limited to the analyzed file set. Files that failed or were skipped are listed in coverage.failed_files and coverage.skipped_files.'
    : 'Coverage is limited to the analyzed file set. External packages and dynamically composed tool registrations are not traced.';

  return {
    runtime_surfaces: ['cli_only', 'github_app_backend'],
    regex_main_method: false,
    primary_method: 'Tree-sitter AST parsing plus semantic tool-registration and call-path analysis.',
    anti_overfit_policy: {
      hardcoded_agent_schema_rules: false,
      memorized_framework_schema_rules: false,
      note: 'Detection relies on language and framework structural first principles, not memorized project-specific schemas.',
    },
    evidence_integrity_policy: [
      'Only report operations tied to parsed code and traced evidence.',
      'No hardcoded repository-specific shortcuts in detector logic.',
      'Uncertainty is surfaced explicitly through unresolved_calls, depth_limit_hit, and evidence_kind fields.',
    ],
    coverage_note: coverageNote,
  };
}
