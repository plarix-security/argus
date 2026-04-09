export interface MethodologyDisclosure {
  ast_based: boolean;
  semantic_registration_analysis: boolean;
  regex_free: boolean;
  uses_regex_for_helpers: boolean;
  ready_for_full_large_scale_coverage: boolean;
  note: string;
}

const DISCLOSURE: MethodologyDisclosure = {
  ast_based: true,
  semantic_registration_analysis: true,
  regex_free: false,
  uses_regex_for_helpers: true,
  ready_for_full_large_scale_coverage: false,
  note: 'WyScan does not use regex-only fallback detection, but it still uses regex in helper paths (normalization, glob conversion, and text cleanup). Coverage is best-effort, not complete for large-scale systems.',
};

export function getMethodologyDisclosure(): MethodologyDisclosure {
  return DISCLOSURE;
}
