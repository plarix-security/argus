import { getMethodologyDisclosure } from '../methodology-disclosure';

describe('methodology disclosure', () => {
  it('truthfully reports regex and readiness flags', () => {
    const disclosure = getMethodologyDisclosure();

    expect(disclosure.ast_based).toBe(true);
    expect(disclosure.semantic_registration_analysis).toBe(true);
    expect(disclosure.regex_free).toBe(false);
    expect(disclosure.uses_regex_for_helpers).toBe(true);
    expect(disclosure.ready_for_full_large_scale_coverage).toBe(false);
  });
});
