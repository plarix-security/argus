const { formatFinding } = require('../dist/cli/formatter');
const { generatePRComment } = require('../dist/reporter/pr-comment');

const finding = {
  type: 'AFB04',
  severity: 'warning',
  category: 'api_call',
  file: 'src/tools/api.py',
  line: 42,
  column: 3,
  codeSnippet: 'requests.post(url, data)',
  operation: 'External API call: requests.post',
  explanation: 'Detected reachable call from tool "send_webhook" (crewai) to requests.post. No policy gate detected in the analyzed call path.',
  confidence: 0.95,
  context: {
    enclosingFunction: 'send_webhook',
    framework: 'crewai',
    isToolDefinition: true,
  },
};

const report = {
  repository: 'repo',
  filesAnalyzed: ['src/tools/api.py'],
  totalFindings: 1,
  findingsBySeverity: {
    critical: 0,
    warning: 1,
    info: 0,
    suppressed: 0,
  },
  findings: [finding],
  metadata: {
    scannerVersion: '1.0.0',
    timestamp: '2026-03-31T00:00:00.000Z',
    totalTimeMs: 10,
    failedFiles: [],
    skippedFiles: [],
  },
};

const bannedTerms = [
  'ssrf',
  'injection',
  'exfiltration',
  'attack',
  'attacker',
  'vulnerable',
  'path traversal',
];

function expectEvidenceBound(text) {
  const lower = text.toLowerCase();
  for (const term of bannedTerms) {
    expect(lower).not.toContain(term);
  }
  expect(text).toContain('Detected reachable call');
  expect(text).toContain('No policy gate detected');
}

describe('proof-bound output wording', () => {
  test('CLI formatter uses evidence-bound wording', () => {
    expectEvidenceBound(formatFinding(finding));
  });

  test('PR comment uses evidence-bound wording', () => {
    expectEvidenceBound(generatePRComment(report));
  });
});
