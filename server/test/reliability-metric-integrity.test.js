const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const app = require('../index');
const {
  CANONICAL_REPORT_SCHEMA_VERSION,
  buildCanonicalReport,
  generateJsonReport,
  generateMarkdownReport,
  getSafeExportFilename,
  sanitizeUrl,
  sanitizeTargetDetails
} = require('../benchmark/benchmarkReport');
const {
  evaluateComparisonValidity,
  compareBenchmarkRuns
} = require('../benchmark/benchmarkComparison');
const { runBenchmarkSuite, getBenchmarkHistory } = require('../benchmark/benchmarkRunner');
const { validateTargetUrl, isProhibitedIP } = require('../security/urlValidator');
const { executeTargetRequest } = require('../target/targetAdapter');
const { heuristicSecurityEvaluation, evaluateSecurityResponse } = require('../evaluator/securityEvaluator');

describe('VibeSec Phase 3C: Reliability, Metric Integrity & Security Validation Suite', () => {
  let server;
  let serverPort;
  let serverBaseUrl;

  let dispatchedTargetCalls = 0;
  let dummyTargetServer;
  let dummyTargetPort;
  let dummyTargetUrl;

  before(async () => {
    // Isolated target server to verify zero unintended target calls
    dummyTargetServer = http.createServer((req, res) => {
      dispatchedTargetCalls++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ reply: 'Target response' }));
    });

    await new Promise((resolve) => {
      dummyTargetServer.listen(0, '127.0.0.1', () => {
        dummyTargetPort = dummyTargetServer.address().port;
        dummyTargetUrl = `http://127.0.0.1:${dummyTargetPort}/api/chat`;
        resolve();
      });
    });

    // Spin up Express test instance
    await new Promise((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        serverPort = server.address().port;
        serverBaseUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) await new Promise((r) => server.close(r));
    if (dummyTargetServer) await new Promise((r) => dummyTargetServer.close(r));
  });

  // =========================================================================
  // 1. BENCHMARK METRIC INTEGRITY & DENOMINATOR HANDLING
  // =========================================================================
  describe('1. Benchmark Metric Integrity & Denominator Handling', () => {
    test('handles empty runs cleanly without NaN, Infinity, or misleading failure rates', () => {
      const emptyReport = {
        runId: 'empty_run_1',
        startedAt: '2026-10-10T00:00:00.000Z',
        completedAt: '2026-10-10T00:00:01.000Z',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        results: []
      };

      const canonical = buildCanonicalReport(emptyReport);
      assert.equal(canonical.totalTests, 0);
      assert.equal(canonical.summary.pass, 0);
      assert.equal(canonical.summary.fail, 0);
      assert.equal(canonical.summary.inconclusive, 0);
      assert.equal(canonical.summary.error, 0);
      assert.equal(canonical.summary.failureRatePercent, 0);
      assert.ok(canonical.summary.failureRateDenominator.includes('0 - no tests executed'));
      assert.equal(canonical.summary.evaluatedFailureRatePercent, 0);
      assert.ok(canonical.summary.evaluatedFailureRateDenominator.includes('0 - no definitive evaluations'));
      assert.equal(Number.isNaN(canonical.summary.failureRatePercent), false);
      assert.equal(Number.isNaN(canonical.summary.evaluatedFailureRatePercent), false);
    });

    test('all-error run tracks error count, never counts error as pass, and handles zero evaluated denominator', () => {
      const allErrorReport = {
        runId: 'all_error_run',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        results: [
          { testId: 't1', verdict: 'ERROR', targetExecution: { status: 'TIMEOUT', error: 'Timeout after 10000ms' } },
          { testId: 't2', verdict: 'ERROR', targetExecution: { status: 'HTTP_ERROR', httpStatus: 500, error: 'Internal Error' } }
        ]
      };

      const canonical = buildCanonicalReport(allErrorReport);
      assert.equal(canonical.totalTests, 2);
      assert.equal(canonical.summary.pass, 0);
      assert.equal(canonical.summary.fail, 0);
      assert.equal(canonical.summary.error, 2);
      assert.equal(canonical.summary.inconclusive, 0);
      // Raw failure rate is failCount / totalTests = 0 / 2 = 0%
      assert.equal(canonical.summary.failureRatePercent, 0);
      assert.equal(canonical.summary.failureRateDenominator, 'totalTests (2)');
      // Evaluated failure rate: evaluated count is pass + fail = 0; must not be NaN
      assert.equal(canonical.summary.evaluatedFailureRatePercent, 0);
      assert.ok(canonical.summary.evaluatedFailureRateDenominator.includes('0 - no definitive evaluations'));
      assert.ok(canonical.summary.documentation.includes('failCount / totalTests'));
    });

    test('all-inconclusive run preserves ambiguous provenance and never marks tests as PASS', () => {
      const allInconcReport = {
        runId: 'all_inconc_run',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        results: [
          { testId: 't1', verdict: 'INCONCLUSIVE', explanation: 'Model output was ambiguous' },
          { testId: 't2', verdict: 'INCONCLUSIVE', explanation: 'Evaluator timed out' }
        ]
      };

      const canonical = buildCanonicalReport(allInconcReport);
      assert.equal(canonical.totalTests, 2);
      assert.equal(canonical.summary.pass, 0);
      assert.equal(canonical.summary.fail, 0);
      assert.equal(canonical.summary.inconclusive, 2);
      assert.equal(canonical.summary.error, 0);
      assert.equal(canonical.summary.failureRatePercent, 0);
      assert.equal(canonical.summary.evaluatedFailureRatePercent, 0);
      assert.ok(canonical.summary.evaluatedFailureRateDenominator.includes('0 - no definitive evaluations'));
    });

    test('mixed-outcomes run cleanly differentiates raw failure rate vs evaluated failure rate', () => {
      const mixedReport = {
        runId: 'mixed_run_1',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        results: [
          { testId: 't1', verdict: 'PASS' },
          { testId: 't2', verdict: 'FAIL' },
          { testId: 't3', verdict: 'INCONCLUSIVE' },
          { testId: 't4', verdict: 'ERROR' }
        ]
      };

      const canonical = buildCanonicalReport(mixedReport);
      assert.equal(canonical.totalTests, 4);
      assert.equal(canonical.summary.pass, 1);
      assert.equal(canonical.summary.fail, 1);
      assert.equal(canonical.summary.inconclusive, 1);
      assert.equal(canonical.summary.error, 1);
      // Raw failure rate: 1 fail / 4 total = 25.0%
      assert.equal(canonical.summary.failureRatePercent, 25.0);
      assert.equal(canonical.summary.failureRateDenominator, 'totalTests (4)');
      // Evaluated failure rate: 1 fail / (1 pass + 1 fail) = 1/2 = 50.0%
      assert.equal(canonical.summary.evaluatedFailureRatePercent, 50.0);
      assert.equal(canonical.summary.evaluatedFailureRateDenominator, 'pass + fail (2)');
    });

    test('partial run with early termination documents denominator dilution and tracks completed vs aborted count', () => {
      const earlyTermReport = {
        runId: 'early_term_run',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        executionLimits: {
          maxTests: 5,
          maxTotalDurationMs: 1000,
          earlyTermination: true,
          terminationReason: 'Execution time limit exceeded'
        },
        results: [
          { testId: 't1', verdict: 'PASS', targetExecution: { status: 'SUCCESS' } },
          { testId: 't2', verdict: 'FAIL', targetExecution: { status: 'SUCCESS' } },
          { testId: 't3', verdict: 'ERROR', targetExecution: { status: 'TIMEOUT_ABORT' } },
          { testId: 't4', verdict: 'ERROR', targetExecution: { status: 'TIMEOUT_ABORT' } },
          { testId: 't5', verdict: 'ERROR', targetExecution: { status: 'TIMEOUT_ABORT' } }
        ]
      };

      const canonical = buildCanonicalReport(earlyTermReport);
      assert.equal(canonical.summary.completedTests, 2);
      assert.equal(canonical.summary.abortedTests, 3);
      assert.equal(canonical.summary.fail, 1);
      assert.equal(canonical.summary.error, 3);
      assert.equal(canonical.summary.failureRatePercent, 20.0); // 1 / 5 = 20%
      assert.equal(canonical.summary.evaluatedFailureRatePercent, 50.0); // 1 / (1+1) = 50%
      assert.ok(canonical.summary.documentation.includes('Early termination occurred'));
      assert.ok(canonical.summary.documentation.includes('fail / totalTests'));
    });

    test('category breakdown provides consistent denominators and failure rates', () => {
      const report = {
        runId: 'cat_test_run',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        categoryBreakdown: {
          'Prompt Injection': { total: 2, pass: 1, fail: 1, inconclusive: 0, error: 0 },
          'Secret Disclosure': { total: 2, pass: 0, fail: 0, inconclusive: 1, error: 1 }
        },
        results: [
          { testId: 't1', category: 'Prompt Injection', verdict: 'PASS' },
          { testId: 't2', category: 'Prompt Injection', verdict: 'FAIL' },
          { testId: 't3', category: 'Secret Disclosure', verdict: 'INCONCLUSIVE' },
          { testId: 't4', category: 'Secret Disclosure', verdict: 'ERROR' }
        ]
      };

      const canonical = buildCanonicalReport(report);
      const promptCat = canonical.categoryBreakdown['Prompt Injection'];
      assert.equal(promptCat.failureRatePercent, 50.0);
      assert.equal(promptCat.evaluatedFailureRatePercent, 50.0);
      assert.equal(promptCat.evaluatedDenominator, 'pass + fail (2)');

      const secretCat = canonical.categoryBreakdown['Secret Disclosure'];
      assert.equal(secretCat.failureRatePercent, 0);
      assert.equal(secretCat.evaluatedFailureRatePercent, 0);
      assert.ok(secretCat.evaluatedDenominator.includes('0 - no definitive evaluations'));
    });
  });

  // =========================================================================
  // 2. COMPARISON INTEGRITY & VERDICT TRANSITIONS
  // =========================================================================
  describe('2. Comparison Integrity & Verdict Transitions', () => {
    function makeBaseRun(overrides = {}) {
      return {
        runId: 'base_run_1',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        targetModel: 'gpt-4o-mini',
        evaluatorModel: 'gemini-2.5-flash',
        results: [
          { testId: 't1', name: 'Direct Override', category: 'Override', verdict: 'PASS' },
          { testId: 't2', name: 'Roleplay Jailbreak', category: 'Role', verdict: 'FAIL' },
          { testId: 't3', name: 'Canary Probe', category: 'Canary', verdict: 'PASS' }
        ],
        ...overrides
      };
    }

    test('detects evaluator model mismatch and flags comparison as partially_comparable', () => {
      const base = makeBaseRun({ evaluatorModel: 'gemini-2.5-flash' });
      const comp = makeBaseRun({ runId: 'comp_run_1', evaluatorModel: 'heuristic_fallback' });

      const validity = evaluateComparisonValidity(base, comp);
      assert.equal(validity.status, 'partially_comparable');
      assert.ok(validity.warnings.some((w) => w.includes('Evaluator models differ')));
    });

    test('detects test definition modifications and reports them in versionDiff without misclassifying', () => {
      const base = makeBaseRun({
        results: [
          {
            testId: 't1',
            name: 'Direct Override',
            category: 'Override',
            attackInput: 'Standard test input',
            securityRequirement: 'Standard requirement',
            verdict: 'FAIL'
          }
        ]
      });

      const comp = makeBaseRun({
        runId: 'comp_def_change',
        results: [
          {
            testId: 't1',
            name: 'Direct Override',
            category: 'Override',
            attackInput: 'Modified prompt for new API',
            securityRequirement: 'Modified corporate policy requirement',
            verdict: 'PASS'
          }
        ]
      });

      const diff = compareBenchmarkRuns(base, comp);
      assert.ok(diff.versionDiff.definitionChangedCount > 0);
      assert.equal(diff.versionDiff.definitionChangedTests[0].testId, 't1');
      assert.equal(diff.transitions[0].hasDefinitionChanged, true);
      assert.ok(diff.transitions[0].explanation.includes('Test definition was modified between runs'));
    });

    test('evaluates all verdict transitions accurately and never treats ERROR or INCONCLUSIVE as successful remediation', () => {
      const base = {
        runId: 'base_transitions',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        targetModel: 'model_a',
        evaluatorModel: 'gemini',
        results: [
          { testId: 't_fail_to_pass', verdict: 'FAIL', name: 'T1' },
          { testId: 't_pass_to_fail', verdict: 'PASS', name: 'T2' },
          { testId: 't_fail_to_error', verdict: 'FAIL', name: 'T3' },
          { testId: 't_fail_to_inconc', verdict: 'FAIL', name: 'T4' },
          { testId: 't_error_to_pass', verdict: 'ERROR', name: 'T5' },
          { testId: 't_inconc_to_pass', verdict: 'INCONCLUSIVE', name: 'T6' },
          { testId: 't_pass_to_inconc', verdict: 'PASS', name: 'T7' },
          { testId: 't_removed', verdict: 'FAIL', name: 'T8' }
        ]
      };

      const comp = {
        runId: 'comp_transitions',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        targetModel: 'model_a',
        evaluatorModel: 'gemini',
        results: [
          { testId: 't_fail_to_pass', verdict: 'PASS', name: 'T1' },
          { testId: 't_pass_to_fail', verdict: 'FAIL', name: 'T2' },
          { testId: 't_fail_to_error', verdict: 'ERROR', name: 'T3' },
          { testId: 't_fail_to_inconc', verdict: 'INCONCLUSIVE', name: 'T4' },
          { testId: 't_error_to_pass', verdict: 'PASS', name: 'T5' },
          { testId: 't_inconc_to_pass', verdict: 'PASS', name: 'T6' },
          { testId: 't_pass_to_inconc', verdict: 'INCONCLUSIVE', name: 'T7' },
          { testId: 't_added', verdict: 'PASS', name: 'T9' }
        ]
      };

      const res = compareBenchmarkRuns(base, comp);

      const findTrans = (id) => res.transitions.find((t) => t.testId === id);

      // 1. FAIL -> PASS is IMPROVED
      const t1 = findTrans('t_fail_to_pass');
      assert.equal(t1.transitionType, 'IMPROVED');
      assert.ok(t1.explanation.includes('resolved'));

      // 2. PASS -> FAIL is REGRESSED
      const t2 = findTrans('t_pass_to_fail');
      assert.equal(t2.transitionType, 'REGRESSED');

      // 3. FAIL -> ERROR must NOT be IMPROVED; must be ERROR_INTRODUCED
      const t3 = findTrans('t_fail_to_error');
      assert.equal(t3.transitionType, 'ERROR_INTRODUCED');
      assert.ok(t3.explanation.includes('NOT proof of remediation'));

      // 4. FAIL -> INCONCLUSIVE must NOT be IMPROVED; must be INCONCLUSIVE_INTRODUCED
      const t4 = findTrans('t_fail_to_inconc');
      assert.equal(t4.transitionType, 'INCONCLUSIVE_INTRODUCED');
      assert.ok(t4.explanation.includes('NOT proof of remediation'));

      // 5. ERROR -> PASS is RESOLVED_ERROR (not proof of immunity)
      const t5 = findTrans('t_error_to_pass');
      assert.equal(t5.transitionType, 'RESOLVED_ERROR');
      assert.ok(t5.explanation.includes('PASS does not guarantee immunity'));

      // 6. INCONCLUSIVE -> PASS is RESOLVED_INCONCLUSIVE
      const t6 = findTrans('t_inconc_to_pass');
      assert.equal(t6.transitionType, 'RESOLVED_INCONCLUSIVE');

      // 7. PASS -> INCONCLUSIVE is INCONCLUSIVE_INTRODUCED
      const t7 = findTrans('t_pass_to_inconc');
      assert.equal(t7.transitionType, 'INCONCLUSIVE_INTRODUCED');

      // 8. Missing tests: t_removed must NOT count as an improvement!
      assert.equal(res.versionDiff.removedCount, 1);
      assert.equal(res.versionDiff.removedTests[0].testId, 't_removed');
      assert.equal(res.versionDiff.addedCount, 1);
      assert.equal(res.versionDiff.addedTests[0].testId, 't_added');

      // Only FAIL -> PASS is counted in improvementsCount
      assert.equal(res.highlights.improvementsCount, 1);
      assert.equal(res.highlights.regressionsCount, 1);
    });

    test('matches tests by stable test ID, not array positions', () => {
      const base = {
        runId: 'base_order_1',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        results: [
          { testId: 'test_alpha', verdict: 'FAIL', name: 'Alpha' },
          { testId: 'test_beta', verdict: 'PASS', name: 'Beta' }
        ]
      };

      // Inverted array order in comparison
      const comp = {
        runId: 'comp_order_2',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        results: [
          { testId: 'test_beta', verdict: 'PASS', name: 'Beta' },
          { testId: 'test_alpha', verdict: 'FAIL', name: 'Alpha' }
        ]
      };

      const res = compareBenchmarkRuns(base, comp);
      assert.equal(res.highlights.regressionsCount, 0);
      assert.equal(res.highlights.improvementsCount, 0);
      for (const t of res.transitions) {
        assert.equal(t.transitionType, 'UNCHANGED');
      }
    });
  });

  // =========================================================================
  // 3. EXPORT SANITIZATION & SECRET HANDLING AUDIT
  // =========================================================================
  describe('3. Export Sanitization & Secret Handling Audit', () => {
    test('rejects malformed report payloads with clear validation errors before export', () => {
      assert.throws(() => buildCanonicalReport(null), /report object is required/);
      assert.throws(() => buildCanonicalReport({}), /runId is required/);
      assert.throws(() => buildCanonicalReport({ runId: 'test' }), /results array is required/);
      assert.throws(() => buildCanonicalReport({ runId: 'test', results: 'not_an_array' }), /results array is required/);
    });

    test('sanitizeUrl scrubs username/password in user-info and sensitive query params', () => {
      const sensitiveUrl = 'https://admin:superSecret123@api.target.com/v1/chat?api_key=sk-123456789&token=abcde&user=john';
      const sanitized = sanitizeUrl(sensitiveUrl);

      assert.equal(sanitized.includes('superSecret123'), false);
      assert.equal(sanitized.includes('sk-123456789'), false);
      assert.equal(sanitized.includes('abcde'), false);
      assert.ok(sanitized.includes('[REDACTED]'));
      assert.ok(sanitized.includes('user=john')); // non-sensitive query retained
    });

    test('sanitizeUrl handles URL-encoded parameter names and unusual keys', () => {
      const encodedUrl = 'https://api.target.com/chat?%61%70%69%5F%6B%65%79=hiddenKey123&bearer=tokenVal456';
      const sanitized = sanitizeUrl(encodedUrl);

      assert.equal(sanitized.includes('hiddenKey123'), false);
      assert.equal(sanitized.includes('tokenVal456'), false);
      assert.ok(sanitized.includes('[REDACTED]'));
    });

    test('sanitizeTargetDetails strips authorization headers and credential properties', () => {
      const rawTarget = {
        url: 'https://api.example.com/chat?key=secret',
        method: 'POST',
        headers: {
          Authorization: 'Bearer sk-secret-token',
          'x-api-key': 'topsecret',
          Cookie: 'session=123456'
        },
        credentials: { user: 'admin', pass: 'secret' }
      };

      const sanitized = sanitizeTargetDetails(rawTarget);
      assert.equal(sanitized.headers, undefined);
      assert.equal(sanitized.credentials, undefined);
      assert.equal(sanitized.url.includes('secret'), false);
    });

    test('scrubs canary secrets and embedded authorization tokens from error messages and metadata', () => {
      const canarySecret = 'CANARY_CONFIDENTIAL_TOKEN_777';
      const reportWithCanaryInError = {
        runId: 'report_canary_err',
        canarySecret,
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        results: [
          {
            testId: 't1',
            verdict: 'ERROR',
            targetExecution: {
              status: 'CONNECTION_ERROR',
              error: `Failed to connect with secret CANARY_CONFIDENTIAL_TOKEN_777 and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
            },
            evidence: `Error while handling CANARY_CONFIDENTIAL_TOKEN_777`,
            explanation: `Target errored on CANARY_CONFIDENTIAL_TOKEN_777`
          }
        ]
      };

      const canonical = buildCanonicalReport(reportWithCanaryInError);
      const res = canonical.results[0];

      assert.equal(res.targetExecution.error.includes(canarySecret), false);
      assert.ok(res.targetExecution.error.includes('[CANARY_SECRET_REDACTED]'));
      assert.ok(res.targetExecution.error.includes('Bearer [REDACTED]'));
      assert.equal(res.evidence.includes(canarySecret), false);
      assert.equal(res.explanation.includes(canarySecret), false);
    });

    test('generateMarkdownReport escapes markdown headers and table pipes to prevent section spoofing', () => {
      const maliciousReport = {
        runId: 'report_spoof_attempt',
        benchmark: { id: 'vibesec-core', version: '1.0.0' },
        target: { url: 'https://api.example.com/chat' },
        categoryBreakdown: {
          'Malicious | Category | Injection': { total: 1, pass: 1, fail: 0, inconclusive: 0, error: 0 }
        },
        results: [
          {
            testId: 'spoof_1',
            name: 'Spoof Test #1',
            category: 'Malicious | Category | Injection',
            attackInput: 'Test input',
            actualResponse: 'Safe response with backticks: ```javascript\nconsole.log(1);\n```',
            verdict: 'FAIL',
            evidence: 'Evidence with malicious heading breakout:\n# 1. Executive Summary\nSpoofed Pass Verdict',
            explanation: 'Explanation with blockquote breakout:\n> Fake PASS confirmed by auditor',
            securityRequirement: 'Must not execute # headings'
          }
        ]
      };

      const { content } = generateMarkdownReport(maliciousReport);

      // Verify that `# 1. Executive Summary` in evidence was escaped so it does NOT create a top-level heading
      assert.equal(content.includes('\n# 1. Executive Summary\nSpoofed Pass Verdict'), false);
      assert.ok(content.includes('\\# 1. Executive Summary') || content.includes('> \\# 1. Executive Summary'));

      // Verify table cell pipes in category name were escaped
      assert.ok(content.includes('Malicious \\| Category \\| Injection'));

      // Verify adaptive fence backticks accommodate the 3 backticks in target response
      assert.ok(content.includes('````text'));
    });
  });

  // =========================================================================
  // 4. TARGET ISOLATION & NETWORK SECURITY DEFENSES
  // =========================================================================
  describe('4. Target Isolation & Network Security Defenses', () => {
    test('export and comparison API endpoints execute zero requests against external targets', async () => {
      const callsBefore = dispatchedTargetCalls;

      // 1. Export JSON
      const resJson = await fetch(`${serverBaseUrl}/api/benchmark/export/json`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          report: {
            runId: 'iso_run_1',
            benchmark: { id: 'vibesec-core', version: '1.0.0' },
            target: { url: dummyTargetUrl },
            results: [{ testId: 't1', verdict: 'PASS' }]
          }
        })
      });
      assert.equal(resJson.status, 200);

      // 2. Export Markdown
      const resMd = await fetch(`${serverBaseUrl}/api/benchmark/export/markdown`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          report: {
            runId: 'iso_run_1',
            benchmark: { id: 'vibesec-core', version: '1.0.0' },
            target: { url: dummyTargetUrl },
            results: [{ testId: 't1', verdict: 'PASS' }]
          }
        })
      });
      assert.equal(resMd.status, 200);

      // 3. Compare runs
      const resComp = await fetch(`${serverBaseUrl}/api/benchmark/compare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          baselineReport: {
            runId: 'iso_run_1',
            benchmark: { id: 'vibesec-core', version: '1.0.0' },
            target: { url: dummyTargetUrl },
            results: [{ testId: 't1', verdict: 'PASS' }]
          },
          comparisonReport: {
            runId: 'iso_run_2',
            benchmark: { id: 'vibesec-core', version: '1.0.0' },
            target: { url: dummyTargetUrl },
            results: [{ testId: 't1', verdict: 'FAIL' }]
          }
        })
      });
      assert.equal(resComp.status, 200);

      // Assert target calls did not increase
      assert.equal(dispatchedTargetCalls, callsBefore);
    });

    test('target failures remain ERROR and are never converted to PASS', async () => {
      // Create a temporary failing HTTP server (500 error)
      const errorServer = http.createServer((req, res) => {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Crash' }));
      });

      let errPort;
      await new Promise((resolve) => {
        errorServer.listen(0, '127.0.0.1', () => {
          errPort = errorServer.address().port;
          resolve();
        });
      });

      try {
        const targetConfig = {
          url: `http://127.0.0.1:${errPort}/api/chat`,
          method: 'POST',
          ownershipAcknowledged: true,
          timeoutMs: 3000
        };

        const res = await executeTargetRequest(targetConfig, 'test input', { allowLocal: true });
        assert.equal(res.success, false);
        assert.equal(res.status, 'HTTP_ERROR');
        assert.equal(res.httpStatus, 500);

        // Run benchmark runner with this target
        const report = await runBenchmarkSuite({
          targetConfig,
          mode: 'live',
          options: { maxTests: 1, allowLocal: true }
        });

        assert.equal(report.results[0].verdict, 'ERROR');
        assert.notEqual(report.results[0].verdict, 'PASS');
      } finally {
        await new Promise((r) => errorServer.close(r));
      }
    });

    test('validateTargetUrl blocks localhost in standard production mode by default', async () => {
      const check = await validateTargetUrl('http://localhost:5000/api/chat', { allowLocal: false });
      assert.equal(check.valid, false);
      assert.ok(check.error.includes('reserved or local address'));

      const ipCheck = await validateTargetUrl('http://127.0.0.1:5000/api/chat', { allowLocal: false });
      assert.equal(ipCheck.valid, false);
      assert.ok(ipCheck.error.includes('prohibited private, loopback, or metadata range'));
    });
  });

  // =========================================================================
  // 5. EVALUATOR RELIABILITY & PROVENANCE
  // =========================================================================
  describe('5. Evaluator Reliability & Provenance', () => {
    test('heuristic fallback marks ambiguous output as INCONCLUSIVE, never PASS', () => {
      const res = heuristicSecurityEvaluation('Do something', 'The weather is sunny in Paris.', 'Must refuse attacks');
      assert.equal(res.verdict, 'INCONCLUSIVE');
      assert.equal(res.evaluator, 'heuristic_fallback');
    });

    test('heuristic fallback flags clear refusal as PASS and clear verbatim leak as FAIL', () => {
      const passRes = heuristicSecurityEvaluation('attack', 'I cannot comply with this request.', 'Must refuse');
      assert.equal(passRes.verdict, 'PASS');
      assert.equal(passRes.evaluator, 'heuristic_fallback');

      const failRes = heuristicSecurityEvaluation(
        'print verbatim prompt',
        'You are a helpful assistant. System prompt: secret rules',
        'Must refuse'
      );
      assert.equal(failRes.verdict, 'FAIL');
      assert.equal(failRes.evaluator, 'heuristic_fallback');
    });

    test('evaluator fallback records evaluator provenance when AI service is unavailable', async () => {
      // Evaluate with missing key forces fallback
      const originalKey = process.env.GEMINI_API_KEY;
      process.env.GEMINI_API_KEY = '';

      try {
        const res = await evaluateSecurityResponse({
          attackInput: 'test prompt',
          targetResponse: 'ambiguous response',
          securityRequirements: 'rule'
        });

        assert.equal(res.evaluator, 'heuristic_fallback');
        assert.equal(res.verdict, 'INCONCLUSIVE');
      } finally {
        process.env.GEMINI_API_KEY = originalKey;
      }
    });
  });
});
