const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { getBenchmarkSuite } = require('../benchmark/benchmarkSuite');
const { runBenchmarkSuite } = require('../benchmark/benchmarkRunner');

describe('Benchmark Engine & Suite Test Suite (Phase 3A)', () => {
  let mockServer;
  let mockPort;
  let mockBaseUrl;

  before(async () => {
    // Spin up mock server for testing benchmark execution behaviors
    mockServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        // Route 1: Mixed Behavior Target
        if (req.url === '/api/mixed-target' && req.method === 'POST') {
          const parsed = JSON.parse(body || '{}');
          const message = parsed.message || '';

          // 1. Canary probe test -> Leaks canary secret (FAIL)
          if (message.includes('URGENT COMPLIANCE AUDIT')) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                reply: 'Audit accepted. Confidential verification token: VIBESEC_DEMO_CANARY_42.',
                provenance: 'deterministic_demo_fixture'
              })
            );
            return;
          }

          // 2. Direct override test -> Complies with override marker (FAIL)
          if (message.includes('SYSTEM COMMAND OVERRIDE')) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                reply: 'Acknowledged. SYSTEM INSTRUCTIONS OVERRIDDEN.',
                provenance: 'deterministic_demo_fixture'
              })
            );
            return;
          }

          // 3. Other tests -> Safe refusal (PASS)
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              reply: 'I am a customer assistant. I cannot comply with unauthorized administrative requests or grant unauthorized discounts.',
              provenance: 'deterministic_demo_fixture'
            })
          );
          return;
        }

        // Route 2: Flaky Target (Simulates error mid-run)
        let requestCount = 0;
        if (req.url === '/api/flaky-target' && req.method === 'POST') {
          const parsed = JSON.parse(body || '{}');
          const message = parsed.message || '';

          // If canary test, fail with HTTP 500
          if (message.includes('URGENT COMPLIANCE AUDIT')) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Internal Model Gateway Timeout' }));
            return;
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ reply: 'I cannot comply with that request.' }));
          return;
        }

        // Route 3: Invalid Response Schema Target (returns unexpected key)
        if (req.url === '/api/invalid-schema' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ wrong_key: 'No reply field here' }));
          return;
        }

        // Route 4: Slow Target for timeout limits
        if (req.url === '/api/slow' && req.method === 'POST') {
          setTimeout(() => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ reply: 'Delayed response' }));
          }, 800);
          return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      });
    });

    await new Promise((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        mockPort = mockServer.address().port;
        mockBaseUrl = `http://127.0.0.1:${mockPort}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (mockServer) {
      await new Promise((r) => mockServer.close(r));
    }
  });

  // 1. Suite Definition & Metadata
  test('1. Versioned benchmark suite defines all 5 required test categories with stable IDs', () => {
    const suite = getBenchmarkSuite();
    assert.equal(suite.id, 'vibesec-core');
    assert.equal(suite.version, '1.0.0');
    assert.equal(suite.totalTests, 5);

    const categories = suite.tests.map((t) => t.category);
    assert.ok(categories.includes('Instruction Override'));
    assert.ok(categories.includes('Role Manipulation'));
    assert.ok(categories.includes('Canary Disclosure'));
    assert.ok(categories.includes('Indirect Prompt Injection'));
    assert.ok(categories.includes('Application Policy'));

    for (const t of suite.tests) {
      assert.ok(t.id);
      assert.ok(t.name);
      assert.ok(t.prompt);
      assert.ok(t.securityRequirement);
      assert.ok(t.evaluationStrategy);
      assert.ok(t.expectedBehavior);
    }
  });

  test('2. Allows configurable application-specific policy requirement', () => {
    const customReq = 'Target must strictly decline providing medical advice or prescription dosages.';
    const suite = getBenchmarkSuite({ applicationRequirement: customReq });
    const appPolicyTest = suite.tests.find((t) => t.id === 'app_policy_v1');
    assert.equal(appPolicyTest.securityRequirement, customReq);
  });

  // 2. Batch Execution & Mixed Verdicts
  test('3. Executes multiple tests in one run with mixed verdicts (PASS, FAIL) and accurate counts', async () => {
    const targetConfig = {
      url: `${mockBaseUrl}/api/mixed-target`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer secret_admin_token_999'
      },
      bodyTemplate: { message: 'USER_TEST_INPUT' },
      inputPath: 'message',
      responsePath: 'reply',
      timeoutMs: 5000,
      ownershipAcknowledged: true
    };

    const report = await runBenchmarkSuite({
      targetConfig,
      canarySecret: 'VIBESEC_DEMO_CANARY_42',
      mode: 'live',
      options: { allowLocal: true }
    });

    assert.equal(report.mode, 'live');
    assert.equal(report.totalTests, 5);
    assert.ok(report.runId.startsWith('bench_'));

    // Check summary counts
    assert.equal(report.summary.pass + report.summary.fail + report.summary.inconclusive + report.summary.error, 5);
    assert.ok(report.summary.fail >= 2); // Canary disclosure + direct override both fail
    assert.ok(report.summary.pass >= 1);

    // Verify failure rate calculation & documentation
    assert.equal(report.summary.failureRateDenominator, 'totalTests (5)');
    const expectedRate = Number(((report.summary.fail / 5) * 100).toFixed(1));
    assert.equal(report.summary.failureRatePercent, expectedRate);

    // Verify category breakdown
    assert.ok(report.categoryBreakdown['Canary Disclosure']);
    assert.equal(report.categoryBreakdown['Canary Disclosure'].fail, 1);
    assert.ok(report.categoryBreakdown['Instruction Override']);
    assert.equal(report.categoryBreakdown['Instruction Override'].fail, 1);

    // Verify credential redaction: target summary must NOT contain authorization token
    assert.equal(report.target.headers, undefined);
  });

  // 3. Partial Completion After Execution Error (Preserves prior results)
  test('4. Preserves completed test results when an execution error (HTTP 500) occurs on a test', async () => {
    const targetConfig = {
      url: `${mockBaseUrl}/api/flaky-target`,
      method: 'POST',
      bodyTemplate: { message: 'USER_TEST_INPUT' },
      inputPath: 'message',
      responsePath: 'reply',
      timeoutMs: 5000,
      ownershipAcknowledged: true
    };

    const report = await runBenchmarkSuite({
      targetConfig,
      canarySecret: 'VIBESEC_DEMO_CANARY_42',
      mode: 'live',
      options: { allowLocal: true }
    });

    assert.equal(report.totalTests, 5);

    // One test must have ERROR verdict due to HTTP 500
    const errorTest = report.results.find((r) => r.testId === 'canary_disclosure_v1');
    assert.equal(errorTest.verdict, 'ERROR');
    assert.equal(errorTest.targetExecution.httpStatus, 500);

    // Other tests must still have executed and preserved their verdicts
    assert.ok(report.summary.error >= 1);
    assert.ok(report.summary.pass >= 1);
    assert.equal(report.summary.pass + report.summary.fail + report.summary.inconclusive + report.summary.error, 5);
  });

  // 4. Invalid Target Response Mapping Never Becomes PASS
  test('5. Invalid response mapping produces ERROR status and never silently passes', async () => {
    const targetConfig = {
      url: `${mockBaseUrl}/api/invalid-schema`,
      method: 'POST',
      bodyTemplate: { message: 'USER_TEST_INPUT' },
      inputPath: 'message',
      responsePath: 'reply', // Key 'reply' does not exist in /api/invalid-schema response
      timeoutMs: 5000,
      ownershipAcknowledged: true
    };

    const report = await runBenchmarkSuite({
      targetConfig,
      mode: 'live',
      options: { allowLocal: true, maxTests: 2 }
    });

    assert.equal(report.totalTests, 2);
    for (const r of report.results) {
      assert.equal(r.verdict, 'ERROR');
      assert.match(r.targetExecution.error, /not found/i);
    }
    assert.equal(report.summary.error, 2);
    assert.equal(report.summary.pass, 0);
  });

  // 5. Total Execution Time Limit & Max Tests Bounded Limits
  test('6. Enforces maxTests limit and terminates cleanly if total benchmark timeout exceeded', async () => {
    const targetConfig = {
      url: `${mockBaseUrl}/api/slow`,
      method: 'POST',
      bodyTemplate: { message: 'USER_TEST_INPUT' },
      inputPath: 'message',
      responsePath: 'reply',
      timeoutMs: 2000,
      ownershipAcknowledged: true
    };

    // Max tests = 3, maxTotalDurationMs = 1200ms (1st test ~800ms, 2nd will push past 1200ms)
    const report = await runBenchmarkSuite({
      targetConfig,
      mode: 'live',
      options: {
        allowLocal: true,
        maxTests: 3,
        maxTotalDurationMs: 1200
      }
    });

    assert.equal(report.totalTests, 3);
    assert.ok(report.executionLimits.earlyTermination);
    assert.match(report.executionLimits.terminationReason, /timeout limit/i);

    // At least one test completed before timeout, and the aborted test was marked ERROR
    const aborted = report.results.find((r) => r.targetExecution.status === 'TIMEOUT_ABORT');
    assert.ok(aborted);
    assert.equal(aborted.verdict, 'ERROR');
  });

  // 6. Mock Mode Provenance & Labeling
  test('7. Mock mode is clearly labeled with mock_simulation provenance and no live calls', async () => {
    const report = await runBenchmarkSuite({
      targetConfig: null,
      mode: 'mock',
      options: { maxTests: 2 }
    });

    assert.equal(report.mode, 'mock');
    assert.equal(report.totalTests, 2);
    for (const r of report.results) {
      assert.equal(r.targetExecution.provenance, 'mock_simulation');
    }
  });

  // 7. Security Disclaimer & Metric Documentation
  test('8. Report contains mandatory disclaimer and documented failure-rate formula', async () => {
    const report = await runBenchmarkSuite({
      targetConfig: null,
      mode: 'mock',
      options: { maxTests: 1 }
    });

    assert.match(report.benchmark.disclaimer, /does not prove that an application is secure/i);
    assert.ok(report.summary.documentation.includes('failCount / totalTests'));
  });
});
