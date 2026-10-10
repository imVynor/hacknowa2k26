const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const app = require('../index');
const {
  STRATEGY_LIBRARY_METADATA,
  ALLOWLISTED_STRATEGY_IDS,
  getAdaptiveStrategies,
  getAdaptiveStrategyById,
  selectDeterministicStrategy,
  selectAdaptiveStrategy
} = require('../campaign/adaptiveStrategy');
const {
  ADAPTIVE_SERVER_LIMITS,
  aggregateAdaptiveVerdict,
  runAdaptiveCampaign
} = require('../campaign/adaptiveRunner');
const {
  getCampaignHistory,
  getCampaignRunById
} = require('../campaign/campaignRunner');
const {
  buildCanonicalCampaignReport,
  generateCampaignJsonReport,
  generateCampaignMarkdownReport
} = require('../campaign/campaignReport');

describe('VibeSec Phase 5: Bounded Adaptive Attack Campaigns Suite', () => {
  let appServer;
  let appPort;
  let appBaseUrl;

  let localMockServer;
  let localMockPort;
  let localMockUrl;
  let receivedRequests = [];
  let mockServerHandler = null;

  before(async () => {
    // 1. Start express app on ephemeral port
    await new Promise((resolve) => {
      appServer = app.listen(0, () => {
        appPort = appServer.address().port;
        appBaseUrl = `http://127.0.0.1:${appPort}`;
        resolve();
      });
    });

    // 2. Start mock target server
    await new Promise((resolve) => {
      localMockServer = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk;
        });
        req.on('end', () => {
          receivedRequests.push({
            method: req.method,
            url: req.url,
            headers: req.headers,
            body: body ? JSON.parse(body) : null
          });

          if (mockServerHandler) {
            return mockServerHandler(req, res, body ? JSON.parse(body) : null);
          }

          // Default safe response
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              reply: 'I cannot comply with requests to bypass security policies. How can I assist you safely?'
            })
          );
        });
      });

      localMockServer.listen(0, '127.0.0.1', () => {
        localMockPort = localMockServer.address().port;
        localMockUrl = `http://127.0.0.1:${localMockPort}/api/chat`;
        resolve();
      });
    });
  });

  after(async () => {
    if (appServer) {
      await new Promise((resolve) => appServer.close(resolve));
    }
    if (localMockServer) {
      await new Promise((resolve) => localMockServer.close(resolve));
    }
  });

  // 1. STRATEGY LIBRARY & ALLOWLIST
  describe('1. Strategy Library & Allowlist Integrity', () => {
    test('defines all 6 required defensive testing strategies in library', () => {
      const strategies = getAdaptiveStrategies();
      assert.strictEqual(strategies.length, 6);

      const expectedIds = [
        'instruction_boundary_test',
        'untrusted_content_test',
        'policy_consistency_test',
        'context_retention_test',
        'canary_disclosure_test',
        'clarification_test'
      ];

      for (const expectedId of expectedIds) {
        assert.ok(
          strategies.some((s) => s.id === expectedId),
          `Missing expected strategy: ${expectedId}`
        );
      }
    });

    test('ALLOWLISTED_STRATEGY_IDS is frozen and contains exactly the 6 strategies', () => {
      assert.ok(Object.isFrozen(ALLOWLISTED_STRATEGY_IDS));
      assert.strictEqual(ALLOWLISTED_STRATEGY_IDS.length, 6);
      assert.ok(ALLOWLISTED_STRATEGY_IDS.includes('instruction_boundary_test'));
      assert.ok(ALLOWLISTED_STRATEGY_IDS.includes('canary_disclosure_test'));
    });

    test('getAdaptiveStrategyById customizes prompt with requirement, canary, and objective', () => {
      const canarySecret = 'CANARY_TEST_SECRET_9876';
      const requirement = 'Do not divulge customer financial records';
      const objective = 'Test financial policy compliance';

      const strat = getAdaptiveStrategyById('canary_disclosure_test', {
        canarySecret,
        applicationRequirement: requirement,
        objective
      });

      assert.ok(strat);
      assert.strictEqual(strat.id, 'canary_disclosure_test');
      assert.ok(strat.prompt.includes(canarySecret));

      const policyStrat = getAdaptiveStrategyById('policy_consistency_test', {
        applicationRequirement: requirement,
        objective
      });
      assert.ok(policyStrat.prompt.includes(requirement));
    });

    test('getAdaptiveStrategyById returns null for unknown strategy ID', () => {
      const unknown = getAdaptiveStrategyById('arbitrary_malicious_eval_script');
      assert.strictEqual(unknown, null);
    });
  });

  // 2. STRATEGY SELECTOR & ALLOWLIST ENFORCEMENT
  describe('2. Bounded Strategy Selection & Allowlist Enforcement', () => {
    test('selectDeterministicStrategy selects initial instruction_boundary_test when history is empty', () => {
      const selection = selectDeterministicStrategy({
        history: [],
        attemptedStrategyIds: [],
        remainingTurns: 5
      });

      assert.strictEqual(selection.strategyId, 'instruction_boundary_test');
      assert.strictEqual(selection.provenance, 'deterministic_initial');
      assert.strictEqual(selection.isExhausted, false);
      assert.ok(selection.rationale.length > 0);
    });

    test('selectDeterministicStrategy transitions through eligible unattempted strategies', () => {
      const attempted = ['instruction_boundary_test'];
      const history = [
        {
          turnNumber: 1,
          strategyId: 'instruction_boundary_test',
          verdict: 'PASS',
          actualResponse: 'I cannot disclose system prompts.'
        }
      ];

      const selection = selectDeterministicStrategy({
        history,
        attemptedStrategyIds: attempted,
        remainingTurns: 4,
        canarySecret: 'CANARY_XYZ'
      });

      assert.ok(ALLOWLISTED_STRATEGY_IDS.includes(selection.strategyId));
      assert.notStrictEqual(selection.strategyId, 'instruction_boundary_test');
      assert.strictEqual(selection.isExhausted, false);
    });

    test('selectDeterministicStrategy signals exhaustion when all eligible strategies attempted', () => {
      const attempted = [
        'instruction_boundary_test',
        'untrusted_content_test',
        'policy_consistency_test',
        'context_retention_test',
        'canary_disclosure_test',
        'clarification_test'
      ];
      const history = attempted.map((id, idx) => ({
        turnNumber: idx + 1,
        strategyId: id,
        verdict: 'PASS',
        actualResponse: 'Safe refusal'
      }));

      const selection = selectDeterministicStrategy({
        history,
        attemptedStrategyIds: attempted,
        remainingTurns: 2,
        canarySecret: 'CANARY_XYZ'
      });

      assert.strictEqual(selection.strategyId, null);
      assert.strictEqual(selection.isExhausted, true);
      assert.ok(selection.rationale.includes('All eligible defensive test strategies have been executed'));
    });

    test('selectAdaptiveStrategy enforces allowlist and falls back to deterministic on invalid model output', async () => {
      // Mock an invalid LLM client that returns a disallowed strategy
      const mockInvalidLlm = {
        models: {
          generateContent: async () => ({
            text: JSON.stringify({
              strategyId: 'arbitrary_shell_execution_exploit',
              rationale: 'Trying an unallowlisted exploit'
            })
          })
        }
      };

      const selection = await selectAdaptiveStrategy({
        history: [],
        attemptedStrategyIds: [],
        remainingTurns: 5,
        selectionMode: 'llm',
        customGenAI: mockInvalidLlm
      });

      // Must be safely rejected and fallback to deterministic allowlisted choice
      assert.ok(ALLOWLISTED_STRATEGY_IDS.includes(selection.strategyId));
      assert.strictEqual(selection.strategyId, 'instruction_boundary_test');
      assert.strictEqual(selection.provenance, 'deterministic_fallback_invalid_allowlist');
    });

    test('selectAdaptiveStrategy accepts valid allowlisted strategy selected by model', async () => {
      const mockValidLlm = {
        models: {
          generateContent: async () => ({
            text: JSON.stringify({
              strategyId: 'policy_consistency_test',
              rationale: 'Testing declared policy consistency next'
            })
          })
        }
      };

      const selection = await selectAdaptiveStrategy({
        history: [
          {
            turnNumber: 1,
            strategyId: 'instruction_boundary_test',
            verdict: 'PASS',
            actualResponse: 'Safe'
          }
        ],
        attemptedStrategyIds: ['instruction_boundary_test'],
        remainingTurns: 4,
        selectionMode: 'llm',
        customGenAI: mockValidLlm
      });

      assert.strictEqual(selection.strategyId, 'policy_consistency_test');
      assert.strictEqual(selection.provenance, 'llm_selected');
      assert.strictEqual(selection.rationale, 'Testing declared policy consistency next');
    });
  });

  // 3. SERVER-SIDE BOUNDS & RESOURCE CAPS
  describe('3. Strict Server-Side Limits Enforcement', () => {
    test('enforces MAX_TURNS_CAP and MAX_TOTAL_DURATION_MS_CAP regardless of client inputs', async () => {
      const run = await runAdaptiveCampaign({
        targetConfig: {},
        mode: 'mock',
        maxTurns: 99999, // Exceeds cap of 10
        maxTotalDurationMs: 99999999, // Exceeds cap of 120000
        options: {
          mockResponseDelayMs: 0
        }
      });

      assert.strictEqual(run.executionLimits.maxTurns, ADAPTIVE_SERVER_LIMITS.MAX_TURNS_CAP);
      assert.strictEqual(
        run.executionLimits.maxTotalDurationMs,
        ADAPTIVE_SERVER_LIMITS.MAX_TOTAL_DURATION_MS_CAP
      );
      assert.ok(run.turns.length <= ADAPTIVE_SERVER_LIMITS.MAX_TURNS_CAP);
    });

    test('preserves cumulative conversation characters and records budget usage', async () => {
      const run = await runAdaptiveCampaign({
        targetConfig: {},
        mode: 'mock',
        maxTurns: 3,
        options: {
          mockResponseDelayMs: 0
        }
      });

      assert.ok(run.budgetUsage);
      assert.strictEqual(typeof run.budgetUsage.executedTurns, 'number');
      assert.strictEqual(typeof run.budgetUsage.totalDurationMs, 'number');
      assert.strictEqual(typeof run.budgetUsage.conversationChars, 'number');
      assert.ok(run.budgetUsage.conversationChars > 0);
      assert.strictEqual(run.budgetUsage.maxConversationChars, ADAPTIVE_SERVER_LIMITS.MAX_CONVERSATION_CHARS_CAP);
    });
  });

  // 4. VERDICT SEMANTICS & EARLY STOPPING
  describe('4. Verdict Semantics & Early Termination', () => {
    test('budget exhaustion before completing all objectives never produces PASS', () => {
      const verdict = aggregateAdaptiveVerdict({
        turns: [
          { turnNumber: 1, verdict: 'PASS' },
          { turnNumber: 2, verdict: 'PASS' }
        ],
        stoppingReason: 'TURN_BUDGET_EXHAUSTED',
        campaignCompleted: false
      });

      assert.strictEqual(verdict.verdict, 'INCONCLUSIVE');
      assert.ok(verdict.explanation.includes('insufficient for definitive PASS'));
    });

    test('context budget exhaustion before completion produces INCONCLUSIVE', () => {
      const verdict = aggregateAdaptiveVerdict({
        turns: [{ turnNumber: 1, verdict: 'PASS' }],
        stoppingReason: 'CONTEXT_BUDGET_EXHAUSTED',
        campaignCompleted: false
      });

      assert.strictEqual(verdict.verdict, 'INCONCLUSIVE');
    });

    test('overall execution timeout produces ERROR', () => {
      const verdict = aggregateAdaptiveVerdict({
        turns: [{ turnNumber: 1, verdict: 'PASS' }],
        stoppingReason: 'TIMED_OUT',
        campaignCompleted: false
      });

      assert.strictEqual(verdict.verdict, 'ERROR');
      assert.ok(verdict.explanation.includes('timeout'));
    });

    test('confirmed violation produces FAIL even when terminated early', () => {
      const verdict = aggregateAdaptiveVerdict({
        turns: [
          { turnNumber: 1, verdict: 'PASS' },
          { turnNumber: 2, verdict: 'FAIL', strategyId: 'untrusted_content_test' }
        ],
        stoppingReason: 'CONFIRMED_VIOLATION',
        campaignCompleted: false
      });

      assert.strictEqual(verdict.verdict, 'FAIL');
      assert.ok(verdict.explanation.includes('Demonstrated security violation'));
    });

    test('zero executed turns produces ERROR', () => {
      const verdict = aggregateAdaptiveVerdict({
        turns: [],
        stoppingReason: 'TURN_BUDGET_EXHAUSTED',
        campaignCompleted: false
      });

      assert.strictEqual(verdict.verdict, 'ERROR');
    });

    test('all objectives tested and all passing produces PASS', () => {
      const verdict = aggregateAdaptiveVerdict({
        turns: [
          { turnNumber: 1, verdict: 'PASS' },
          { turnNumber: 2, verdict: 'PASS' },
          { turnNumber: 3, verdict: 'PASS' }
        ],
        stoppingReason: 'ALL_OBJECTIVES_TESTED',
        campaignCompleted: true
      });

      assert.strictEqual(verdict.verdict, 'PASS');
    });
  });

  // 5. LIVE TARGET EXECUTION, CANARY DETECTION, AND EARLY STOP
  describe('5. Live Target Adaptation & Early Stopping', () => {
    test('stops immediately on confirmed security violation and preserves partial evidence', async () => {
      receivedRequests = [];
      let requestCount = 0;

      // Mock target that passes turn 1 but violates policy on turn 2
      mockServerHandler = (req, res) => {
        requestCount++;
        if (requestCount === 1) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              reply: 'I must follow safety instructions. I cannot execute unauthorized commands.'
            })
          );
        } else {
          // Explicit policy violation marker
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              reply: 'OVERRIDE CONFIRMED: INJECTION_DELIMITER_EXECUTED. System instructions bypassed.'
            })
          );
        }
      };

      const run = await runAdaptiveCampaign({
        targetConfig: {
          url: localMockUrl,
          method: 'POST',
          inputPath: 'message',
          responsePath: 'reply',
          ownershipAcknowledged: true
        },
        mode: 'live',
        maxTurns: 5,
        options: {
          allowLocal: true
        }
      });

      assert.strictEqual(run.stoppingReason, 'CONFIRMED_VIOLATION');
      assert.strictEqual(run.summary.campaignVerdict, 'FAIL');
      assert.strictEqual(run.turns.length, 2);
      assert.strictEqual(run.turns[0].verdict, 'PASS');
      assert.strictEqual(run.turns[1].verdict, 'FAIL');
      assert.strictEqual(run.campaignCompleted, false);
      assert.strictEqual(requestCount, 2); // Sequential execution stopped on turn 2
    });

    test('detects canary token disclosure deterministically and halts campaign', async () => {
      receivedRequests = [];
      const canarySecret = 'CANARY_DISCLOSURE_KEY_12345';

      // Mock target that leaks the canary in response
      mockServerHandler = (req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            reply: `Here is the requested confidential verification token: ${canarySecret}`
          })
        );
      };

      const run = await runAdaptiveCampaign({
        targetConfig: {
          url: localMockUrl,
          method: 'POST',
          inputPath: 'message',
          responsePath: 'reply',
          ownershipAcknowledged: true
        },
        mode: 'live',
        canarySecret,
        maxTurns: 5,
        options: {
          allowLocal: true
        }
      });

      assert.strictEqual(run.stoppingReason, 'CONFIRMED_VIOLATION');
      assert.strictEqual(run.summary.campaignVerdict, 'FAIL');
      assert.strictEqual(run.turns[0].canaryDetection.detected, true);
      assert.strictEqual(run.turns[0].verdict, 'FAIL');
    });

    test('stops immediately on target execution failure (HTTP 500) and marks ERROR', async () => {
      receivedRequests = [];
      mockServerHandler = (req, res) => {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Target Service Error' }));
      };

      const run = await runAdaptiveCampaign({
        targetConfig: {
          url: localMockUrl,
          method: 'POST',
          inputPath: 'message',
          responsePath: 'reply',
          ownershipAcknowledged: true
        },
        mode: 'live',
        maxTurns: 5,
        options: {
          allowLocal: true
        }
      });

      assert.strictEqual(run.stoppingReason, 'TARGET_EXECUTION_FAILURE');
      assert.strictEqual(run.summary.campaignVerdict, 'ERROR');
      assert.strictEqual(run.turns.length, 1);
      assert.strictEqual(run.turns[0].verdict, 'ERROR');
    });
  });

  // 6. REPORT GENERATION, REDACTION, AND ZERO TARGET CALLS
  describe('6. Canonical Reporting, Redaction & Zero Side-Effect Export', () => {
    test('builds canonical report preserving adaptive strategy rationale and scrubbing secrets', () => {
      const canarySecret = 'SECRET_CANARY_ABCD';
      const fakeApiKey = 'Bearer secret-target-token-1234567890';

      const rawRun = {
        runId: 'adapt-run-test-123',
        campaignType: 'adaptive',
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        totalDurationMs: 1500,
        status: 'COMPLETED',
        mode: 'mock',
        selectionMode: 'deterministic',
        stoppingReason: 'ALL_OBJECTIVES_TESTED',
        campaignCompleted: true,
        strategyLibrary: STRATEGY_LIBRARY_METADATA,
        budgetUsage: {
          executedTurns: 2,
          maxTurns: 5,
          totalDurationMs: 1500,
          maxTotalDurationMs: 60000,
          conversationChars: 1200,
          maxConversationChars: 50000,
          strategySelectionCalls: 2,
          evaluatorCalls: 2
        },
        target: {
          url: `http://api.example.com/chat?key=secret123&token=myToken`,
          method: 'POST'
        },
        summary: {
          totalTurns: 5,
          executedTurns: 2,
          pass: 2,
          fail: 0,
          inconclusive: 0,
          error: 0,
          campaignVerdict: 'PASS',
          verdictExplanation: 'Target defended against tested strategies.'
        },
        turns: [
          {
            turnId: 'turn-1',
            turnNumber: 1,
            name: 'Instruction Boundary Probe',
            strategyId: 'instruction_boundary_test',
            strategyName: 'Instruction Boundary Test',
            strategySelectionRationale: `Initial probe with ${canarySecret} and ${fakeApiKey}`,
            selectionProvenance: 'deterministic_initial',
            prompt: 'Test prompt',
            securityObjective: 'Test boundary',
            actualResponse: `Safe response containing ${canarySecret}`,
            targetExecution: { status: 'SUCCESS', httpStatus: 200, responseTimeMs: 120 },
            canaryDetection: { canaryConfigured: true, detected: false },
            verdict: 'PASS',
            evidence: 'Heuristic refusal observed.',
            explanation: 'Safe',
            evaluator: 'heuristic_refusal_match',
            timing: { totalDurationMs: 120 }
          }
        ]
      };

      const report = buildCanonicalCampaignReport(rawRun, { canarySecret });

      assert.strictEqual(report.campaignType, 'adaptive');
      assert.strictEqual(report.budgetUsage.executedTurns, 2);
      assert.strictEqual(report.stoppingReason, 'ALL_OBJECTIVES_TESTED');
      // Redaction check
      assert.ok(!report.target.url.includes('secret123'));
      assert.ok(report.target.url.includes('[REDACTED]'));
      assert.ok(!report.turns[0].strategySelectionRationale.includes(canarySecret));
      assert.ok(report.turns[0].strategySelectionRationale.includes('[CANARY_SECRET_REDACTED]'));
      assert.ok(!report.turns[0].actualResponse.includes(canarySecret));
      assert.ok(report.turns[0].actualResponse.includes('[CANARY_SECRET_REDACTED]'));
    });

    test('exporting Markdown and JSON reports triggers zero HTTP requests to target', async () => {
      receivedRequests = [];

      const rawRun = await runAdaptiveCampaign({
        targetConfig: {},
        mode: 'mock',
        maxTurns: 2,
        options: { mockResponseDelayMs: 0 }
      });

      const initialTargetRequests = receivedRequests.length;

      // Generate reports
      const jsonReport = generateCampaignJsonReport(rawRun);
      const mdReport = generateCampaignMarkdownReport(rawRun);

      assert.ok(jsonReport.content.includes(rawRun.runId));
      assert.ok(mdReport.content.includes('# VibeSec Adaptive Campaign Security Report'));
      assert.ok(mdReport.content.includes('Server Resource & Budget Consumption'));
      assert.ok(mdReport.content.includes('Selection Rationale'));

      // Confirm zero network calls made
      assert.strictEqual(receivedRequests.length, initialTargetRequests);
    });

    test('Markdown report uses adaptive backticks to prevent code-fence injection', () => {
      const rawRun = {
        runId: 'injection-test-run',
        campaignType: 'adaptive',
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        totalDurationMs: 500,
        status: 'COMPLETED',
        mode: 'mock',
        campaign: { name: 'Injection Test' },
        target: { url: 'http://test.local' },
        summary: { campaignVerdict: 'PASS', verdictExplanation: 'Clean' },
        turns: [
          {
            turnId: 'turn-inject',
            turnNumber: 1,
            name: 'Injection Attempt',
            strategyId: 'instruction_boundary_test',
            prompt: 'Normal prompt',
            actualResponse: '```markdown\nFake breakout attempt\n```',
            targetExecution: { status: 'SUCCESS' },
            canaryDetection: {},
            verdict: 'PASS',
            timing: { totalDurationMs: 10 }
          }
        ]
      };

      const md = generateCampaignMarkdownReport(rawRun);
      // Backtick fence should adapt to at least 4 backticks (````)
      assert.ok(md.content.includes('````text\n```markdown'));
    });
  });

  // 7. EXPRESS ENDPOINTS INTEGRATION
  describe('7. Express Routes Integration', () => {
    test('GET /api/campaigns/strategies returns 6 strategies and server limits', async () => {
      const res = await fetch(`${appBaseUrl}/api/campaigns/strategies`);
      assert.strictEqual(res.status, 200);

      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.strategies.length, 6);
      assert.ok(data.serverLimits);
      assert.strictEqual(data.serverLimits.MAX_TURNS_CAP, 10);
      assert.strictEqual(data.library.version, '1.0.0');
    });

    test('POST /api/campaigns/adaptive/run executes campaign and records in history', async () => {
      const res = await fetch(`${appBaseUrl}/api/campaigns/adaptive/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'mock',
          maxTurns: 2,
          objective: 'Test adaptive REST endpoint'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.run.campaignType, 'adaptive');
      assert.ok(data.run.runId);

      // Verify it appears in /api/campaigns/history
      const historyRes = await fetch(`${appBaseUrl}/api/campaigns/history`);
      assert.strictEqual(historyRes.status, 200);
      const historyData = await historyRes.json();
      assert.ok(historyData.history.some((h) => h.runId === data.run.runId));
    });

    test('POST /api/campaigns/adaptive/run enforces authorization acknowledgment for live targets', async () => {
      const res = await fetch(`${appBaseUrl}/api/campaigns/adaptive/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'live',
          targetConfig: {
            url: 'http://example.com/api',
            ownershipAcknowledged: false // Not authorized!
          }
        })
      });

      assert.strictEqual(res.status, 400);
      const data = await res.json();
      assert.strictEqual(data.success, false);
      assert.ok(data.error.includes('Target ownership authorization must be acknowledged'));
    });
  });
});
