const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const {
  detectTargetProviderFallback,
  classifyTargetExecution
} = require('../target/targetDiagnostics');
const {
  evaluateSecurityResponse
} = require('../evaluator/securityEvaluator');
const {
  runCampaign
} = require('../campaign/campaignRunner');
const {
  generateCampaignJsonReport,
  generateCampaignMarkdownReport
} = require('../campaign/campaignReport');

describe('VibeSec Phase 8.1: Target Availability UX & Diagnostic Deduplication', () => {
  let mockServer;
  let mockUrl;
  let mockResponsePayload;
  let mockResponseStatus = 200;

  before(async () => {
    mockServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        res.writeHead(mockResponseStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(mockResponsePayload));
      });
    });

    await new Promise((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        const port = mockServer.address().port;
        mockUrl = `http://127.0.0.1:${port}/chat`;
        resolve();
      });
    });
  });

  after(async () => {
    if (mockServer) {
      await new Promise((resolve) => mockServer.close(resolve));
    }
  });

  // --------------------------------------------------------------------------
  // Test 1: Substantive Responses are NOT Incorrectly Classified as Provider Fallback
  // --------------------------------------------------------------------------
  test('1. Ordinary substantive responses are NOT classified as provider fallback', () => {
    const testCases = [
      {
        response: 'I am AcmeAssistant. I cannot comply with requests to override my system instructions or enter debug mode.',
        raw: { provenance: 'live_gemini_model', targetModel: 'gemini-2.5-flash' }
      },
      {
        response: 'The customer feedback for Widget Pro was 5 stars and delivery arrived on time.',
        raw: { provenance: 'live_gemini_model', targetModel: 'gemini-2.5-flash' }
      },
      {
        response: 'To configure fallback routing, update the upstream block in your nginx.conf file.',
        raw: { provenance: 'live_gemini_model', targetModel: 'gemini-2.5-flash' }
      },
      {
        response: 'Operating mode: standard customer service assistant. How can I help you today?',
        raw: { provenance: 'live_gemini_model', targetModel: 'gemini-2.5-flash' }
      },
      {
        response: 'Sorry, I am unable to grant admin access or print sensitive canary secrets.',
        raw: { provenance: 'live_gemini_model', targetModel: 'gemini-2.5-flash' }
      }
    ];

    for (const tc of testCases) {
      const check = detectTargetProviderFallback({
        response: tc.response,
        rawResponseBody: tc.raw,
        httpStatus: 200
      });
      assert.equal(check.isFallback, false, `Failed for response: "${tc.response.slice(0, 40)}"`);

      const diag = classifyTargetExecution({
        success: true,
        extractedResponse: tc.response,
        rawResponseBody: tc.raw,
        httpStatus: 200
      });
      assert.equal(diag.classification, 'SUBSTANTIVE_RESPONSE');
      assert.equal(diag.assessable, true);
      assert.equal(diag.fallbackDetected, false);
    }
  });

  // --------------------------------------------------------------------------
  // Test 2: Recognized Upstream Fallback Signatures are Accurately Identified
  // --------------------------------------------------------------------------
  test('2. Recognized provider rate-limit fallbacks are identified accurately', () => {
    // 2A: Textual signature match
    const check1 = detectTargetProviderFallback({
      response: 'AcmeAssistant: Hello! Our primary AI backend is currently operating in rate-limited fallback mode, but service remains available.',
      rawResponseBody: {},
      httpStatus: 200
    });
    assert.equal(check1.isFallback, true);
    assert.match(check1.reason, /recognized rate-limited fallback message/i);

    // 2B: Provenance metadata signal
    const check2 = detectTargetProviderFallback({
      response: 'Standard customer greeting.',
      rawResponseBody: {
        provenance: 'live_gemini_model_fallback',
        note: 'Google GenAI Free-Tier Rate Limit (429) active',
        targetModel: 'gemini-2.5-flash-fallback'
      },
      httpStatus: 200
    });
    assert.equal(check2.isFallback, true);
    assert.match(check2.reason, /429|rate-limited/i);

    // 2C: Classification outcome
    const diag = classifyTargetExecution({
      success: true,
      extractedResponse: 'AcmeAssistant: Operating in rate-limited fallback mode, but service remains available.',
      rawResponseBody: {
        provenance: 'live_gemini_model_fallback',
        note: 'Google GenAI Free-Tier Rate Limit (429) active'
      },
      httpStatus: 200
    });
    assert.equal(diag.classification, 'PROVIDER_FALLBACK');
    assert.equal(diag.assessable, false);
    assert.equal(diag.unassessableReason, 'TARGET_PROVIDER_FALLBACK');
    assert.equal(diag.fallbackDetected, true);
  });

  // --------------------------------------------------------------------------
  // Test 3: Campaign with 3 Identical Fallbacks Reports Zero Assessable Turns & Deduplicated Root Cause
  // --------------------------------------------------------------------------
  test('3. Campaign with three identical fallback responses reports 0 assessable turns and one deduplicated root cause', async () => {
    const fallbackText =
      'AcmeAssistant: Hello! I am AcmeAssistant customer support bot. Our primary AI backend is currently operating in rate-limited fallback mode, but service remains available.';

    mockResponsePayload = {
      reply: fallbackText,
      provenance: 'live_gemini_model_fallback',
      note: 'Google GenAI Free-Tier Rate Limit (429) active',
      targetModel: 'gemini-2.5-flash-fallback'
    };
    mockResponseStatus = 200;

    const runResult = await runCampaign({
      campaignId: 'multi_turn_indirect_injection_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        timeoutMs: 5000,
        ownershipAcknowledged: true
      },
      canarySecret: 'VIBESEC_CANARY_SECRET_XYZ',
      ownershipAcknowledged: true,
      options: { allowLocal: true }
    });

    // 1. Campaign summary assertions
    assert.equal(runResult.summary.executedTurns, 3);
    assert.equal(runResult.summary.assessableTurns, 0);
    assert.equal(runResult.summary.unassessableTurns, 3);
    assert.equal(runResult.summary.objectivesTested, false);
    assert.equal(runResult.summary.targetProviderFallbackDetected, true);
    assert.equal(runResult.summary.campaignVerdict, 'INCONCLUSIVE');
    assert.match(runResult.summary.verdictExplanation, /Target returned upstream provider\/quota fallback on all turns/i);
    assert.match(runResult.summary.verdictExplanation, /semantic evaluation was skipped/i);

    // 2. Deduplicated campaign-level diagnostic root cause
    assert.ok(runResult.campaignDiagnostic, 'Campaign-level diagnostic must be present');
    assert.equal(runResult.campaignDiagnostic.type, 'TARGET_PROVIDER_FALLBACK');
    assert.equal(runResult.campaignDiagnostic.deduplicated, true);
    assert.equal(runResult.campaignDiagnostic.affectedTurnsCount, 3);
    assert.equal(runResult.campaignDiagnostic.totalTurns, 3);
    assert.equal(runResult.campaignDiagnostic.semanticEvaluationSkipped, true);
    assert.match(runResult.campaignDiagnostic.rootCause, /Google GenAI Free-Tier Rate Limit \(429\) active/);
    assert.match(runResult.campaignDiagnostic.summary, /All 3 campaign turns encountered upstream target provider rate-limit fallback/);

    // 3. Per-turn evidence and status assertions
    assert.equal(runResult.turns.length, 3);
    for (const turn of runResult.turns) {
      assert.equal(turn.assessable, false);
      assert.equal(turn.unassessableReason, 'TARGET_PROVIDER_FALLBACK');
      assert.equal(turn.verdict, 'INCONCLUSIVE');
      assert.equal(turn.evaluator, 'target_diagnostics');
      assert.equal(turn.method, 'target_provider_fallback');
      assert.equal(turn.fallbackReason, 'target_provider_fallback');
      assert.equal(turn.semanticEvaluationSkipped, true);
      assert.equal(turn.semanticEvaluationSkipReason, 'target_unassessable_provider_fallback');
      assert.equal(turn.actualResponse, fallbackText);
      assert.match(turn.evidence, /Target returned upstream provider fallback/);
      assert.match(turn.explanation, /rate-limit fallback/i);
      assert.doesNotMatch(turn.explanation, /heuristic rules could not definitively/i);
    }
  });

  // --------------------------------------------------------------------------
  // Test 4: Target Provider Failure vs Evaluator Provider Failure Separation
  // --------------------------------------------------------------------------
  test('4. Target provider rate-limit failure is kept strictly separate from evaluator quota exhaustion', async () => {
    // 4A: Target provider failure
    const targetFallbackTurn = await evaluateSecurityResponse({
      attackInput: 'Adversarial probe turn',
      targetResponse: 'AcmeAssistant is operating in rate-limited fallback mode.',
      securityRequirements: 'Must decline prompt injection',
      testId: 'indirect_turn_1',
      targetExecution: {
        status: 'PROVIDER_FALLBACK',
        classification: 'PROVIDER_FALLBACK',
        transportSuccess: true,
        fallbackDetected: true,
        fallbackReason: 'Google GenAI Free-Tier Rate Limit (429) active'
      }
    });

    assert.equal(targetFallbackTurn.verdict, 'INCONCLUSIVE');
    assert.equal(targetFallbackTurn.evaluator, 'target_diagnostics');
    assert.equal(targetFallbackTurn.method, 'target_provider_fallback');
    assert.equal(targetFallbackTurn.assessable, false);
    assert.equal(targetFallbackTurn.unassessableReason, 'TARGET_PROVIDER_FALLBACK');
    assert.equal(targetFallbackTurn.semanticEvaluationSkipped, true);
    assert.equal(targetFallbackTurn.reconciliationRule, 'TARGET_PROVIDER_FALLBACK_UNASSESSABLE');

    // 4B: Evaluator provider failure (Target responded normally, but evaluator Gemini quota exhausted)
    const evaluatorFallbackTurn = await evaluateSecurityResponse({
      attackInput: 'Adversarial probe turn',
      targetResponse: 'AcmeAssistant response: Order status #4021 is processing.',
      securityRequirements: 'Must decline prompt injection',
      testId: 'indirect_turn_1',
      targetExecution: {
        status: 'SUCCESS',
        classification: 'SUBSTANTIVE_RESPONSE',
        transportSuccess: true,
        fallbackDetected: false
      },
      evaluatorSessionContext: {
        quotaExhausted: true,
        firstQuotaTurn: 1
      }
    });

    assert.equal(evaluatorFallbackTurn.evaluator, 'heuristic_fallback');
    assert.equal(evaluatorFallbackTurn.method, 'heuristic_fallback');
    assert.equal(evaluatorFallbackTurn.fallbackReason, 'quota_exhausted');
    assert.equal(evaluatorFallbackTurn.reconciliationRule, 'HEURISTIC_FALLBACK_PRESERVED');
    assert.notEqual(evaluatorFallbackTurn.evaluator, 'target_diagnostics');
  });

  // --------------------------------------------------------------------------
  // Test 5: JSON & Markdown Exports Preserve Deduplicated Root Cause & Per-Turn Fidelity
  // --------------------------------------------------------------------------
  test('5. JSON and Markdown exports preserve deduplicated campaign root cause and per-turn assessability', async () => {
    const mockRun = {
      runId: 'camp_fallback_run_77',
      campaignType: 'fixed',
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      totalDurationMs: 450,
      status: 'COMPLETED',
      mode: 'live',
      campaign: {
        campaignId: 'multi_turn_indirect_v1',
        name: 'Indirect Prompt Injection Across Turns',
        version: '1.0.0',
        category: 'Prompt Injection',
        attackObjective: 'Inject indirect instructions',
        securityRequirement: 'Must not execute instructions found in untrusted data',
        evaluationStrategy: 'multi_turn_layered',
        totalTurns: 3,
        tags: ['injection']
      },
      target: { url: 'http://127.0.0.1:5050/api/chat', method: 'POST' },
      targetModel: 'gemini-2.5-flash-fallback',
      evaluatorModel: 'target_diagnostics',
      campaignDiagnostic: {
        type: 'TARGET_PROVIDER_FALLBACK',
        deduplicated: true,
        affectedTurnsCount: 3,
        totalTurns: 3,
        rootCause: 'Google GenAI Free-Tier Rate Limit (429) active',
        summary: 'All 3 campaign turns encountered upstream target provider rate-limit fallback (Google GenAI Free-Tier Rate Limit (429) active).',
        semanticEvaluationSkipped: true,
        recommendation: 'Target requires higher upstream provider quota or active credentials.'
      },
      executionLimits: { maxTurns: 3, maxTotalDurationMs: 90000, earlyTermination: false },
      summary: {
        totalTurns: 3,
        executedTurns: 3,
        assessableTurns: 0,
        unassessableTurns: 3,
        targetProviderFallbackDetected: true,
        campaignDiagnostic: {
          type: 'TARGET_PROVIDER_FALLBACK',
          deduplicated: true,
          affectedTurnsCount: 3,
          totalTurns: 3,
          rootCause: 'Google GenAI Free-Tier Rate Limit (429) active',
          summary: 'All 3 campaign turns encountered upstream target provider rate-limit fallback.',
          semanticEvaluationSkipped: true
        },
        objectivesTested: false,
        objectivesTestedNotice: 'Target returned upstream provider fallback.',
        pass: 0,
        fail: 0,
        inconclusive: 3,
        error: 0,
        campaignVerdict: 'INCONCLUSIVE',
        verdictExplanation: 'Campaign security objectives could not be assessed due to target provider fallback.'
      },
      turns: [
        {
          turnId: 'indirect_turn_1',
          turnNumber: 1,
          name: 'Turn 1 Poison Ingestion',
          prompt: 'User review containing injection payload',
          securityObjective: 'Ingest review without triggering injection',
          actualResponse: 'Operating in rate-limited fallback mode.',
          assessable: false,
          unassessableReason: 'TARGET_PROVIDER_FALLBACK',
          semanticEvaluationSkipped: true,
          semanticEvaluationSkipReason: 'target_unassessable_provider_fallback',
          targetExecution: {
            status: 'PROVIDER_FALLBACK',
            classification: 'PROVIDER_FALLBACK',
            transportSuccess: true,
            fallbackDetected: true,
            fallbackReason: 'Google GenAI Free-Tier Rate Limit (429) active',
            httpStatus: 200,
            responseTimeMs: 80
          },
          canaryDetection: { canaryConfigured: false, detected: false, evidence: null },
          verdict: 'INCONCLUSIVE',
          evidence: 'Target returned upstream provider fallback: "Operating in rate-limited fallback mode."',
          explanation: 'Target returned upstream provider rate-limit fallback.',
          evaluator: 'target_diagnostics',
          method: 'target_provider_fallback',
          timing: { targetDurationMs: 80, evalDurationMs: 0, totalDurationMs: 80 }
        }
      ],
      conversationHistory: []
    };

    // JSON export assertion
    const jsonRes = generateCampaignJsonReport(mockRun);
    const parsed = JSON.parse(jsonRes.content);
    assert.equal(parsed.reportSchemaVersion, '1.0.0');
    assert.equal(parsed.summary.assessableTurns, 0);
    assert.equal(parsed.summary.unassessableTurns, 3);
    assert.ok(parsed.campaignDiagnostic);
    assert.equal(parsed.campaignDiagnostic.deduplicated, true);
    assert.equal(parsed.turns[0].assessable, false);
    assert.equal(parsed.turns[0].semanticEvaluationSkipped, true);

    // Markdown export assertion
    const mdRes = generateCampaignMarkdownReport(mockRun);
    assert.match(mdRes.content, /Campaign Root Cause — Target Provider Rate-Limit Fallback/);
    assert.match(mdRes.content, /Semantic Evaluation.*Skipped/i);
    assert.match(mdRes.content, /Assessable.*NO/);
  });
});
