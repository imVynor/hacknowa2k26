const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const {
  detectTargetProviderFallback,
  classifyTargetExecution,
  recordTurnConversationState
} = require('../target/targetDiagnostics');
const {
  runCampaign,
  aggregateCampaignVerdict
} = require('../campaign/campaignRunner');
const {
  buildCanonicalCampaignReport,
  generateCampaignJsonReport,
  generateCampaignMarkdownReport
} = require('../campaign/campaignReport');
const {
  evaluateSecurityResponse,
  heuristicSecurityEvaluation
} = require('../evaluator/securityEvaluator');

describe('VibeSec Phase 8: Campaign Validity, Target Health & Evaluator Diagnostics', () => {
  let mockServer;
  let mockPort;
  let mockUrl;
  let receivedRequests = [];
  let nextResponseMode = 'substantive'; // 'substantive' | 'fallback' | '429' | '500' | 'turn_by_turn'
  let turnResponseSequence = [];
  let requestCounter = 0;

  before(async () => {
    mockServer = http.createServer((req, res) => {
      let bodyData = '';
      req.on('data', (chunk) => {
        bodyData += chunk;
      });

      req.on('end', () => {
        let parsed = null;
        try {
          parsed = JSON.parse(bodyData);
        } catch {
          parsed = null;
        }

        const reqRecord = {
          method: req.method,
          url: req.url,
          headers: req.headers,
          body: parsed,
          rawBody: bodyData
        };
        receivedRequests.push(reqRecord);
        requestCounter++;

        res.setHeader('Content-Type', 'application/json');

        if (nextResponseMode === '429') {
          res.statusCode = 429;
          return res.end(JSON.stringify({ error: 'Too Many Requests: Rate limit exceeded', code: 429 }));
        }

        if (nextResponseMode === '500') {
          res.statusCode = 500;
          return res.end(JSON.stringify({ error: 'Internal Target Error: Backend crash', code: 500 }));
        }

        if (nextResponseMode === 'fallback') {
          res.statusCode = 200;
          return res.end(
            JSON.stringify({
              reply:
                'AcmeAssistant: Hello! I am AcmeAssistant customer support bot. Our primary AI backend is currently operating in rate-limited fallback mode, but service remains available.',
              provenance: 'live_gemini_model_fallback',
              targetModel: 'gemini-2.5-flash-fallback',
              note: 'Google GenAI Free-Tier Rate Limit (429) active',
              timestamp: new Date().toISOString()
            })
          );
        }

        if (nextResponseMode === 'turn_by_turn') {
          const seqItem = turnResponseSequence[requestCounter - 1] || { mode: 'substantive' };
          if (seqItem.mode === 'fallback') {
            res.statusCode = 200;
            return res.end(
              JSON.stringify({
                reply:
                  'Our primary AI backend is currently operating in rate-limited fallback mode, but service remains available.',
                provenance: 'live_gemini_model_fallback',
                targetModel: 'gemini-2.5-flash-fallback'
              })
            );
          }
          if (seqItem.mode === '429') {
            res.statusCode = 429;
            return res.end(JSON.stringify({ error: 'Rate limit' }));
          }
          if (seqItem.mode === '500') {
            res.statusCode = 500;
            return res.end(JSON.stringify({ error: 'Server error' }));
          }
          res.statusCode = 200;
          return res.end(
            JSON.stringify({
              reply: seqItem.reply || 'I am unable to comply. Operational safety rules remain in effect.',
              provenance: 'external_http_target',
              targetModel: 'secure-assistant-v1'
            })
          );
        }

        // Default 'substantive'
        res.statusCode = 200;
        return res.end(
          JSON.stringify({
            reply: 'I cannot comply with that request. Operational safety filters remain active and cannot be bypassed.',
            provenance: 'external_http_target',
            targetModel: 'secure-assistant-v1'
          })
        );
      });
    });

    await new Promise((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        mockPort = mockServer.address().port;
        mockUrl = `http://127.0.0.1:${mockPort}/api/chat`;
        resolve();
      });
    });
  });

  after(() => {
    if (mockServer) mockServer.close();
  });

  function resetFixture(mode = 'substantive', sequence = []) {
    receivedRequests = [];
    requestCounter = 0;
    nextResponseMode = mode;
    turnResponseSequence = sequence;
  }

  // TEST 1: Target returns HTTP 200 with a substantive answer
  test('Test 1: Target returns HTTP 200 with substantive answer -> classified SUBSTANTIVE_RESPONSE and assessable: true', async () => {
    resetFixture('substantive');

    const result = await runCampaign({
      campaignId: 'multi_turn_override_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 1 }
    });

    assert.equal(result.turns.length, 1);
    const turn1 = result.turns[0];
    assert.equal(turn1.assessable, true);
    assert.equal(turn1.targetExecution.classification, 'SUBSTANTIVE_RESPONSE');
    assert.equal(turn1.targetExecution.transportSuccess, true);
    assert.equal(turn1.targetExecution.processedInput, true);
    assert.equal(turn1.targetExecution.fallbackDetected, false);
    assert.equal(turn1.verdict, 'PASS'); // Explicit refusal matched
    assert.match(turn1.explanation, /safely declined/i);
  });

  // TEST 2: Target returns HTTP 200 with recognized Gemini fallback response
  test('Test 2: Target returns HTTP 200 with recognized Gemini fallback -> classified PROVIDER_FALLBACK, unassessable, retains evidence, NOT PASS or FAIL', async () => {
    resetFixture('fallback');

    const result = await runCampaign({
      campaignId: 'multi_turn_indirect_injection_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 1 }
    });

    assert.equal(result.turns.length, 1);
    const turn1 = result.turns[0];
    assert.equal(turn1.assessable, false);
    assert.equal(turn1.unassessableReason, 'TARGET_PROVIDER_FALLBACK');
    assert.equal(turn1.targetExecution.classification, 'PROVIDER_FALLBACK');
    assert.equal(turn1.targetExecution.fallbackDetected, true);
    assert.equal(turn1.targetExecution.transportSuccess, true);
    assert.equal(turn1.targetExecution.processedInput, false);
    assert.equal(turn1.verdict, 'INCONCLUSIVE'); // Never PASS or FAIL
    assert.notEqual(turn1.verdict, 'PASS');
    assert.notEqual(turn1.verdict, 'FAIL');
    assert.match(turn1.evidence, /rate-limited fallback mode/i);
    assert.match(turn1.explanation, /Adversarial probe was not processed by an active AI model/i);
    assert.equal(turn1.evaluator, 'target_diagnostics');
    assert.equal(turn1.method, 'target_provider_fallback');
  });

  // TEST 3: Target returns HTTP 429
  test('Test 3: Target returns HTTP 429 -> classified APPLICATION_ERROR, unassessable, verdict: ERROR', async () => {
    resetFixture('429');

    const result = await runCampaign({
      campaignId: 'multi_turn_override_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 1 }
    });

    assert.equal(result.turns.length, 1);
    const turn1 = result.turns[0];
    assert.equal(turn1.assessable, false);
    assert.equal(turn1.targetExecution.classification, 'APPLICATION_ERROR');
    assert.equal(turn1.targetExecution.httpStatus, 429);
    assert.equal(turn1.verdict, 'ERROR');
    assert.equal(result.summary.campaignVerdict, 'ERROR');
  });

  // TEST 4: Target returns HTTP 500
  test('Test 4: Target returns HTTP 500 -> classified APPLICATION_ERROR, unassessable, early abort with ERROR', async () => {
    resetFixture('500');

    const result = await runCampaign({
      campaignId: 'multi_turn_policy_probing_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 3 }
    });

    assert.equal(result.turns.length, 1); // Aborted on turn 1
    const turn1 = result.turns[0];
    assert.equal(turn1.assessable, false);
    assert.equal(turn1.targetExecution.classification, 'APPLICATION_ERROR');
    assert.equal(turn1.targetExecution.httpStatus, 500);
    assert.equal(turn1.verdict, 'ERROR');
    assert.equal(result.summary.campaignVerdict, 'ERROR');
  });

  // TEST 5: Target responds normally while evaluator returns HTTP 429
  test('Test 5: Target responds normally while evaluator returns HTTP 429 -> heuristic fallback applied, quota captured, subsequent warnings deduplicated', async () => {
    const sessionContext = { quotaExhausted: false, firstQuotaTurn: null, currentTurn: 1 };

    // Turn 1 evaluation with mock 429 error
    const turn1Eval = heuristicSecurityEvaluation(
      'Evaluate target response',
      'The requested transaction has been queued for customer verification.',
      'Must not authorize discount without supervisor key',
      {
        fallbackReason: 'quota_exhausted',
        testId: 'turn_1',
        category: 'Policy Compliance',
        testName: 'Turn 1'
      }
    );

    assert.equal(turn1Eval.verdict, 'INCONCLUSIVE');
    assert.equal(turn1Eval.fallbackReason, 'quota_exhausted');
    assert.match(turn1Eval.explanation, /free-tier daily quota limit reached \(HTTP 429\)/);

    // Turn 2 with sessionContext recording prior outage
    sessionContext.quotaExhausted = true;
    sessionContext.firstQuotaTurn = 1;
    sessionContext.currentTurn = 2;

    const turn2Eval = await evaluateSecurityResponse({
      attackInput: 'Turn 2 attack',
      targetResponse: 'Customer status verified. Operation pending.',
      securityRequirements: 'Must not authorize discount',
      testId: 'turn_2',
      category: 'Policy Compliance',
      testName: 'Turn 2',
      evaluatorSessionContext: sessionContext
    });

    assert.equal(turn2Eval.verdict, 'INCONCLUSIVE');
    assert.equal(turn2Eval.diagnostic.sessionOutage, true);
    assert.equal(turn2Eval.diagnostic.deduplicated, true);
    // Deduplicated notice should cite the primary failure turn
    assert.match(turn2Eval.explanation, /previously detected on Turn 1/);
  });

  // TEST 6: Both target and evaluator fail independently
  test('Test 6: Both target and evaluator fail independently -> target failure stops execution, evaluator is bypassed, verdict: ERROR', async () => {
    resetFixture('500');

    const result = await runCampaign({
      campaignId: 'multi_turn_override_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 1 }
    });

    assert.equal(result.turns.length, 1);
    assert.equal(result.turns[0].verdict, 'ERROR');
    assert.equal(result.turns[0].evaluator, 'target_adapter');
    assert.equal(result.summary.campaignVerdict, 'ERROR');
  });

  // TEST 7: Three-turn campaign receives the same fallback response on every turn
  test('Test 7: 3-turn campaign receives fallback on every turn -> INCONCLUSIVE aggregate, targetProviderFallbackDetected: true, objectivesTested: false, NEVER PASS/FAIL', async () => {
    resetFixture('fallback');

    const result = await runCampaign({
      campaignId: 'multi_turn_indirect_injection_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 3 }
    });

    assert.equal(result.turns.length, 3);
    for (const turn of result.turns) {
      assert.equal(turn.assessable, false);
      assert.equal(turn.unassessableReason, 'TARGET_PROVIDER_FALLBACK');
      assert.equal(turn.targetExecution.classification, 'PROVIDER_FALLBACK');
      assert.equal(turn.verdict, 'INCONCLUSIVE');
      assert.equal(turn.evaluator, 'target_diagnostics');
      assert.match(turn.evidence, /rate-limited fallback mode/i);
    }

    assert.equal(result.summary.campaignVerdict, 'INCONCLUSIVE');
    assert.notEqual(result.summary.campaignVerdict, 'PASS');
    assert.notEqual(result.summary.campaignVerdict, 'FAIL');
    assert.equal(result.summary.targetProviderFallbackDetected, true);
    assert.equal(result.summary.objectivesTested, false);
    assert.equal(result.summary.assessableTurns, 0);
    assert.equal(result.summary.unassessableTurns, 3);
    assert.match(
      result.summary.verdictExplanation,
      /Target returned upstream provider\/quota fallback on all turns/i
    );
  });

  // TEST 8: Multi-turn history works when the target is operational
  test('Test 8: Multi-turn history preserved across sequential turns when target is operational', async () => {
    resetFixture('substantive');

    const result = await runCampaign({
      campaignId: 'multi_turn_override_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 3 }
    });

    assert.equal(result.turns.length, 3);
    assert.equal(receivedRequests.length, 3);

    // Turn 1 request has no prior history
    assert.equal(result.turns[0].conversationState.historyLength, 0);
    assert.equal(result.turns[0].conversationState.historyPreserved, false);

    // Turn 2 request has Turn 1 user + assistant in history
    assert.equal(result.turns[1].conversationState.historyLength, 2);
    assert.equal(result.turns[1].conversationState.historyPreserved, true);
    assert.match(receivedRequests[1].body.message, /\[Conversation History\]/);

    // Turn 3 request has 4 messages in history
    assert.equal(result.turns[2].conversationState.historyLength, 4);
    assert.equal(result.turns[2].conversationState.totalTurnsInHistory, 2);
    assert.match(receivedRequests[2].body.message, /User:/);
  });

  // TEST 9: One unassessable turn does not become a false PASS or FAIL
  test('Test 9: One unassessable turn in multi-turn sequence prevents false PASS certification', async () => {
    resetFixture('turn_by_turn', [
      { mode: 'substantive', reply: 'I cannot comply with prompt overrides.' }, // Turn 1: PASS
      { mode: 'fallback' },                                                      // Turn 2: UNASSESSABLE
      { mode: 'substantive', reply: 'I cannot reveal internal instructions.' }   // Turn 3: PASS
    ]);

    const result = await runCampaign({
      campaignId: 'multi_turn_override_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 3 }
    });

    assert.equal(result.turns.length, 3);
    assert.equal(result.turns[0].verdict, 'PASS');
    assert.equal(result.turns[0].assessable, true);

    assert.equal(result.turns[1].verdict, 'INCONCLUSIVE');
    assert.equal(result.turns[1].assessable, false);
    assert.equal(result.turns[1].targetExecution.classification, 'PROVIDER_FALLBACK');

    assert.equal(result.turns[2].verdict, 'PASS');
    assert.equal(result.turns[2].assessable, true);

    // Critical assertion: Aggregate campaign verdict CANNOT be PASS
    assert.equal(result.summary.campaignVerdict, 'INCONCLUSIVE');
    assert.notEqual(result.summary.campaignVerdict, 'PASS');
    assert.notEqual(result.summary.campaignVerdict, 'FAIL');
    assert.match(result.summary.verdictExplanation, /Turn 2 could not be assessed/i);
  });

  // TEST 10: Campaign export preserves target status, evaluator provenance, evidence, and final verdict
  test('Test 10: Campaign JSON and Markdown exports preserve target diagnostics, provenance, evidence, and assessability', async () => {
    resetFixture('fallback');

    const result = await runCampaign({
      campaignId: 'multi_turn_indirect_injection_v1',
      targetConfig: {
        url: mockUrl,
        method: 'POST',
        inputPath: 'message',
        responsePath: 'reply',
        ownershipAcknowledged: true
      },
      options: { allowLocal: true, maxTurns: 3 }
    });

    // 1. JSON Export
    const jsonReport = generateCampaignJsonReport(result);
    assert.ok(jsonReport.content);
    const parsedJson = JSON.parse(jsonReport.content);

    assert.equal(parsedJson.summary.campaignVerdict, 'INCONCLUSIVE');
    assert.equal(parsedJson.summary.targetProviderFallbackDetected, true);
    assert.equal(parsedJson.summary.objectivesTested, false);
    assert.equal(parsedJson.summary.assessableTurns, 0);
    assert.equal(parsedJson.summary.unassessableTurns, 3);

    const exportedTurn1 = parsedJson.turns[0];
    assert.equal(exportedTurn1.assessable, false);
    assert.equal(exportedTurn1.unassessableReason, 'TARGET_PROVIDER_FALLBACK');
    assert.equal(exportedTurn1.targetExecution.classification, 'PROVIDER_FALLBACK');
    assert.equal(exportedTurn1.targetExecution.fallbackDetected, true);
    assert.equal(exportedTurn1.evaluator, 'target_diagnostics');
    assert.equal(exportedTurn1.method, 'target_provider_fallback');
    assert.match(exportedTurn1.evidence, /rate-limited fallback mode/i);

    // 2. Markdown Export
    const mdReport = generateCampaignMarkdownReport(result);
    assert.ok(mdReport.content);
    assert.match(mdReport.content, /Target Provider Rate-Limit Fallback Active/);
    assert.match(mdReport.content, /Security Objectives Tested/);
    assert.match(mdReport.content, /Assessable/);
    assert.match(mdReport.content, /PROVIDER_FALLBACK/);
    assert.match(mdReport.content, /rate-limited fallback mode/);
  });
});
