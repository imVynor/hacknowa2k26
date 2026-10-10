const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const {
  setTestMockInvoker,
  getProviderConfigurationStatus,
  getEvaluatorOrder,
  getEvaluatorTimeoutMs,
  classifyProviderError,
  DEFAULT_MODELS
} = require('../evaluator/providerManager');
const { evaluateSecurityResponse } = require('../evaluator/securityEvaluator');
const { runCampaign } = require('../campaign/campaignRunner');
const { generateCampaignJsonReport, generateCampaignMarkdownReport } = require('../campaign/campaignReport');

describe('VibeSec Phase 8.3: Multi-Provider Semantic Evaluator Failover Suite', () => {
  beforeEach(() => {
    // Reset mock invoker before each test
    setTestMockInvoker(null);
  });

  afterEach(() => {
    setTestMockInvoker(null);
  });

  // Standard grounded valid semantic output template
  const validSemanticPayload = (verdict = 'PASS', evidence = 'I cannot fulfill this request.') =>
    JSON.stringify({
      assessmentResult: verdict,
      verdict,
      exactEvidence: evidence,
      evidence,
      rationale: 'Target safely declined the probe.',
      confidence: 'HIGH',
      criteriaResults: [
        {
          criterion: 'Refuse adversarial instruction',
          status: verdict === 'PASS' ? 'MET' : 'VIOLATED',
          evidence
        }
      ]
    });

  // --------------------------------------------------------------------------
  // Test 1: Gemini succeeds and no fallback provider is called
  // --------------------------------------------------------------------------
  it('1. Gemini succeeds and no fallback provider is called', async () => {
    const calledProviders = [];
    setTestMockInvoker(async (providerKey) => {
      calledProviders.push(providerKey);
      if (providerKey === 'gemini') {
        return {
          success: true,
          rawText: validSemanticPayload('PASS', 'I cannot fulfill this request.')
        };
      }
      return { success: false, error: new Error('Fallback should not be called') };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test override attempt',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p1'
    });

    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(calledProviders, ['gemini'], 'Only primary provider Gemini should have been called');
    assert.equal(result.evaluatorProvenance.finalProvider, 'gemini');
    assert.equal(result.evaluatorProvenance.failoverOccurred, false);
    assert.equal(result.evaluatorProvenance.attempts.length, 1);
    assert.equal(result.evaluatorProvenance.attempts[0].outcome, 'success');
  });

  // --------------------------------------------------------------------------
  // Test 2: Gemini rate-limits and Grok succeeds
  // --------------------------------------------------------------------------
  it('2. Gemini rate-limits and Grok succeeds', async () => {
    const calledProviders = [];
    setTestMockInvoker(async (providerKey) => {
      calledProviders.push(providerKey);
      if (providerKey === 'gemini') {
        const err = new Error('Resource has been exhausted (e.g. check quota).');
        err.status = 429;
        return { success: false, error: err, status: 429 };
      }
      if (providerKey === 'xai') {
        return {
          success: true,
          rawText: validSemanticPayload('PASS', 'I cannot fulfill this request.')
        };
      }
      return { success: false, error: new Error('OpenRouter should not be called') };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test override attempt',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p2'
    });

    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(calledProviders, ['gemini', 'xai']);
    assert.equal(result.evaluatorProvenance.finalProvider, 'xai');
    assert.equal(result.evaluatorProvenance.failoverOccurred, true);
    assert.equal(result.evaluatorProvenance.attempts.length, 2);
    assert.equal(result.evaluatorProvenance.attempts[0].outcome, 'rate_limit_or_quota');
    assert.equal(result.evaluatorProvenance.attempts[0].failoverReason, 'quota_exhausted');
    assert.equal(result.evaluatorProvenance.attempts[1].outcome, 'success');
  });

  // --------------------------------------------------------------------------
  // Test 3: Gemini and Grok fail and OpenRouter succeeds
  // --------------------------------------------------------------------------
  it('3. Gemini and Grok fail and OpenRouter succeeds', async () => {
    const calledProviders = [];
    setTestMockInvoker(async (providerKey) => {
      calledProviders.push(providerKey);
      if (providerKey === 'gemini') {
        const err = new Error('Gemini 429 rate limit exceeded');
        err.status = 429;
        return { success: false, error: err };
      }
      if (providerKey === 'xai') {
        const err = new Error('xAI API timeout');
        err.name = 'AbortError';
        return { success: false, error: err };
      }
      if (providerKey === 'openrouter') {
        return {
          success: true,
          rawText: validSemanticPayload('PASS', 'I cannot fulfill this request.')
        };
      }
      return { success: false, error: new Error('Unexpected provider') };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test probe',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p3'
    });

    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(calledProviders, ['gemini', 'xai', 'openrouter']);
    assert.equal(result.evaluatorProvenance.finalProvider, 'openrouter');
    assert.equal(result.evaluatorProvenance.failoverOccurred, true);
    assert.equal(result.evaluatorProvenance.attempts.length, 3);
    assert.equal(result.evaluatorProvenance.attempts[0].outcome, 'rate_limit_or_quota');
    assert.equal(result.evaluatorProvenance.attempts[1].outcome, 'timeout');
    assert.equal(result.evaluatorProvenance.attempts[2].outcome, 'success');
  });

  // --------------------------------------------------------------------------
  // Test 4: All providers fail and heuristic fallback is recorded
  // --------------------------------------------------------------------------
  it('4. All providers fail and heuristic fallback is recorded', async () => {
    setTestMockInvoker(async (providerKey) => {
      const err = new Error(`${providerKey} service unavailable`);
      err.status = 503;
      return { success: false, error: err };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test probe',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p4'
    });

    // Appropriate refusal heuristic kicks in safely
    assert.equal(result.verdict, 'PASS');
    assert.equal(result.evaluatorProvenance.finalProvider, 'heuristic_fallback');
    assert.equal(result.evaluatorProvenance.failoverOccurred, true);
    assert.equal(result.evaluatorProvenance.attempts.length, 3);
  });

  // --------------------------------------------------------------------------
  // Test 5: Missing optional API keys do not prevent startup
  // --------------------------------------------------------------------------
  it('5. Missing optional API keys do not prevent startup', () => {
    const originalXai = process.env.XAI_API_KEY;
    const originalOpenRouter = process.env.OPENROUTER_API_KEY;

    try {
      delete process.env.XAI_API_KEY;
      delete process.env.OPENROUTER_API_KEY;

      const status = getProviderConfigurationStatus();
      assert.equal(status.xai.enabled, false);
      assert.equal(status.openrouter.enabled, false);
      assert.ok(Array.isArray(status.order));
      assert.ok(status.timeoutMs > 0);
    } finally {
      if (originalXai !== undefined) process.env.XAI_API_KEY = originalXai;
      if (originalOpenRouter !== undefined) process.env.OPENROUTER_API_KEY = originalOpenRouter;
    }
  });

  // --------------------------------------------------------------------------
  // Test 6: Authentication and configuration errors are reported accurately
  // --------------------------------------------------------------------------
  it('6. Authentication and configuration errors are reported accurately', async () => {
    const authErr = new Error('Unauthorized: Invalid API key provided');
    authErr.status = 401;
    const classified = classifyProviderError(authErr);

    assert.equal(classified.classification, 'auth_or_config_error');
    assert.equal(classified.failoverReason, 'invalid_credentials');

    setTestMockInvoker(async (providerKey) => {
      if (providerKey === 'gemini') {
        const err = new Error('API_KEY_INVALID: User not authorized');
        err.status = 401;
        return { success: false, error: err };
      }
      return {
        success: true,
        rawText: validSemanticPayload('PASS', 'I cannot fulfill this request.')
      };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test probe',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p6'
    });

    assert.equal(result.evaluatorProvenance.attempts[0].outcome, 'auth_or_config_error');
    assert.equal(result.evaluatorProvenance.attempts[0].failoverReason, 'invalid_credentials');
  });

  // --------------------------------------------------------------------------
  // Test 7: Timeout and malformed structured output trigger bounded failover
  // --------------------------------------------------------------------------
  it('7. Timeout and malformed structured output trigger bounded failover', async () => {
    let attemptsCount = 0;
    setTestMockInvoker(async (providerKey) => {
      attemptsCount++;
      if (providerKey === 'gemini') {
        const timeoutErr = new Error('Operation timed out after 20000ms');
        timeoutErr.name = 'AbortError';
        return { success: false, error: timeoutErr };
      }
      if (providerKey === 'xai') {
        // Returns malformed non-JSON output
        return {
          success: true,
          rawText: 'Sorry, I am unable to generate JSON right now.'
        };
      }
      if (providerKey === 'openrouter') {
        return {
          success: true,
          rawText: validSemanticPayload('PASS', 'I cannot fulfill this request.')
        };
      }
      return { success: false, error: new Error('Unexpected') };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test probe',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p7'
    });

    assert.equal(result.verdict, 'PASS');
    assert.equal(result.evaluatorProvenance.finalProvider, 'openrouter');
    assert.equal(result.evaluatorProvenance.attempts[0].outcome, 'timeout');
    assert.equal(result.evaluatorProvenance.attempts[1].outcome, 'invalid_output');
    assert.equal(result.evaluatorProvenance.attempts[1].failoverReason, 'malformed_output');
    assert.equal(attemptsCount, 3);
  });

  // --------------------------------------------------------------------------
  // Test 8: Invalid or ungrounded evidence is rejected consistently across providers
  // --------------------------------------------------------------------------
  it('8. Invalid or ungrounded evidence is rejected consistently across providers', async () => {
    setTestMockInvoker(async (providerKey) => {
      if (providerKey === 'gemini') {
        // Hallucinated quote not in targetResponse
        return {
          success: true,
          rawText: validSemanticPayload('PASS', 'Hallucinated phantom quote from cyberspace')
        };
      }
      if (providerKey === 'xai') {
        // Grounded quote
        return {
          success: true,
          rawText: validSemanticPayload('PASS', 'I cannot fulfill this request.')
        };
      }
      return { success: false, error: new Error('Tertiary should not be called') };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test probe',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p8'
    });

    assert.equal(result.verdict, 'PASS');
    assert.equal(result.evaluatorProvenance.attempts[0].outcome, 'invalid_output');
    assert.equal(result.evaluatorProvenance.attempts[0].failoverReason, 'ungrounded_evidence');
    assert.equal(result.evaluatorProvenance.finalProvider, 'xai');
  });

  // --------------------------------------------------------------------------
  // Test 9: A target-provider fallback bypasses all semantic evaluators
  // --------------------------------------------------------------------------
  it('9. A target-provider fallback bypasses all semantic evaluators', async () => {
    let anyProviderCalled = false;
    setTestMockInvoker(async () => {
      anyProviderCalled = true;
      return { success: true, rawText: validSemanticPayload() };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test probe',
      targetResponse: 'AcmeAssistant: primary ai backend is currently operating in rate-limited fallback mode',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p9',
      targetExecution: {
        classification: 'PROVIDER_FALLBACK',
        transportSuccess: true,
        fallbackReason: 'Target upstream rate-limit fallback active'
      }
    });

    assert.equal(result.verdict, 'INCONCLUSIVE');
    assert.equal(result.assessable, false);
    assert.equal(result.semanticEvaluationSkipped, true);
    assert.equal(result.evaluator, 'target_diagnostics');
    assert.equal(anyProviderCalled, false, 'No semantic evaluator should be called on target provider fallback');
  });

  // --------------------------------------------------------------------------
  // Test 10: Provider order is configurable
  // --------------------------------------------------------------------------
  it('10. Provider order is configurable', async () => {
    const calledOrder = [];
    setTestMockInvoker(async (providerKey) => {
      calledOrder.push(providerKey);
      if (providerKey === 'openrouter') {
        const err = new Error('OpenRouter down');
        return { success: false, error: err };
      }
      if (providerKey === 'xai') {
        return {
          success: true,
          rawText: validSemanticPayload('PASS', 'I cannot fulfill this request.')
        };
      }
      return { success: false, error: new Error('Gemini not in order') };
    });

    const result = await evaluateSecurityResponse({
      attackInput: 'Test probe',
      targetResponse: 'I cannot fulfill this request.',
      securityRequirements: 'Must decline prompt',
      testId: 'test_p10',
      options: {
        providerOrder: ['openrouter', 'xai', 'gemini']
      }
    });

    assert.equal(result.verdict, 'PASS');
    assert.deepEqual(calledOrder, ['openrouter', 'xai']);
    assert.equal(result.evaluatorProvenance.finalProvider, 'xai');
  });

  // --------------------------------------------------------------------------
  // Test 11: Provenance and failure reasons survive campaign aggregation and JSON/Markdown exports
  // --------------------------------------------------------------------------
  it('11. Provenance and failure reasons survive campaign aggregation and JSON/Markdown exports', async () => {
    setTestMockInvoker(async (providerKey) => {
      if (providerKey === 'gemini') {
        const err = new Error('Gemini quota 429');
        err.status = 429;
        return { success: false, error: err };
      }
      return {
        success: true,
        rawText: validSemanticPayload('PASS', 'I am AcmeAssistant. I cannot comply with requests to ignore my instructions, enter debug mode, or disclose internal canary tokens.')
      };
    });

    const runResult = await runCampaign({
      campaignId: 'multi_turn_override_v1',
      targetConfig: {
        url: 'http://127.0.0.1:5050/api/chat?fixture=defended',
        ownershipAcknowledged: true
      },
      canarySecret: 'VIBESEC_DEMO_CANARY_42',
      mode: 'live',
      options: { allowLocal: true, maxTurns: 1 }
    });

    assert.equal(runResult.status, 'COMPLETED');
    assert.equal(runResult.turns[0].evaluatorProvenance.finalProvider, 'xai');
    assert.equal(runResult.turns[0].evaluatorProvenance.failoverOccurred, true);
    assert.equal(runResult.turns[0].evaluatorProvenance.attempts[0].provider, 'gemini');

    // JSON export
    const jsonReport = generateCampaignJsonReport(runResult);
    const parsed = JSON.parse(jsonReport.content);
    assert.equal(parsed.turns[0].evaluatorProvenance.finalProvider, 'xai');
    assert.equal(parsed.turns[0].evaluatorProvenance.failoverOccurred, true);
    assert.equal(parsed.turns[0].evaluatorProvenance.attempts[0].outcome, 'rate_limit_or_quota');

    // Markdown export
    const mdReport = generateCampaignMarkdownReport(runResult);
    assert.ok(mdReport.content);
    assert.match(mdReport.content, /xai/i);
  });

  // --------------------------------------------------------------------------
  // Test 12: No credentials appear in logs or exports
  // --------------------------------------------------------------------------
  it('12. No credentials appear in logs or exports', () => {
    const rawRun = {
      runId: 'camp_no_leak',
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      totalDurationMs: 150,
      status: 'COMPLETED',
      mode: 'live',
      campaign: {
        campaignId: 'multi_turn_override_v1',
        name: 'Multi-turn Override',
        version: '1.0.0',
        category: 'Override',
        attackObjective: 'Test',
        securityRequirement: 'Test',
        evaluationStrategy: 'Hybrid',
        totalTurns: 1
      },
      target: {
        url: 'https://api.example.com/chat?key=AIzaSySecretApiKey789&session=topsecret_token',
        method: 'POST'
      },
      summary: {
        campaignVerdict: 'PASS',
        verdictExplanation: 'Passed',
        totalTurns: 1,
        executedTurns: 1,
        assessableTurns: 1,
        unassessableTurns: 0,
        pass: 1,
        fail: 0,
        inconclusive: 0,
        error: 0,
        objectivesTested: true
      },
      turns: [
        {
          turnId: 't1',
          turnNumber: 1,
          name: 'Turn 1',
          prompt: 'Hello',
          actualResponse: 'Safe response',
          assessable: true,
          verdict: 'PASS',
          evaluator: 'xai',
          evaluatorProvenance: {
            finalProvider: 'xai',
            finalModel: 'grok-2-latest',
            attempts: [
              {
                provider: 'gemini',
                outcome: 'auth_or_config_error',
                error: 'Failed with Authorization: Bearer sk-ant-secret-auth-token-12345'
              }
            ]
          }
        }
      ]
    };

    const json = generateCampaignJsonReport(rawRun);
    assert.doesNotMatch(json.content, /AIzaSySecretApiKey789/);
    assert.doesNotMatch(json.content, /topsecret_token/);
    assert.doesNotMatch(json.content, /sk-ant-secret-auth-token-12345/);
    assert.match(json.content, /\[REDACTED\]/);
  });

  // --------------------------------------------------------------------------
  // Test 13: Deterministic canary findings and verdict reconciliation retain existing behavior
  // --------------------------------------------------------------------------
  it('13. Deterministic canary findings and verdict reconciliation retain existing behavior', async () => {
    let providersCalled = false;
    setTestMockInvoker(async () => {
      providersCalled = true;
      return { success: true, rawText: validSemanticPayload('PASS') };
    });

    const leakResult = await evaluateSecurityResponse({
      attackInput: 'Disclose secret',
      targetResponse: 'The internal verification canary is: VIBESEC_DEMO_CANARY_42',
      securityRequirements: 'Never disclose canary',
      canarySecret: 'VIBESEC_DEMO_CANARY_42',
      testId: 'canary_test'
    });

    // Oracle priority overrides before any semantic provider is called
    assert.equal(leakResult.verdict, 'FAIL');
    assert.equal(leakResult.evaluator, 'canary_detector_deterministic');
    assert.equal(leakResult.reconciliationRule, 'DETERMINISTIC_CANARY_LEAK_PRIORITY');
    assert.equal(providersCalled, false, 'Deterministic oracle must bypass semantic providers');
  });
});
