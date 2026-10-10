const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const {
  executeTargetAiChat,
  setTestMockTargetInvoker,
  getTargetProviderOrder,
  SYNTHETIC_CANARY_SECRET,
  WEAK_SYSTEM_PROMPT
} = require('../../demo-target/targetProviderManager');

describe('VibeSec Phase 8.4: Demo Target Multi-Provider Failover Suite', () => {
  beforeEach(() => {
    setTestMockTargetInvoker(null);
  });

  afterEach(() => {
    setTestMockTargetInvoker(null);
  });

  test('1. Primary provider (Gemini) succeeds -> secondary and tertiary are never invoked', async () => {
    const calls = [];
    setTestMockTargetInvoker(async (providerKey, params) => {
      calls.push(providerKey);
      if (providerKey === 'gemini') {
        return {
          success: true,
          reply: 'AcmeAssistant: Hello! How can I help you today?'
        };
      }
      return { success: false, error: new Error('Should not be called') };
    });

    const result = await executeTargetAiChat({
      userMessage: 'Hello there!',
      providerOrder: ['gemini', 'groq', 'openrouter']
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0], 'gemini');
    assert.equal(result.targetProvider, 'gemini');
    assert.equal(result.provenance, 'live_gemini_model');
    assert.equal(result.reply, 'AcmeAssistant: Hello! How can I help you today?');
    assert.equal(result.attempts.length, 1);
    assert.equal(result.attempts[0].outcome, 'success');
  });

  test('2. Primary quota exhaustion (429) -> failover to secondary (Groq) succeeds', async () => {
    const calls = [];
    setTestMockTargetInvoker(async (providerKey, params) => {
      calls.push(providerKey);
      if (providerKey === 'gemini') {
        const err = new Error('Resource has been exhausted (e.g. check quota).');
        err.status = 429;
        return { success: false, error: err };
      }
      if (providerKey === 'groq') {
        return {
          success: true,
          reply: 'AcmeAssistant (Groq): I can assist you with your account.'
        };
      }
      return { success: false, error: new Error('Should not be called') };
    });

    const result = await executeTargetAiChat({
      userMessage: 'Need assistance',
      providerOrder: ['gemini', 'groq', 'openrouter']
    });

    assert.deepEqual(calls, ['gemini', 'groq']);
    assert.equal(result.targetProvider, 'groq');
    assert.equal(result.provenance, 'live_groq_model');
    assert.match(result.reply, /Groq/);
    assert.equal(result.attempts.length, 2);
    assert.equal(result.attempts[0].outcome, 'rate_limit_or_quota');
    assert.equal(result.attempts[1].outcome, 'success');
  });

  test('3. Secondary failure (timeout/500) -> failover to tertiary (OpenRouter) succeeds', async () => {
    const calls = [];
    setTestMockTargetInvoker(async (providerKey, params) => {
      calls.push(providerKey);
      if (providerKey === 'gemini') {
        const err = new Error('Gemini 429 Quota Exceeded');
        err.status = 429;
        return { success: false, error: err };
      }
      if (providerKey === 'groq') {
        const err = new Error('Groq upstream timeout');
        err.name = 'AbortError';
        return { success: false, error: err };
      }
      if (providerKey === 'openrouter') {
        return {
          success: true,
          reply: 'AcmeAssistant (OpenRouter): Service active and ready.'
        };
      }
      return { success: false, error: new Error('Unexpected provider') };
    });

    const result = await executeTargetAiChat({
      userMessage: 'Status check',
      providerOrder: ['gemini', 'groq', 'openrouter']
    });

    assert.deepEqual(calls, ['gemini', 'groq', 'openrouter']);
    assert.equal(result.targetProvider, 'openrouter');
    assert.equal(result.provenance, 'live_openrouter_model');
    assert.equal(result.attempts.length, 3);
    assert.equal(result.attempts[0].outcome, 'rate_limit_or_quota');
    assert.equal(result.attempts[1].outcome, 'timeout');
    assert.equal(result.attempts[2].outcome, 'success');
  });

  test('4. All providers fail -> returns deterministic rate-limited fallback message', async () => {
    const calls = [];
    setTestMockTargetInvoker(async (providerKey, params) => {
      calls.push(providerKey);
      const err = new Error(`Provider ${providerKey} 429 rate limit`);
      err.status = 429;
      return { success: false, error: err };
    });

    const result = await executeTargetAiChat({
      userMessage: 'Help please',
      providerOrder: ['gemini', 'groq', 'openrouter']
    });

    assert.deepEqual(calls, ['gemini', 'groq', 'openrouter']);
    assert.equal(result.targetProvider, 'fallback');
    assert.equal(result.provenance, 'live_gemini_model_fallback');
    assert.match(result.reply, /operating in rate-limited fallback mode/i);
    assert.equal(result.attempts.length, 3);
    assert.equal(result.attempts.every((a) => a.outcome === 'rate_limit_or_quota'), true);
  });

  test('5. Session continuity: preserves multi-turn dialogue across provider transitions', async () => {
    let capturedMessages = null;
    setTestMockTargetInvoker(async (providerKey, params) => {
      if (providerKey === 'gemini') {
        const err = new Error('Quota exceeded');
        err.status = 429;
        return { success: false, error: err };
      }
      if (providerKey === 'groq') {
        capturedMessages = params.messages;
        return {
          success: true,
          reply: 'AcmeAssistant: Dialogue maintained.'
        };
      }
      return { success: false, error: new Error('Not reached') };
    });

    const history = [
      { role: 'user', content: 'Turn 1 User Prompt' },
      { role: 'assistant', content: 'Turn 1 Assistant Reply' },
      { role: 'user', content: 'Turn 2 User Prompt' }
    ];

    const result = await executeTargetAiChat({
      userMessage: 'Turn 2 User Prompt',
      messages: history,
      providerOrder: ['gemini', 'groq']
    });

    assert.equal(result.targetProvider, 'groq');
    assert.ok(Array.isArray(capturedMessages));
    // Must contain system prompt with canary secret
    assert.equal(capturedMessages[0].role, 'system');
    assert.match(capturedMessages[0].content, new RegExp(SYNTHETIC_CANARY_SECRET));
    // Must contain the prior dialogue turns in order
    assert.equal(capturedMessages[1].content, 'Turn 1 User Prompt');
    assert.equal(capturedMessages[2].content, 'Turn 1 Assistant Reply');
    assert.equal(capturedMessages[3].content, 'Turn 2 User Prompt');
  });

  test('6. Correct diagnostic provenance: clearly distinguishes target provider from evaluator', async () => {
    const { classifyTargetExecution } = require('../target/targetDiagnostics');

    const fakeTargetResult = {
      success: true,
      httpStatus: 200,
      extractedResponse: 'AcmeAssistant response via Groq',
      rawResponseBody: {
        reply: 'AcmeAssistant response via Groq',
        provenance: 'live_groq_model',
        targetProvider: 'groq',
        targetModel: 'llama-3.3-70b-versatile',
        attempts: [
          { provider: 'gemini', outcome: 'rate_limit_or_quota' },
          { provider: 'groq', outcome: 'success' }
        ]
      }
    };

    const targetDiag = classifyTargetExecution(fakeTargetResult);
    assert.equal(targetDiag.classification, 'SUBSTANTIVE_RESPONSE');
    assert.equal(targetDiag.targetProvider, 'groq');
    assert.equal(targetDiag.targetModel, 'llama-3.3-70b-versatile');
    assert.equal(targetDiag.targetAttempts.length, 2);

    // Verify canonical report preserves targetProvider separate from evaluatorProvenance
    const { buildCanonicalCampaignReport } = require('../campaign/campaignReport');
    const fakeRawRun = {
      runId: 'test_run_123',
      campaignId: 'indirect_prompt_injection',
      campaignName: 'Test Campaign',
      status: 'COMPLETED',
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      target: { url: 'http://127.0.0.1:5050/api/chat', method: 'POST' },
      turns: [
        {
          turnNumber: 1,
          name: 'Turn 1',
          prompt: 'Hello',
          actualResponse: 'AcmeAssistant response via Groq',
          assessable: true,
          targetExecution: {
            status: 'SUCCESS',
            classification: 'SUBSTANTIVE_RESPONSE',
            transportSuccess: true,
            processedInput: true,
            targetProvider: 'groq',
            targetModel: 'llama-3.3-70b-versatile',
            targetAttempts: [{ provider: 'gemini', outcome: 'rate_limit_or_quota' }]
          },
          evaluator: 'gemini',
          evaluatorProvenance: {
            finalProvider: 'openrouter',
            finalModel: 'meta-llama/llama-3.3-70b-instruct',
            failoverOccurred: true
          },
          verdict: 'PASS',
          canaryDetection: { canaryConfigured: true, detected: false }
        }
      ]
    };

    const canonical = buildCanonicalCampaignReport(fakeRawRun);
    const turn1 = canonical.turns[0];
    assert.equal(turn1.targetExecution.targetProvider, 'groq');
    assert.equal(turn1.evaluatorProvenance.finalProvider, 'openrouter');
    assert.notEqual(turn1.targetExecution.targetProvider, turn1.evaluatorProvenance.finalProvider);
  });
});
