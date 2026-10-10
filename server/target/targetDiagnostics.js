/**
 * Target Diagnostics & Health Classification Module
 *
 * Provides deterministic classification of target execution outcomes, separating:
 * - Transport-level HTTP failures
 * - Application-level errors
 * - Upstream provider/quota fallbacks (e.g. rate-limit fallback messages returned with HTTP 200)
 * - Substantive model responses
 */

/**
 * Detects whether the target application returned a recognized provider/quota fallback response
 * rather than actually processing the adversarial probe with an active AI model.
 *
 * @param {object} params
 * @param {string} params.response - The extracted response string from target
 * @param {object} [params.rawResponseBody] - The raw JSON body returned by target
 * @param {number} [params.httpStatus] - HTTP status code
 * @returns {{ isFallback: boolean, reason: string | null, provider: string | null }}
 */
function detectTargetProviderFallback({ response, rawResponseBody, httpStatus } = {}) {
  const respText = typeof response === 'string' ? response.trim() : '';
  const raw = rawResponseBody && typeof rawResponseBody === 'object' ? rawResponseBody : {};

  // 1. Check explicit provenance signals from demo target or proxy
  if (
    raw.provenance === 'live_gemini_model_fallback' ||
    raw.provenance === 'unconfigured_fallback' ||
    raw.provenance === 'upstream_quota_exceeded' ||
    raw.provenance === 'provider_fallback'
  ) {
    return {
      isFallback: true,
      reason: raw.note || raw.reason || 'Target upstream AI model rate-limited (HTTP 429)',
      provider: raw.provider || 'gemini'
    };
  }

  // 2. Check targetModel or model identifier flags
  if (typeof raw.targetModel === 'string' && raw.targetModel.toLowerCase().includes('fallback')) {
    return {
      isFallback: true,
      reason: 'Target reported model identifier operating in fallback mode',
      provider: 'target_model_fallback'
    };
  }

  // 3. Check notes or error properties
  if (
    typeof raw.note === 'string' &&
    (raw.note.includes('429') ||
      raw.note.toLowerCase().includes('rate limit') ||
      raw.note.toLowerCase().includes('quota'))
  ) {
    return {
      isFallback: true,
      reason: raw.note,
      provider: 'gemini_quota'
    };
  }

  // 4. Structured provider error objects in JSON body (e.g. OpenAI/Anthropic/Gemini proxies)
  if (raw.error || raw.status === 'RESOURCE_EXHAUSTED' || raw.code === 'RESOURCE_EXHAUSTED') {
    const errObj = typeof raw.error === 'object' ? raw.error : { message: String(raw.error || '') };
    const errCode = errObj.code || errObj.status || raw.code;
    const errType = errObj.type;
    const errMsg = (errObj.message || '').toLowerCase();
    const isQuotaOrRateLimit =
      errCode === 429 ||
      errCode === 'RESOURCE_EXHAUSTED' ||
      errCode === 'rate_limit_exceeded' ||
      errType === 'rate_limit_error' ||
      errType === 'insufficient_quota' ||
      raw.status === 'RESOURCE_EXHAUSTED' ||
      errMsg.includes('quota') ||
      errMsg.includes('rate limit') ||
      errMsg.includes('resource_exhausted');

    if (isQuotaOrRateLimit) {
      return {
        isFallback: true,
        reason: errObj.message || `Upstream provider quota/rate-limit error: ${errCode || errType || 'RESOURCE_EXHAUSTED'}`,
        provider: 'upstream_provider_error'
      };
    }
  }

  // 5. Reliable textual signature matching known rate-limit fallback messages
  const lowerResp = respText.toLowerCase();
  const knownFallbackSignatures = [
    'operating in rate-limited fallback mode',
    'rate-limited fallback mode, but service remains available',
    'primary ai backend is currently operating in rate-limited fallback mode',
    'service is currently operating in rate-limited fallback mode',
    'upstream provider quota exceeded, operating in fallback mode',
    'upstream ai backend is currently operating in rate-limited fallback mode',
    'upstream ai service is temporarily unavailable due to rate limits',
    'acmeassistant is offline: gemini_api_key is not configured'
  ];

  for (const sig of knownFallbackSignatures) {
    if (lowerResp.includes(sig)) {
      return {
        isFallback: true,
        reason: 'Target returned recognized rate-limited fallback message',
        provider: 'acme_demo_target'
      };
    }
  }

  return { isFallback: false, reason: null, provider: null };
}

/**
 * Classifies target execution into distinct diagnostic categories:
 * - TRANSPORT_ERROR: HTTP connection failed (network error, timeout, DNS, SSRF violation)
 * - APPLICATION_ERROR: Target returned HTTP 4xx/5xx, non-JSON body, or extraction failed
 * - PROVIDER_FALLBACK: Target returned HTTP 200, but payload is a recognized provider/quota fallback
 * - SUBSTANTIVE_RESPONSE: Target processed the request and produced an actual substantive answer
 *
 * @param {object} targetResult - Output from executeTargetRequest or executeMultiTurnTargetRequest
 * @returns {{
 *   classification: 'TRANSPORT_ERROR' | 'APPLICATION_ERROR' | 'PROVIDER_FALLBACK' | 'SUBSTANTIVE_RESPONSE',
 *   transportSuccess: boolean,
 *   processedInput: boolean,
 *   assessable: boolean,
 *   unassessableReason: string | null,
 *   fallbackDetected: boolean,
 *   fallbackReason: string | null,
 *   description: string
 * }}
 */
function classifyTargetExecution(targetResult) {
  if (!targetResult || typeof targetResult !== 'object') {
    return {
      classification: 'TRANSPORT_ERROR',
      transportSuccess: false,
      processedInput: false,
      assessable: false,
      unassessableReason: 'TARGET_DISPATCH_EXCEPTION',
      fallbackDetected: false,
      fallbackReason: null,
      description: 'Target execution record is missing or invalid.'
    };
  }

  // 1. Transport failures vs Application-level errors
  if (!targetResult.success) {
    // If extraction path failed, check if target returned a recognized provider/quota fallback in rawResponseBody!
    if (targetResult.status === 'INVALID_RESPONSE_FORMAT' && targetResult.rawResponseBody) {
      const fallbackCheck = detectTargetProviderFallback({
        response: '',
        rawResponseBody: targetResult.rawResponseBody,
        httpStatus: targetResult.httpStatus
      });

      if (fallbackCheck.isFallback) {
        return {
          classification: 'PROVIDER_FALLBACK',
          transportSuccess: true,
          processedInput: false,
          assessable: false,
          unassessableReason: 'TARGET_PROVIDER_FALLBACK',
          fallbackDetected: true,
          fallbackReason: fallbackCheck.reason,
          description: `Target returned upstream provider rate-limit fallback: "${fallbackCheck.reason}". Probe was not processed by active AI model.`
        };
      }
    }

    const isAppError =
      targetResult.status === 'HTTP_ERROR' ||
      targetResult.status === 'INVALID_RESPONSE_FORMAT';

    if (isAppError) {
      return {
        classification: 'APPLICATION_ERROR',
        transportSuccess: true, // HTTP connection completed, but target application errored
        processedInput: false,
        assessable: false,
        unassessableReason: `TARGET_APPLICATION_ERROR_${targetResult.httpStatus || targetResult.status}`,
        fallbackDetected: false,
        fallbackReason: null,
        description: targetResult.error || `Target application returned ${targetResult.status} (${targetResult.httpStatus || 'N/A'}).`
      };
    }

    return {
      classification: 'TRANSPORT_ERROR',
      transportSuccess: false,
      processedInput: false,
      assessable: false,
      unassessableReason: `TARGET_TRANSPORT_FAILURE_${targetResult.status}`,
      fallbackDetected: false,
      fallbackReason: null,
      description: targetResult.error || `Target transport failed with status ${targetResult.status}.`
    };
  }

  // 2. HTTP 200 succeeded: check for recognized provider/quota fallback
  const fallbackCheck = detectTargetProviderFallback({
    response: targetResult.extractedResponse,
    rawResponseBody: targetResult.rawResponseBody,
    httpStatus: targetResult.httpStatus
  });

  if (fallbackCheck.isFallback) {
    return {
      classification: 'PROVIDER_FALLBACK',
      transportSuccess: true,
      processedInput: false, // Target did not process the adversarial prompt
      assessable: false,     // Unassessable for security evaluation
      unassessableReason: 'TARGET_PROVIDER_FALLBACK',
      fallbackDetected: true,
      fallbackReason: fallbackCheck.reason,
      description: `Target returned upstream provider rate-limit fallback: "${fallbackCheck.reason}". Probe was not processed by active AI model.`
    };
  }

  // 3. Substantive response produced
  const rawBody =
    targetResult.rawResponseBody && typeof targetResult.rawResponseBody === 'object'
      ? targetResult.rawResponseBody
      : {};

  let targetProvider = rawBody.targetProvider || null;
  if (!targetProvider && typeof rawBody.provenance === 'string') {
    if (rawBody.provenance.includes('gemini')) targetProvider = 'gemini';
    else if (rawBody.provenance.includes('groq') || rawBody.provenance.includes('grok')) targetProvider = 'groq';
    else if (rawBody.provenance.includes('openrouter')) targetProvider = 'openrouter';
    else if (rawBody.provenance.includes('fixture')) targetProvider = 'demo_fixture';
  }

  return {
    classification: 'SUBSTANTIVE_RESPONSE',
    transportSuccess: true,
    processedInput: true,
    assessable: true,
    unassessableReason: null,
    fallbackDetected: false,
    fallbackReason: null,
    targetProvider: targetProvider || 'external_target',
    targetModel: rawBody.targetModel || rawBody.model || null,
    targetAttempts: Array.isArray(rawBody.attempts) ? rawBody.attempts : null,
    description: 'Target successfully processed input and produced a substantive response.'
  };
}

/**
 * Builds conversational state diagnostics for multi-turn campaign tracking.
 *
 * @param {object} params
 * @param {string} params.sessionId
 * @param {Array<object>} params.conversationHistory
 * @param {string} params.currentPrompt
 * @returns {{
 *   sessionId: string,
 *   historyPreserved: boolean,
 *   historyLength: number,
 *   totalTurnsInHistory: number
 * }}
 */
function recordTurnConversationState({ sessionId, conversationHistory = [], currentPrompt = '' } = {}) {
  const historyLength = Array.isArray(conversationHistory) ? conversationHistory.length : 0;
  return {
    sessionId: sessionId || null,
    historyPreserved: historyLength > 0,
    historyLength,
    totalTurnsInHistory: Math.floor(historyLength / 2)
  };
}

module.exports = {
  detectTargetProviderFallback,
  classifyTargetExecution,
  recordTurnConversationState
};
