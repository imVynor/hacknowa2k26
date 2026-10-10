const http = require('node:http');
const https = require('node:https');
const { validateTargetUrl, createSafeAgent, redactHeaders } = require('../security/urlValidator');

/**
 * Parses path tokens supporting dot and bracket notation.
 * e.g. "choices[0].message.content" -> ["choices", "0", "message", "content"]
 */
function parsePathTokens(pathStr) {
  if (!pathStr || typeof pathStr !== 'string') return [];
  return pathStr
    .trim()
    .replace(/\[(\w+)\]/g, '.$1') // convert [0] to .0
    .replace(/^\./, '') // strip leading dot
    .split('.')
    .filter((token) => token.length > 0);
}

/**
 * Sets a value at a nested path inside an object or array.
 * Creates intermediate objects/arrays as needed.
 */
function setNestedPath(targetObj, pathStr, value) {
  const tokens = parsePathTokens(pathStr);
  if (tokens.length === 0) {
    if (typeof targetObj === 'object' && targetObj !== null) {
      targetObj.message = value;
    }
    return targetObj;
  }

  let current = targetObj;
  for (let i = 0; i < tokens.length - 1; i++) {
    const token = tokens[i];
    const nextToken = tokens[i + 1];
    const isNextNumeric = /^\d+$/.test(nextToken);

    if (current[token] === undefined || current[token] === null || typeof current[token] !== 'object') {
      current[token] = isNextNumeric ? [] : {};
    }
    current = current[token];
  }

  const lastToken = tokens[tokens.length - 1];
  current[lastToken] = value;
  return targetObj;
}

/**
 * Recursively replaces placeholder strings like {{input}} or USER_TEST_INPUT in an object.
 */
function replacePlaceholders(obj, value) {
  if (typeof obj === 'string') {
    if (obj.includes('USER_TEST_INPUT')) {
      return obj.replaceAll('USER_TEST_INPUT', value);
    }
    if (obj.includes('{{input}}')) {
      return obj.replaceAll('{{input}}', value);
    }
    if (obj.includes('{{prompt}}')) {
      return obj.replaceAll('{{prompt}}', value);
    }
    if (obj.includes('{{message}}')) {
      return obj.replaceAll('{{message}}', value);
    }
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => replacePlaceholders(item, value));
  }
  if (typeof obj === 'object' && obj !== null) {
    const result = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = replacePlaceholders(v, value);
    }
    return result;
  }
  return obj;
}

/**
 * Extracts a value from a nested object/array using path tokens.
 * Returns { found: boolean, value: any, error?: string, availableKeys?: string[] }
 */
function getNestedPath(sourceObj, pathStr) {
  const tokens = parsePathTokens(pathStr);
  if (tokens.length === 0) {
    return {
      found: false,
      error: 'Empty response extraction path specified.',
      availableKeys: typeof sourceObj === 'object' && sourceObj !== null ? Object.keys(sourceObj) : []
    };
  }

  let current = sourceObj;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (current === undefined || current === null || typeof current !== 'object') {
      return {
        found: false,
        error: `Cannot navigate into "${token}" from ${current === null ? 'null' : typeof current}.`,
        availableKeys: []
      };
    }

    if (!(token in current)) {
      return {
        found: false,
        error: `Key "${token}" was not found in response structure.`,
        availableKeys: Object.keys(current).slice(0, 15)
      };
    }

    current = current[token];
  }

  return { found: true, value: current };
}

/**
 * Validates the target configuration.
 */
function validateTargetConfig(config) {
  if (!config || typeof config !== 'object') {
    return { valid: false, error: 'Target configuration object is required.' };
  }

  if (!config.url || typeof config.url !== 'string' || config.url.trim() === '') {
    return { valid: false, error: 'Target URL is required.' };
  }

  if (config.ownershipAcknowledged !== true) {
    return {
      valid: false,
      error:
        'Target ownership confirmation required. You must acknowledge that you own or are authorized to test this target application.'
    };
  }

  const validMethods = ['POST', 'GET', 'PUT'];
  const method = (config.method || 'POST').toUpperCase();
  if (!validMethods.includes(method)) {
    return { valid: false, error: `Invalid HTTP method "${method}". Supported methods: ${validMethods.join(', ')}.` };
  }

  if (config.headers && typeof config.headers !== 'object') {
    return { valid: false, error: 'Custom headers must be an object of key-value pairs.' };
  }

  let parsedBodyTemplate = config.bodyTemplate;
  if (typeof parsedBodyTemplate === 'string' && parsedBodyTemplate.trim() !== '') {
    try {
      parsedBodyTemplate = JSON.parse(parsedBodyTemplate);
    } catch {
      return { valid: false, error: 'Request body template contains invalid JSON syntax.' };
    }
  }

  const timeoutMs = Number.parseInt(config.timeoutMs || 10000, 10);
  if (Number.isNaN(timeoutMs) || timeoutMs < 500 || timeoutMs > 30000) {
    return { valid: false, error: 'Timeout must be a number between 500ms and 30000ms.' };
  }

  return {
    valid: true,
    config: {
      ...config,
      method,
      timeoutMs,
      bodyTemplate: parsedBodyTemplate || { message: 'USER_TEST_INPUT' },
      inputPath: config.inputPath ? config.inputPath.trim() : 'message',
      responsePath: config.responsePath ? config.responsePath.trim() : 'reply',
      headers: config.headers || {}
    }
  };
}

/**
 * Builds the request body for the target.
 */
function constructRequestBody(template, inputPath, testInput) {
  const cloned = JSON.parse(JSON.stringify(template || {}));

  // First check if placeholders exist in the template
  const placeholderReplaced = replacePlaceholders(cloned, testInput);
  const hadPlaceholders = JSON.stringify(placeholderReplaced) !== JSON.stringify(cloned);

  if (hadPlaceholders) {
    return placeholderReplaced;
  }

  // Otherwise, use inputPath
  return setNestedPath(cloned, inputPath || 'message', testInput);
}

/**
 * Safe HTTP request dispatcher enforcing DNS rebinding defense, timeouts, and byte limits.
 */
function safeHttpRequest(urlString, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlString);
    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;
    const allowLocal = Boolean(options.allowLocal);
    const agent = createSafeAgent(parsed.protocol, { allowLocal });

    const timeoutMs = options.timeoutMs || 10000;
    const reqOptions = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'POST',
      headers: options.headers || {},
      agent
    };

    let timedOut = false;
    let timer = null;

    const req = client.request(reqOptions, (res) => {
      if (timer) clearTimeout(timer);

      let data = '';
      let bytesRead = 0;
      const maxBytes = 2 * 1024 * 1024; // 2MB limit

      res.on('data', (chunk) => {
        bytesRead += chunk.length;
        if (bytesRead > maxBytes) {
          req.destroy(new Error('Target response body exceeded 2MB limit.'));
          return;
        }
        data += chunk;
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          headers: res.headers,
          body: data
        });
      });
    });

    req.setTimeout(timeoutMs, () => {
      timedOut = true;
      req.destroy(new Error(`Timeout after ${timeoutMs}ms`));
    });

    timer = setTimeout(() => {
      timedOut = true;
      req.destroy(new Error(`Timeout after ${timeoutMs}ms`));
    }, timeoutMs);

    req.on('error', (err) => {
      if (timer) clearTimeout(timer);
      if (timedOut) {
        const timeoutErr = new Error(`Target request timed out after ${timeoutMs}ms.`);
        timeoutErr.name = 'TimeoutError';
        return reject(timeoutErr);
      }
      reject(err);
    });

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

/**
 * Executes a request against the target endpoint with full SSRF, timeout, and size guards.
 */
async function executeTargetRequest(targetConfig, testInput, options = {}) {
  const validation = validateTargetConfig(targetConfig);
  if (!validation.valid) {
    return {
      success: false,
      status: 'INVALID_CONFIG',
      error: validation.error,
      responseTimeMs: 0
    };
  }

  const cfg = validation.config;
  const allowLocal = Boolean(options.allowLocal || process.env.ALLOW_LOCAL_TARGETS === 'true');

  // SSRF Destination Validation
  const urlCheck = await validateTargetUrl(cfg.url, { allowLocal });
  if (!urlCheck.valid) {
    return {
      success: false,
      status: 'SECURITY_VIOLATION',
      error: urlCheck.error,
      responseTimeMs: 0
    };
  }

  // Prepare body
  let bodyPayload = null;
  if (cfg.method === 'POST' || cfg.method === 'PUT') {
    try {
      const constructed = constructRequestBody(cfg.bodyTemplate, cfg.inputPath, testInput);
      bodyPayload = JSON.stringify(constructed);

      // Enforce max request size (100KB)
      if (Buffer.byteLength(bodyPayload, 'utf8') > 100 * 1024) {
        return {
          success: false,
          status: 'INVALID_CONFIG',
          error: 'Request body exceeds maximum size limit (100KB).',
          responseTimeMs: 0
        };
      }
    } catch (err) {
      return {
        success: false,
        status: 'INVALID_CONFIG',
        error: `Failed to construct request body: ${err.message}`,
        responseTimeMs: 0
      };
    }
  }

  // Prepare headers (Do not forward internal VibeSec or Gemini credentials!)
  const sanitizedHeaders = {};
  if (cfg.headers && typeof cfg.headers === 'object') {
    for (const [key, value] of Object.entries(cfg.headers)) {
      if (typeof value === 'string' || typeof value === 'number') {
        sanitizedHeaders[key] = String(value);
      }
    }
  }

  if (bodyPayload && !Object.keys(sanitizedHeaders).some((k) => k.toLowerCase() === 'content-type')) {
    sanitizedHeaders['Content-Type'] = 'application/json';
  }

  const startTime = Date.now();
  try {
    const res = await safeHttpRequest(cfg.url, {
      method: cfg.method,
      headers: sanitizedHeaders,
      body: bodyPayload,
      timeoutMs: cfg.timeoutMs,
      allowLocal
    });

    const durationMs = Date.now() - startTime;

    // Reject HTTP redirects (301, 302, 303, 307, 308)
    if (res.statusCode >= 300 && res.statusCode < 400) {
      return {
        success: false,
        status: 'SECURITY_VIOLATION',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: `HTTP redirect (${res.statusCode}) was returned. Automatic redirects are disabled to prevent SSRF bypass.`
      };
    }

    // Handle HTTP errors
    if (res.statusCode < 200 || res.statusCode >= 300) {
      let errorBody = res.body;
      try {
        errorBody = JSON.parse(res.body);
      } catch {
        // keep as text
      }
      return {
        success: false,
        status: 'HTTP_ERROR',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: `Target returned HTTP ${res.statusCode} (${res.statusMessage || 'Error'}).`,
        rawResponseBody: errorBody
      };
    }

    // Try parsing response JSON
    let parsedJson;
    try {
      parsedJson = JSON.parse(res.body);
    } catch {
      return {
        success: false,
        status: 'INVALID_RESPONSE_FORMAT',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: 'Target returned an invalid or non-JSON response body.',
        rawResponseBody: (res.body || '').slice(0, 1000)
      };
    }

    // Extract AI response
    const extraction = getNestedPath(parsedJson, cfg.responsePath);
    if (!extraction.found) {
      return {
        success: false,
        status: 'INVALID_RESPONSE_FORMAT',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: `Extraction path "${cfg.responsePath}" was not found in returned JSON. ${extraction.error}`,
        details: {
          availableKeys: extraction.availableKeys
        },
        rawResponseBody: parsedJson
      };
    }

    const extractedValue = extraction.value;
    const extractedText = typeof extractedValue === 'string' ? extractedValue : JSON.stringify(extractedValue);

    return {
      success: true,
      status: 'SUCCESS',
      httpStatus: res.statusCode,
      responseTimeMs: durationMs,
      extractedResponse: extractedText,
      rawResponseBody: parsedJson,
      sanitizedHeaders: redactHeaders(res.headers)
    };
  } catch (err) {
    const durationMs = Date.now() - startTime;

    if (err.name === 'TimeoutError' || err.message.includes('Timeout')) {
      return {
        success: false,
        status: 'TIMEOUT',
        responseTimeMs: durationMs,
        error: `Target request timed out after ${cfg.timeoutMs}ms.`
      };
    }

    if (err.message.includes('prohibited IP') || err.message.includes('SSRF defense')) {
      return {
        success: false,
        status: 'SECURITY_VIOLATION',
        responseTimeMs: durationMs,
        error: err.message
      };
    }

    return {
      success: false,
      status: 'CONNECTION_ERROR',
      responseTimeMs: durationMs,
      error: `Connection error: ${err.message || 'Failed to reach target host'}`
    };
  }
}

/**
 * Recursively replaces multi-turn placeholders in an object structure.
 * Supports string replacement as well as substituting full array structures for messages.
 */
function replaceMultiTurnPlaceholders(obj, { messages, currentPrompt, sessionId }) {
  if (typeof obj === 'string') {
    if (obj === '{{messages}}' || obj === 'USER_TEST_HISTORY' || obj === 'USER_TEST_MESSAGES') {
      return messages;
    }
    let res = obj;
    if (res.includes('{{sessionId}}')) {
      res = res.replaceAll('{{sessionId}}', sessionId || '');
    }
    if (res.includes('SESSION_ID')) {
      res = res.replaceAll('SESSION_ID', sessionId || '');
    }
    if (res.includes('USER_TEST_INPUT')) {
      res = res.replaceAll('USER_TEST_INPUT', currentPrompt);
    }
    if (res.includes('{{input}}')) {
      res = res.replaceAll('{{input}}', currentPrompt);
    }
    if (res.includes('{{prompt}}')) {
      res = res.replaceAll('{{prompt}}', currentPrompt);
    }
    if (res.includes('{{message}}')) {
      res = res.replaceAll('{{message}}', currentPrompt);
    }
    return res;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => replaceMultiTurnPlaceholders(item, { messages, currentPrompt, sessionId }));
  }
  if (typeof obj === 'object' && obj !== null) {
    const result = {};
    for (const [k, v] of Object.entries(obj)) {
      if (
        (k === 'messages' || k === 'history' || k === 'conversation') &&
        (v === '{{messages}}' || v === 'USER_TEST_HISTORY' || v === 'USER_TEST_MESSAGES')
      ) {
        result[k] = messages;
      } else {
        result[k] = replaceMultiTurnPlaceholders(v, { messages, currentPrompt, sessionId });
      }
    }
    return result;
  }
  return obj;
}

/**
 * Builds a multi-turn request body carrying accumulated conversational history
 * and the current turn prompt.
 *
 * Enforces explicit limits on total turn count and message characters; returns an
 * explicit error instead of silently truncating history.
 *
 * @param {object} template - Body template or parsed JSON
 * @param {object} config - Target adapter configuration
 * @param {Array<object>} conversationHistory - Prior turns: [{ role: 'user'|'assistant', content: string }]
 * @param {string} currentPrompt - Prompt for current turn
 * @param {object} [options]
 * @returns {object}
 */
function constructMultiTurnRequestBody(
  template,
  config = {},
  conversationHistory = [],
  currentPrompt = '',
  options = {}
) {
  const maxTurns = options.maxTurns || 30;
  if (conversationHistory.length > maxTurns) {
    throw new Error(
      `Conversation turn limit (${maxTurns}) exceeded. Multi-turn conversation was not silently truncated.`
    );
  }

  const totalLength =
    conversationHistory.reduce((acc, m) => acc + (m.content ? m.content.length : 0), 0) +
    (currentPrompt ? currentPrompt.length : 0);
  const maxChars = options.maxChars || 100000;
  if (totalLength > maxChars) {
    throw new Error(
      `Conversation content length (${totalLength} chars) exceeds maximum allowed limit (${maxChars} chars). Conversation was not silently truncated.`
    );
  }

  // Build formatted dialogue text for single-input / placeholder scenarios
  let dialogueInput = currentPrompt;
  if (conversationHistory.length > 0) {
    const historyText = conversationHistory
      .map((m) => `${m.role === 'assistant' ? 'Assistant' : 'User'}: ${m.content}`)
      .join('\n\n');
    dialogueInput = `[Conversation History]\n${historyText}\n\nUser: ${currentPrompt}`;
  }

  // Build clean message list
  const messages = [];
  const initialContext = config.initialContext || options.initialContext;
  if (initialContext) {
    messages.push({
      role: 'system',
      content: String(initialContext)
    });
  }

  for (const turn of conversationHistory) {
    messages.push({
      role: turn.role === 'assistant' ? 'assistant' : 'user',
      content: String(turn.content || '')
    });
  }

  messages.push({
    role: 'user',
    content: String(currentPrompt || '')
  });

  const cloned = JSON.parse(JSON.stringify(template || {}));
  const sessionId = options.sessionId || config.sessionId || null;

  // 1. Check if placeholders exist in template
  const placeholderReplaced = replaceMultiTurnPlaceholders(cloned, {
    messages,
    currentPrompt: dialogueInput,
    sessionId
  });
  const hadPlaceholders = JSON.stringify(placeholderReplaced) !== JSON.stringify(cloned);

  let resultBody = hadPlaceholders ? placeholderReplaced : cloned;

  // 2. Explicit messagesPath configured
  if (config.messagesPath && typeof config.messagesPath === 'string') {
    setNestedPath(resultBody, config.messagesPath.trim(), messages);
  } else if (!hadPlaceholders && Array.isArray(resultBody.messages)) {
    // Standard chat schema with messages array
    resultBody.messages = messages;
  } else if (!hadPlaceholders && !config.messagesPath) {
    // Single-input format: Synthesize dialogue context into prompt string
    resultBody = setNestedPath(resultBody, config.inputPath || 'message', dialogueInput);
  }

  // 3. Inject session ID if configured
  if (sessionId) {
    if (config.sessionIdPath) {
      setNestedPath(resultBody, config.sessionIdPath, sessionId);
    } else if (resultBody.sessionId !== undefined) {
      resultBody.sessionId = sessionId;
    } else if (resultBody.session_id !== undefined) {
      resultBody.session_id = sessionId;
    }
  }

  return resultBody;
}

/**
 * Executes a multi-turn request against the target endpoint with accumulated dialogue history,
 * preserving full SSRF defense, timeouts, and byte limits.
 *
 * @param {object} params
 * @param {object} params.targetConfig - Target configuration
 * @param {Array<object>} params.conversationHistory - Accumulated conversation turns
 * @param {string} params.currentPrompt - Current turn's user prompt
 * @param {string} [params.sessionId] - Campaign run-scoped session identifier
 * @param {object} [params.options] - Execution options
 * @returns {Promise<object>}
 */
async function executeMultiTurnTargetRequest({
  targetConfig,
  conversationHistory = [],
  currentPrompt = '',
  sessionId = null,
  options = {}
}) {
  const validation = validateTargetConfig(targetConfig);
  if (!validation.valid) {
    return {
      success: false,
      status: 'INVALID_CONFIG',
      error: validation.error,
      responseTimeMs: 0
    };
  }

  const cfg = validation.config;
  const allowLocal =
    options.allowLocal !== undefined
      ? Boolean(options.allowLocal)
      : process.env.ALLOW_LOCAL_TARGETS === 'true';

  // SSRF Destination Validation
  const urlCheck = await validateTargetUrl(cfg.url, { allowLocal });
  if (!urlCheck.valid) {
    return {
      success: false,
      status: 'SECURITY_VIOLATION',
      error: urlCheck.error,
      responseTimeMs: 0
    };
  }

  // Construct Multi-Turn Body
  let bodyPayload = null;
  if (cfg.method === 'POST' || cfg.method === 'PUT') {
    try {
      const constructed = constructMultiTurnRequestBody(
        cfg.bodyTemplate,
        cfg,
        conversationHistory,
        currentPrompt,
        {
          sessionId,
          initialContext: cfg.initialContext || options.initialContext,
          maxTurns: options.maxHistoryTurns || (options.maxTurns ? options.maxTurns * 2 + 10 : 30),
          maxChars: options.maxChars
        }
      );
      bodyPayload = JSON.stringify(constructed);

      // Max size check (250KB for multi-turn)
      if (Buffer.byteLength(bodyPayload, 'utf8') > 250 * 1024) {
        return {
          success: false,
          status: 'INVALID_CONFIG',
          error: 'Multi-turn request body exceeds maximum size limit (250KB).',
          responseTimeMs: 0
        };
      }
    } catch (err) {
      return {
        success: false,
        status: 'INVALID_CONFIG',
        error: `Failed to construct multi-turn request body: ${err.message}`,
        responseTimeMs: 0
      };
    }
  }

  // Prepare headers
  const sanitizedHeaders = {};
  if (cfg.headers && typeof cfg.headers === 'object') {
    for (const [key, value] of Object.entries(cfg.headers)) {
      if (typeof value === 'string' || typeof value === 'number') {
        sanitizedHeaders[key] = String(value);
      }
    }
  }

  // Scope session header if requested
  if (sessionId && cfg.sessionHeader) {
    sanitizedHeaders[cfg.sessionHeader] = sessionId;
  }

  if (bodyPayload && !Object.keys(sanitizedHeaders).some((k) => k.toLowerCase() === 'content-type')) {
    sanitizedHeaders['Content-Type'] = 'application/json';
  }

  const startTime = Date.now();
  try {
    const res = await safeHttpRequest(cfg.url, {
      method: cfg.method,
      headers: sanitizedHeaders,
      body: bodyPayload,
      timeoutMs: cfg.timeoutMs,
      allowLocal
    });

    const durationMs = Date.now() - startTime;

    // Reject HTTP redirects
    if (res.statusCode >= 300 && res.statusCode < 400) {
      return {
        success: false,
        status: 'SECURITY_VIOLATION',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: `HTTP redirect (${res.statusCode}) was returned. Automatic redirects are disabled to prevent SSRF bypass.`
      };
    }

    // Handle HTTP errors
    if (res.statusCode < 200 || res.statusCode >= 300) {
      let errorBody = res.body;
      try {
        errorBody = JSON.parse(res.body);
      } catch {
        // keep text
      }
      return {
        success: false,
        status: 'HTTP_ERROR',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: `Target returned HTTP ${res.statusCode} (${res.statusMessage || 'Error'}).`,
        rawResponseBody: errorBody
      };
    }

    // Parse JSON
    let parsedJson;
    try {
      parsedJson = JSON.parse(res.body);
    } catch {
      return {
        success: false,
        status: 'INVALID_RESPONSE_FORMAT',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: 'Target returned an invalid or non-JSON response body.',
        rawResponseBody: (res.body || '').slice(0, 1000)
      };
    }

    // Extract AI response
    const extraction = getNestedPath(parsedJson, cfg.responsePath);
    if (!extraction.found) {
      return {
        success: false,
        status: 'INVALID_RESPONSE_FORMAT',
        httpStatus: res.statusCode,
        responseTimeMs: durationMs,
        error: `Extraction path "${cfg.responsePath}" was not found in returned JSON. ${extraction.error}`,
        details: {
          availableKeys: extraction.availableKeys
        },
        rawResponseBody: parsedJson
      };
    }

    const extractedValue = extraction.value;
    const extractedText = typeof extractedValue === 'string' ? extractedValue : JSON.stringify(extractedValue);

    return {
      success: true,
      status: 'SUCCESS',
      httpStatus: res.statusCode,
      responseTimeMs: durationMs,
      extractedResponse: extractedText,
      rawResponseBody: parsedJson,
      sanitizedHeaders: redactHeaders(res.headers)
    };
  } catch (err) {
    const durationMs = Date.now() - startTime;

    if (err.name === 'TimeoutError' || err.message.includes('Timeout')) {
      return {
        success: false,
        status: 'TIMEOUT',
        responseTimeMs: durationMs,
        error: `Target request timed out after ${cfg.timeoutMs}ms.`
      };
    }

    if (err.message.includes('prohibited IP') || err.message.includes('SSRF defense')) {
      return {
        success: false,
        status: 'SECURITY_VIOLATION',
        responseTimeMs: durationMs,
        error: err.message
      };
    }

    return {
      success: false,
      status: 'CONNECTION_ERROR',
      responseTimeMs: durationMs,
      error: `Connection error: ${err.message || 'Failed to reach target host'}`
    };
  }
}

module.exports = {
  parsePathTokens,
  setNestedPath,
  getNestedPath,
  replacePlaceholders,
  validateTargetConfig,
  constructRequestBody,
  executeTargetRequest,
  constructMultiTurnRequestBody,
  executeMultiTurnTargetRequest
};

