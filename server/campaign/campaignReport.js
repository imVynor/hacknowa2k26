/**
 * VibeSec Canonical Campaign Report & Exporter (v1.0.0)
 * Generates canonical, sanitized, evidence-backed reports for multi-turn security campaigns
 * in JSON and Markdown formats.
 */

const { getCampaignRunById } = require('./campaignRunner');

const CANONICAL_CAMPAIGN_REPORT_SCHEMA_VERSION = '1.0.0';

/**
 * Sanitizes target URLs by stripping or masking sensitive query parameters and credentials.
 * @param {string} urlString
 * @returns {string}
 */
function sanitizeUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') return urlString || '';
  try {
    const parsed = new URL(urlString);
    const sensitiveKeys = new Set([
      'key',
      'api_key',
      'apikey',
      'token',
      'secret',
      'password',
      'pass',
      'auth',
      'access_token',
      'session',
      'jwt',
      'bearer',
      'credential',
      'credentials',
      'sig',
      'signature'
    ]);

    for (const param of Array.from(parsed.searchParams.keys())) {
      const lower = param.toLowerCase();
      let decodedLower = lower;
      try {
        decodedLower = decodeURIComponent(param).toLowerCase();
      } catch {
        // ignore malformed encoding
      }

      if (sensitiveKeys.has(lower) || sensitiveKeys.has(decodedLower)) {
        parsed.searchParams.set(param, '[REDACTED]');
      }
    }

    if (parsed.username) parsed.username = '[REDACTED]';
    if (parsed.password) parsed.password = '[REDACTED]';
    return parsed.toString().replaceAll('%5BREDACTED%5D', '[REDACTED]');
  } catch {
    return urlString
      .replace(/:\/\/([^:@\s]+):([^@\s]+)@/g, '://[REDACTED]:[REDACTED]@')
      .replace(/(api[_-]?key|apikey|token|key|secret|password|auth|bearer|jwt)=([^&]+)/gi, '$1=[REDACTED]');
  }
}

/**
 * Scrubs known secrets, tokens, and authorization patterns from error messages and text.
 * @param {string} text
 * @param {string} [canarySecret]
 * @returns {string}
 */
function scrubSensitiveText(text, canarySecret) {
  if (!text || typeof text !== 'string') return text || '';
  let scrubbed = text;
  if (canarySecret && typeof canarySecret === 'string' && canarySecret.trim().length >= 4) {
    scrubbed = scrubbed.replaceAll(canarySecret.trim(), '[CANARY_SECRET_REDACTED]');
  }
  scrubbed = scrubbed.replace(/Bearer\s+[a-zA-Z0-9_\-\.]{10,}/gi, 'Bearer [REDACTED]');
  scrubbed = scrubbed.replace(/Basic\s+[a-zA-Z0-9+/=]{8,}/gi, 'Basic [REDACTED]');
  scrubbed = scrubbed.replace(/(?:cookie|set-cookie):\s*([^\r\n;]+)/gi, 'Cookie: [REDACTED]');
  scrubbed = scrubbed.replace(/(?:authorization|x-api-key|x-auth-token):\s*([^\r\n]+)/gi, 'Authorization: [REDACTED]');
  scrubbed = scrubbed.replace(/(api[_-]?key[:=]\s*)[a-zA-Z0-9_\-\.]{8,}/gi, '$1[REDACTED]');
  scrubbed = scrubbed.replace(/(password[:=]\s*)[^\s,;"']+/gi, '$1[REDACTED]');
  return scrubbed;
}

/**
 * Sanitizes target details to guarantee no credentials or authorization headers are leaked.
 */
function sanitizeTargetDetails(target) {
  if (!target || typeof target !== 'object') {
    return { mode: 'mock' };
  }
  return {
    url: sanitizeUrl(target.url),
    method: target.method || 'POST',
    inputPath: target.inputPath || 'message',
    responsePath: target.responsePath || 'reply',
    messagesPath: target.messagesPath || null,
    sessionIdPath: target.sessionIdPath || null,
    timeoutMs: target.timeoutMs || 10000
  };
}

/**
 * Safely wraps text in markdown code fences using adaptive backtick lengths to prevent injection.
 */
function formatCodeBlock(content, language = '') {
  if (content === null || content === undefined) {
    return '*(none)*';
  }
  const text = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
  const matches = text.match(/`{3,}/g);
  let maxBackticks = 2;
  if (matches) {
    for (const m of matches) {
      if (m.length > maxBackticks) maxBackticks = m.length;
    }
  }
  const fence = '`'.repeat(Math.max(3, maxBackticks + 1));
  return `${fence}${language}\n${text}\n${fence}`;
}

/**
 * Escapes inline markdown special characters.
 */
function escapeMarkdownInline(text) {
  if (!text || typeof text !== 'string') return text || '';
  return text
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/\*/g, '\\*')
    .replace(/_/g, '\\_')
    .replace(/`/g, '\\`');
}

/**
 * Escapes markdown blockquote content.
 */
function escapeMarkdownQuote(text) {
  if (!text || typeof text !== 'string') return text || '';
  return text
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`')
    .replace(/\n/g, ' ');
}

/**
 * Builds the canonical sanitized report model from a raw campaign execution record.
 * Guarantees zero sensitive header or secret leakage.
 *
 * @param {object} rawRun - Raw campaign execution record from runner
 * @param {object} [options]
 * @returns {object} Canonical campaign report
 */
function buildCanonicalCampaignReport(rawRun, options = {}) {
  if (!rawRun || typeof rawRun !== 'object') {
    throw new Error('Valid campaign run record is required to build report.');
  }

  const canarySecret =
    options.canarySecret ||
    rawRun.canarySecret ||
    rawRun.options?.canarySecret ||
    null;
  const turns = Array.isArray(rawRun.turns) ? rawRun.turns : [];

  const sanitizedTurns = turns.map((t) => ({
    turnId: t.turnId,
    turnNumber: t.turnNumber,
    name: t.name,
    strategyId: t.strategyId || null,
    strategyName: t.strategyName || null,
    strategySelectionRationale: t.strategySelectionRationale
      ? scrubSensitiveText(t.strategySelectionRationale, canarySecret)
      : null,
    selectionProvenance: t.selectionProvenance || null,
    prompt: t.prompt,
    securityObjective: t.securityObjective,
    actualResponse: t.actualResponse ? scrubSensitiveText(t.actualResponse, canarySecret) : null,
    assessable: t.assessable !== undefined ? Boolean(t.assessable) : true,
    unassessableReason: t.unassessableReason || null,
    conversationState: t.conversationState || null,
    targetExecution: {
      status: t.targetExecution?.status || 'UNKNOWN',
      classification: t.targetExecution?.classification || 'UNKNOWN',
      transportSuccess: Boolean(t.targetExecution?.transportSuccess),
      processedInput: Boolean(t.targetExecution?.processedInput),
      assessable: t.targetExecution?.assessable !== undefined ? Boolean(t.targetExecution.assessable) : (t.assessable !== undefined ? Boolean(t.assessable) : true),
      unassessableReason: t.targetExecution?.unassessableReason || t.unassessableReason || null,
      fallbackDetected: Boolean(t.targetExecution?.fallbackDetected),
      fallbackReason: t.targetExecution?.fallbackReason || null,
      httpStatus: t.targetExecution?.httpStatus || 0,
      responseTimeMs: t.targetExecution?.responseTimeMs || 0,
      provenance: t.targetExecution?.provenance || 'unknown',
      targetProvider: t.targetExecution?.targetProvider || null,
      targetModel: t.targetExecution?.targetModel || null,
      targetAttempts: Array.isArray(t.targetExecution?.targetAttempts)
        ? t.targetExecution.targetAttempts.map((att) => ({
            provider: att.provider,
            model: att.model || 'unknown',
            outcome: att.outcome,
            latencyMs: att.latencyMs || 0,
            error: att.error ? scrubSensitiveText(att.error, canarySecret) : null
          }))
        : null,
      error: t.targetExecution?.error ? scrubSensitiveText(t.targetExecution.error, canarySecret) : null
    },
    canaryDetection: {
      canaryConfigured: Boolean(t.canaryDetection?.canaryConfigured),
      detected: Boolean(t.canaryDetection?.detected),
      evidence: t.canaryDetection?.evidence ? '[CANARY_SECRET_DETECTED]' : null
    },
    verdict: t.verdict,
    evidence: t.evidence ? scrubSensitiveText(t.evidence, canarySecret) : null,
    explanation: t.explanation ? scrubSensitiveText(t.explanation, canarySecret) : '',
    reconciliationRule: t.reconciliationRule || null,
    criteria: t.criteria || null,
    semanticEvaluationSkipped: Boolean(t.semanticEvaluationSkipped),
    semanticEvaluationSkipReason: t.semanticEvaluationSkipReason || null,
    evaluator: t.evaluator || 'unknown',
    method: t.method || t.evaluator || 'unknown',
    evaluatorProvenance: t.evaluatorProvenance
      ? {
          finalProvider: t.evaluatorProvenance.finalProvider,
          finalModel: t.evaluatorProvenance.finalModel,
          failoverOccurred: Boolean(t.evaluatorProvenance.failoverOccurred),
          attempts: (t.evaluatorProvenance.attempts || []).map((att) => ({
            provider: att.provider,
            model: att.model || 'unknown',
            outcome: att.outcome,
            failoverReason: att.failoverReason || null,
            latencyMs: att.latencyMs || 0,
            error: att.error ? scrubSensitiveText(att.error, canarySecret) : null
          }))
        }
      : null,
    timing: {
      targetDurationMs: t.timing?.targetDurationMs || 0,
      evalDurationMs: t.timing?.evalDurationMs || 0,
      totalDurationMs: t.timing?.totalDurationMs || 0
    }
  }));

  const sanitizedConversation = (rawRun.conversationHistory || []).map((msg) => ({
    role: msg.role,
    content: scrubSensitiveText(msg.content, canarySecret)
  }));

  const campaignType = rawRun.campaignType || (rawRun.strategyLibrary ? 'adaptive' : 'fixed');
  const assessableCount = sanitizedTurns.filter((t) => t.assessable).length;
  const unassessableCount = sanitizedTurns.filter((t) => !t.assessable).length;
  const providerFallbackActive = sanitizedTurns.some(
    (t) => t.targetExecution?.classification === 'PROVIDER_FALLBACK'
  );

  return {
    reportType: 'campaign_evaluation',
    reportSchemaVersion: CANONICAL_CAMPAIGN_REPORT_SCHEMA_VERSION,
    runId: rawRun.runId,
    campaignType,
    startedAt: rawRun.startedAt,
    completedAt: rawRun.completedAt,
    totalDurationMs: rawRun.totalDurationMs || 0,
    status: rawRun.status || 'COMPLETED',
    mode: rawRun.mode || 'live',
    selectionMode: rawRun.selectionMode || null,
    strategyLibrary: rawRun.strategyLibrary || null,
    budgetUsage: rawRun.budgetUsage || null,
    stoppingReason: rawRun.stoppingReason || null,
    campaignCompleted:
      rawRun.campaignCompleted !== undefined ? Boolean(rawRun.campaignCompleted) : true,
    campaign: {
      campaignId: rawRun.campaign?.campaignId || 'unknown',
      name: rawRun.campaign?.name || (campaignType === 'adaptive' ? 'Adaptive Campaign' : 'Unnamed Campaign'),
      version: rawRun.campaign?.version || '1.0.0',
      category: rawRun.campaign?.category || (campaignType === 'adaptive' ? 'Adaptive Evaluation' : 'General'),
      attackObjective: rawRun.campaign?.attackObjective || rawRun.objective || '',
      securityRequirement: rawRun.campaign?.securityRequirement || rawRun.applicationRequirement || '',
      evaluationStrategy: rawRun.campaign?.evaluationStrategy || 'hybrid',
      totalTurns: rawRun.campaign?.totalTurns || turns.length,
      tags: rawRun.campaign?.tags || []
    },
    target: sanitizeTargetDetails(rawRun.target),
    targetModel: rawRun.targetModel || 'unknown',
    evaluatorModel: rawRun.evaluatorModel || 'heuristic_fallback',
    campaignDiagnostic: rawRun.campaignDiagnostic || rawRun.summary?.campaignDiagnostic || null,
    executionLimits: {
      maxTurns: rawRun.executionLimits?.maxTurns || turns.length,
      maxTotalDurationMs: rawRun.executionLimits?.maxTotalDurationMs || 90000,
      earlyTermination: Boolean(rawRun.executionLimits?.earlyTermination ?? !rawRun.campaignCompleted),
      terminationReason: rawRun.executionLimits?.terminationReason || rawRun.stoppingReason
        ? scrubSensitiveText(rawRun.executionLimits?.terminationReason || rawRun.stoppingReason, canarySecret)
        : null
    },
    summary: {
      totalTurns: rawRun.summary?.totalTurns || turns.length,
      executedTurns: rawRun.summary?.executedTurns || turns.length,
      assessableTurns: rawRun.summary?.assessableTurns ?? assessableCount,
      unassessableTurns: rawRun.summary?.unassessableTurns ?? unassessableCount,
      targetProviderFallbackDetected:
        rawRun.summary?.targetProviderFallbackDetected !== undefined
          ? Boolean(rawRun.summary.targetProviderFallbackDetected)
          : providerFallbackActive,
      campaignDiagnostic: rawRun.summary?.campaignDiagnostic || rawRun.campaignDiagnostic || null,
      objectivesTested:
        rawRun.summary?.objectivesTested !== undefined
          ? Boolean(rawRun.summary.objectivesTested)
          : (unassessableCount === 0 && !rawRun.executionLimits?.earlyTermination),
      objectivesTestedNotice: rawRun.summary?.objectivesTestedNotice
        ? scrubSensitiveText(rawRun.summary.objectivesTestedNotice, canarySecret)
        : null,
      pass: rawRun.summary?.pass || 0,
      fail: rawRun.summary?.fail || 0,
      inconclusive: rawRun.summary?.inconclusive || 0,
      error: rawRun.summary?.error || 0,
      campaignVerdict: rawRun.summary?.campaignVerdict || 'INCONCLUSIVE',
      verdictExplanation: rawRun.summary?.verdictExplanation
        ? scrubSensitiveText(rawRun.summary.verdictExplanation, canarySecret)
        : ''
    },
    turns: sanitizedTurns,
    conversationHistory: sanitizedConversation,
    disclaimer:
      rawRun.disclaimer ||
      (campaignType === 'adaptive'
        ? 'Passing an adaptive campaign demonstrates resilience against the specific tested response-driven strategy sequence under evaluated conditions. External AI models are non-deterministic, and replaying a run does not guarantee identical outputs.'
        : 'Passing a multi-turn campaign demonstrates resilience against the specific tested conversation sequence under evaluated conditions. It does not prove complete immunity against all adaptive or multi-turn attacks.'),
    storageNotice: 'Campaign history is held in-memory and will be cleared when the server process restarts.'
  };
}

/**
 * Serializes a campaign report to JSON format.
 */
function generateCampaignJsonReport(reportOrRun, options = {}) {
  const canonical =
    reportOrRun.reportSchemaVersion === CANONICAL_CAMPAIGN_REPORT_SCHEMA_VERSION
      ? reportOrRun
      : buildCanonicalCampaignReport(reportOrRun, options);

  return {
    filename: `vibesec-campaign-${canonical.runId}.json`,
    mimeType: 'application/json',
    content: JSON.stringify(canonical, null, 2)
  };
}

/**
 * Formats a campaign report as an auditable Markdown document.
 */
function generateCampaignMarkdownReport(reportOrRun, options = {}) {
  const canonical =
    reportOrRun.reportSchemaVersion === CANONICAL_CAMPAIGN_REPORT_SCHEMA_VERSION
      ? reportOrRun
      : buildCanonicalCampaignReport(reportOrRun, options);

  const {
    runId,
    campaignType,
    startedAt,
    completedAt,
    totalDurationMs,
    status,
    mode,
    selectionMode,
    strategyLibrary,
    budgetUsage,
    stoppingReason,
    campaignCompleted,
    campaign,
    target,
    targetModel,
    evaluatorModel,
    executionLimits,
    summary,
    turns,
    disclaimer,
    storageNotice
  } = canonical;

  const isAdaptive = campaignType === 'adaptive';
  const lines = [];

  lines.push(
    isAdaptive
      ? `# VibeSec Adaptive Campaign Security Report`
      : `# VibeSec Multi-Turn Campaign Security Report`
  );
  lines.push(``);
  lines.push(`> **Run ID**: \`${runId}\`  `);
  lines.push(`> **Campaign Mode**: \`${isAdaptive ? 'ADAPTIVE (RESPONSE-DRIVEN)' : 'FIXED SCENARIO'}\`  `);
  lines.push(`> **Generated At**: \`${new Date().toISOString()}\`  `);
  lines.push(`> **Schema Version**: \`${CANONICAL_CAMPAIGN_REPORT_SCHEMA_VERSION}\``);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // 1. Executive Summary
  lines.push(`## 1. Executive Summary`);
  lines.push(``);

  const verdictIcon =
    summary.campaignVerdict === 'PASS'
      ? '✅ PASS'
      : summary.campaignVerdict === 'FAIL'
        ? '❌ FAIL'
        : summary.campaignVerdict === 'INCONCLUSIVE'
          ? '⚠️ INCONCLUSIVE'
          : '🛑 ERROR';

  lines.push(`### Campaign Scorecard: **${verdictIcon}**`);
  lines.push(``);
  lines.push(`> **Campaign Verdict**: **${summary.campaignVerdict}**  `);
  lines.push(`> **Verdict Rationale**: ${escapeMarkdownQuote(summary.verdictExplanation)}`);
  lines.push(``);

  const campaignDiag = canonical.campaignDiagnostic || summary.campaignDiagnostic;
  if (campaignDiag && campaignDiag.type === 'TARGET_PROVIDER_FALLBACK') {
    lines.push(`> [!CAUTION]`);
    lines.push(`> **Campaign Root Cause — Target Provider Rate-Limit Fallback Active**: ${escapeMarkdownInline(campaignDiag.summary)}`);
    lines.push(`> *Root Cause: "${escapeMarkdownInline(campaignDiag.rootCause)}"*  `);
    lines.push(`> *Semantic evaluation was skipped across all affected turns (${campaignDiag.affectedTurnsCount}/${campaignDiag.totalTurns}). Probes were not processed by an active AI model.*`);
    if (campaignDiag.recommendation) {
      lines.push(`> *Recommendation: ${escapeMarkdownInline(campaignDiag.recommendation)}*`);
    }
    lines.push(``);
  } else if (summary.targetProviderFallbackDetected) {
    lines.push(`> [!CAUTION]`);
    lines.push(
      `> **Target Provider Rate-Limit Fallback Active**: The target returned upstream provider/quota fallback responses rather than executing probes with an active AI model. Security objectives could not be assessed.`
    );
    lines.push(``);
  }

  if (executionLimits?.earlyTermination || (isAdaptive && !campaignCompleted)) {
    lines.push(`> [!WARNING]`);
    lines.push(
      `> **Incomplete Execution Notice**: This campaign terminated early (${escapeMarkdownInline(
        executionLimits.terminationReason || stoppingReason || 'Limit reached'
      )}). Partial evidence is preserved. Incomplete runs can never produce a PASS verdict.`
    );
    lines.push(``);
  }

  lines.push(`- **Campaign Scenario**: ${campaign.name} (\`${campaign.campaignId}\` v${campaign.version})`);
  lines.push(`- **Category**: \`${campaign.category}\``);
  lines.push(`- **Execution Mode**: \`${mode.toUpperCase()}\``);
  lines.push(`- **Execution Status**: \`${status}\``);
  lines.push(`- **Target Execution Health**: ${summary.targetProviderFallbackDetected ? '⚠️ Rate-Limit Fallback Active (Unassessable)' : '✅ Operational'}`);
  lines.push(`- **Security Objectives Tested**: ${summary.objectivesTested ? '✅ YES' : '⚠️ NO (Unassessable / Incomplete)'}`);
  if (summary.objectivesTestedNotice) {
    lines.push(`- **Objective Assessment Notice**: *${escapeMarkdownInline(summary.objectivesTestedNotice)}*`);
  }
  if (isAdaptive) {
    lines.push(`- **Strategy Library**: \`${strategyLibrary?.name || 'VibeSec Adaptive Library'}\` v${strategyLibrary?.version || '1.0.0'}`);
    lines.push(`- **Selection Mode**: \`${(selectionMode || 'deterministic').toUpperCase()}\``);
    lines.push(`- **Stopping Reason**: \`${stoppingReason || 'ALL_OBJECTIVES_TESTED'}\``);
    lines.push(`- **Objectives Completed**: \`${campaignCompleted ? 'YES' : 'NO (EARLY STOP)'}\``);
  }
  lines.push(`- **Started At**: \`${startedAt}\``);
  lines.push(`- **Completed At**: \`${completedAt}\` (${totalDurationMs} ms total duration)`);
  lines.push(`- **Target URL**: \`${target.url || 'Mock Target'}\` (${target.method})`);
  lines.push(`- **Target Model Identifier**: \`${targetModel}\``);
  lines.push(`- **Evaluator Model Identifier**: \`${evaluatorModel}\``);
  lines.push(``);

  // Budget Usage Table (Adaptive campaigns)
  if (isAdaptive && budgetUsage) {
    lines.push(`### Server Resource & Budget Consumption`);
    lines.push(``);
    lines.push(`| Resource Limit | Consumed | Server Cap | Status |`);
    lines.push(`|:---|:---:|:---:|:---:|`);
    lines.push(
      `| Conversational Turns | ${budgetUsage.executedTurns} | ${budgetUsage.maxTurns} | ${budgetUsage.executedTurns >= budgetUsage.maxTurns ? '⚠️ Exhausted' : '✅ Within Limit'} |`
    );
    lines.push(
      `| Total Execution Duration | ${budgetUsage.totalDurationMs} ms | ${budgetUsage.maxTotalDurationMs} ms | ${budgetUsage.totalDurationMs >= budgetUsage.maxTotalDurationMs ? '⚠️ Exhausted' : '✅ Within Limit'} |`
    );
    lines.push(
      `| Cumulative Characters | ${budgetUsage.conversationChars} | ${budgetUsage.maxConversationChars} | ${budgetUsage.conversationChars >= budgetUsage.maxConversationChars ? '⚠️ Exhausted' : '✅ Within Limit'} |`
    );
    lines.push(
      `| Strategy Selection Invocations | ${budgetUsage.strategySelectionCalls} | 10 | ✅ OK |`
    );
    lines.push(
      `| Evaluator Invocations | ${budgetUsage.evaluatorCalls} | 10 | ✅ OK |`
    );
    lines.push(``);
  }

  // Turn Breakdown Table
  lines.push(`### Turn Execution Breakdown`);
  lines.push(``);
  if (isAdaptive) {
    lines.push(`| Turn | Strategy ID | Verdict | Assessable | Target Status | Duration | Evaluation Method | Selection Rationale |`);
    lines.push(`|:---:|:---|:---:|:---:|:---|:---:|:---|:---|`);
    for (const t of turns) {
      const tIcon =
        t.verdict === 'PASS'
          ? '✅ PASS'
          : t.verdict === 'FAIL'
            ? '❌ FAIL'
            : t.verdict === 'INCONCLUSIVE'
              ? '⚠️ INCONCLUSIVE'
              : '🛑 ERROR';
      const assessableLabel = t.assessable ? '✅ Yes' : '⚠️ No';
      lines.push(
        `| ${t.turnNumber} | \`${t.strategyId || t.name}\` | **${tIcon}** | ${assessableLabel} | \`${t.targetExecution.classification || t.targetExecution.status}\` | ${t.timing.totalDurationMs} ms | \`${t.method || t.evaluator}\` | ${escapeMarkdownInline(t.strategySelectionRationale || 'N/A')} |`
      );
    }
  } else {
    lines.push(`| Turn | Name | Verdict | Assessable | Target Status | Duration | Evaluation Method |`);
    lines.push(`|:---:|:---|:---:|:---:|:---|:---:|:---|`);
    for (const t of turns) {
      const tIcon =
        t.verdict === 'PASS'
          ? '✅ PASS'
          : t.verdict === 'FAIL'
            ? '❌ FAIL'
            : t.verdict === 'INCONCLUSIVE'
              ? '⚠️ INCONCLUSIVE'
              : '🛑 ERROR';
      const assessableLabel = t.assessable ? '✅ Yes' : '⚠️ No';
      lines.push(
        `| ${t.turnNumber} | ${escapeMarkdownInline(t.name)} | **${tIcon}** | ${assessableLabel} | \`${t.targetExecution.classification || t.targetExecution.status}\` | ${t.timing.totalDurationMs} ms | \`${t.method || t.evaluator}\` |`
      );
    }
  }
  lines.push(``);

  // 2. Scenario Objectives & Security Policy
  lines.push(`## 2. Campaign Objectives & Security Requirement`);
  lines.push(``);
  lines.push(`- **Attack Objective**: *${escapeMarkdownInline(campaign.attackObjective)}*`);
  lines.push(`- **Security Requirement**: *${escapeMarkdownInline(campaign.securityRequirement)}*`);
  lines.push(`- **Evaluation Strategy**: \`${campaign.evaluationStrategy}\``);
  lines.push(``);

  // 3. Conversation Timeline & Turn Evidence
  lines.push(`## 3. Conversational Timeline & Turn-by-Turn Evidence`);
  lines.push(``);

  turns.forEach((t) => {
    const tIcon =
      t.verdict === 'PASS'
        ? '✅ PASS'
        : t.verdict === 'FAIL'
          ? '❌ FAIL'
          : t.verdict === 'INCONCLUSIVE'
            ? '⚠️ INCONCLUSIVE'
            : '🛑 ERROR';

    lines.push(`### Turn ${t.turnNumber}: ${escapeMarkdownInline(t.name)} (\`${t.turnId}\`)`);
    lines.push(``);
    if (isAdaptive && t.strategyId) {
      lines.push(`- **Selected Strategy**: \`${t.strategyId}\` (${escapeMarkdownInline(t.strategyName || '')})`);
      lines.push(`- **Selection Rationale**: *${escapeMarkdownInline(t.strategySelectionRationale || 'N/A')}*`);
      lines.push(`- **Selection Provenance**: \`${t.selectionProvenance || 'deterministic'}\``);
    }
    lines.push(`- **Security Objective**: *${escapeMarkdownInline(t.securityObjective)}*`);
    lines.push(`- **Turn Verdict**: **${tIcon}**`);
    lines.push(`- **Evaluator**: \`${t.evaluator}\``);
    lines.push(`- **Evaluation Method**: \`${t.method || t.evaluator}\``);
    if (t.reconciliationRule) {
      lines.push(`- **Reconciliation Rule**: \`${t.reconciliationRule}\``);
    }
    if (t.semanticEvaluationSkipped) {
      lines.push(`- **Semantic Evaluation**: ⚠️ Skipped (${escapeMarkdownInline(t.semanticEvaluationSkipReason || 'Target Unassessable')})`);
    }
    lines.push(`- **Assessable**: ${t.assessable ? '✅ YES' : `⚠️ NO (${escapeMarkdownInline(t.unassessableReason || 'Target Unassessable')})`}`);
    lines.push(
      `- **Target Dispatch**: Status \`${t.targetExecution.status}\` (${t.targetExecution.classification || 'N/A'}, HTTP ${t.targetExecution.httpStatus || 'N/A'}, ${t.targetExecution.responseTimeMs} ms)`
    );
    if (t.targetExecution.targetProvider) {
      lines.push(
        `- **Target AI Provider**: \`${t.targetExecution.targetProvider}\`${t.targetExecution.targetModel ? ` (Model: \`${t.targetExecution.targetModel}\`)` : ''}`
      );
    }
    if (t.evaluatorProvenance?.finalProvider) {
      lines.push(
        `- **Evaluator AI Provider**: \`${t.evaluatorProvenance.finalProvider}\`${t.evaluatorProvenance.finalModel ? ` (Model: \`${t.evaluatorProvenance.finalModel}\`)` : ''}`
      );
    }
    if (t.canaryDetection.canaryConfigured) {
      lines.push(
        `- **Synthetic Canary Leak**: ${t.canaryDetection.detected ? '**DETECTED! (VIOLATION)**' : 'Not detected'}`
      );
    }
    lines.push(``);

    lines.push(`#### Adversarial Prompt Sent to Target`);
    lines.push(formatCodeBlock(t.prompt, 'text'));
    lines.push(``);

    lines.push(`#### Actual Target Response`);
    lines.push(formatCodeBlock(t.actualResponse, 'text'));
    lines.push(``);

    lines.push(`#### Evaluation Evidence & Explanation`);
    lines.push(`> **Evidence**: ${escapeMarkdownQuote(t.evidence)}  `);
    lines.push(`> **Explanation**: ${escapeMarkdownQuote(t.explanation)}`);
    lines.push(``);
    lines.push(`---`);
    lines.push(``);
  });

  // 4. Inconclusive or Error Outcomes
  const issues = turns.filter((t) => t.verdict === 'ERROR' || t.verdict === 'INCONCLUSIVE');
  lines.push(`## 4. Execution Issues & Inconclusive Outcomes`);
  lines.push(``);
  if (issues.length === 0) {
    lines.push(`*No execution errors or inconclusive turns were recorded during this campaign.*`);
  } else {
    lines.push(`| Turn | Verdict | Target Status | Error / Issue Detail |`);
    lines.push(`|:---:|:---:|:---|:---|`);
    for (const issue of issues) {
      lines.push(
        `| ${issue.turnNumber} | **${issue.verdict}** | \`${issue.targetExecution.status}\` | ${escapeMarkdownQuote(issue.explanation || issue.targetExecution.error)} |`
      );
    }
  }
  lines.push(``);

  // 5. Methodology & Disclaimers
  lines.push(`## 5. Methodology & Disclaimers`);
  lines.push(``);
  lines.push(`> [!NOTE]`);
  lines.push(`> ${disclaimer}`);
  lines.push(``);
  lines.push(`- **Deterministic Marker Evaluation**: Hardened refusal and explicit breach markers are validated deterministically.`);
  lines.push(`- **Synthetic Canary Verification**: Canary tokens are synthetic values configured for this defensive test and should never be disclosed.`);
  lines.push(`- **In-Memory Retention**: ${storageNotice}`);
  lines.push(``);

  return {
    filename: `vibesec-campaign-${canonical.runId}.md`,
    mimeType: 'text/markdown',
    content: lines.join('\n')
  };
}

module.exports = {
  CANONICAL_CAMPAIGN_REPORT_SCHEMA_VERSION,
  sanitizeUrl,
  scrubSensitiveText,
  formatCodeBlock,
  buildCanonicalCampaignReport,
  generateCampaignJsonReport,
  generateCampaignMarkdownReport
};
