/**
 * VibeSec Canonical Benchmark Report & Exporter (v1.0.0)
 * Generates canonical, sanitized, evidence-backed reports in JSON and Markdown formats.
 */

const { getBenchmarkHistory } = require('./benchmarkRunner');
const { BENCHMARK_TEST_CASES } = require('./benchmarkSuite');

const CANONICAL_REPORT_SCHEMA_VERSION = '1.0.0';

/**
 * Sanitizes target URLs by stripping or masking sensitive query parameters and credentials.
 * @param {string} urlString
 * @returns {string}
 */
/**
 * Sanitizes target URLs by stripping or masking sensitive query parameters and credentials.
 * Handles both plain and encoded query parameters, as well as URL user-info.
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
        // ignore malformed percent encoding
      }

      if (sensitiveKeys.has(lower) || sensitiveKeys.has(decodedLower)) {
        parsed.searchParams.set(param, '[REDACTED]');
      }
    }

    if (parsed.username) {
      parsed.username = '[REDACTED]';
    }
    if (parsed.password) {
      parsed.password = '[REDACTED]';
    }
    return parsed.toString().replaceAll('%5BREDACTED%5D', '[REDACTED]');
  } catch {
    // If not a full URL or relative, apply strict regex redactions
    return urlString
      .replace(/:\/\/([^:@\s]+):([^@\s]+)@/g, '://[REDACTED]:[REDACTED]@')
      .replace(/(api[_-]?key|apikey|token|key|secret|password|auth|bearer|jwt)=([^&]+)/gi, '$1=[REDACTED]');
  }
}

/**
 * Scrubs known secrets, tokens, and authorization patterns from error messages and logs.
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
  // Mask authorization headers or bearer tokens appearing in raw error strings
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
 * @param {object} target
 * @returns {object}
 */
function sanitizeTargetDetails(target) {
  if (!target || typeof target !== 'object') {
    return { mode: 'mock' };
  }

  const sanitized = {
    url: sanitizeUrl(target.url),
    method: target.method || 'POST',
    inputPath: target.inputPath || 'message',
    responsePath: target.responsePath || 'reply'
  };

  // Explicitly guarantee no authorization or header objects are included
  return sanitized;
}

/**
 * Generates a safe, OS-compatible filename derived from report metadata.
 * @param {object} report
 * @param {'json' | 'md'} extension
 * @returns {string}
 */
function getSafeExportFilename(report, extension = 'json') {
  const runId = String(report.runId || 'run')
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .slice(0, 40);
  const benchmarkId = String(report.benchmark?.id || 'vibesec-benchmark')
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .slice(0, 30);
  const dateStr = report.startedAt
    ? String(report.startedAt).replace(/[:.]/g, '-').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20)
    : Date.now().toString();
  const safeExt = extension.toLowerCase() === 'md' ? 'md' : 'json';
  return `${benchmarkId}_${runId}_${dateStr}.${safeExt}`;
}

/**
 * Validates and transforms a raw benchmark report into the canonical VibeSec report representation.
 * @param {object} rawReport
 * @returns {object} Canonical report
 */
function buildCanonicalReport(rawReport) {
  if (!rawReport || typeof rawReport !== 'object') {
    throw new Error('Invalid report: report object is required.');
  }

  if (!rawReport.runId || typeof rawReport.runId !== 'string') {
    throw new Error('Invalid report: runId is required and must be a string.');
  }

  if (!Array.isArray(rawReport.results)) {
    throw new Error('Invalid report: results array is required.');
  }

  const canarySecret = rawReport.canarySecret || null;
  const testCaseDefaults = new Map(BENCHMARK_TEST_CASES.map((tc) => [tc.id, tc]));

  const results = rawReport.results.map((r, idx) => {
    const defaultTc = testCaseDefaults.get(r.testId) || {};
    const rawError = r.targetExecution?.error || null;
    const sanitizedError = scrubSensitiveText(rawError, canarySecret);
    const sanitizedEvidence = scrubSensitiveText(r.evidence, canarySecret);
    const sanitizedExplanation = scrubSensitiveText(r.explanation, canarySecret);

    return {
      testId: r.testId || `test_${idx + 1}`,
      benchmarkVersion: r.benchmarkVersion || rawReport.benchmark?.version || '1.0.0',
      category: r.category || defaultTc.category || 'General Security',
      name: r.name || defaultTc.name || r.testId || `Test ${idx + 1}`,
      attackInput: r.attackInput || defaultTc.prompt || '',
      securityRequirement: r.securityRequirement || defaultTc.securityRequirement || '',
      evaluationStrategy: r.evaluationStrategy || defaultTc.evaluationStrategy || 'contextual_ai',
      actualResponse: r.actualResponse ?? null,
      targetExecution: {
        status: r.targetExecution?.status || 'UNKNOWN',
        httpStatus: r.targetExecution?.httpStatus ?? 0,
        responseTimeMs: r.targetExecution?.responseTimeMs ?? 0,
        provenance: r.targetExecution?.provenance || 'unknown',
        fixtureNotice: r.targetExecution?.fixtureNotice || null,
        error: sanitizedError
      },
      canaryDetection: {
        canaryConfigured: Boolean(r.canaryDetection?.canaryConfigured),
        detected: Boolean(r.canaryDetection?.detected),
        evidence: r.canaryDetection?.evidence || null
      },
      verdict: ['PASS', 'FAIL', 'INCONCLUSIVE', 'ERROR'].includes(r.verdict) ? r.verdict : 'ERROR',
      evidence: sanitizedEvidence || 'No evidence recorded.',
      explanation: sanitizedExplanation || 'No explanation provided.',
      evaluator: r.evaluator || 'contextual_ai',
      timing: {
        targetDurationMs: r.timing?.targetDurationMs ?? 0,
        evalDurationMs: r.timing?.evalDurationMs ?? 0,
        totalDurationMs: r.timing?.totalDurationMs ?? 0
      }
    };
  });

  const totalTests = results.length;
  let passCount = 0;
  let failCount = 0;
  let inconclusiveCount = 0;
  let errorCount = 0;
  let abortedCount = 0;
  let completedCount = 0;

  for (const r of results) {
    if (r.targetExecution?.status === 'TIMEOUT_ABORT') {
      abortedCount++;
    } else {
      completedCount++;
    }

    if (r.verdict === 'PASS') passCount++;
    else if (r.verdict === 'FAIL') failCount++;
    else if (r.verdict === 'INCONCLUSIVE') inconclusiveCount++;
    else if (r.verdict === 'ERROR') errorCount++;
  }

  const rawFailureRate = totalTests > 0 ? Number(((failCount / totalTests) * 100).toFixed(1)) : 0;
  const evaluatedCount = passCount + failCount;
  const evaluatedFailureRate =
    evaluatedCount > 0 ? Number(((failCount / evaluatedCount) * 100).toFixed(1)) : 0;

  const failureRateDenominator = totalTests > 0
    ? `totalTests (${totalTests})`
    : `totalTests (0 - no tests executed)`;
  const evaluatedFailureRateDenominator =
    evaluatedCount > 0
      ? `pass + fail (${evaluatedCount})`
      : `pass + fail (0 - no definitive evaluations)`;

  const disclaimer =
    rawReport.disclaimer ||
    rawReport.benchmark?.disclaimer ||
    'Passing this benchmark does not prove that an application is secure. It demonstrates resilience against tested adversarial vectors under specific evaluation constraints.';

  const isEarlyTerminated = Boolean(rawReport.executionLimits?.earlyTermination);
  const plannedTotal = rawReport.executionLimits?.maxTests || totalTests;

  const documentation = isEarlyTerminated
    ? `Early termination occurred (${abortedCount} tests aborted). Raw failure rate (${rawFailureRate}%) is fail / totalTests; aborted tests are recorded as ERROR. Evaluated failure rate (${evaluatedFailureRate}%) is calculated strictly over definitive evaluated tests (pass + fail = ${evaluatedCount}), excluding INCONCLUSIVE (${inconclusiveCount}) and ERROR (${errorCount}). PASS does not guarantee security.`
    : `Failure rate is calculated as failCount / totalTests (${rawFailureRate}%). Evaluated failure rate (${evaluatedFailureRate}%) is calculated strictly from definitive results (pass + fail = ${evaluatedCount}), excluding INCONCLUSIVE (${inconclusiveCount}) and ERROR (${errorCount}). Inconclusive and error tests are explicitly tracked and never silently count as pass. PASS does not guarantee security.`;

  // Preserve and harden category breakdown
  const categoryBreakdown = {};
  if (rawReport.categoryBreakdown && typeof rawReport.categoryBreakdown === 'object') {
    for (const [k, v] of Object.entries(rawReport.categoryBreakdown)) {
      const catTotal = v.total || 0;
      const catPass = v.pass || 0;
      const catFail = v.fail || 0;
      const catInconc = v.inconclusive || 0;
      const catErr = v.error || 0;
      const catEval = catPass + catFail;
      categoryBreakdown[k] = {
        total: catTotal,
        pass: catPass,
        fail: catFail,
        inconclusive: catInconc,
        error: catErr,
        failureRatePercent: catTotal > 0 ? Number(((catFail / catTotal) * 100).toFixed(1)) : 0,
        evaluatedFailureRatePercent: catEval > 0 ? Number(((catFail / catEval) * 100).toFixed(1)) : 0,
        evaluatedDenominator: catEval > 0 ? `pass + fail (${catEval})` : 'pass + fail (0 - no definitive evaluations)'
      };
    }
  }

  const canonical = {
    reportSchemaVersion: CANONICAL_REPORT_SCHEMA_VERSION,
    runId: rawReport.runId,
    startedAt: rawReport.startedAt || new Date().toISOString(),
    completedAt: rawReport.completedAt || new Date().toISOString(),
    totalDurationMs: rawReport.totalDurationMs ?? 0,
    mode: rawReport.mode === 'mock' ? 'mock' : 'live',
    benchmark: {
      id: rawReport.benchmark?.id || 'vibesec-core',
      name: rawReport.benchmark?.name || 'VibeSec Core Security Benchmark',
      version: rawReport.benchmark?.version || '1.0.0',
      disclaimer
    },
    target: sanitizeTargetDetails(rawReport.target),
    targetModel: rawReport.targetModel || (rawReport.mode === 'mock' ? 'mock_assistant' : 'external_target'),
    evaluatorModel: rawReport.evaluatorModel || 'gemini-2.5-flash',
    totalTests,
    summary: {
      plannedTotal,
      completedTests: completedCount,
      abortedTests: abortedCount,
      pass: passCount,
      fail: failCount,
      inconclusive: inconclusiveCount,
      error: errorCount,
      failureRatePercent: rawFailureRate,
      failureRateDenominator,
      evaluatedFailureRatePercent: evaluatedFailureRate,
      evaluatedFailureRateDenominator,
      documentation
    },
    categoryBreakdown,
    executionLimits: {
      maxTests: plannedTotal,
      maxTotalDurationMs: rawReport.executionLimits?.maxTotalDurationMs || 60000,
      earlyTermination: isEarlyTerminated,
      terminationReason: rawReport.executionLimits?.terminationReason || null,
      abortedCount,
      completedCount
    },
    disclaimer,
    results
  };

  return canonical;
}

/**
 * Returns a completed benchmark run by runId from in-memory history.
 * @param {string} runId
 * @returns {object|null}
 */
function getRunById(runId) {
  if (!runId || typeof runId !== 'string') return null;
  const history = getBenchmarkHistory();
  return history.find((r) => r.runId === runId) || null;
}

/**
 * Formats a code block with adaptive fence backticks to prevent untrusted content breakout.
 * @param {any} content
 * @param {string} [language='text']
 * @returns {string}
 */
function formatCodeBlock(content, language = 'text') {
  if (content === null || content === undefined || content === '') {
    return '*(Empty response)*';
  }
  const str = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
  const matches = str.match(/`+/g) || [];
  const maxBackticks = matches.reduce((max, cur) => Math.max(max, cur.length), 0);
  const fence = '`'.repeat(Math.max(3, maxBackticks + 1));
  return `${fence}${language}\n${str}\n${fence}`;
}

/**
 * Sanitizes a string for use in Markdown table cells by escaping pipes, HTML tags, and line breaks.
 * @param {string} str
 * @returns {string}
 */
function sanitizeTableCell(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .trim();
}

/**
 * Escapes blockquote contents to prevent forged Markdown headings or section breakout.
 * @param {string} str
 * @returns {string}
 */
function escapeMarkdownQuote(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/\r?\n/g, '\n> ')
    .replace(/(^|\n> )[ \t]*#/g, '$1\\#')
    .replace(/(^|\n> )[ \t]*\|/g, '$1\\|');
}

/**
 * Escapes inline strings against markdown formatting breakout.
 * @param {string} str
 * @returns {string}
 */
function escapeMarkdownInline(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/\r?\n/g, ' ')
    .replace(/#/g, '\\#')
    .replace(/`/g, '\\`');
}

/**
 * Generates downloadable JSON report content and safe filename.
 * @param {object} reportOrRunId
 * @returns {{ content: string, filename: string, mimeType: string }}
 */
function generateJsonReport(reportOrRunId) {
  const report = typeof reportOrRunId === 'string' ? getRunById(reportOrRunId) : reportOrRunId;
  if (!report) {
    throw new Error('Benchmark report not found.');
  }

  const canonical = buildCanonicalReport(report);
  const content = JSON.stringify(canonical, null, 2);
  const filename = getSafeExportFilename(canonical, 'json');

  return {
    content,
    filename,
    mimeType: 'application/json'
  };
}

/**
 * Generates downloadable Markdown report content and safe filename.
 * @param {object} reportOrRunId
 * @returns {{ content: string, filename: string, mimeType: string }}
 */
function generateMarkdownReport(reportOrRunId) {
  const report = typeof reportOrRunId === 'string' ? getRunById(reportOrRunId) : reportOrRunId;
  if (!report) {
    throw new Error('Benchmark report not found.');
  }

  const canonical = buildCanonicalReport(report);
  const filename = getSafeExportFilename(canonical, 'md');

  const {
    runId,
    startedAt,
    completedAt,
    totalDurationMs,
    mode,
    benchmark,
    target,
    targetModel,
    evaluatorModel,
    totalTests,
    summary,
    categoryBreakdown,
    executionLimits,
    results,
    disclaimer
  } = canonical;

  const lines = [];

  lines.push(`# VibeSec Security Evaluation Benchmark Report`);
  lines.push(``);
  lines.push(`> **Run ID**: \`${runId}\`  `);
  lines.push(`> **Generated At**: \`${new Date().toISOString()}\`  `);
  lines.push(`> **Schema Version**: \`${CANONICAL_REPORT_SCHEMA_VERSION}\``);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // 1. Executive Summary
  lines.push(`## 1. Executive Summary`);
  lines.push(``);
  if (executionLimits?.earlyTermination) {
    lines.push(`> [!WARNING]`);
    lines.push(
      `> **Early Termination Notice**: This run terminated early before completing all tests (${executionLimits.terminationReason || 'Time/Test limit reached'}). Aborted tests are recorded as ERROR.`
    );
    lines.push(``);
  }
  lines.push(`- **Benchmark Suite**: ${benchmark.name} (\`${benchmark.id}\` v${benchmark.version})`);
  lines.push(`- **Execution Mode**: \`${mode.toUpperCase()}\``);
  lines.push(`- **Started At**: \`${startedAt}\``);
  lines.push(`- **Completed At**: \`${completedAt}\` (${totalDurationMs} ms total duration)`);
  lines.push(`- **Target URL**: \`${target.url || 'Mock Target'}\` (${target.method})`);
  lines.push(`- **Target Model Identifier**: \`${targetModel}\``);
  lines.push(`- **Evaluator Model Identifier**: \`${evaluatorModel}\``);
  lines.push(``);

  // Verdict Summary Table
  lines.push(`### Aggregate Verdicts`);
  lines.push(``);
  lines.push(`| Verdict | Count | Proportion | Meaning |`);
  lines.push(`|:---|:---:|:---:|:---|`);
  lines.push(
    `| **PASS** | **${summary.pass}** | ${totalTests > 0 ? ((summary.pass / totalTests) * 100).toFixed(1) : 0}% | Security violation was not demonstrated |`
  );
  lines.push(
    `| **FAIL** | **${summary.fail}** | ${totalTests > 0 ? ((summary.fail / totalTests) * 100).toFixed(1) : 0}% | Evidence confirms security violation |`
  );
  lines.push(
    `| **INCONCLUSIVE** | **${summary.inconclusive}** | ${totalTests > 0 ? ((summary.inconclusive / totalTests) * 100).toFixed(1) : 0}% | Ambiguous behavior / indeterminate response |`
  );
  lines.push(
    `| **ERROR** | **${summary.error}** | ${totalTests > 0 ? ((summary.error / totalTests) * 100).toFixed(1) : 0}% | Target timeout, HTTP 500, or invalid mapping |`
  );
  lines.push(`| **Total Tests** | **${totalTests}** | 100% | Executed test suite cases |`);
  lines.push(``);

  // Documented Failure Rates
  lines.push(`### Documented Failure Rates`);
  lines.push(``);
  lines.push(`- **Overall Failure Rate**: **${summary.failureRatePercent}%**`);
  lines.push(`  - **Formula**: \`failCount / totalTests\``);
  lines.push(`  - **Denominator**: ${summary.failureRateDenominator}`);
  lines.push(`- **Evaluated Failure Rate**: **${summary.evaluatedFailureRatePercent}%**`);
  lines.push(`  - **Formula**: \`failCount / (passCount + failCount)\``);
  lines.push(`  - **Denominator**: ${summary.evaluatedFailureRateDenominator}`);
  lines.push(`  - *Note: Inconclusive and error results are explicitly visible and never count as PASS.*`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // 2. Category-Level Results
  lines.push(`## 2. Category-Level Results`);
  lines.push(``);
  lines.push(`| Security Category | Total Tests | PASS | FAIL | INCONCLUSIVE | ERROR | Failure Rate |`);
  lines.push(`|:---|:---:|:---:|:---:|:---:|:---:|:---:|`);
  for (const [catName, catData] of Object.entries(categoryBreakdown)) {
    const catFailureRate = catData.failureRatePercent !== undefined ? `${catData.failureRatePercent}%` : 'N/A';
    lines.push(
      `| ${sanitizeTableCell(catName)} | ${catData.total} | ${catData.pass} | ${catData.fail} | ${catData.inconclusive} | ${catData.error} | ${catFailureRate} |`
    );
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // 3. Individual Test Findings & Evidence
  lines.push(`## 3. Individual Test Findings & Evidence`);
  lines.push(``);

  results.forEach((r, index) => {
    const verdictIcon =
      r.verdict === 'PASS'
        ? '✅ PASS'
        : r.verdict === 'FAIL'
          ? '❌ FAIL'
          : r.verdict === 'INCONCLUSIVE'
            ? '⚠️ INCONCLUSIVE'
            : '🛑 ERROR';

    lines.push(`### Test ${index + 1}: ${escapeMarkdownInline(r.name)} (\`${r.testId}\`)`);
    lines.push(``);
    lines.push(`- **Category**: ${escapeMarkdownInline(r.category)}`);
    lines.push(`- **Verdict**: **${verdictIcon}**`);
    lines.push(`- **Evaluation Strategy**: \`${r.evaluationStrategy}\``);
    lines.push(`- **Target Provenance**: \`${r.targetExecution?.provenance || 'unknown'}\``);
    lines.push(
      `- **HTTP Execution**: Status \`${r.targetExecution?.status}\` (${r.targetExecution?.httpStatus || 'N/A'}, ${r.targetExecution?.responseTimeMs || 0} ms)`
    );
    if (r.canaryDetection?.canaryConfigured) {
      lines.push(
        `- **Synthetic Canary Leak**: ${r.canaryDetection?.detected ? '**DETECTED! (VIOLATION)**' : 'Not detected'}`
      );
    }
    lines.push(`- **Security Requirement**: *${escapeMarkdownInline(r.securityRequirement)}*`);
    lines.push(``);

    lines.push(`#### Adversarial Attack Input`);
    lines.push(formatCodeBlock(r.attackInput, 'text'));
    lines.push(``);

    lines.push(`#### Actual Target Response`);
    lines.push(formatCodeBlock(r.actualResponse, 'text'));
    lines.push(``);

    lines.push(`#### Evaluation Evidence & Explanation`);
    lines.push(`> **Evidence**: ${escapeMarkdownQuote(r.evidence)}`);
    lines.push(`> `);
    lines.push(`> **Explanation**: ${escapeMarkdownQuote(r.explanation)}`);
    lines.push(``);
    lines.push(`---`);
    lines.push(``);
  });

  // 4. Execution Errors & Inconclusive Outcomes
  const issues = results.filter((r) => r.verdict === 'ERROR' || r.verdict === 'INCONCLUSIVE');
  lines.push(`## 4. Execution Errors & Inconclusive Outcomes`);
  lines.push(``);
  if (issues.length === 0) {
    lines.push(`*No execution errors or inconclusive verdicts occurred during this benchmark run.*`);
  } else {
    lines.push(`| Test ID | Verdict | Execution Status | Error / Issue Detail |`);
    lines.push(`|:---|:---:|:---|:---|`);
    for (const issue of issues) {
      const detail = issue.targetExecution?.error || issue.explanation || 'No error details recorded.';
      lines.push(
        `| \`${issue.testId}\` | **${issue.verdict}** | \`${issue.targetExecution?.status}\` | ${sanitizeTableCell(detail)} |`
      );
    }
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // 5. Scope Limitations & Benchmark Disclaimer
  lines.push(`## 5. Scope Limitations & Benchmark Disclaimer`);
  lines.push(``);
  lines.push(`> [!IMPORTANT]`);
  lines.push(`> **Security Disclaimer**: ${disclaimer}`);
  lines.push(`> `);
  lines.push(
    `> **Data Privacy Notice**: This report contains adversarial test prompts and real responses observed from the target AI endpoint during evaluation. Sensitive headers, authorization tokens, and credentials were automatically redacted. Arbitrary confidential secrets in raw target response bodies cannot be guaranteed to be fully identified or redacted without prior schema knowledge.`
  );
  lines.push(``);

  return {
    content: lines.join('\n'),
    filename,
    mimeType: 'text/markdown'
  };
}

module.exports = {
  CANONICAL_REPORT_SCHEMA_VERSION,
  sanitizeUrl,
  sanitizeTargetDetails,
  getSafeExportFilename,
  buildCanonicalReport,
  getRunById,
  generateJsonReport,
  generateMarkdownReport
};
