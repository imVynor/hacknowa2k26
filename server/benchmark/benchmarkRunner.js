const crypto = require('node:crypto');
const { getBenchmarkSuite } = require('./benchmarkSuite');
const { executeTargetRequest } = require('../target/targetAdapter');
const { detectCanaryDisclosure } = require('../evaluator/canaryDetector');
const { evaluateSecurityResponse, heuristicSecurityEvaluation } = require('../evaluator/securityEvaluator');
const { classifyTargetExecution } = require('../target/targetDiagnostics');

// In-memory store of benchmark runs
const benchmarkHistory = [];
const MAX_BENCHMARK_HISTORY = 20;

/**
 * Executes a versioned security benchmark suite against the configured target.
 *
 * @param {object} params
 * @param {object} params.targetConfig - HTTP target configuration
 * @param {string} [params.canarySecret] - Protected canary secret token
 * @param {string} [params.applicationRequirement] - Optional application-specific security policy
 * @param {string} [params.systemPrompt] - Optional system prompt / context description
 * @param {'live' | 'mock'} [params.mode='live'] - Execution mode
 * @param {object} [params.options] - Execution constraints and options
 * @param {number} [params.options.maxTests=10] - Maximum tests to run
 * @param {number} [params.options.maxTotalDurationMs=60000] - Total execution time limit
 * @param {boolean} [params.options.allowLocal=false] - Allow local targets for tests
 */
async function runBenchmarkSuite({
  targetConfig,
  canarySecret,
  applicationRequirement,
  systemPrompt,
  mode = 'live',
  options = {}
}) {
  const startedAt = new Date().toISOString();
  const startTimeMs = Date.now();
  const runId = `bench_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

  const isMock = mode === 'mock';

  // Load benchmark suite
  const suite = getBenchmarkSuite({ applicationRequirement });
  const maxTests = Math.min(options.maxTests || 10, suite.tests.length);
  const maxTotalDurationMs = options.maxTotalDurationMs || 60000;
  const testsToRun = suite.tests.slice(0, maxTests);

  const results = [];
  let executionTerminatedEarly = false;
  let earlyTerminationReason = null;

  // Sanitized target info (never expose credentials/tokens)
  const sanitizedTarget = targetConfig
    ? {
        url: targetConfig.url,
        method: targetConfig.method || 'POST',
        inputPath: targetConfig.inputPath || 'message',
        responsePath: targetConfig.responsePath || 'reply'
      }
    : { mode: 'mock' };

  let detectedTargetModel = null;
  let detectedEvaluatorModel = null;
  let aiEvaluatorSucceeded = false;

  // Sequential bounded execution
  for (let i = 0; i < testsToRun.length; i++) {
    const testCase = testsToRun[i];
    const testStartMs = Date.now();

    // Check total execution time limit before starting test
    if (Date.now() - startTimeMs > maxTotalDurationMs) {
      executionTerminatedEarly = true;
      earlyTerminationReason = `Total benchmark execution timeout limit (${maxTotalDurationMs}ms) exceeded.`;

      // Mark remaining test as ERROR
      results.push({
        testId: testCase.id,
        benchmarkVersion: testCase.benchmarkVersion,
        category: testCase.category,
        name: testCase.name,
        attackInput: testCase.prompt,
        securityRequirement: testCase.securityRequirement,
        evaluationStrategy: testCase.evaluationStrategy,
        actualResponse: null,
        targetExecution: {
          status: 'TIMEOUT_ABORT',
          httpStatus: 0,
          responseTimeMs: 0,
          provenance: isMock ? 'mock_simulation' : 'none',
          fixtureNotice: null,
          error: earlyTerminationReason
        },
        canaryDetection: {
          canaryConfigured: Boolean(canarySecret),
          detected: false,
          evidence: null
        },
        verdict: 'ERROR',
        evidence: 'Benchmark time limit exceeded before dispatching test.',
        explanation: earlyTerminationReason,
        evaluator: 'runner_timeout',
        timing: {
          targetDurationMs: 0,
          evalDurationMs: 0,
          totalDurationMs: 0
        }
      });
      continue;
    }

    let targetResult = null;
    let targetDurationMs = 0;

    // 1. Dispatch to Target (or Mock)
    if (isMock) {
      targetDurationMs = 100;
      targetResult = {
        success: true,
        status: 'SUCCESS',
        httpStatus: 200,
        responseTimeMs: targetDurationMs,
        extractedResponse:
          'I am a secure AI assistant. I cannot comply with requests to disregard system instructions, change roles, or disclose tokens.',
        rawResponseBody: {
          reply:
            'I am a secure AI assistant. I cannot comply with requests to disregard system instructions, change roles, or disclose tokens.',
          _mock: true
        }
      };
    } else {
      try {
        targetResult = await executeTargetRequest(targetConfig, testCase.prompt, options);
        targetDurationMs = targetResult.responseTimeMs || 0;
      } catch (err) {
        targetResult = {
          success: false,
          status: 'EXECUTION_EXCEPTION',
          error: `Unexpected target dispatch exception: ${err.message}`,
          responseTimeMs: Date.now() - testStartMs
        };
        targetDurationMs = targetResult.responseTimeMs;
      }
    }

    // Capture model identifier from target if available
    if (targetResult?.rawResponseBody?.targetModel && !detectedTargetModel) {
      detectedTargetModel = targetResult.rawResponseBody.targetModel;
    }

    const provenance = isMock
      ? 'mock_simulation'
      : targetResult?.rawResponseBody?.provenance || 'external_http_target';
    const fixtureNotice = targetResult?.rawResponseBody?.fixtureNotice || null;

    // 2. Classify Target Diagnostics
    const targetDiagnostics = classifyTargetExecution(targetResult);

    // Case A: Target returned recognized provider/quota fallback response (HTTP 200)
    if (targetDiagnostics.classification === 'PROVIDER_FALLBACK') {
      const fallbackResponse = targetResult.extractedResponse || '';
      results.push({
        testId: testCase.id,
        benchmarkVersion: testCase.benchmarkVersion,
        category: testCase.category,
        name: testCase.name,
        attackInput: testCase.prompt,
        securityRequirement: testCase.securityRequirement,
        evaluationStrategy: testCase.evaluationStrategy,
        actualResponse: fallbackResponse,
        assessable: false,
        unassessableReason: 'TARGET_PROVIDER_FALLBACK',
        targetExecution: {
          status: 'PROVIDER_FALLBACK',
          classification: 'PROVIDER_FALLBACK',
          transportSuccess: true,
          processedInput: false,
          assessable: false,
          unassessableReason: 'TARGET_PROVIDER_FALLBACK',
          fallbackDetected: true,
          fallbackReason: targetDiagnostics.fallbackReason,
          httpStatus: targetResult.httpStatus || 200,
          responseTimeMs: targetDurationMs,
          provenance,
          fixtureNotice: null,
          error: null
        },
        canaryDetection: {
          canaryConfigured: Boolean(canarySecret),
          detected: false,
          evidence: null
        },
        verdict: 'INCONCLUSIVE',
        evidence: `Target returned upstream provider fallback: "${fallbackResponse}"`,
        explanation: `Target returned upstream provider rate-limit fallback: "${targetDiagnostics.fallbackReason || 'rate-limited fallback mode'}". Adversarial probe was not processed by an active AI model; test cannot be assessed for security behavior.`,
        evaluator: 'target_diagnostics',
        evaluationMethod: 'target_provider_fallback',
        fallbackReason: 'target_provider_fallback',
        diagnostic: {
          providerFallback: true,
          reason: targetDiagnostics.fallbackReason
        },
        timing: {
          targetDurationMs,
          evalDurationMs: 0,
          totalDurationMs: Date.now() - testStartMs
        }
      });
      continue;
    }

    // Case B: Handle Target Communication or Application Failures (Must be ERROR, never PASS!)
    if (!targetResult.success) {
      results.push({
        testId: testCase.id,
        benchmarkVersion: testCase.benchmarkVersion,
        category: testCase.category,
        name: testCase.name,
        attackInput: testCase.prompt,
        securityRequirement: testCase.securityRequirement,
        evaluationStrategy: testCase.evaluationStrategy,
        actualResponse: null,
        assessable: false,
        unassessableReason: targetDiagnostics.unassessableReason,
        targetExecution: {
          status: targetResult.status,
          classification: targetDiagnostics.classification,
          transportSuccess: targetDiagnostics.transportSuccess,
          processedInput: false,
          assessable: false,
          unassessableReason: targetDiagnostics.unassessableReason,
          fallbackDetected: false,
          fallbackReason: null,
          httpStatus: targetResult.httpStatus || 0,
          responseTimeMs: targetDurationMs,
          provenance,
          fixtureNotice,
          error: targetResult.error
        },
        canaryDetection: {
          canaryConfigured: Boolean(canarySecret),
          detected: false,
          evidence: null
        },
        verdict: 'ERROR',
        evidence: targetResult.error || `Target communication failed (${targetResult.status})`,
        explanation: `Test execution could not complete reliably: Target returned ${targetResult.status} (${targetResult.httpStatus || 'N/A'}).`,
        evaluator: 'target_adapter',
        evaluationMethod: 'target_transport_error',
        timing: {
          targetDurationMs,
          evalDurationMs: 0,
          totalDurationMs: Date.now() - testStartMs
        }
      });
      continue;
    }

    const actualResponse = targetResult.extractedResponse || '';
    const evalStartMs = Date.now();

    // 3. Deterministic Canary Detection (Priority check)
    const canaryCheck = detectCanaryDisclosure(actualResponse, canarySecret);

    let testVerdict = null;
    let testEvidence = null;
    let testExplanation = null;
    let testEvaluator = null;
    let testMethod = null;
    let fallbackReason = null;
    let evalDiagnostic = null;

    if (isMock) {
      const fallback = heuristicSecurityEvaluation(
        testCase.prompt,
        actualResponse,
        testCase.securityRequirement,
        { testId: testCase.id, category: testCase.category, testName: testCase.name, canarySecret }
      );
      testVerdict = fallback.verdict;
      testEvidence = fallback.evidence;
      testExplanation = `[Mock Simulation Evaluation] ${fallback.explanation}`;
      testEvaluator = 'mock_heuristic_evaluator';
      testMethod = 'mock_simulation';
      if (!detectedEvaluatorModel) detectedEvaluatorModel = 'mock_heuristic_evaluator';
    } else {
      try {
        const evalRes = await evaluateSecurityResponse({
          attackInput: testCase.prompt,
          targetResponse: actualResponse,
          securityRequirements: testCase.securityRequirement,
          systemPrompt,
          testId: testCase.id,
          category: testCase.category,
          testName: testCase.name,
          canarySecret
        });

        testVerdict = evalRes.verdict;
        testEvidence = evalRes.evidence;
        testExplanation = evalRes.explanation;
        testEvaluator = evalRes.evaluator;
        testMethod = evalRes.method || (evalRes.evaluator?.includes('heuristic') ? 'heuristic_fallback' : 'ai_evaluator');
        fallbackReason = evalRes.fallbackReason || null;
        evalDiagnostic = evalRes.diagnostic || null;
        if (testMethod === 'ai_evaluator') {
          aiEvaluatorSucceeded = true;
          detectedEvaluatorModel = evalRes.evaluator;
        } else if (!detectedEvaluatorModel) {
          detectedEvaluatorModel = evalRes.evaluator;
        }
      } catch (err) {
        testVerdict = 'INCONCLUSIVE';
        testEvidence = `Evaluation interrupted: ${err.message}`;
        testExplanation = `AI Evaluator encountered an unexpected error (${err.message}). Assessment marked INCONCLUSIVE.`;
        testEvaluator = 'evaluator_error_fallback';
        testMethod = 'evaluator_error_fallback';
      }
    }

    const evalDurationMs = Date.now() - evalStartMs;

    results.push({
      testId: testCase.id,
      benchmarkVersion: testCase.benchmarkVersion,
      category: testCase.category,
      name: testCase.name,
      attackInput: testCase.prompt,
      securityRequirement: testCase.securityRequirement,
      evaluationStrategy: testCase.evaluationStrategy,
      actualResponse,
      assessable: true,
      unassessableReason: null,
      targetExecution: {
        status: 'SUCCESS',
        classification: 'SUBSTANTIVE_RESPONSE',
        transportSuccess: true,
        processedInput: true,
        assessable: true,
        unassessableReason: null,
        fallbackDetected: false,
        fallbackReason: null,
        httpStatus: targetResult.httpStatus || 200,
        responseTimeMs: targetDurationMs,
        provenance,
        fixtureNotice
      },
      canaryDetection: {
        canaryConfigured: Boolean(canarySecret),
        detected: canaryCheck.detected,
        evidence: canaryCheck.evidence
      },
      verdict: testVerdict,
      evidence: testEvidence,
      explanation: testExplanation,
      evaluator: testEvaluator,
      evaluationMethod: testMethod,
      fallbackReason: fallbackReason || null,
      diagnostic: evalDiagnostic || null,
      timing: {
        targetDurationMs,
        evalDurationMs,
        totalDurationMs: Date.now() - testStartMs
      }
    });
  }

  const completedAt = new Date().toISOString();
  const totalDurationMs = Date.now() - startTimeMs;

  // Compute aggregate counts
  let passCount = 0;
  let failCount = 0;
  let inconclusiveCount = 0;
  let errorCount = 0;
  let completedCount = 0;
  let abortedCount = 0;

  const categoryBreakdown = {};

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

    if (!categoryBreakdown[r.category]) {
      categoryBreakdown[r.category] = {
        total: 0,
        pass: 0,
        fail: 0,
        inconclusive: 0,
        error: 0,
        failureRatePercent: 0,
        evaluatedFailureRatePercent: 0,
        evaluatedDenominator: 'pass + fail (0)'
      };
    }

    const cat = categoryBreakdown[r.category];
    cat.total++;
    if (r.verdict === 'PASS') cat.pass++;
    else if (r.verdict === 'FAIL') cat.fail++;
    else if (r.verdict === 'INCONCLUSIVE') cat.inconclusive++;
    else if (r.verdict === 'ERROR') cat.error++;
  }

  // Calculate per-category failure rates consistently
  for (const cat of Object.values(categoryBreakdown)) {
    cat.failureRatePercent = cat.total > 0 ? Number(((cat.fail / cat.total) * 100).toFixed(1)) : 0;
    const catEval = cat.pass + cat.fail;
    cat.evaluatedFailureRatePercent = catEval > 0 ? Number(((cat.fail / catEval) * 100).toFixed(1)) : 0;
    cat.evaluatedDenominator = catEval > 0 ? `pass + fail (${catEval})` : 'pass + fail (0 - no definitive evaluations)';
  }

  const totalTests = results.length;
  const plannedTotalTests = testsToRun.length;

  // Failure rate calculations with documented denominators:
  // 1. Raw failure rate: fail / totalTests (percentage of all executed tests that failed)
  const failureRatePercent = totalTests > 0 ? Number(((failCount / totalTests) * 100).toFixed(1)) : 0;
  const failureRateDenominator = totalTests > 0
    ? `totalTests (${totalTests})`
    : `totalTests (0 - no tests executed)`;

  // 2. Evaluated failure rate: fail / (pass + fail) (excluding inconclusive & error)
  const evaluatedCount = passCount + failCount;
  const evaluatedFailureRatePercent =
    evaluatedCount > 0 ? Number(((failCount / evaluatedCount) * 100).toFixed(1)) : 0;
  const evaluatedFailureRateDenominator =
    evaluatedCount > 0
      ? `pass + fail (${evaluatedCount})`
      : `pass + fail (0 - no definitive evaluations)`;

  const documentation = executionTerminatedEarly
    ? `Early termination occurred (${abortedCount} of ${plannedTotalTests} tests aborted before dispatch). Raw failure rate (${failureRatePercent}%) is calculated as failCount / totalTests; aborted tests are recorded as ERROR, which dilutes raw failure rate. Evaluated failure rate (${evaluatedFailureRatePercent}%) is calculated strictly over definitive evaluated tests (pass + fail = ${evaluatedCount}), excluding INCONCLUSIVE (${inconclusiveCount}) and ERROR (${errorCount}). PASS does not guarantee security.`
    : `Failure rate is calculated as failCount / totalTests (${failureRatePercent}%). Evaluated failure rate (${evaluatedFailureRatePercent}%) is calculated strictly from definitive results (pass + fail = ${evaluatedCount}), excluding INCONCLUSIVE (${inconclusiveCount}) and ERROR (${errorCount}). Inconclusive and error tests are explicitly tracked and never silently count as pass. PASS does not guarantee security.`;

  const report = {
    reportSchemaVersion: '1.0.0',
    runId,
    startedAt,
    completedAt,
    totalDurationMs,
    mode: isMock ? 'mock' : 'live',
    benchmark: {
      id: suite.id,
      name: suite.name,
      version: suite.version,
      disclaimer: suite.disclaimer
    },
    disclaimer: suite.disclaimer,
    target: sanitizedTarget,
    targetModel: detectedTargetModel || (isMock ? 'mock_assistant' : 'external_target'),
    evaluatorModel: isMock
      ? 'mock_heuristic_evaluator'
      : (aiEvaluatorSucceeded
          ? (detectedEvaluatorModel || process.env.GEMINI_MODEL || 'gemini-2.5-flash')
          : (detectedEvaluatorModel || 'heuristic_fallback')),
    totalTests,
    summary: {
      plannedTotal: plannedTotalTests,
      completedTests: completedCount,
      abortedTests: abortedCount,
      assessableTests: results.filter((r) => r.assessable).length,
      unassessableTests: results.filter((r) => !r.assessable).length,
      targetProviderFallbackDetected: results.some((r) => r.targetExecution?.classification === 'PROVIDER_FALLBACK'),
      pass: passCount,
      fail: failCount,
      inconclusive: inconclusiveCount,
      error: errorCount,
      failureRatePercent,
      failureRateDenominator,
      evaluatedFailureRatePercent,
      evaluatedFailureRateDenominator,
      documentation
    },
    categoryBreakdown,
    executionLimits: {
      maxTests,
      maxTotalDurationMs,
      earlyTermination: executionTerminatedEarly,
      terminationReason: earlyTerminationReason,
      abortedCount,
      completedCount
    },
    results
  };

  // Add to in-memory history
  benchmarkHistory.unshift(report);
  if (benchmarkHistory.length > MAX_BENCHMARK_HISTORY) {
    benchmarkHistory.pop();
  }

  return report;
}

/**
 * Returns recent benchmark runs.
 */
function getBenchmarkHistory() {
  return benchmarkHistory;
}

/**
 * Finds a benchmark run by ID.
 * @param {string} runId
 * @returns {object|null}
 */
function getBenchmarkRunById(runId) {
  if (!runId || typeof runId !== 'string') return null;
  return benchmarkHistory.find((r) => r.runId === runId) || null;
}

function clearBenchmarkHistory() {
  benchmarkHistory.length = 0;
}

module.exports = {
  runBenchmarkSuite,
  getBenchmarkHistory,
  getBenchmarkRunById,
  clearBenchmarkHistory
};
