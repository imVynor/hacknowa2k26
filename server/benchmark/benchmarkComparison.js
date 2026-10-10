/**
 * VibeSec Benchmark Comparison Engine (v1.0.0)
 * Evaluates differences, transitions, and compatibility between two completed benchmark runs.
 */

const { getRunById, buildCanonicalReport } = require('./benchmarkReport');

/**
 * Validates and classifies compatibility between baseline and comparison benchmark runs.
 *
 * @param {object} baseline - Canonical baseline report
 * @param {object} comparison - Canonical comparison report
 * @returns {{ status: 'comparable' | 'partially_comparable' | 'not_directly_comparable', reason: string, warnings: string[] }}
 */
function evaluateComparisonValidity(baseline, comparison) {
  const warnings = [];

  const baseSuite = baseline.benchmark || {};
  const compSuite = comparison.benchmark || {};

  const baseTarget = baseline.target || {};
  const compTarget = comparison.target || {};

  const baseModel = baseline.targetModel || '';
  const compModel = comparison.targetModel || '';

  const baseEvaluator = baseline.evaluatorModel || '';
  const compEvaluator = comparison.evaluatorModel || '';

  const baseVersion = baseSuite.version || '1.0.0';
  const compVersion = compSuite.version || '1.0.0';

  const baseSuiteId = baseSuite.id || 'vibesec-core';
  const compSuiteId = compSuite.id || 'vibesec-core';

  const baseMap = new Map((baseline.results || []).map((r) => [r.testId, r]));
  const compMap = new Map((comparison.results || []).map((r) => [r.testId, r]));

  const baseTestIds = new Set(baseMap.keys());
  const compTestIds = new Set(compMap.keys());

  const addedTestIds = [...compTestIds].filter((id) => !baseTestIds.has(id));
  const removedTestIds = [...baseTestIds].filter((id) => !compTestIds.has(id));

  // Detect test definition modifications for common test IDs
  const definitionChangedTests = [];
  for (const id of baseTestIds) {
    if (compTestIds.has(id)) {
      const bTest = baseMap.get(id);
      const cTest = compMap.get(id);
      const bAttack = (bTest.attackInput || '').trim();
      const cAttack = (cTest.attackInput || '').trim();
      const bReq = (bTest.securityRequirement || '').trim();
      const cReq = (cTest.securityRequirement || '').trim();

      const attackChanged = Boolean(bAttack && cAttack && bAttack !== cAttack);
      const reqChanged = Boolean(bReq && cReq && bReq !== cReq);
      const stratChanged = Boolean(
        bTest.evaluationStrategy &&
        cTest.evaluationStrategy &&
        bTest.evaluationStrategy !== cTest.evaluationStrategy
      );

      if (attackChanged || reqChanged || stratChanged) {
        definitionChangedTests.push({
          testId: id,
          name: cTest.name || bTest.name,
          attackChanged,
          reqChanged,
          stratChanged
        });
      }
    }
  }

  // Check 1: Incompatible benchmark suite IDs
  if (baseSuiteId !== compSuiteId) {
    return {
      status: 'not_directly_comparable',
      reason: `Mismatched benchmark suites: Baseline ran '${baseSuiteId}' while Comparison ran '${compSuiteId}'.`,
      warnings: [`Benchmark suite identifiers differ: '${baseSuiteId}' vs '${compSuiteId}'.`]
    };
  }

  // Check 2: Different benchmark suite versions
  if (baseVersion !== compVersion) {
    warnings.push(
      `Benchmark suite version difference detected: Baseline v${baseVersion} vs Comparison v${compVersion}.`
    );
    if (addedTestIds.length > 0) {
      warnings.push(`Tests added in v${compVersion}: ${addedTestIds.join(', ')}.`);
    }
    if (removedTestIds.length > 0) {
      warnings.push(`Tests removed in v${compVersion}: ${removedTestIds.join(', ')}.`);
    }

    return {
      status: 'not_directly_comparable',
      reason: `Incompatible benchmark versions: Baseline used v${baseVersion} while Comparison used v${compVersion} (${addedTestIds.length} added, ${removedTestIds.length} removed). Like-for-like score comparison is invalid.`,
      warnings
    };
  }

  // Check 3: Check early termination or incomplete execution
  const baseIncomplete = Boolean(baseline.executionLimits?.earlyTermination);
  const compIncomplete = Boolean(comparison.executionLimits?.earlyTermination);

  if (baseIncomplete || compIncomplete) {
    warnings.push(
      `One or both runs terminated early due to timeout or limits: Baseline=${baseIncomplete ? 'Early Termination' : 'Complete'}, Comparison=${compIncomplete ? 'Early Termination' : 'Complete'}.`
    );
  }

  // Check 4: Check target URL and model parity
  const targetUrlSame = (baseTarget.url || '').toLowerCase() === (compTarget.url || '').toLowerCase();
  const targetModelSame = baseModel.toLowerCase() === compModel.toLowerCase();

  if (!targetUrlSame) {
    warnings.push(
      `Targets differ: Baseline tested '${baseTarget.url || 'mock'}' while Comparison tested '${compTarget.url || 'mock'}'.`
    );
  }
  if (!targetModelSame && (baseModel || compModel)) {
    warnings.push(
      `Target models differ: Baseline was '${baseModel || 'unspecified'}' while Comparison was '${compModel || 'unspecified'}'.`
    );
  }

  // Check 5: Check evaluator model and evaluation method parity
  const evaluatorModelSame = baseEvaluator.toLowerCase() === compEvaluator.toLowerCase();
  if (!evaluatorModelSame && (baseEvaluator || compEvaluator)) {
    warnings.push(
      `Evaluator models differ: Baseline evaluated with '${baseEvaluator || 'unspecified'}' while Comparison evaluated with '${compEvaluator || 'unspecified'}'. AI evaluation criteria may diverge.`
    );
  }

  // Check 6: Check for test definition changes
  if (definitionChangedTests.length > 0) {
    warnings.push(
      `Test definitions modified for ${definitionChangedTests.length} test(s) (${definitionChangedTests.map((t) => t.testId).join(', ')}). Attack input or security requirements differ between runs.`
    );
  }

  // If any differences were detected in target, model, evaluator, or completeness, classify as partially comparable
  const isPartiallyComparable =
    baseIncomplete ||
    compIncomplete ||
    !targetUrlSame ||
    !targetModelSame ||
    !evaluatorModelSame;

  if (isPartiallyComparable) {
    const reasons = [];
    if (!targetUrlSame || !targetModelSame) reasons.push('different target endpoints or models');
    if (!evaluatorModelSame) reasons.push('different evaluator models');
    if (baseIncomplete || compIncomplete) reasons.push('early termination / incomplete execution');

    return {
      status: 'partially_comparable',
      reason: `Partially comparable: Runs share benchmark suite '${baseSuiteId}' v${baseVersion}, but differ in ${reasons.join(', ')}. Direct like-for-like comparison has limitations.`,
      warnings
    };
  }

  // All checks match
  return {
    status: 'comparable',
    reason: `Directly comparable: Both runs evaluated the same target endpoint ('${baseTarget.url || 'mock'}') using identical benchmark suite '${baseSuiteId}' v${baseVersion} and matching evaluator model '${baseEvaluator || 'standard'}'.`,
    warnings
  };
}

/**
 * Compares two completed benchmark runs.
 *
 * @param {object|string} baselineRef - Baseline runId or canonical report object
 * @param {object|string} comparisonRef - Comparison runId or canonical report object
 * @returns {object} Detailed benchmark comparison result
 */
function compareBenchmarkRuns(baselineRef, comparisonRef) {
  const rawBaseline = typeof baselineRef === 'string' ? getRunById(baselineRef) : baselineRef;
  if (!rawBaseline) {
    throw new Error(
      `Baseline benchmark run '${typeof baselineRef === 'string' ? baselineRef : 'undefined'}' not found in history.`
    );
  }

  const rawComparison = typeof comparisonRef === 'string' ? getRunById(comparisonRef) : comparisonRef;
  if (!rawComparison) {
    throw new Error(
      `Comparison benchmark run '${typeof comparisonRef === 'string' ? comparisonRef : 'undefined'}' not found in history.`
    );
  }

  const baseline = buildCanonicalReport(rawBaseline);
  const comparison = buildCanonicalReport(rawComparison);

  // 1. Evaluate comparison validity
  const validity = evaluateComparisonValidity(baseline, comparison);

  // 2. Aggregate metric deltas
  const totalTestsDelta = comparison.totalTests - baseline.totalTests;
  const passDelta = comparison.summary.pass - baseline.summary.pass;
  const failDelta = comparison.summary.fail - baseline.summary.fail;
  const inconclusiveDelta = comparison.summary.inconclusive - baseline.summary.inconclusive;
  const errorDelta = comparison.summary.error - baseline.summary.error;
  const failureRateDeltaPercent = Number(
    (comparison.summary.failureRatePercent - baseline.summary.failureRatePercent).toFixed(1)
  );
  const evaluatedFailureRateDeltaPercent = Number(
    (comparison.summary.evaluatedFailureRatePercent - baseline.summary.evaluatedFailureRatePercent).toFixed(1)
  );

  // 3. Map tests by stable test ID
  const baselineMap = new Map();
  for (const r of baseline.results || []) {
    baselineMap.set(r.testId, r);
  }

  const comparisonMap = new Map();
  for (const r of comparison.results || []) {
    comparisonMap.set(r.testId, r);
  }

  const allTestIds = new Set([...baselineMap.keys(), ...comparisonMap.keys()]);

  const transitions = [];
  const improvements = []; // FAIL -> PASS
  const regressions = []; // PASS -> FAIL, or other -> FAIL
  const newErrorsOrInconclusive = []; // -> ERROR or INCONCLUSIVE
  const addedTests = [];
  const removedTests = [];
  const definitionChangedTests = [];

  for (const testId of allTestIds) {
    const baseTest = baselineMap.get(testId);
    const compTest = comparisonMap.get(testId);

    // Added in comparison
    if (!baseTest && compTest) {
      addedTests.push({
        testId,
        name: compTest.name,
        category: compTest.category,
        comparisonVerdict: compTest.verdict
      });
      continue;
    }

    // Removed in comparison
    if (baseTest && !compTest) {
      removedTests.push({
        testId,
        name: baseTest.name,
        category: baseTest.category,
        baselineVerdict: baseTest.verdict
      });
      continue;
    }

    // Check definition change
    const bAttack = (baseTest.attackInput || '').trim();
    const cAttack = (compTest.attackInput || '').trim();
    const bReq = (baseTest.securityRequirement || '').trim();
    const cReq = (compTest.securityRequirement || '').trim();
    const attackChanged = Boolean(bAttack && cAttack && bAttack !== cAttack);
    const reqChanged = Boolean(bReq && cReq && bReq !== cReq);
    const stratChanged = Boolean(
      baseTest.evaluationStrategy &&
      compTest.evaluationStrategy &&
      baseTest.evaluationStrategy !== compTest.evaluationStrategy
    );
    const hasDefinitionChanged = attackChanged || reqChanged || stratChanged;

    if (hasDefinitionChanged) {
      definitionChangedTests.push({
        testId,
        name: compTest.name,
        category: compTest.category,
        attackChanged,
        reqChanged,
        stratChanged
      });
    }

    // Present in both: inspect verdict transition
    const baseVerdict = baseTest.verdict;
    const compVerdict = compTest.verdict;

    let transitionType = 'UNCHANGED';
    let explanation = `Verdict remained ${baseVerdict}.`;

    if (baseVerdict === 'FAIL' && compVerdict === 'PASS') {
      transitionType = 'IMPROVED';
      explanation =
        'Security finding resolved: Test changed from FAIL to PASS for the evaluated vector. Note: This demonstrates vector resolution, not absolute proof of complete remediation.';
      improvements.push({
        testId,
        name: compTest.name,
        category: compTest.category,
        baselineVerdict: baseVerdict,
        comparisonVerdict: compVerdict
      });
    } else if (baseVerdict === 'PASS' && compVerdict === 'FAIL') {
      transitionType = 'REGRESSED';
      explanation = 'Security regression introduced: Test changed from PASS to FAIL.';
      regressions.push({
        testId,
        name: compTest.name,
        category: compTest.category,
        baselineVerdict: baseVerdict,
        comparisonVerdict: compVerdict,
        evidence: compTest.evidence
      });
    } else if (baseVerdict !== 'FAIL' && compVerdict === 'FAIL') {
      transitionType = 'REGRESSED';
      explanation = `Vulnerability demonstrated: Test transitioned from ${baseVerdict} to FAIL.`;
      regressions.push({
        testId,
        name: compTest.name,
        category: compTest.category,
        baselineVerdict: baseVerdict,
        comparisonVerdict: compVerdict,
        evidence: compTest.evidence
      });
    } else if (compVerdict === 'ERROR') {
      if (baseVerdict === 'ERROR') {
        transitionType = 'UNCHANGED_ERROR';
        explanation = 'Test execution errored in both runs.';
      } else {
        transitionType = 'ERROR_INTRODUCED';
        explanation = `Execution failure introduced: Test transitioned from ${baseVerdict} to ERROR. This is an execution failure, NOT proof of remediation.`;
        newErrorsOrInconclusive.push({
          testId,
          name: compTest.name,
          category: compTest.category,
          baselineVerdict: baseVerdict,
          comparisonVerdict: compVerdict,
          reason: compTest.targetExecution?.error || compTest.explanation
        });
      }
    } else if (compVerdict === 'INCONCLUSIVE') {
      if (baseVerdict === 'INCONCLUSIVE') {
        transitionType = 'UNCHANGED_INCONCLUSIVE';
        explanation = 'Evaluation remained inconclusive in both runs.';
      } else {
        transitionType = 'INCONCLUSIVE_INTRODUCED';
        explanation = `Ambiguity introduced: Test transitioned from ${baseVerdict} to INCONCLUSIVE. This is indeterminate behavior, NOT proof of remediation.`;
        newErrorsOrInconclusive.push({
          testId,
          name: compTest.name,
          category: compTest.category,
          baselineVerdict: baseVerdict,
          comparisonVerdict: compVerdict
        });
      }
    } else if (baseVerdict === 'ERROR' && compVerdict === 'PASS') {
      transitionType = 'RESOLVED_ERROR';
      explanation = 'Execution error resolved to clean PASS. Note: PASS does not guarantee immunity.';
    } else if (baseVerdict === 'INCONCLUSIVE' && compVerdict === 'PASS') {
      transitionType = 'RESOLVED_INCONCLUSIVE';
      explanation = 'Inconclusive verdict resolved to clean PASS. Note: PASS does not guarantee immunity.';
    }

    if (hasDefinitionChanged) {
      explanation = `[Note: Test definition was modified between runs] ${explanation}`;
    }

    transitions.push({
      testId,
      name: compTest.name,
      category: compTest.category,
      baselineVerdict: baseVerdict,
      comparisonVerdict: compVerdict,
      transitionType,
      hasDefinitionChanged,
      explanation,
      baselineEvidence: baseTest.evidence,
      comparisonEvidence: compTest.evidence
    });
  }

  return {
    comparedAt: new Date().toISOString(),
    validity,
    baseline: {
      runId: baseline.runId,
      startedAt: baseline.startedAt,
      benchmark: baseline.benchmark,
      target: baseline.target,
      targetModel: baseline.targetModel,
      evaluatorModel: baseline.evaluatorModel,
      summary: baseline.summary
    },
    comparison: {
      runId: comparison.runId,
      startedAt: comparison.startedAt,
      benchmark: comparison.benchmark,
      target: comparison.target,
      targetModel: comparison.targetModel,
      evaluatorModel: comparison.evaluatorModel,
      summary: comparison.summary
    },
    metricsDelta: {
      totalTestsDelta,
      passDelta,
      failDelta,
      inconclusiveDelta,
      errorDelta,
      failureRateDeltaPercent,
      evaluatedFailureRateDeltaPercent
    },
    transitions,
    highlights: {
      regressionsCount: regressions.length,
      improvementsCount: improvements.length,
      newErrorsCount: newErrorsOrInconclusive.length,
      regressions,
      improvements,
      newErrorsOrInconclusive
    },
    versionDiff: {
      addedCount: addedTests.length,
      removedCount: removedTests.length,
      definitionChangedCount: definitionChangedTests.length,
      addedTests,
      removedTests,
      definitionChangedTests
    }
  };
}

module.exports = {
  evaluateComparisonValidity,
  compareBenchmarkRuns
};
