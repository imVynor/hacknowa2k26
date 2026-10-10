require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { GoogleGenAI } = require('@google/genai');

const { executeTargetRequest } = require('./target/targetAdapter');
const {
  runExperiment,
  getRunHistory,
  clearRunHistory,
  ATTACK_PRESETS,
  TARGET_SCHEMA_PRESETS
} = require('./experiment/experimentEngine');
const { getBenchmarkSuite } = require('./benchmark/benchmarkSuite');
const {
  runBenchmarkSuite,
  getBenchmarkHistory,
  getBenchmarkRunById,
  clearBenchmarkHistory
} = require('./benchmark/benchmarkRunner');
const {
  buildCanonicalReport,
  getRunById,
  generateJsonReport,
  generateMarkdownReport
} = require('./benchmark/benchmarkReport');
const { compareBenchmarkRuns } = require('./benchmark/benchmarkComparison');
const {
  getCampaignDefinitions,
  getCampaignById,
  CAMPAIGN_SUITE_METADATA
} = require('./campaign/campaignSuite');
const {
  runCampaign,
  recordCampaignRun,
  getCampaignHistory,
  getCampaignRunById,
  clearCampaignHistory
} = require('./campaign/campaignRunner');
const {
  getAdaptiveStrategies,
  STRATEGY_LIBRARY_METADATA
} = require('./campaign/adaptiveStrategy');
const {
  runAdaptiveCampaign,
  ADAPTIVE_SERVER_LIMITS
} = require('./campaign/adaptiveRunner');
const {
  buildCanonicalCampaignReport,
  generateCampaignJsonReport,
  generateCampaignMarkdownReport
} = require('./campaign/campaignReport');
const { getProviderConfigurationStatus } = require('./evaluator/providerManager');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Root endpoint
app.get('/', (req, res) => {
  const hasKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim() !== '');
  res.json({
    message: 'VibeSec Server is running!',
    geminiKeyConfigured: hasKey,
    model: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
    endpoints: {
      health: 'GET /api/health',
      testGemini: 'GET /api/test-gemini',
      generate: 'POST /api/generate',
      testConnection: 'POST /api/target/test-connection',
      runExperiment: 'POST /api/experiment/run',
      experimentPresets: 'GET /api/experiment/presets',
      experimentHistory: 'GET /api/experiment/history',
      benchmarkSuite: 'GET /api/benchmark/suite',
      runBenchmark: 'POST /api/benchmark/run',
      benchmarkHistory: 'GET /api/benchmark/history',
      benchmarkReport: 'GET /api/benchmark/report/:runId',
      benchmarkExportJson: 'GET /api/benchmark/report/:runId/export/json',
      benchmarkExportMarkdown: 'GET /api/benchmark/report/:runId/export/markdown',
      benchmarkCompare: 'POST /api/benchmark/compare',
      campaignsList: 'GET /api/campaigns',
      campaignDetail: 'GET /api/campaigns/:campaignId',
      campaignRun: 'POST /api/campaigns/run',
      campaignHistory: 'GET /api/campaigns/history',
      campaignHistoryDetail: 'GET /api/campaigns/history/:runId',
      campaignExportJson: 'GET /api/campaigns/history/:runId/export/json',
      campaignExportMarkdown: 'GET /api/campaigns/history/:runId/export/markdown',
      campaignExportGeneral: 'POST /api/campaigns/export/:format',
      adaptiveStrategies: 'GET /api/campaigns/strategies',
      adaptiveCampaignRun: 'POST /api/campaigns/adaptive/run',
      demoReset: 'POST /api/demo/reset'
    }
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  const providerStatus = getProviderConfigurationStatus();
  res.json({
    status: 'ok',
    geminiConfigured: providerStatus.gemini.enabled,
    evaluatorProviders: providerStatus,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

/**
 * Development & Demo State Reset Endpoint
 * Safely clears in-memory run histories (experiment, benchmark, and campaign stores).
 * Strictly restricted to development or local test mode.
 */
app.post('/api/demo/reset', (req, res) => {
  const isDev = process.env.NODE_ENV !== 'production' || process.env.ALLOW_LOCAL_TARGETS === 'true';
  if (!isDev) {
    return res.status(403).json({
      success: false,
      error: 'Demo reset endpoint is only available in development or local test mode.'
    });
  }

  clearRunHistory();
  clearBenchmarkHistory();
  clearCampaignHistory();

  return res.json({
    success: true,
    message: 'In-memory demo state and run histories cleared successfully.',
    timestamp: new Date().toISOString()
  });
});

// Test Gemini API endpoint
app.get('/api/test-gemini', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey.trim() === '' || apiKey === 'your_gemini_api_key_here') {
    return res.status(400).json({
      success: false,
      error: 'GEMINI_API_KEY is missing or not configured in server/.env',
      help: 'Please set GEMINI_API_KEY=your_key in server/.env and restart the server.'
    });
  }

  const modelName = process.env.GEMINI_MODEL || 'gemini-2.5-flash';

  try {
    const ai = new GoogleGenAI({ apiKey });
    const startTime = Date.now();

    const response = await ai.models.generateContent({
      model: modelName,
      contents: 'Respond with: "Gemini API connection confirmed."'
    });

    const elapsed = Date.now() - startTime;

    return res.json({
      success: true,
      message: 'Gemini API call succeeded!',
      model: modelName,
      durationMs: elapsed,
      reply: response.text
    });
  } catch (error) {
    console.error('Error invoking Gemini API:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Gemini API call failed',
      details: error.statusText || error.code || 'Check console logs for details'
    });
  }
});

// Generic generation endpoint
app.post('/api/generate', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey.trim() === '') {
    return res.status(400).json({
      success: false,
      error: 'GEMINI_API_KEY is not configured in server/.env'
    });
  }

  const { prompt, systemInstruction, model } = req.body;
  if (!prompt) {
    return res.status(400).json({ success: false, error: 'prompt is required in request body' });
  }

  const modelName = model || process.env.GEMINI_MODEL || 'gemini-2.5-flash';

  try {
    const ai = new GoogleGenAI({ apiKey });
    const config = {};
    if (systemInstruction) {
      config.systemInstruction = systemInstruction;
    }

    const startTime = Date.now();
    const response = await ai.models.generateContent({
      model: modelName,
      contents: prompt,
      config: Object.keys(config).length > 0 ? config : undefined
    });

    const elapsed = Date.now() - startTime;

    return res.json({
      success: true,
      model: modelName,
      durationMs: elapsed,
      response: response.text
    });
  } catch (error) {
    console.error('Error in /api/generate:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Failed to generate content'
    });
  }
});

/**
 * Target Connection Test Endpoint
 * Sends a harmless baseline message to verify target connectivity and response extraction.
 */
app.post('/api/target/test-connection', async (req, res) => {
  const { targetConfig, baselineMessage } = req.body;

  if (!targetConfig) {
    return res.status(400).json({
      success: false,
      status: 'INVALID_CONFIG',
      error: 'targetConfig is required in request body.'
    });
  }

  const message =
    baselineMessage && typeof baselineMessage === 'string' && baselineMessage.trim() !== ''
      ? baselineMessage.trim()
      : 'Hello, this is a VibeSec connection verification test.';

  const result = await executeTargetRequest(targetConfig, message);

  if (result.status === 'SECURITY_VIOLATION') {
    return res.status(403).json(result);
  }
  if (result.status === 'INVALID_CONFIG') {
    return res.status(400).json(result);
  }

  return res.json(result);
});

/**
 * Experiment Presets Endpoint
 * Returns predefined attack cases and target schema templates.
 */
app.get('/api/experiment/presets', (req, res) => {
  res.json({
    attackPresets: ATTACK_PRESETS,
    targetPresets: TARGET_SCHEMA_PRESETS
  });
});

/**
 * Experiment Run Endpoint
 * Dispatches test case against external target, captures response, and evaluates security posture.
 */
app.post('/api/experiment/run', async (req, res) => {
  const {
    targetConfig,
    attackCase,
    securityRequirements,
    systemPrompt,
    canarySecret,
    mode = 'live'
  } = req.body;

  if (mode !== 'mock' && !targetConfig) {
    return res.status(400).json({
      success: false,
      error: 'targetConfig is required for live execution mode.'
    });
  }

  try {
    const experimentResult = await runExperiment({
      targetConfig,
      attackCase,
      securityRequirements,
      systemPrompt,
      canarySecret,
      mode
    });

    return res.json({
      success: true,
      experiment: experimentResult
    });
  } catch (error) {
    console.error('Error running experiment:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Experiment execution failed'
    });
  }
});

/**
 * Experiment History Endpoint
 * Returns recent test runs.
 */
app.get('/api/experiment/history', (req, res) => {
  res.json({
    runs: getRunHistory()
  });
});

/**
 * Benchmark Suite Metadata Endpoint
 */
app.get('/api/benchmark/suite', (req, res) => {
  const { applicationRequirement } = req.query;
  const suite = getBenchmarkSuite({ applicationRequirement });
  res.json({
    success: true,
    suite
  });
});

/**
 * Benchmark Run Endpoint
 * Executes the full benchmark suite against the target and produces an aggregate report.
 */
app.post('/api/benchmark/run', async (req, res) => {
  const {
    targetConfig,
    canarySecret,
    applicationRequirement,
    systemPrompt,
    mode = 'live',
    options = {},
    maxTests,
    maxTotalDurationMs
  } = req.body;

  if (mode !== 'mock') {
    if (!targetConfig) {
      return res.status(400).json({
        success: false,
        error: 'targetConfig is required for live benchmark execution mode.'
      });
    }

    if (targetConfig.ownershipAcknowledged !== true) {
      return res.status(400).json({
        success: false,
        error: 'Ownership authorization must be explicitly acknowledged before running benchmarks against an external target.'
      });
    }
  }

  const runnerOptions = {
    ...options,
    ...(maxTests ? { maxTests: Number(maxTests) } : {}),
    ...(maxTotalDurationMs ? { maxTotalDurationMs: Number(maxTotalDurationMs) } : {})
  };

  try {
    const report = await runBenchmarkSuite({
      targetConfig,
      canarySecret,
      applicationRequirement,
      systemPrompt,
      mode,
      options: runnerOptions
    });

    return res.json({
      success: true,
      report
    });
  } catch (error) {
    console.error('Error running benchmark suite:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Benchmark execution failed'
    });
  }
});

/**
 * Benchmark History Endpoint
 */
app.get('/api/benchmark/history', (req, res) => {
  const history = getBenchmarkHistory();
  res.json({
    success: true,
    history,
    runs: history
  });
});

/**
 * Benchmark Canonical Report Endpoint
 */
app.get('/api/benchmark/report/:runId', (req, res) => {
  const report = getRunById(req.params.runId);
  if (!report) {
    return res.status(404).json({
      success: false,
      error: `Benchmark run '${req.params.runId}' not found in history.`
    });
  }

  try {
    const canonical = buildCanonicalReport(report);
    return res.json({
      success: true,
      report: canonical
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Benchmark Export JSON Endpoint
 */
app.get('/api/benchmark/report/:runId/export/json', (req, res) => {
  try {
    const { content, filename } = generateJsonReport(req.params.runId);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(content);
  } catch (error) {
    return res.status(404).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Benchmark Export Markdown Endpoint
 */
app.get('/api/benchmark/report/:runId/export/markdown', (req, res) => {
  try {
    const { content, filename } = generateMarkdownReport(req.params.runId);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(content);
  } catch (error) {
    return res.status(404).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Benchmark General Export Endpoint (supports body payload or runId)
 */
app.post('/api/benchmark/export/:format', (req, res) => {
  const { format } = req.params;
  const { runId, report } = req.body || {};

  const targetReport = report || (runId ? getRunById(runId) : null);
  if (!targetReport) {
    return res.status(400).json({
      success: false,
      error: 'A valid report object or existing runId must be provided in request body.'
    });
  }

  try {
    const isMarkdown = format === 'markdown' || format === 'md';
    const exported = isMarkdown ? generateMarkdownReport(targetReport) : generateJsonReport(targetReport);

    if (req.query.download === 'true') {
      res.setHeader('Content-Type', exported.mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${exported.filename}"`);
      return res.send(exported.content);
    }

    return res.json({
      success: true,
      filename: exported.filename,
      mimeType: exported.mimeType,
      content: exported.content
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Benchmark Comparison Endpoint
 * Compares two completed benchmark runs by runId or report objects.
 */
app.post('/api/benchmark/compare', (req, res) => {
  const { baselineRunId, comparisonRunId, baselineReport, comparisonReport } = req.body || {};

  const baseline = baselineReport || (baselineRunId ? getRunById(baselineRunId) : null);
  const comparison = comparisonReport || (comparisonRunId ? getRunById(comparisonRunId) : null);

  if (!baseline) {
    return res.status(400).json({
      success: false,
      error: `Baseline run '${baselineRunId || 'undefined'}' not found in history.`
    });
  }

  if (!comparison) {
    return res.status(400).json({
      success: false,
      error: `Comparison run '${comparisonRunId || 'undefined'}' not found in history.`
    });
  }

  try {
    const comparisonResult = compareBenchmarkRuns(baseline, comparison);
    return res.json({
      success: true,
      comparison: comparisonResult
    });
  } catch (error) {
    console.error('Error comparing benchmark runs:', error);
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// ==========================================
// Multi-Turn Security Campaign Endpoints (Phase 4)
// ==========================================

/**
 * List available multi-turn campaign definitions
 */
app.get('/api/campaigns', (req, res) => {
  const { applicationRequirement } = req.query;
  const campaigns = getCampaignDefinitions({ applicationRequirement });
  res.json({
    success: true,
    metadata: CAMPAIGN_SUITE_METADATA,
    totalCampaigns: campaigns.length,
    campaigns
  });
});

/**
 * List campaign execution history (registered before :campaignId route)
 */
app.get('/api/campaigns/history', (req, res) => {
  const history = getCampaignHistory();
  res.json({
    success: true,
    totalRuns: history.length,
    history
  });
});

/**
 * Retrieve single campaign run from history
 */
app.get('/api/campaigns/history/:runId', (req, res) => {
  const { runId } = req.params;
  const run = getCampaignRunById(runId);

  if (!run) {
    return res.status(404).json({
      success: false,
      error: `Campaign run "${runId}" not found in history.`
    });
  }

  try {
    const canonical = buildCanonicalCampaignReport(run);
    return res.json({
      success: true,
      run: canonical
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * Export campaign run as JSON
 */
app.get('/api/campaigns/history/:runId/export/json', (req, res) => {
  const { runId } = req.params;
  const run = getCampaignRunById(runId);

  if (!run) {
    return res.status(404).json({
      success: false,
      error: `Campaign run "${runId}" not found in history.`
    });
  }

  try {
    const { content, filename } = generateCampaignJsonReport(run);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(content);
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * Export campaign run as Markdown
 */
app.get('/api/campaigns/history/:runId/export/markdown', (req, res) => {
  const { runId } = req.params;
  const run = getCampaignRunById(runId);

  if (!run) {
    return res.status(404).json({
      success: false,
      error: `Campaign run "${runId}" not found in history.`
    });
  }

  try {
    const { content, filename } = generateCampaignMarkdownReport(run);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(content);
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * Get available adaptive strategy library definitions and server resource bounds
 */
app.get('/api/campaigns/strategies', (req, res) => {
  try {
    const strategies = getAdaptiveStrategies();
    return res.json({
      success: true,
      library: STRATEGY_LIBRARY_METADATA,
      serverLimits: ADAPTIVE_SERVER_LIMITS,
      strategies
    });
  } catch (err) {
    console.error('Error getting adaptive strategies:', err);
    return res.status(500).json({
      success: false,
      error: `Failed to retrieve adaptive strategies: ${err.message}`
    });
  }
});

/**
 * Retrieve a specific campaign definition
 */
app.get('/api/campaigns/:campaignId', (req, res) => {
  const { campaignId } = req.params;
  const { applicationRequirement } = req.query;
  const campaign = getCampaignById(campaignId, { applicationRequirement });

  if (!campaign) {
    return res.status(404).json({
      success: false,
      error: `Campaign "${campaignId}" not found in suite.`
    });
  }

  res.json({
    success: true,
    campaign
  });
});

/**
 * Execute a multi-turn campaign against configured target
 */
app.post('/api/campaigns/run', async (req, res) => {
  const {
    campaignId,
    targetConfig,
    canarySecret,
    applicationRequirement,
    systemPrompt,
    mode = 'live',
    options = {}
  } = req.body || {};

  if (!campaignId || typeof campaignId !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Campaign ID string is required.'
    });
  }

  const campaign = getCampaignById(campaignId, { applicationRequirement });
  if (!campaign) {
    return res.status(404).json({
      success: false,
      error: `Campaign "${campaignId}" was not found.`
    });
  }

  if (mode !== 'mock') {
    if (!targetConfig || typeof targetConfig !== 'object') {
      return res.status(400).json({
        success: false,
        error: 'Target configuration object is required for live campaign execution.'
      });
    }

    if (targetConfig.ownershipAcknowledged !== true) {
      return res.status(400).json({
        success: false,
        error: 'Target ownership authorization must be acknowledged before executing security campaigns.'
      });
    }
  }

  try {
    const rawRun = await runCampaign({
      campaignId,
      targetConfig,
      canarySecret,
      applicationRequirement,
      systemPrompt,
      mode,
      options
    });

    const canonicalReport = buildCanonicalCampaignReport(rawRun, { canarySecret });

    return res.json({
      success: true,
      run: canonicalReport
    });
  } catch (err) {
    console.error('Error running campaign:', err);
    return res.status(500).json({
      success: false,
      error: `Campaign execution failed: ${err.message}`
    });
  }
});



/**
 * Execute an adaptive, response-driven security campaign against target
 */
app.post('/api/campaigns/adaptive/run', async (req, res) => {
  const {
    targetConfig,
    objective,
    applicationRequirement,
    canarySecret,
    mode = 'live',
    selectionMode = 'deterministic',
    maxTurns,
    maxTotalDurationMs,
    seed,
    options = {}
  } = req.body || {};

  if (mode !== 'mock') {
    if (!targetConfig || typeof targetConfig !== 'object') {
      return res.status(400).json({
        success: false,
        error: 'Target configuration object is required for live adaptive campaign execution.'
      });
    }

    if (targetConfig.ownershipAcknowledged !== true) {
      return res.status(400).json({
        success: false,
        error: 'Target ownership authorization must be acknowledged before executing security campaigns.'
      });
    }
  }

  try {
    const rawRun = await runAdaptiveCampaign({
      targetConfig,
      objective,
      applicationRequirement,
      canarySecret,
      mode,
      selectionMode,
      maxTurns,
      maxTotalDurationMs,
      seed,
      options
    });

    // Record in unified campaign history store
    recordCampaignRun(rawRun);

    const canonicalReport = buildCanonicalCampaignReport(rawRun, { canarySecret });

    return res.json({
      success: true,
      run: canonicalReport
    });
  } catch (err) {
    console.error('Error running adaptive campaign:', err);
    return res.status(500).json({
      success: false,
      error: `Adaptive campaign execution failed: ${err.message}`
    });
  }
});

/**
 * Export campaign run as JSON
 */
app.get('/api/campaigns/history/:runId/export/json', (req, res) => {
  const { runId } = req.params;
  const run = getCampaignRunById(runId);

  if (!run) {
    return res.status(404).json({
      success: false,
      error: `Campaign run "${runId}" not found in history.`
    });
  }

  try {
    const { content, filename } = generateCampaignJsonReport(run);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(content);
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * Export campaign run as Markdown
 */
app.get('/api/campaigns/history/:runId/export/markdown', (req, res) => {
  const { runId } = req.params;
  const run = getCampaignRunById(runId);

  if (!run) {
    return res.status(404).json({
      success: false,
      error: `Campaign run "${runId}" not found in history.`
    });
  }

  try {
    const { content, filename } = generateCampaignMarkdownReport(run);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(content);
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * General campaign export endpoint (supports request body report or runId)
 */
app.post('/api/campaigns/export/:format', (req, res) => {
  const { format } = req.params;
  const { runId, report } = req.body || {};

  const targetReport = report || (runId ? getCampaignRunById(runId) : null);
  if (!targetReport) {
    return res.status(400).json({
      success: false,
      error: 'A valid campaign report object or existing runId must be provided in request body.'
    });
  }

  try {
    const isMarkdown = format === 'markdown' || format === 'md';
    const exported = isMarkdown
      ? generateCampaignMarkdownReport(targetReport)
      : generateCampaignJsonReport(targetReport);

    if (req.query.download === 'true') {
      res.setHeader('Content-Type', exported.mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${exported.filename}"`);
      return res.send(exported.content);
    }

    return res.json({
      success: true,
      filename: exported.filename,
      mimeType: exported.mimeType,
      content: exported.content
    });
  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err.message
    });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
    const prov = getProviderConfigurationStatus();
    console.log(
      `🤖 Evaluator Providers: Gemini=${prov.gemini.enabled ? `✅ (${prov.gemini.model})` : '❌ Disabled'}, ` +
      `Groq=${prov.groq?.enabled ? `✅ (${prov.groq.model})` : '❌ Disabled'}, ` +
      `xAI=${prov.xai?.enabled ? `✅ (${prov.xai.model})` : '❌ Disabled'}, ` +
      `OpenRouter=${prov.openrouter.enabled ? `✅ (${prov.openrouter.model})` : '❌ Disabled'} ` +
      `[Order: ${prov.order.join(' -> ')}]`
    );
    if (process.env.ALLOW_LOCAL_TARGETS === 'true') {
      console.log(`⚠️  [DEV MODE] ALLOW_LOCAL_TARGETS=true: local targets (127.0.0.1) permitted for testing.`);
    } else {
      console.log(`🔒 [PROD MODE] Strict SSRF destination filtering active.`);
    }
    console.log(`API endpoints:`);
    console.log(` - http://localhost:${PORT}/api/health`);
    console.log(` - http://localhost:${PORT}/api/test-gemini`);
    console.log(` - http://localhost:${PORT}/api/target/test-connection`);
    console.log(` - http://localhost:${PORT}/api/experiment/run`);
  });
}

module.exports = app;
