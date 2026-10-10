const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const app = require('../index');

describe('Express API Endpoints Integration Suite', () => {
  let server;
  let serverPort;
  let serverBaseUrl;

  let targetMockServer;
  let targetMockPort;
  let targetMockUrl;

  before(async () => {
    // Start target mock server
    targetMockServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        if (req.url === '/chat') {
          const parsed = JSON.parse(body || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ reply: `Echo: ${parsed.message}` }));
          return;
        }
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
      });
    });

    await new Promise((resolve) => {
      targetMockServer.listen(0, '127.0.0.1', () => {
        targetMockPort = targetMockServer.address().port;
        targetMockUrl = `http://127.0.0.1:${targetMockPort}/chat`;
        resolve();
      });
    });

    // Start Express app server on random port
    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        serverPort = server.address().port;
        serverBaseUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) await new Promise((r) => server.close(r));
    if (targetMockServer) await new Promise((r) => targetMockServer.close(r));
  });

  test('GET /api/health returns ok status', async () => {
    const res = await fetch(`${serverBaseUrl}/api/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
  });

  test('GET /api/experiment/presets returns presets list', async () => {
    const res = await fetch(`${serverBaseUrl}/api/experiment/presets`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.attackPresets));
    assert.ok(Array.isArray(data.targetPresets));
    assert.ok(data.attackPresets.length >= 3);
  });

  test('POST /api/target/test-connection rejects missing targetConfig', async () => {
    const res = await fetch(`${serverBaseUrl}/api/target/test-connection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.equal(data.status, 'INVALID_CONFIG');
  });

  test('POST /api/target/test-connection rejects unacknowledged ownership', async () => {
    const res = await fetch(`${serverBaseUrl}/api/target/test-connection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetConfig: {
          url: 'https://api.example.com/chat',
          ownershipAcknowledged: false
        }
      })
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /ownership/i);
  });

  test('POST /api/target/test-connection blocks prohibited SSRF destination (metadata)', async () => {
    const res = await fetch(`${serverBaseUrl}/api/target/test-connection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetConfig: {
          url: 'http://169.254.169.254/latest/meta-data/',
          ownershipAcknowledged: true
        }
      })
    });
    assert.equal(res.status, 403);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.equal(data.status, 'SECURITY_VIOLATION');
  });

  test('POST /api/experiment/run executes mock mode pipeline cleanly', async () => {
    const res = await fetch(`${serverBaseUrl}/api/experiment/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'mock',
        attackCase: { prompt: 'Test Attack' },
        securityRequirements: 'Must not disclose secrets'
      })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.experiment.mode, 'mock');
    assert.equal(data.experiment.targetExecution.status, 'SUCCESS');
  });

  test('GET /api/experiment/history returns stored experiment history', async () => {
    const res = await fetch(`${serverBaseUrl}/api/experiment/history`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.runs));
    assert.ok(data.runs.length >= 1);
  });

  test('GET /api/benchmark/suite returns versioned benchmark metadata and cases', async () => {
    const res = await fetch(`${serverBaseUrl}/api/benchmark/suite`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.suite.id, 'vibesec-core');
    assert.equal(data.suite.version, '1.0.0');
    assert.equal(data.suite.totalTests, 5);
    assert.ok(Array.isArray(data.suite.tests));
    assert.equal(data.suite.tests.length, 5);
  });

  test('POST /api/benchmark/run rejects missing ownership confirmation', async () => {
    const res = await fetch(`${serverBaseUrl}/api/benchmark/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetConfig: {
          url: 'http://127.0.0.1:5050/api/chat',
          ownershipAcknowledged: false
        }
      })
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /ownership/i);
  });

  test('POST /api/benchmark/run executes mock benchmark suite successfully', async () => {
    const res = await fetch(`${serverBaseUrl}/api/benchmark/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'mock',
        targetConfig: {
          url: 'http://127.0.0.1:5050/api/chat',
          ownershipAcknowledged: true
        },
        maxTests: 3
      })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.report.benchmark.id, 'vibesec-core');
    assert.equal(data.report.totalTests, 3);
    assert.equal(data.report.mode, 'mock');
    assert.ok(data.report.runId.startsWith('bench_'));
    assert.ok(Array.isArray(data.report.results));
    assert.equal(data.report.results.length, 3);
  });

  test('GET /api/benchmark/history returns recorded benchmark history', async () => {
    const res = await fetch(`${serverBaseUrl}/api/benchmark/history`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.ok(Array.isArray(data.runs));
    assert.ok(data.runs.length >= 1);
  });
});
