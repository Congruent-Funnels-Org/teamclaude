import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';
import {
  createGuestServer, startGuestListener, GuestUsageTracker, guestStatus,
  hashGuestKey, newGuestKey, resolveGuestKey, presentedGuestKey,
  isAllowedGuestRoute, isWildcardHost, utcDay, secondsToUtcMidnight, checkGuestBody,
  guestHostProblem, guestCap, estimateRequestTokens, scrubErrorBody, GUEST_DEFAULTS,
  findRemoteSource, stripLongContextBetas, zeroCacheFigures, guestBetas, mediaMinimum,
  weighTokens, guestPct, modelPrice, weeklyWindow, guestWeeklyPct, guestPause5hPct, MODEL_PRICES,
} from '../src/guest.js';
import { pruneGuestLogs, renderGuestTranscript, setGuestLogBytes, guestLogBytes, openGuestLog, runGuestLogPrune, resetGuestLogDays, guestLogDay, GUEST_LOG_DEFAULTS } from '../src/guest-log.js';
import { sanitizeMultiline, sanitizeText, safeGuestLine } from '../src/safe-text.js';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync, rmSync, chmodSync, symlinkSync } from 'node:fs';
import { gunzipSync, gzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Guest stream logs default ON and to ~/.local/share: every test here writes
// under a temp dir instead (guest-log.js reads XDG_DATA_HOME per request).
// The operator notifier (jan-notify) is STUBBED first on PATH: a test must
// never reach the real one (it toasts Jan's screen). The stub only records.
const NOTIFY_LOG = await (async () => {
  const { mkdtempSync, writeFileSync, chmodSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  process.env.XDG_DATA_HOME = mkdtempSync(join(tmpdir(), 'tc-guest-xdg-'));
  const bin = mkdtempSync(join(tmpdir(), 'tc-guest-stubbin-'));
  const logFile = join(bin, 'notify.log');
  writeFileSync(join(bin, 'jan-notify'), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${logFile}'\n`);
  chmodSync(join(bin, 'jan-notify'), 0o755);
  process.env.PATH = `${bin}:${process.env.PATH}`;
  process.env.TC_TEST_STUB_BIN = bin;
  return logFile;
})();

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function oauth(name) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000 };
}

const KEY = 'tcg-test-key-0123456789';

function guestsConfig(extra = {}) {
  return { keys: [{ name: 'phoebe', keyHash: hashGuestKey(KEY), account: 'ai', dailyTokenCap: 'unlimited', enabled: true, ...extra }] };
}

// ── units ────────────────────────────────────────────────────────────────────

test('hashGuestKey is sha256 hex; newGuestKey is prefixed and random', () => {
  assert.match(hashGuestKey('x'), /^[0-9a-f]{64}$/);
  assert.equal(hashGuestKey('x'), '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881');
  const a = newGuestKey(); const b = newGuestKey();
  assert.ok(a.startsWith('tcg-') && a.length > 30);
  assert.notEqual(a, b);
});

test('resolveGuestKey matches the hash, ignores disabled and malformed entries', () => {
  const g = guestsConfig();
  assert.equal(resolveGuestKey(g, KEY)?.name, 'phoebe');
  assert.equal(resolveGuestKey(g, KEY + 'x'), null);
  assert.equal(resolveGuestKey(g, ''), null);
  assert.equal(resolveGuestKey(g, null), null);
  assert.equal(resolveGuestKey(guestsConfig({ enabled: false }), KEY), null);
  assert.equal(resolveGuestKey(guestsConfig({ keyHash: 'nothex' }), KEY), null);
  assert.equal(resolveGuestKey(guestsConfig({ account: '' }), KEY), null);
  // A plaintext key in the hash slot is not a match for itself.
  assert.equal(resolveGuestKey({ keys: [{ name: 'n', keyHash: KEY, account: 'ai' }] }, KEY), null);
  assert.equal(resolveGuestKey(undefined, KEY), null);
});

test('presentedGuestKey reads x-api-key, then a Bearer token', () => {
  assert.equal(presentedGuestKey({ 'x-api-key': 'a' }), 'a');
  assert.equal(presentedGuestKey({ authorization: 'Bearer b' }), 'b');
  assert.equal(presentedGuestKey({ authorization: 'Basic b' }), null);
  assert.equal(presentedGuestKey({}), null);
});

test('only the inference routes are allowed, matched on the exact pathname', () => {
  assert.ok(isAllowedGuestRoute('POST', '/v1/messages'));
  assert.ok(isAllowedGuestRoute('POST', '/v1/messages?beta=true'));
  assert.ok(isAllowedGuestRoute('POST', '/v1/messages/count_tokens?beta=true'));
  assert.ok(isAllowedGuestRoute('GET', '/v1/models'));
  assert.ok(isAllowedGuestRoute('GET', '/v1/models/claude-haiku-4-5'));
  for (const [m, u] of [
    ['GET', '/v1/messages'], ['POST', '/v1/models'], ['GET', '/teamclaude/status'],
    ['POST', '/teamclaude/reload'], ['GET', '/teamclaude/dashboard'], ['POST', '/v1/oauth/token'],
    ['POST', '/api/event_logging/batch'], ['GET', '/api/oauth/profile'], ['POST', '/tc-acct/jan/v1/messages'],
    ['POST', '//v1/messages'], ['POST', '/v1/./messages'], ['POST', '/v1/messages/../models'],
    ['POST', '/v1/messages/'], ['POST', '/V1/messages'], ['POST', 'http://x/v1/messages'],
    ['POST', '/v1/responses'], ['GET', '/v1/models/../../teamclaude/status'], ['POST', '/mcp'],
  ]) assert.equal(isAllowedGuestRoute(m, u), false, `${m} ${u}`);
});

test('only one literal tailnet/loopback IP may be the listen host', () => {
  for (const h of ['0.0.0.0', '::', '', ' ', '*', undefined, '0', '::0', '0:0:0:0:0:0:0:0', '[::]', '::ffff:0.0.0.0', '::ffff:0:0',
    '0.0.0.0.', 'localhost', 'enso', 'enso.tail207e06.ts.net', '192.168.1.5', '10.0.0.1', '100.128.0.1', '100.63.255.255',
    '8.8.8.8', 'fe80::1', '2001:db8::1', '::ffff:192.168.1.5', '1.2.3']) {
    assert.ok(isWildcardHost(h), `should refuse ${String(h)}`);
    assert.ok(guestHostProblem(h));
  }
  for (const h of ['100.99.200.17', '100.64.0.1', '100.127.255.254', '127.0.0.1', '::1', '[::1]', 'fd7a:115c:a1e0::1', '::ffff:100.99.200.17']) {
    assert.equal(guestHostProblem(h), null, h);
  }
});

test('the token cap is a backstop: missing or unusable = 100M; "unlimited" is explicit', () => {
  assert.equal(guestCap({}), 100_000_000);
  assert.equal(guestCap({ dailyTokenCap: 0 }), 100_000_000);
  assert.equal(guestCap({ dailyTokenCap: -5 }), 100_000_000);
  assert.equal(guestCap({ dailyTokenCap: 'lots' }), 100_000_000);
  assert.equal(guestCap({ dailyTokenCap: 3000000 }), 3000000);
  assert.equal(guestCap({ dailyTokenCap: 'unlimited' }), Infinity);
});

test('estimateRequestTokens = bytes/3 + max_tokens', () => {
  const body = Buffer.from(JSON.stringify({ max_tokens: 100, messages: [] }));
  assert.equal(estimateRequestTokens(body), Math.ceil(body.length / 3) + 100);
  assert.equal(estimateRequestTokens(Buffer.alloc(0)), 0);
  assert.equal(estimateRequestTokens(Buffer.from('nope')), 2);
});

test('scrubErrorBody never names an account', () => {
  const out = scrubErrorBody(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Upstream refused the credential for account "ai@x.com" (403)' } }), 502, ['ai@x.com']);
  assert.ok(!out.includes('ai@x.com'));
  assert.match(JSON.parse(out).error.message, /relay could not serve/);
  const kept = JSON.parse(scrubErrorBody(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'prompt is too long' } }), 400, ['ai@x.com']));
  assert.equal(kept.error.message, 'prompt is too long');
  assert.match(scrubErrorBody('<html>ai@x.com</html>', 502, ['ai@x.com']), /relay could not serve/);
});

test('GuestUsageTracker resets "today" on a new UTC day and keeps lifetime totals', () => {
  let now = Date.UTC(2026, 9, 14, 23, 59);
  const t = new GuestUsageTracker({ now: () => now });
  t.recordRequest('n'); t.recordTokens('n', 100); t.recordTokens('n', -5); t.recordTokens('n', NaN);
  assert.equal(t.tokensToday('n'), 100);
  now = Date.UTC(2026, 9, 15, 0, 1);
  assert.equal(t.tokensToday('n'), 0);
  assert.deepEqual({ ...t.get('n'), lastSeen: null }, { requestsToday: 0, tokensToday: 0, requests: 1, tokens: 100, lastSeen: null });
  const copy = new GuestUsageTracker({ now: () => now });
  copy.restore(t.export());
  assert.equal(copy.get('n').tokens, 100);
  assert.equal(utcDay(Date.UTC(2026, 0, 2, 3)), '2026-01-02');
  assert.equal(secondsToUtcMidnight(Date.UTC(2026, 0, 2, 23, 59, 0)), 60);
});

test('guestStatus shows counters and never a key or hash', () => {
  const s = guestStatus({ guests: { listen: { host: 'h', port: 1 }, ...guestsConfig({ dailyTokenCap: 5 }) } }, new GuestUsageTracker());
  assert.equal(s.keys[0].name, 'phoebe');
  assert.equal(s.keys[0].dailyTokenCap, 5);
  assert.ok(!JSON.stringify(s).includes(hashGuestKey(KEY)));
});

// ── integration: a guest server in front of a mock upstream ─────────────────

// The mock upstream answers per account (by the bearer it receives), so a test
// can make the PINNED account fail and prove the other one is never asked.
async function withGuest(run, { upstreamFor = {}, guests = guestsConfig(), accounts = ['jan', 'ai'], hooks = {}, guestUsage: usage = null, configExtra = {}, persist = null } = {}) {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      const who = String(req.headers.authorization || '').replace('Bearer t-', '');
      seen.push({ who, path: req.url, method: req.method, apiKey: req.headers['x-api-key'], cookie: req.headers.cookie, beta: req.headers['anthropic-beta'], body });
      const h = upstreamFor[who];
      if (h) return h(req, res, body);
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'sess=secret', 'x-ok': '1' });
      res.end(JSON.stringify({ id: 'm', type: 'message', content: [{ type: 'text', text: 'hi' }], usage: { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 100, cache_creation_input_tokens: 20 } }));
    });
  });
  const upstreamPort = await listen(upstream);
  // No refresh token: a 401 must not send the test to the real OAuth endpoint.
  const am = new AccountManager(accounts.map(n => ({ ...oauth(n), refreshToken: undefined })), 0.98);
  const config = { proxy: { apiKey: 'main-key' }, upstream: `http://127.0.0.1:${upstreamPort}`, guests, ...configExtra };
  const guestUsage = usage || new GuestUsageTracker();
  const logs = [];
  const guest = createGuestServer({ accountManager: am, config, guestUsage, hooks, persist, log: m => logs.push(m) });
  const port = await listen(guest);
  try {
    return await run({ port, seen, am, guestUsage, config, logs, guest });
  } finally {
    guest.closeAllConnections?.();
    guest.close();
    upstream.closeAllConnections?.();
    upstream.close();
  }
}

const ask = (port, { key = KEY, path = '/v1/messages?beta=true', method = 'POST', headers = {}, body = null } = {}) => fetch(`http://127.0.0.1:${port}${path}`, {
  method,
  headers: { 'content-type': 'application/json', ...(key ? { 'x-api-key': key } : {}), ...headers },
  body: method === 'GET' ? undefined : (body ?? JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 16, messages: [{ role: 'user', content: 'hi' }] })),
});

test('a guest request is served by its pinned account with the account token, guest key stripped', async () => {
  await withGuest(async ({ port, seen, guestUsage }) => {
    const res = await ask(port, { headers: { cookie: 'c=1' } });
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.equal(body.content[0].text, 'hi');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].who, 'ai');
    assert.equal(seen[0].apiKey, undefined);
    assert.equal(seen[0].cookie, undefined);
    assert.ok(!seen[0].body.includes(KEY));
    assert.equal(res.headers.get('set-cookie'), null);
    assert.equal(res.headers.get('x-ok'), null);   // not on the allow-list
    // input + output + cache read + cache write
    assert.equal(guestUsage.tokensToday('phoebe'), 135);
    assert.equal(guestUsage.get('phoebe').requestsToday, 1);
  });
});

test('a Bearer guest key works too; GET /v1/models is forwarded on the pin', async () => {
  await withGuest(async ({ port, seen }) => {
    const res = await ask(port, { key: null, path: '/v1/models', method: 'GET', headers: { authorization: `Bearer ${KEY}` } });
    await res.text();
    assert.equal(res.status, 200);
    assert.equal(seen[0].who, 'ai');
    assert.equal(seen[0].path, '/v1/models');
  });
});

test('a wrong or missing key is 401 and never reaches upstream', async () => {
  await withGuest(async ({ port, seen }) => {
    for (const key of ['nope', null, 'main-key']) {
      const res = await ask(port, { key });
      assert.equal(res.status, 401, String(key));
      await res.text();
    }
    assert.equal(seen.length, 0);
  });
});

test('a disabled key is 401', async () => {
  await withGuest(async ({ port, seen }) => {
    const res = await ask(port);
    assert.equal(res.status, 401);
    assert.equal(seen.length, 0);
  }, { guests: guestsConfig({ enabled: false }) });
});

test('everything off the allow-list is 404, even with a valid key', async () => {
  await withGuest(async ({ port, seen }) => {
    for (const [method, path] of [['GET', '/teamclaude/status'], ['POST', '/teamclaude/reload'], ['GET', '/teamclaude/dashboard'],
      ['POST', '/api/event_logging/batch'], ['POST', '/tc-acct/jan/v1/messages'], ['GET', '/'], ['POST', '/v1/oauth/token']]) {
      const res = await ask(port, { method, path });
      assert.equal(res.status, 404, `${method} ${path}`);
      await res.text();
    }
    assert.equal(seen.length, 0);
  });
});

test('CONNECT and upgrades are refused at the socket', async () => {
  await withGuest(async ({ port, seen }) => {
    const reply = (raw) => new Promise((resolve) => {
      const s = net.connect(port, '127.0.0.1', () => s.write(raw));
      let out = '';
      s.on('data', d => { out += d; });
      s.on('close', () => resolve(out));
      s.on('error', () => resolve(out));
    });
    const c = await reply(`CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nProxy-Authorization: Basic ${Buffer.from('ai:' + KEY).toString('base64')}\r\n\r\n`);
    assert.match(c, /^HTTP\/1\.1 405/);
    const u = await reply(`GET /v1/messages HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nx-api-key: ${KEY}\r\n\r\n`);
    assert.match(u, /^HTTP\/1\.1 404/);
    assert.equal(seen.length, 0);
  });
});

test('a pin to an unconfigured account is 503, never rotation', async () => {
  await withGuest(async ({ port, seen }) => {
    const res = await ask(port);
    assert.equal(res.status, 503);
    assert.equal(seen.length, 0);
  }, { guests: guestsConfig({ account: 'ghost' }) });
});

// The hard pin. Every failure the forwarding path knows how to fail over from
// is aimed at the pinned account; the other account must never be asked.
for (const [label, handler] of [
  ['rate-limit 429 with headers', (req, res) => { res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '1', 'anthropic-ratelimit-requests-remaining': '0' }); res.end('{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}'); }],
  ['headerless 429', (req, res) => { res.writeHead(429, { 'content-type': 'application/json' }); res.end('{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}'); }],
  ['quota-rejected 429', (req, res) => { res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '3600', 'anthropic-ratelimit-unified-status': 'rejected', 'anthropic-ratelimit-unified-reset': String(Math.floor(Date.now() / 1000) + 3600) }); res.end('{"type":"error","error":{"type":"rate_limit_error","message":"quota"}}'); }],
  ['529 overloaded', (req, res) => { res.writeHead(529, { 'content-type': 'application/json' }); res.end('{"type":"error","error":{"type":"overloaded_error","message":"busy"}}'); }],
  ['500', (req, res) => { res.writeHead(500, { 'content-type': 'application/json' }); res.end('{"type":"error","error":{"type":"api_error","message":"x"}}'); }],
  ['401 dead credential', (req, res) => { res.writeHead(401, { 'content-type': 'application/json' }); res.end('{"type":"error","error":{"type":"authentication_error","message":"bad"}}'); }],
  ['403 refused credential', (req, res) => { res.writeHead(403, { 'content-type': 'application/json' }); res.end('{"type":"error","error":{"type":"permission_error","message":"no"}}'); }],
]) {
  test(`hard pin: ${label} on the pinned account never fails over to another account`, { timeout: 60_000 }, async () => {
    await withGuest(async ({ port, seen }) => {
      const res = await ask(port);
      await res.text();
      assert.notEqual(res.status, 200);
      assert.ok(seen.length >= 1);
      assert.deepEqual([...new Set(seen.map(s => s.who))], ['ai'], `asked: ${seen.map(s => s.who).join(',')}`);
    }, { upstreamFor: { ai: handler } });
  });
}

test('hard pin: a paused / exhausted pinned account is an error, not another account', async () => {
  await withGuest(async ({ port, seen, am }) => {
    am.accounts[1].status = 'exhausted';
    am.accounts[1].resetAt = Date.now() + 3600_000;
    am.markExhausted?.(1, Date.now() + 3600_000);
    const res = await ask(port);
    await res.text();
    assert.ok(seen.every(s => s.who === 'ai'));
  });
});

test('the daily cap answers 429 once reached, before anything is sent', async () => {
  await withGuest(async ({ port, seen, guestUsage }) => {
    const first = await ask(port);
    await first.text();
    assert.equal(first.status, 200);
    assert.ok(guestUsage.tokensToday('phoebe') >= 100);
    const second = await ask(port);
    const body = await second.json();
    assert.equal(second.status, 429);
    assert.match(body.error.message, /Daily limit reached/);
    assert.ok(Number(second.headers.get('retry-after')) > 0);
    assert.equal(seen.length, 1);
  }, { guests: guestsConfig({ dailyTokenCap: 100 }) });
});

test('streaming usage (message_start + message_delta) is booked, cache included', async () => {
  const sse = (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":1,"cache_read_input_tokens":40,"cache_creation_input_tokens":3}}}\n\n');
    res.write('event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":9,"cache_read_input_tokens":40}}\n\n');
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  };
  await withGuest(async ({ port, guestUsage }) => {
    const res = await ask(port);
    await res.text();
    assert.equal(res.status, 200);
    // 7 input + 43 cache (counted once, at message_start) + 9 output
    assert.equal(guestUsage.tokensToday('phoebe'), 59);
  }, { upstreamFor: { ai: sse } });
});

test('a key added on reload works without a restart (keys read live)', async () => {
  await withGuest(async ({ port, config }) => {
    const before = await ask(port);
    assert.equal(before.status, 401);
    config.guests = guestsConfig();
    const after = await ask(port);
    await after.text();
    assert.equal(after.status, 200);
  }, { guests: { keys: [] } });
});

// ── the pin-leak fix on the MAIN listener (pre-existing bug) ─────────────────

// Before KAN-3837 the 429 and 5xx one-hop failovers did not check the pin, so a
// /tc-acct/ (or TC_ACCT) request could be answered by a different account.
for (const status of [529, 500]) {
  test(`main listener: a pinned request that gets ${status} does not hop to another account`, async () => {
    const seen = [];
    const upstream = http.createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const who = String(req.headers.authorization || '').replace('Bearer t-', '');
        seen.push(who);
        if (who === 'beta') { res.writeHead(status, { 'content-type': 'application/json' }); res.end('{"type":"error","error":{"type":"overloaded_error","message":"x"}}'); return; }
        res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}');
      });
    });
    const upstreamPort = await listen(upstream);
    const am = new AccountManager([oauth('alpha'), oauth('beta')], 0.98);
    const proxy = createProxyServer(am, { proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
    const proxyPort = await listen(proxy);
    try {
      const res = await fetch(`http://127.0.0.1:${proxyPort}/tc-acct/beta/v1/messages`, { method: 'POST', headers: { 'x-api-key': 'k', 'content-type': 'application/json' }, body: '{"model":"x","messages":[]}' });
      await res.text();
      assert.equal(res.status, status);
      assert.deepEqual([...new Set(seen)], ['beta']);
    } finally {
      proxy.closeAllConnections?.(); proxy.close();
      upstream.closeAllConnections?.(); upstream.close();
    }
  });
}

test('main listener: an UNPINNED request still hops once on 529 (behaviour kept)', async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const who = String(req.headers.authorization || '').replace('Bearer t-', '');
      seen.push(who);
      if (seen.length === 1) { res.writeHead(529, { 'content-type': 'application/json' }); res.end('{}'); return; }
      res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}');
    });
  });
  const upstreamPort = await listen(upstream);
  const am = new AccountManager([oauth('alpha'), oauth('beta')], 0.98);
  const proxy = createProxyServer(am, { proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);
  try {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, { method: 'POST', headers: { 'x-api-key': 'k', 'content-type': 'application/json' }, body: '{"model":"x","messages":[]}' });
    await res.text();
    assert.equal(res.status, 200);
    assert.equal(new Set(seen).size, 2);
  } finally {
    proxy.closeAllConnections?.(); proxy.close();
    upstream.closeAllConnections?.(); upstream.close();
  }
});

// ── listener lifecycle ──────────────────────────────────────────────────────

test('startGuestListener refuses a wildcard host and does nothing without config', () => {
  const logs = [];
  const am = new AccountManager([oauth('ai')], 0.98);
  const r = startGuestListener({ accountManager: am, config: { guests: { listen: { host: '0.0.0.0', port: 3460 }, keys: [] } }, guestUsage: new GuestUsageTracker() }, { log: m => logs.push(m) });
  assert.equal(r.server, null);
  assert.match(r.state.error, /unspecified address/);
  const off = startGuestListener({ accountManager: am, config: {}, guestUsage: new GuestUsageTracker() }, { log: () => {} });
  assert.equal(off.server, null);
  assert.equal(off.state.listening, false);
});

test('startGuestListener retries an address that is not on this machine, never another', async () => {
  const logs = [];
  const am = new AccountManager([oauth('ai')], 0.98);
  // A tailnet-range address this machine does not hold.
  const r = startGuestListener({ accountManager: am, config: { guests: { listen: { host: '100.64.0.123', port: 3460 }, keys: [] } }, guestUsage: new GuestUsageTracker() }, { retryMs: 30, log: m => logs.push(m) });
  await new Promise(resolve => setTimeout(resolve, 120));
  r.stop();
  assert.equal(r.state.listening, false);
  assert.ok(logs.filter(l => /retrying/.test(l)).length >= 2, logs.join('\n'));
  assert.ok(!r.server.listening);
});

test('startGuestListener binds the configured address', async () => {
  const am = new AccountManager([oauth('ai')], 0.98);
  const probe = net.createServer(); await new Promise(r => probe.listen(0, '127.0.0.1', r));
  const port = probe.address().port; await new Promise(r => probe.close(r));
  const r = startGuestListener({ accountManager: am, config: { guests: { listen: { host: '127.0.0.1', port }, keys: [] } }, guestUsage: new GuestUsageTracker() }, { log: () => {} });
  await new Promise(resolve => setTimeout(resolve, 50));
  try {
    assert.equal(r.state.listening, true);
    assert.equal(r.server.address().address, '127.0.0.1');
  } finally { r.stop(); }
});

test('teamclaude status renders a Guests section', async () => {
  const { renderStatus } = await import('../src/status-renderer.js');
  const out = renderStatus({ accounts: [], guests: { listen: { host: '100.99.200.17', port: 3460 }, listening: { listening: false, error: 'EADDRNOTAVAIL' },
    keys: [{ name: 'phoebe', account: 'ai@x', enabled: true, dailyTokenCap: 3000000, tokensToday: 1234, requestsToday: 2, lastSeen: null }] } }, { color: false });
  const text = Array.isArray(out) ? out.join('\n') : out;
  assert.match(text, /Guests 100\.99\.200\.17:3460, not listening \(EADDRNOTAVAIL\)/);
  assert.match(text, /phoebe {2}enabled {2}→ ai@x {2}1,234\/3,000,000 tokens today, 2 req/);
});

// ── bounce 1: caps, limits, leaks ───────────────────────────────────────────

test('a key with no cap configured is served (the usage cap is the limit, 100M backstop)', async () => {
  await withGuest(async ({ port, seen }) => {
    const res = await ask(port);
    assert.equal(res.status, 200);
    await res.text();
    assert.equal(seen.length, 1);
  }, { guests: guestsConfig({ dailyTokenCap: undefined }) });
});

// A slow upstream so requests overlap. Each request's estimate (~51 tokens)
// fits a 120-token cap once, but not three times: reserve-before-send has to
// stop the parallel ones even though nothing has been booked yet.
const slow = (req, res) => setTimeout(() => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ usage: { input_tokens: 40, output_tokens: 10 } }));
}, 150);

test('parallel requests at the cap edge cannot all slip under it', async () => {
  await withGuest(async ({ port, seen, guestUsage }) => {
    const results = await Promise.all([ask(port), ask(port), ask(port)]);
    const statuses = results.map(r => r.status);
    await Promise.all(results.map(r => r.text()));
    // concurrency 2 + reservation: exactly the first 2 can be in flight, and
    // only as many as the cap's estimate room allows.
    assert.ok(statuses.filter(s => s === 200).length <= 2, statuses.join(','));
    assert.ok(statuses.includes(429), statuses.join(','));
    assert.ok(seen.length <= 2);
    assert.ok(guestUsage.tokensToday('phoebe') <= 120 + 50, String(guestUsage.tokensToday('phoebe')));
  }, { upstreamFor: { ai: slow }, guests: guestsConfig({ dailyTokenCap: 120, maxConcurrent: 5 }) });
});

test('at most maxConcurrent (default 8) requests per key are in flight', async () => {
  assert.equal(GUEST_DEFAULTS.maxConcurrent, 8);
  assert.equal(GUEST_DEFAULTS.requestsPerMinute, 240);
  await withGuest(async ({ port, seen }) => {
    const results = await Promise.all([ask(port), ask(port), ask(port), ask(port)]);
    const statuses = results.map(r => r.status);
    await Promise.all(results.map(r => r.text()));
    assert.equal(statuses.filter(s => s === 200).length, 2, statuses.join(','));
    assert.equal(statuses.filter(s => s === 429).length, 2);
    assert.equal(seen.length, 2);
    // and the slots come back
    const after = await ask(port);
    await after.text();
    assert.equal(after.status, 200);
  }, { upstreamFor: { ai: slow }, guests: guestsConfig({ maxConcurrent: 2 }) });
});

test('requests per minute are limited per key, count_tokens included', async () => {
  await withGuest(async ({ port }) => {
    const codes = [];
    for (let i = 0; i < 4; i++) {
      const r = await ask(port, { path: '/v1/messages/count_tokens' });
      await r.text();
      codes.push(r.status);
    }
    assert.deepEqual(codes, [200, 200, 200, 429]);
  }, { guests: guestsConfig({ requestsPerMinute: 3 }) });
});

test('an oversized body is 413 and never forwarded', async () => {
  await withGuest(async ({ port, seen }) => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, { method: 'POST', headers: { 'x-api-key': KEY, 'content-type': 'application/json' }, body: 'x'.repeat(5000) }).catch(e => e);
    if (res instanceof Error) return; // the socket may be cut mid-upload; either way nothing went upstream
    assert.equal(res.status, 413);
    await res.text().catch(() => {});
    assert.equal(seen.length, 0);
  }, { guests: { ...guestsConfig(), maxBodyBytes: 1000 } });
});

test('the listener is bounded: maxConnections and timeouts', async () => {
  await withGuest(async ({ guest }) => {
    assert.equal(guest.maxConnections, GUEST_DEFAULTS.maxConnections);
    assert.equal(guest.headersTimeout, GUEST_DEFAULTS.headersTimeoutMs);
    assert.equal(guest.requestTimeout, GUEST_DEFAULTS.requestTimeoutMs);
  });
});

test('a throw inside the guest handler is a 500, not a crash', async () => {
  const boom = new GuestUsageTracker();
  boom.recordRequest = () => { throw new Error('forced'); };
  await withGuest(async ({ port, logs }) => {
    const res = await ask(port);
    await res.text();
    assert.equal(res.status, 500);
    assert.ok(logs.some(l => /guest handler error: forced/.test(l)));
    // still serving
    const again = await ask(port);
    await again.text();
    assert.equal(again.status, 500);
  }, { guestUsage: boom });
});

test('only allow-listed response headers reach the guest', async () => {
  const leaky = (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'anthropic-organization-id': 'org-secret', 'request-id': 'req_1',
      'anthropic-ratelimit-unified-status': 'allowed', 'x-envoy-upstream-service-time': '5', 'set-cookie': 'a=b' });
    res.end('{"usage":{"input_tokens":1,"output_tokens":1}}');
  };
  await withGuest(async ({ port }) => {
    const res = await ask(port);
    await res.text();
    assert.equal(res.headers.get('anthropic-organization-id'), null);
    assert.equal(res.headers.get('x-envoy-upstream-service-time'), null);
    assert.equal(res.headers.get('set-cookie'), null);
    assert.equal(res.headers.get('request-id'), 'req_1');
    // the pinned account's quota state is not the guest's business
    assert.equal(res.headers.get('anthropic-ratelimit-unified-status'), null);
  }, { upstreamFor: { ai: leaky } });
});

test('a refused credential (403) does not name the account to the guest', async () => {
  const refuse = (req, res) => { res.writeHead(403, { 'content-type': 'application/json' }); res.end('{"type":"error","error":{"type":"permission_error","message":"no"}}'); };
  await withGuest(async ({ port }) => {
    const res = await ask(port);
    const text = await res.text();
    assert.ok(res.status >= 400);
    assert.ok(!/\bai\b|"ai"|jan/.test(text), text);
    assert.doesNotThrow(() => JSON.parse(text));
  }, { upstreamFor: { ai: refuse } });
});

test('a guest session id is namespaced before routing', async () => {
  const sessions = [];
  await withGuest(async ({ port }) => {
    const res = await ask(port, { headers: { 'x-claude-code-session-id': 'jans-session-1' } });
    await res.text();
    assert.deepEqual(sessions, ['guest:phoebe:jans-session-1']);
  }, { hooks: { onRequestStart: (_id, info) => sessions.push(info.sessionId) } });
});

test('guest prompts are not written to the request log unless guests.logBodies', async () => {
  const { mkdtempSync, readdirSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'tc-guest-log-'));
  try {
    await withGuest(async ({ port }) => {
      const res = await ask(port);
      await res.text();
      assert.deepEqual(readdirSync(dir), []);
    }, { configExtra: { logDir: dir } });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── bounce 2: no way around the cap ─────────────────────────────────────────

test('an answer cut short before message_delta is booked at its worst case', async () => {
  const hang = (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":1}}}\n\n');
    const t = setInterval(() => res.write('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"' + 'x'.repeat(2000) + '"}}\n\n'), 10);
    res.on('close', () => clearInterval(t));
  };
  await withGuest(async ({ port, guestUsage }) => {
    const ac = new AbortController();
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, { method: 'POST', signal: ac.signal,
      headers: { 'x-api-key': KEY, 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'm', max_tokens: 1000, stream: true, messages: [] }) });
    const reader = res.body.getReader();
    let got = 0;
    while (got < 10_000) { const { value } = await reader.read(); got += value.length; }
    ac.abort();
    await new Promise(r => setTimeout(r, 150));
    // 7 input from message_start + the full 1000 output it was allowed
    assert.ok(guestUsage.tokensToday('phoebe') >= 1007, String(guestUsage.tokensToday('phoebe')));
  }, { upstreamFor: { ai: hang } });
});

test('input a server-side round adds after message_start is booked from message_delta', async () => {
  const grow = (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":10,"output_tokens":1}}}\n\n');
    res.write('event: message_delta\ndata: {"type":"message_delta","usage":{"input_tokens":90000,"cache_read_input_tokens":0,"output_tokens":5}}\n\n');
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  };
  await withGuest(async ({ port, guestUsage }) => {
    const res = await ask(port);
    await res.text();
    assert.equal(guestUsage.tokensToday('phoebe'), 90005);
  }, { upstreamFor: { ai: grow } });
});

test('web search / web fetch pass; code execution, advisor and MCP servers are refused; custom tools pass', async () => {
  await withGuest(async ({ port, seen }) => {
    const mk = (extra) => JSON.stringify({ model: 'm', max_tokens: 16, messages: [], ...extra });
    for (const extra of [
      { tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 8 }] },
      { tools: [{ name: 'Read', input_schema: {} }, { type: 'web_fetch_20250910', name: 'web_fetch' }] },
    ]) {
      const r = await ask(port, { body: mk(extra) });
      assert.equal(r.status, 200, JSON.stringify(extra));
      await r.text();
    }
    assert.equal(seen.length, 2);
    seen.length = 0;
    for (const extra of [
      { tools: [{ type: 'code_execution_20250825', name: 'code_execution' }] },
      { tools: [{ type: 'bash_code_execution_20250825', name: 'bash' }] },
      { tools: [{ type: 'web_search_20250305x', name: 'web_search' }] },
      { tools: [{ type: 'advisor_20260301', name: 'advisor' }] },
      { tools: 'web_search' },
      { mcp_servers: [{ type: 'url', url: 'https://x', name: 'x' }] },
    ]) {
      const r = await ask(port, { body: mk(extra) });
      assert.equal(r.status, 400, JSON.stringify(extra));
      await r.text();
    }
    assert.equal(seen.length, 0);
    const ok = await ask(port, { body: mk({ tools: [{ name: 'Read', input_schema: { type: 'object' } }, { type: 'custom', name: 'Bash', input_schema: {} }] }) });
    await ok.text();
    assert.equal(ok.status, 200);
  });
});

test('compressed bodies are 415; bad JSON or max_tokens are 400; nothing is forwarded', async () => {
  await withGuest(async ({ port, seen }) => {
    const { gzipSync } = await import('node:zlib');
    const gz = await fetch(`http://127.0.0.1:${port}/v1/messages`, { method: 'POST',
      headers: { 'x-api-key': KEY, 'content-type': 'application/json', 'content-encoding': 'gzip' },
      body: gzipSync(JSON.stringify({ model: 'm', max_tokens: 16, messages: [] })) });
    assert.equal(gz.status, 415);
    await gz.text();
    for (const body of ['not json', '[]', '{"model":"m","messages":[]}', '{"max_tokens":0}', '{"max_tokens":-1}',
      '{"max_tokens":1000000000}', '{"max_tokens":"16"}', '{"max_tokens":16.5}']) {
      const r = await ask(port, { body });
      assert.equal(r.status, 400, body);
      await r.text();
    }
    const ct = await ask(port, { path: '/v1/messages/count_tokens', body: 'nope' });
    assert.equal(ct.status, 400);
    await ct.text();
    assert.equal(seen.length, 0);
  });
});

test('checkGuestBody: count_tokens needs no max_tokens; models needs no body', () => {
  assert.ok(checkGuestBody('/v1/messages/count_tokens', {}, Buffer.from('{"messages":[]}')).ok);
  assert.ok(checkGuestBody('/v1/models', {}, Buffer.alloc(0)).ok);
  assert.equal(checkGuestBody('/v1/messages', { 'content-encoding': 'identity' }, Buffer.from('{"max_tokens":5}')).ok, true);
  assert.equal(checkGuestBody('/v1/messages', { 'content-encoding': 'br' }, Buffer.from('{"max_tokens":5}')).status, 415);
});

test('bad-key refusals are logged once per remote per minute', async () => {
  await withGuest(async ({ port, logs }) => {
    for (let i = 0; i < 6; i++) { const r = await ask(port, { key: 'nope', path: '/v1/messages?\u001b[31m' }); await r.text(); }
    const lines = logs.filter(l => /bad key/.test(l));
    assert.equal(lines.length, 1);
    assert.ok(!lines[0].includes('\u001b'));
  });
});

// ── bounce 3: tiny body, huge input; pre-body cap; cache side channel ──────

test('content by reference, thread and container are refused (bytes/3 would under-reserve)', async () => {
  await withGuest(async ({ port, seen }) => {
    const mk = (extra) => JSON.stringify({ model: 'm', max_tokens: 16, messages: [{ role: 'user', content: 'hi' }], ...extra });
    const msg = (content) => ({ messages: [{ role: 'user', content }] });
    for (const extra of [
      msg([{ type: 'image', source: { type: 'url', url: 'https://x/a.png' } }]),
      msg([{ type: 'document', source: { type: 'url', url: 'https://x/a.pdf' } }]),
      msg([{ type: 'document', source: { type: 'file', file_id: 'file_1' } }]),
      msg([{ type: 'image', file_id: 'file_2' }]),
      msg([{ type: 'tool_result', tool_use_id: 't', content: [{ type: 'document', source: { type: 'url', url: 'https://x' } }] }]),
      msg([{ type: 'container_upload', file_id: 'f' }]),
      { system: [{ type: 'text', text: 's' }, { type: 'document', source: { type: 'url', url: 'https://x' } }] },
      { thread: { type: 'continue', id: 'th_1' } },
      { container: 'cntr_1' },
    ]) {
      const r = await ask(port, { body: mk(extra) });
      assert.equal(r.status, 400, JSON.stringify(extra));
      await r.text();
    }
    assert.equal(seen.length, 0);
    const fine = await ask(port, { body: mk(msg([
      { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0KGgo=' } },
      { type: 'document', source: { type: 'text', media_type: 'text/plain', data: 'hello' } },
      { type: 'tool_use', id: 't', name: 'Fetch', input: { source: { type: 'url', url: 'https://x' }, file_id: 'not-a-ref' } },
    ])) });
    await fine.text();
    assert.equal(fine.status, 200);
  });
});

test('findRemoteSource / stripLongContextBetas units', () => {
  assert.equal(findRemoteSource([{ type: 'text', text: 'x' }]), null);
  assert.match(findRemoteSource([{ content: [{ content: [{ source: { type: 'url' } }] }] }]), /url/);
  assert.equal(stripLongContextBetas('context-1m-2025-08-07'), undefined);
  assert.equal(stripLongContextBetas('oauth-2025-04-20, context-1m-2025-08-07,interleaved-thinking-2025-05-14'), 'oauth-2025-04-20,interleaved-thinking-2025-05-14');
  assert.equal(stripLongContextBetas(undefined), undefined);
});

test('a long-context beta is stripped before forwarding; other betas pass', async () => {
  await withGuest(async ({ port, seen }) => {
    const r = await ask(port, { headers: { 'anthropic-beta': 'context-1m-2025-08-07,interleaved-thinking-2025-05-14' } });
    await r.text();
    assert.equal(r.status, 200);
    assert.ok(!String(seen[0].beta || '').includes('context-1m'), String(seen[0].beta));
    assert.ok(String(seen[0].beta || '').includes('interleaved-thinking-2025-05-14'));
  });
});

test('a capped-out key gets its 429 before the body is read', async () => {
  const usage = new GuestUsageTracker();
  usage.recordTokens('phoebe', 500);
  await withGuest(async ({ port, seen }) => {
    const status = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/v1/messages',
        headers: { 'x-api-key': KEY, 'content-type': 'application/json', 'content-length': String(7 * 1024 * 1024) } }, res => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject);
      req.write('{"max_tokens":');   // a body that will never finish
    });
    assert.equal(status, 429);
    assert.equal(seen.length, 0);
  }, { guestUsage: usage, guests: guestsConfig({ dailyTokenCap: 500 }) });
  assert.equal(GUEST_DEFAULTS.maxBodyBytes, 8 * 1024 * 1024);
});

test('prompt-cache figures reach the guest as 0 but are booked in full', async () => {
  const sse = (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'x-should-retry': 'false' });
    res.write('event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":7,"cache_read_input_tokens":40,"cache_creation_input_tokens":3,"cache_creation":{"ephemeral_5m_input_tokens":3,"ephemeral_1h_input_tokens":0}');
    res.write(',"output_tokens":1}}}\n\n');
    res.write('event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":9,"cache_read_input_tokens": 40}}\n\n');
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  };
  await withGuest(async ({ port, guestUsage }) => {
    const res = await ask(port);
    const text = await res.text();
    assert.equal(res.headers.get('x-should-retry'), 'false');
    assert.ok(!/"cache_read_input_tokens":\s*40/.test(text), text);
    assert.match(text, /"cache_read_input_tokens":0/);
    assert.match(text, /"ephemeral_5m_input_tokens":0/);
    assert.match(text, /"input_tokens":7/);
    assert.equal(guestUsage.tokensToday('phoebe'), 59);
  }, { upstreamFor: { ai: sse } });
  const json = (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"usage":{"input_tokens":2,"output_tokens":3,"cache_read_input_tokens":1000}}'); };
  await withGuest(async ({ port, guestUsage }) => {
    const res = await ask(port);
    const body = await res.json();
    assert.equal(body.usage.cache_read_input_tokens, 0);
    assert.equal(guestUsage.tokensToday('phoebe'), 1005);
  }, { upstreamFor: { ai: json } });
  assert.equal(zeroCacheFigures('{"cache_read_input_tokens" : 12}'), '{"cache_read_input_tokens" : 0}');
});

test('usage crossing 90% of the cap is persisted at once', async () => {
  let saves = 0;
  await withGuest(async ({ port }) => {
    const r = await ask(port);   // books 135 of a 140 cap
    await r.text();
    assert.equal(r.status, 200);
    assert.equal(saves, 1);
  }, { persist: async () => { saves += 1; }, guests: guestsConfig({ dailyTokenCap: 140 }) });
});

// ── bounce 4: compaction, beta allow-list, media floors ─────────────────────

test('betas are allow-listed; the OAuth beta is added for a subscription pin', () => {
  assert.equal(guestBetas('web-search-2025-03-05,web-fetch-2025-09-10'), 'web-search-2025-03-05,web-fetch-2025-09-10');
  assert.equal(guestBetas('files-api-2025-04-14,mcp-servers-2025-12-04,code-execution-2025-08-25,fast-mode-2026-02-01,cache-keepalive-2026-09-03,context-1m-2025-08-07,message-threads-2026-08-12'), undefined);
  assert.equal(guestBetas('claude-code-20250219,interleaved-thinking-2025-05-14,effort-2025-11-24,files-api-2025-04-14'), 'claude-code-20250219,interleaved-thinking-2025-05-14,effort-2025-11-24');
  assert.equal(guestBetas(undefined, { oauth: true }), 'oauth-2025-04-20');
  assert.equal(guestBetas('oauth-2025-04-20', { oauth: true }), 'oauth-2025-04-20');
  assert.equal(guestBetas('effort-2025-11-24', { oauth: false }), 'effort-2025-11-24');
  // exact names: a future beta sharing an allowed prefix does not slip in
  assert.equal(guestBetas('thinking-unbounded-2027-01-01,effort-2027-05-05,claude-code-20270101,oauth-2099-01-01'), undefined);
});

test('a guest request to an OAuth pin carries the OAuth beta upstream, and no disallowed beta', async () => {
  await withGuest(async ({ port, seen }) => {
    const r = await ask(port, { headers: { 'anthropic-beta': 'claude-code-20250219,files-api-2025-04-14,cache-keepalive-2026-09-03,effort-2099-01-01' } });
    await r.text();
    assert.equal(r.status, 200);
    const b = String(seen[0].beta).split(',');
    assert.ok(b.includes('oauth-2025-04-20') && b.includes('claude-code-20250219'), seen[0].beta);
    assert.ok(!b.some(x => /files-api|cache-keepalive|2099/.test(x)), seen[0].beta);
  });
});

test('server-side compaction is refused; clearing edits pass', async () => {
  await withGuest(async ({ port, seen }) => {
    const mk = (cm) => JSON.stringify({ model: 'm', max_tokens: 16, messages: [], context_management: cm });
    for (const cm of [{ edits: [{ type: 'compact_20260112' }] }, { edits: [{ type: 'clear_tool_uses_20250919' }, { type: 'Compact' }] }, { edits: 'compact' }]) {
      const r = await ask(port, { body: mk(cm) });
      assert.equal(r.status, 400, JSON.stringify(cm));
      await r.text();
    }
    assert.equal(seen.length, 0);
    const ok = await ask(port, { body: mk({ edits: [{ type: 'clear_tool_uses_20250919' }, { type: 'clear_thinking_20251015' }] }) });
    await ok.text();
    assert.equal(ok.status, 200);
  });
});

test('usage.iterations[] is booked when it exceeds the top-level figures (buffered and streamed)', async () => {
  const body = (req, res) => { res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ usage: { input_tokens: 10, output_tokens: 5, iterations: [{ input_tokens: 50000, output_tokens: 2000 }, { input_tokens: 10, output_tokens: 5 }] } })); };
  await withGuest(async ({ port, guestUsage }) => {
    const r = await ask(port); await r.text();
    assert.equal(guestUsage.tokensToday('phoebe'), 52015);
  }, { upstreamFor: { ai: body } });
  const sse = (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":10,"output_tokens":1}}}\n\n');
    res.write('event: message_delta\ndata: {"type":"message_delta","usage":{"input_tokens":10,"output_tokens":5,"iterations":[{"input_tokens":30000,"output_tokens":1000},{"input_tokens":10,"output_tokens":5}]}}\n\n');
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  };
  await withGuest(async ({ port, guestUsage }) => {
    const r = await ask(port); await r.text();
    assert.equal(guestUsage.tokensToday('phoebe'), 31015);
  }, { upstreamFor: { ai: sse } });
  // without iterations nothing changes
  await withGuest(async ({ port, guestUsage }) => {
    const r = await ask(port); await r.text();
    assert.equal(guestUsage.tokensToday('phoebe'), 135);
  });
});

test('images and PDFs reserve a floor beyond their bytes', () => {
  const pdf = (pages) => ({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: Buffer.from('%PDF ' + '/Type /Page '.repeat(pages) + '/Type /Pages').toString('base64') } });
  assert.equal(mediaMinimum([{ role: 'user', content: [{ type: 'image', source: { type: 'base64', data: 'x' } }, { type: 'image', source: { type: 'base64', data: 'y' } }] }]), 3200);
  assert.equal(mediaMinimum([{ content: [pdf(2)] }]), 6000);
  assert.equal(mediaMinimum([{ content: [pdf(0)] }]), 100000);
  const objstm = { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: Buffer.from('%PDF /Type /Page /Type /ObjStm').toString('base64') } };
  assert.equal(mediaMinimum([{ content: [objstm] }]), 100000);   // pages hidden in object streams
  assert.equal(mediaMinimum([{ content: [{ type: 'tool_result', content: [{ type: 'image', source: {} }] }] }]), 1600);
  assert.equal(mediaMinimum([{ content: [{ type: 'tool_use', input: { type: 'image' } }] }]), 0);
  const est = checkGuestBody('/v1/messages', {}, Buffer.from(JSON.stringify({ max_tokens: 10, messages: [{ role: 'user', content: [pdf(0)] }] })));
  assert.ok(est.ok && est.estimate >= 100010);
});

test('a PDF of unknown length is refused at a cap it cannot fit', async () => {
  await withGuest(async ({ port, seen }) => {
    const r = await ask(port, { body: JSON.stringify({ model: 'm', max_tokens: 16, messages: [{ role: 'user', content: [{ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: 'JVBERi0=' } }] }] }) });
    await r.text();
    assert.equal(r.status, 429);
    assert.equal(seen.length, 0);
  }, { guests: guestsConfig({ dailyTokenCap: 50000 }) });
});

// ── `teamclaude guest` must not fail open when the live reload fails ────────

test('guest CLI: a running server that fails the reload makes the command exit non-zero', async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { spawnSync } = await import('node:child_process');
  const dir = mkdtempSync(join(tmpdir(), 'tc-guest-cli-'));
  const run = (port, ...args) => {
    const cfg = join(dir, 'tc.json');
    writeFileSync(cfg, JSON.stringify({ proxy: { port, apiKey: 'k' }, accounts: [{ name: 'ai', type: 'oauth' }],
      guests: { keys: [{ name: 'n', keyHash: hashGuestKey('x'), account: 'ai', dailyTokenCap: 5, enabled: true }] } }));
    return spawnSync(process.execPath, [join(import.meta.dirname, '..', 'src', 'index.js'), 'guest', ...args],
      { env: { ...process.env, TEAMCLAUDE_CONFIG: cfg }, encoding: 'utf8', timeout: 20_000 });
  };
  // A port nothing listens on (bound, then closed).
  const srv = http.createServer();
  const port = await listen(srv);
  await new Promise(r => srv.close(r));
  // spawnSync blocks this event loop, so the stub reload endpoint runs in a child process.
  const { spawn } = await import('node:child_process');
  // The stub answers the reload with `status` and /teamclaude/status with `live` guest keys.
  const child = (status, live = [{ name: 'n', enabled: false }]) => new Promise((resolve) => {
    const c = spawn(process.execPath, ['-e', `require('http').createServer((q,r)=>{q.resume();if(q.url==='/teamclaude/status'){r.writeHead(200,{'content-type':'application/json'});r.end(JSON.stringify({guests:{keys:${JSON.stringify(live)}}}));return;}r.writeHead(${status});r.end('{}')}).listen(0,'127.0.0.1',function(){console.log(this.address().port)})`]);
    c.stdout.once('data', d => resolve({ c, port: Number(String(d).trim()) }));
  });
  try {
    const bad = await child(500);
    const r1 = run(bad.port, 'disable', 'n', '--rotate');
    bad.c.kill();
    assert.equal(r1.status, 1, r1.stdout + r1.stderr);
    assert.match(r1.stderr, /refused the reload \(HTTP 500\).*NOT live/);
    const good = await child(200);
    const r2 = run(good.port, 'disable', 'n');
    good.c.kill();
    assert.equal(r2.status, 0, r2.stdout + r2.stderr);
    assert.match(r2.stdout, /Reloaded running server/);
    assert.match(r2.stdout, /Confirmed on the running server: "n" is disabled/);
    // L2: the reload "worked" but the RUNNING server still has the key on → exit 1
    const liar = await child(200, [{ name: 'n', enabled: true }]);
    const r2b = run(liar.port, 'disable', 'n');
    liar.c.kill();
    assert.equal(r2b.status, 1, r2b.stdout + r2b.stderr);
    assert.match(r2b.stderr, /still reports guest "n" as enabled/);
    const mute = await child(200, null);
    const r2c = run(mute.port, 'disable', 'n');
    mute.c.kill();
    assert.equal(r2c.status, 1);
    assert.match(r2c.stderr, /NOT confirmed disabled/);
    const r3 = run(port, 'enable', 'n');   // nothing listens there now
    assert.equal(r3.status, 0, r3.stdout + r3.stderr);
    assert.match(r3.stdout, /No server running/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── KAN-3837 usage: % of weekly cap, web search, stream logs ────────────────

test('weighTokens: priced by model (one table), cache and web searches included, unknown = most expensive', () => {
  // Haiku 4.5: $1 in / $5 out / $0.10 cache read per Mtok, writes 1.25×
  const u = { input_tokens: 1_000_000, output_tokens: 1_000_000, cache_read_input_tokens: 1_000_000, cache_creation_input_tokens: 1_000_000 };
  assert.equal(Math.round(weighTokens(u, 'claude-haiku-4-5')), (1 + 5 + 0.1 + 1.25) * 1e6);
  assert.equal(Math.round(weighTokens({ input_tokens: 1e6 }, 'claude-opus-5-5')), 4e6);
  assert.equal(Math.round(weighTokens({ output_tokens: 1e6 }, 'claude-sonnet-4-6')), 15e6);
  assert.equal(Math.round(weighTokens({ input_tokens: 1e6 }, 'claude-fable-5-1')), 10e6);
  // unknown / missing model = the most expensive row in the table (legacy Opus 4: $15 in)
  assert.equal(Math.round(weighTokens({ input_tokens: 1e6 }, 'claude-mystery-9')), 15e6);
  assert.equal(Math.round(weighTokens({ input_tokens: 1e6 })), 15e6);
  assert.equal(modelPrice('claude-opus-4-8').input, 5);
  // 1h cache writes 2×, web searches $0.01 each
  assert.equal(Math.round(weighTokens({ cache_creation_input_tokens: 1e6, cache_creation: { ephemeral_1h_input_tokens: 1e6 } }, 'claude-haiku-4-5')), 2e6);
  assert.equal(Math.round(weighTokens({ server_tool_use: { web_search_requests: 3 } }, 'claude-haiku-4-5')), 30_000);
  assert.equal(weighTokens(null), 0);
  assert.equal(weighTokens({ input_tokens: -5, output_tokens: 'x' }, 'claude-haiku-4-5'), 0);
  // the guest on Opus and the owner on Haiku: the guest's share is not hidden by token counts
  assert.ok(weighTokens({ output_tokens: 1000 }, 'claude-opus-5') >= 5 * weighTokens({ output_tokens: 1000 }, 'claude-haiku-5-5'));
});

test('guestPct: key override, then guests.dailyWeeklyPct, then 30', () => {
  assert.equal(guestPct({}, {}), 30);
  assert.equal(guestPct({}, { dailyWeeklyPct: 20 }), 20);
  assert.equal(guestPct({ dailyWeeklyPct: 45 }, { dailyWeeklyPct: 20 }), 45);
  assert.equal(guestPct({ dailyWeeklyPct: 0 }, { dailyWeeklyPct: 500 }), 30);
});

test('share % = weekly rise today × guest weighted / account weighted', () => {
  let now = Date.UTC(2026, 9, 15, 10, 0);
  const t = new GuestUsageTracker({ now: () => now });
  t.observeWeekly('ai', 0.20, Date.UTC(2026, 9, 20), now);       // baseline
  t.recordAccountWeighted('ai', 1000);
  t.recordGuestWeighted('phoebe', 250);
  now += 60_000;
  t.observeWeekly('ai', 0.60, Date.UTC(2026, 9, 20), now);       // +40 points
  const s = t.share('phoebe', 'ai');
  assert.equal(s.stale, false);
  assert.ok(Math.abs(s.pct - 10) < 1e-9, String(s.pct));         // 40 × 0.25
  assert.ok(Math.abs(s.risePct - 40) < 1e-9);
  // an older reading never rewinds
  t.observeWeekly('ai', 0.30, Date.UTC(2026, 9, 20), now - 30_000);
  assert.ok(Math.abs(t.share('phoebe', 'ai').pct - 10) < 1e-9);
});

test('share %: a weekly reset inside the day keeps what was used before it', () => {
  let now = Date.UTC(2026, 9, 15, 11, 50);
  const t = new GuestUsageTracker({ now: () => now });
  t.recordAccountWeighted('ai', 100);
  t.recordGuestWeighted('n', 100);
  t.observeWeekly('ai', 0.90, Date.UTC(2026, 9, 15, 12), now);
  now += 5 * 60_000;
  t.observeWeekly('ai', 0.95, Date.UTC(2026, 9, 15, 12), now);   // +5
  now = Date.UTC(2026, 9, 15, 12, 5);
  t.observeWeekly('ai', 0.04, Date.UTC(2026, 9, 22, 12), now);   // reset: new window at 4
  assert.ok(Math.abs(t.share('n', 'ai').pct - 9) < 1e-9, String(t.share('n', 'ai').pct));
  now += 60_000;
  t.observeWeekly('ai', 0.10, Date.UTC(2026, 9, 22, 12), now);   // +6
  assert.ok(Math.abs(t.share('n', 'ai').pct - 15) < 1e-9);
  // a drop once the old reset time has passed is a reset, even with no new reset time
  const u = new GuestUsageTracker({ now: () => now });
  u.recordAccountWeighted('ai', 1); u.recordGuestWeighted('n', 1);
  u.observeWeekly('ai', 0.50, now - 60_000, now);
  u.observeWeekly('ai', 0.55, null, now + 1);
  u.observeWeekly('ai', 0.03, null, now + 2);
  assert.ok(Math.abs(u.share('n', 'ai').pct - 8) < 1e-9);
});

test('share %: a drop while the old window still runs is a lagging reading, not a reset', () => {
  const now = Date.UTC(2026, 9, 15, 10, 0);
  const t = new GuestUsageTracker({ now: () => now });
  t.recordAccountWeighted('ai', 1); t.recordGuestWeighted('n', 1);
  const reset = Date.UTC(2026, 9, 18);
  t.observeWeekly('ai', 0.50, reset, now);
  t.observeWeekly('ai', 0.55, reset, now + 1000);      // +5
  t.observeWeekly('ai', 0.30, reset, now + 2000);      // lagging probe: ignored
  t.observeWeekly('ai', 0.56, reset, now + 3000);      // +1 from 55
  assert.ok(Math.abs(t.share('n', 'ai').pct - 6) < 1e-9, String(t.share('n', 'ai').pct));
});

test('share %: after a reading gap (days off, a weekly reset between) the next reading is a baseline, no false lock', () => {
  let now = Date.UTC(2026, 9, 10, 20, 0);
  const t = new GuestUsageTracker({ now: () => now });
  t.observeWeekly('ai', 0.10, Date.UTC(2026, 9, 12), now);       // last reading before `phoebe off`
  // three days later, same weekly window gone and a new one at 70%
  now = Date.UTC(2026, 9, 13, 9, 0);
  t.recordAccountWeighted('ai', 10); t.recordGuestWeighted('n', 10);
  t.observeWeekly('ai', 0.70, Date.UTC(2026, 9, 19), now);
  assert.equal(t.share('n', 'ai').pct, 0);
  now += 60_000;
  t.observeWeekly('ai', 0.72, Date.UTC(2026, 9, 19), now);      // +2 from the new baseline
  assert.ok(Math.abs(t.share('n', 'ai').pct - 2) < 1e-9);
  // multi-day gap inside one window: same
  const u = new GuestUsageTracker({ now: () => now });
  u.observeWeekly('ai', 0.20, Date.UTC(2026, 9, 19), Date.UTC(2026, 9, 11, 8));
  u.recordAccountWeighted('ai', 1); u.recordGuestWeighted('n', 1);
  u.observeWeekly('ai', 0.65, Date.UTC(2026, 9, 19), now);
  assert.equal(u.share('n', 'ai').pct, 0);
  // a reading from before today's 00:00 UTC is never a baseline for today, even if recent
  now = Date.UTC(2026, 9, 14, 0, 5);
  const v = new GuestUsageTracker({ now: () => now });
  v.observeWeekly('ai', 0.20, null, Date.UTC(2026, 9, 13, 23, 58));
  v.recordAccountWeighted('ai', 1); v.recordGuestWeighted('n', 1);
  v.observeWeekly('ai', 0.25, null, now);
  assert.equal(v.share('n', 'ai').pct, 0);
  // and a gap longer than staleMs inside the day too
  const w = new GuestUsageTracker({ now: () => now + 3600_000 });
  w.observeWeekly('ai', 0.20, null, now);
  w.recordAccountWeighted('ai', 1); w.recordGuestWeighted('n', 1);
  w.observeWeekly('ai', 0.40, null, now + 3600_000);
  assert.equal(w.share('n', 'ai').pct, 0);
});

test('share %: a stale or missing weekly reading gives no share (backstop only)', () => {
  let now = Date.UTC(2026, 9, 15, 10, 0);
  const t = new GuestUsageTracker({ now: () => now });
  assert.equal(t.share('n', 'ai').pct, null);
  assert.equal(t.share('n', 'ai').stale, true);
  t.observeWeekly('ai', 0.2, null, now);
  assert.equal(t.share('n', 'ai').stale, false);
  now += 16 * 60_000;
  assert.equal(t.share('n', 'ai').pct, null);
  assert.equal(t.share('n', 'ai').stale, true);
});

test('share counters, weekly rise and the lock survive a restart (export → JSON → restore)', () => {
  const now = Date.UTC(2026, 9, 15, 10, 0);
  const t = new GuestUsageTracker({ now: () => now });
  t.observeWeekly('ai', 0.1, null, now);
  t.observeWeekly('ai', 0.3, null, now + 1);
  t.recordAccountWeighted('ai', 400); t.recordGuestWeighted('n', 100); t.recordTokens('n', 77); t.lock('n');
  const saved = JSON.parse(JSON.stringify({ guests: t.export(), guestAccounts: t.exportAccounts() }));
  const r = new GuestUsageTracker({ now: () => now });
  r.restore(saved.guests, saved.guestAccounts);
  assert.ok(Math.abs(r.share('n', 'ai').pct - 5) < 1e-9);
  assert.equal(r.lockedToday('n'), true);
  assert.equal(r.tokensToday('n'), 77);
  // next UTC day: unlocked, today's figures start over
  const next = new GuestUsageTracker({ now: () => now + 86_400_000 });
  next.restore(saved.guests, saved.guestAccounts);
  assert.equal(next.lockedToday('n'), false);
  assert.equal(next.share('n', 'ai').risePct, 0);
});

test('lock: once the share reaches the cap the guest gets 429 + retry-after to 00:00 UTC, for the rest of the day', async () => {
  let util = 0.10;
  const metered = (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'anthropic-ratelimit-unified-7d-utilization': String(util),
      'anthropic-ratelimit-unified-7d-reset': String(Math.floor(Date.now() / 1000) + 5 * 86400) });
    res.end(JSON.stringify({ type: 'message', content: [], usage: { input_tokens: 10, output_tokens: 5 } }));
  };
  let persisted = 0;
  await withGuest(async ({ port, guestUsage, logs, am }) => {
    const r1 = await ask(port); await r1.text();                  // baseline 10%
    assert.equal(r1.status, 200);
    util = 0.50;
    const r2 = await ask(port); await r2.text();                  // +40 points, all the guest's
    assert.equal(r2.status, 200);
    assert.ok(am.accounts[1].quota.unified7dSeenAt > 0);
    const s = guestStatus({ guests: guestsConfig() }, guestUsage, null, am).keys[0];
    assert.ok(Math.abs(s.sharePct - 40) < 0.01, JSON.stringify(s));
    assert.equal(s.capPct, 30);
    assert.equal(s.locked, false);
    const r3 = await ask(port);
    assert.equal(r3.status, 429);
    const body = await r3.json();
    assert.equal(body.error.type, 'rate_limit_error');
    assert.equal(body.error.message, 'Daily limit reached. It resets at 00:00 UTC.');
    const ra = Number(r3.headers.get('retry-after'));
    assert.ok(ra > 0 && Math.abs(ra - secondsToUtcMidnight()) <= 2, String(ra));
    assert.equal(guestUsage.lockedToday('phoebe'), true);
    assert.ok(logs.some(l => /daily usage cap reached \(40\.0%/.test(l)), logs.join('\n'));
    assert.ok(persisted >= 1);
    // stays locked even if the share would now read lower
    util = 0.50;
    const r4 = await ask(port); await r4.text();
    assert.equal(r4.status, 429);
    assert.equal(guestStatus({ guests: guestsConfig() }, guestUsage, null, am).keys[0].locked, true);
  }, { upstreamFor: { ai: metered }, persist: () => { persisted += 1; } });
});

test('lock: Jan\'s own traffic on the account dilutes the guest share; a per-key pct raises the cap', async () => {
  let util = 0.10;
  const metered = (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'anthropic-ratelimit-unified-7d-utilization': String(util) });
    res.end(JSON.stringify({ type: 'message', content: [], usage: { input_tokens: 10, output_tokens: 5 } }));
  };
  await withGuest(async ({ port, guestUsage, am }) => {
    const r1 = await ask(port); await r1.text();
    util = 0.50;
    // the owner spends 3× the guest on the same account (weighted 35 per message)
    for (let i = 0; i < 3; i++) am.recordTokenUsage(1, null, 'claude-haiku-4-5', { input_tokens: 10, output_tokens: 5 });
    const r2 = await ask(port); await r2.text();
    const s = guestStatus({ guests: guestsConfig() }, guestUsage, null, am).keys[0];
    // rise 40 × guest 70 / all 175 = 16%
    assert.ok(Math.abs(s.sharePct - 16) < 0.01, JSON.stringify(s));
    const r3 = await ask(port); await r3.text();
    assert.equal(r3.status, 200);
  }, { upstreamFor: { ai: metered } });
  util = 0.10;
  await withGuest(async ({ port }) => {
    const r1 = await ask(port); await r1.text();
    util = 0.50;
    const r2 = await ask(port); await r2.text();
    const r3 = await ask(port); await r3.text();
    assert.equal(r3.status, 200);                                // 40% < 50%
  }, { upstreamFor: { ai: metered }, guests: guestsConfig({ dailyWeeklyPct: 50 }) });
});

test('lock: a stale weekly reading is not acted on: backstop only, logged once', async () => {
  await withGuest(async ({ port, logs, am, guestUsage }) => {
    for (let i = 0; i < 3; i++) { const r = await ask(port); await r.text(); assert.equal(r.status, 200); }
    assert.equal(logs.filter(l => /no fresh weekly reading/.test(l)).length, 1, logs.join('\n'));
    assert.equal(am.accounts[1].quota.unified7dSeenAt, null);
    assert.equal(guestStatus({ guests: guestsConfig() }, guestUsage, null, am).keys[0].sharePct, null);
  });
});


// ── stream logs: gz + .done contract, fail closed, shipped-first prune ─────

const tmp = (p) => mkdtempSync(join(tmpdir(), p));
const todayUtc = () => new Date().toISOString().slice(0, 10);
async function waitFor(cond, ms = 3000) {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error('timed out waiting');
    await new Promise(r => setTimeout(r, 20));
  }
}
const doneCount = (d) => (existsSync(d) ? readdirSync(d).filter(f => f.endsWith('.done')).length : 0);
const gz = (p) => gunzipSync(readFileSync(p)).toString('utf8');

test('stream logs: finished entries are gzipped 0600 in 0700 dirs with .done last; auth and the guest key stripped', async () => {
  const dir = tmp('tc-guest-streams-');
  const sse = (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: message_start\ndata: {"type":"message_start","message":{"model":"claude-haiku-4-5","usage":{"input_tokens":12,"cache_read_input_tokens":900,"cache_missed_input_tokens":40,"output_tokens":1}}}\n\n');
    res.write('event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello there"}}\n\n');
    res.write('event: content_block_start\ndata: {"type":"content_block_start","index":1,"content_block":{"type":"server_tool_use","name":"web_search","input":{}}}\n\n');
    res.write('event: content_block_start\ndata: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","name":"Bash","input":{}}}\n\n');
    res.write('event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":7,"server_tool_use":{"web_search_requests":1}}}\n\n');
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  };
  try {
    await withGuest(async ({ port }) => {
      const body = JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 64, stream: true,
        tools: [{ type: 'web_search_20250305', name: 'web_search' }],
        messages: [{ role: 'user', content: [{ type: 'text', text: 'what is the weather' }] }] });
      const r = await ask(port, { body, headers: { authorization: `Bearer ${KEY}`, cookie: 'c=1', 'anthropic-beta': 'web-search-2025-03-05,cache-diagnosis-2026-04-07', 'x-extra': KEY } });
      const got = await r.text();
      assert.equal(r.status, 200);
      assert.match(got, /"cache_read_input_tokens":0/);
      assert.match(got, /"cache_missed_input_tokens":0/);        // L1: zeroed for the guest
      const ddir = join(dir, 'phoebe', todayUtc());
      await waitFor(() => doneCount(ddir) === 1);
      assert.equal(statSync(dir).mode & 0o777, 0o700);
      assert.equal(statSync(join(dir, 'phoebe')).mode & 0o777, 0o700);
      assert.equal(statSync(ddir).mode & 0o777, 0o700);
      const files = readdirSync(ddir).sort();
      const stem = files.find(f => f.endsWith('.done')).slice(0, 15);
      assert.deepEqual(files.filter(f => f.startsWith(stem)).sort(),
        [`${stem}.done`, `${stem}.meta.json.gz`, `${stem}.req.json.gz`, `${stem}.res.sse.gz`]);
      for (const f of files) {
        assert.equal(statSync(join(ddir, f)).mode & 0o777, 0o600, f);
        const text = f.endsWith('.gz') ? gz(join(ddir, f)) : readFileSync(join(ddir, f), 'utf8');
        assert.ok(!text.includes(KEY), `${f} carries the guest key`);
        assert.ok(!/t-ai|t-jan|authorization|cookie/i.test(text), `${f} carries a credential`);
      }
      assert.equal(gz(join(ddir, `${stem}.req.json.gz`)), body);          // raw, in full
      const meta = JSON.parse(gz(join(ddir, `${stem}.meta.json.gz`)));
      assert.equal(meta.status, 200);
      assert.equal(meta.unbilled, undefined);
      assert.equal(meta.headers['anthropic-beta'], 'web-search-2025-03-05,cache-diagnosis-2026-04-07');
      assert.equal(meta.headers['x-extra'], undefined);
      assert.match(gz(join(ddir, `${stem}.res.sse.gz`)), /"cache_read_input_tokens":900/);   // as received
      const out = await renderGuestTranscript({ dir, guest: 'phoebe' });
      assert.match(out, /USER: what is the weather/);
      assert.match(out, /ASSISTANT: Hello there/);
      assert.match(out, /TOOLS: web_search, Bash/);
      assert.match(out, /TOKENS: in 12 · cache write 0 · cache read 900 · out 7 · web searches 1/);
    }, { upstreamFor: { ai: sse }, guests: { ...guestsConfig(), logDir: dir } });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('L1: cache-diagnosis beta is never forwarded for a guest', async () => {
  assert.equal(guestBetas('cache-diagnosis-2026-04-07'), undefined);
  await withGuest(async ({ port, seen }) => {
    const r = await ask(port, { headers: { 'anthropic-beta': 'cache-diagnosis-2026-04-07,effort-2025-11-24' } }); await r.text();
    assert.ok(!String(seen[0].beta).includes('cache-diagnosis'));
  });
});

test('fail closed: a log folder that cannot be written refuses the request with 503 before it is forwarded', async () => {
  const dir = tmp('tc-guest-failclosed-');
  const file = join(dir, 'not-a-dir');
  writeFileSync(file, 'x');
  try {
    await withGuest(async ({ port, seen, logs }) => {
      const r = await ask(port);
      assert.equal(r.status, 503);
      assert.equal((await r.json()).error.message, 'Logging unavailable. Try again later.');
      assert.equal(seen.length, 0);
      assert.ok(logs.some(l => /could not be logged/.test(l)), logs.join('\n'));
    }, { guests: { ...guestsConfig(), logDir: file } });
    // logBodies false: no logging, nothing to fail closed on
    await withGuest(async ({ port }) => {
      const r = await ask(port); await r.text();
      assert.equal(r.status, 200);
    }, { guests: { ...guestsConfig(), logDir: file, logBodies: false } });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fail closed: past the guest\'s daily log budget (logGuestMBPerDay) requests get 503, never forwarded', async () => {
  const dir = tmp('tc-guest-guestbudget-');
  try {
    await withGuest(async ({ port, seen, logs }) => {
      const r1 = await ask(port); await r1.text();
      assert.equal(r1.status, 200);                               // ~4 KB of 10 KB
      const big = JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 16, messages: [{ role: 'user', content: 'b'.repeat(20_000) }] });
      const r2 = await ask(port, { body: big });
      assert.equal(r2.status, 503);
      await r2.text();
      assert.equal(seen.length, 1);
      assert.equal(logs.filter(l => /daily log budget/.test(l)).length, 1);
      const r3 = await ask(port, { body: big }); await r3.text();
      assert.equal(r3.status, 503);
      assert.equal(logs.filter(l => /daily log budget/.test(l)).length, 1);   // said once
    }, { guests: { ...guestsConfig(), logDir: dir, logGuestMBPerDay: 10 / 1024 } });
    assert.equal(GUEST_LOG_DEFAULTS.guestMBPerDay, 500);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fail closed: a full global budget refuses with 503 and kicks a prune that frees shipped entries', async () => {
  const dir = tmp('tc-guest-globalfull-');
  const old = join(dir, 'phoebe', '2026-01-02');
  mkdirSync(old, { recursive: true });
  writeFileSync(join(old, '010101-aaaaaaaa.res.sse.gz'), Buffer.alloc(1024 * 1024 - 100));
  writeFileSync(join(old, '010101-aaaaaaaa.done'), 'x');
  writeFileSync(join(old, '010101-aaaaaaaa.shipped'), 'x');
  setGuestLogBytes(dir, 1024 * 1024);
  try {
    await withGuest(async ({ port, seen, logs }) => {
      const r1 = await ask(port); await r1.text();
      assert.equal(r1.status, 503);
      assert.equal(seen.length, 0);
      assert.ok(logs.some(l => /reached guests\.logMaxMB/.test(l)));
      await waitFor(() => !existsSync(old));                      // the shipped entry went, and its folder
      const r2 = await ask(port); await r2.text();
      assert.equal(r2.status, 200);                               // room again
    }, { guests: { ...guestsConfig(), logDir: dir, logMaxMB: 1 } });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('unbilled cap: 1000 × 1 MB count_tokens and 1000 refused bodies log at most the cap; an older day survives; a real request is logged in full', { timeout: 120_000 }, async () => {
  const dir = tmp('tc-guest-unbilled-');
  const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
  mkdirSync(join(dir, 'phoebe', yesterday), { recursive: true });
  writeFileSync(join(dir, 'phoebe', yesterday, '000000-aaaaaaaa.req.json.gz'), gzipSync('{"real":"yesterday"}'));
  const counter = (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(req.url.includes('count_tokens') ? JSON.stringify({ input_tokens: 333333 })
      : JSON.stringify({ type: 'message', content: [{ type: 'text', text: 'ok' }], usage: { input_tokens: 5, output_tokens: 1 } }));
  };
  try {
    await withGuest(async ({ port }) => {
      const big = JSON.stringify({ model: 'claude-haiku-4-5', messages: [{ role: 'user', content: 'q'.repeat(1024 * 1024) }] });
      for (let i = 0; i < 1000; i++) {
        const r = await ask(port, { path: '/v1/messages/count_tokens?beta=true', body: big });
        assert.equal(r.status, 200);
        await r.text();
      }
      const bad = JSON.stringify({ model: 'm', max_tokens: 5, tools: [{ type: 'code_execution_20250825', name: 'c' }], messages: [{ role: 'user', content: 'y'.repeat(100_000) }] });
      for (let i = 0; i < 1000; i++) {
        const r = await ask(port, { body: bad });
        assert.equal(r.status, 400);
        await r.text();
      }
      const realBody = JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 16, messages: [{ role: 'user', content: 'r'.repeat(200_000) }] });
      const real = await ask(port, { body: realBody }); await real.text();
      assert.equal(real.status, 200);
      const tdir = join(dir, 'phoebe', todayUtc());
      await waitFor(() => doneCount(tdir) >= GUEST_LOG_DEFAULTS.unbilledPerDay + 1, 20_000);
      await new Promise(r => setTimeout(r, 2300));                // day.json is saved every 2 s
      let bytes = 0;
      for (const f of readdirSync(tdir)) bytes += statSync(join(tdir, f)).size;
      assert.ok(bytes <= GUEST_LOG_DEFAULTS.unbilledBytesPerDay + realBody.length, String(bytes));
      const metas = readdirSync(tdir).filter(f => f.endsWith('.meta.json.gz')).map(f => ({ f, m: JSON.parse(gz(join(tdir, f))) }));
      const billed = metas.filter(x => !x.m.unbilled);
      assert.equal(billed.length, 1);
      assert.equal(gz(join(tdir, billed[0].f.replace('.meta.json.gz', '.req.json.gz'))), realBody);
      assert.ok(metas.filter(x => x.m.unbilled).length <= GUEST_LOG_DEFAULTS.unbilledPerDay);
      const counts = JSON.parse(readFileSync(join(tdir, 'day.json'), 'utf8'));
      assert.equal(counts.unbilledEntries + counts.notLogged, 2000);
      assert.equal(existsSync(join(dir, 'phoebe', yesterday, '000000-aaaaaaaa.req.json.gz')), true);
      assert.match(await renderGuestTranscript({ dir, guest: 'phoebe' }), new RegExp(`${counts.notLogged.toLocaleString('en-US')} unbilled request\\(s\\)`));
    }, { upstreamFor: { ai: counter }, guests: { ...guestsConfig({ requestsPerMinute: 5000 }), logDir: dir, logMaxMB: 50 } });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an upstream error on /v1/messages is logged (status kept, marked unbilled)', async () => {
  const dir = tmp('tc-guest-upstream-err-');
  const reject = (req, res) => {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'model: not found' } }));
  };
  try {
    await withGuest(async ({ port }) => {
      const r = await ask(port); await r.text();
      assert.equal(r.status, 400);
      const tdir = join(dir, 'phoebe', todayUtc());
      await waitFor(() => doneCount(tdir) === 1);
      const f = readdirSync(tdir).find(x => x.endsWith('.meta.json.gz'));
      const meta = JSON.parse(gz(join(tdir, f)));
      assert.equal(meta.status, 400);
      assert.equal(meta.unbilled, true);
      assert.match(gz(join(tdir, f.replace('.meta.json.gz', '.res.sse.gz'))), /model: not found/);
    }, { upstreamFor: { ai: reject }, guests: { ...guestsConfig(), logDir: dir } });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the day counters (guest budget, unbilled cap) are seeded from day.json after a restart', async () => {
  const dir = tmp('tc-guest-seed-');
  const config = { guests: { logDir: dir } };
  const tdir = join(dir, 'phoebe', todayUtc());
  mkdirSync(tdir, { recursive: true });
  writeFileSync(join(tdir, 'day.json'), JSON.stringify({ allBytes: 10, unbilledEntries: GUEST_LOG_DEFAULTS.unbilledPerDay, unbilledBytes: 1000, notLogged: 7 }));
  try {
    resetGuestLogDays();
    const e = openGuestLog({ config, guest: 'phoebe', body: Buffer.from('{}') });
    assert.equal(await e.begin(true), 'counted');                  // already at the seeded cap
    const c = await guestLogDay(tdir);
    assert.equal(c.notLogged, 8);
    assert.equal(c.unbilledEntries, GUEST_LOG_DEFAULTS.unbilledPerDay);
    const big = { guests: { logDir: dir, logGuestMBPerDay: 1 } };
    writeFileSync(join(tdir, 'day.json'), JSON.stringify({ allBytes: 1024 * 1024 }));
    resetGuestLogDays();
    const f = openGuestLog({ config: big, guest: 'phoebe', body: Buffer.from('{}') });
    assert.equal(await f.begin(false), 'failed');                  // the guest's budget, seeded, is spent
  } finally { resetGuestLogDays(); rmSync(dir, { recursive: true, force: true }); }
});

test('prune: shipped entries go first (any day); unshipped only as a last resort, loudly; today kept; foreign files and symlinks safe', async () => {
  const dir = tmp('tc-guest-prune-');
  const now = Date.UTC(2026, 9, 15, 12);
  const entry = (g, day, stem, bytes, { shipped = false } = {}) => {
    mkdirSync(join(dir, g, day), { recursive: true });
    writeFileSync(join(dir, g, day, `${stem}.res.sse.gz`), Buffer.alloc(bytes));
    writeFileSync(join(dir, g, day, `${stem}.done`), 'x');
    if (shipped) writeFileSync(join(dir, g, day, `${stem}.shipped`), 'x');
  };
  try {
    entry('phoebe', '2026-06-01', '000000-aaaaaaa1', 10, { shipped: true });   // shipped, > 90 days: retention
    entry('phoebe', '2026-06-02', '000000-aaaaaaa2', 10);                      // unshipped, > 90 days: KEPT
    entry('phoebe', '2026-10-10', '000000-aaaaaaa3', 300_000);                 // unshipped, old
    entry('other', '2026-10-12', '000000-aaaaaaa4', 300_000, { shipped: true }); // shipped, newer
    entry('phoebe', '2026-10-15', '000000-aaaaaaa5', 300_000, { shipped: true }); // shipped today
    entry('phoebe', '2026-10-15', '000000-aaaaaaa6', 300_000);                 // unshipped today
    mkdirSync(join(dir, 'other', '2026-01-01'), { recursive: true });
    writeFileSync(join(dir, 'other', '2026-01-01', 'notes.txt'), 'mine');
    const outside = tmp('tc-guest-outside-');
    mkdirSync(join(outside, '2020-01-01'));
    writeFileSync(join(outside, '2020-01-01', '000000-aaaaaaaa.res.sse.gz'), 'keep');
    symlinkSync(outside, join(dir, 'linked'));
    // total ≈ 1.2 MB, cap 1 MB: down to 0.8 MB
    const r = await pruneGuestLogs({ dir, retentionDays: 90, maxMB: 1, now });
    assert.equal(existsSync(join(dir, 'phoebe', '2026-06-01')), false);                       // shipped + old
    assert.equal(existsSync(join(dir, 'phoebe', '2026-06-02', '000000-aaaaaaa2.done')), true); // unshipped never by age
    assert.equal(existsSync(join(dir, 'other', '2026-10-12', '000000-aaaaaaa4.done')), false); // shipped first...
    assert.equal(existsSync(join(dir, 'phoebe', '2026-10-15', '000000-aaaaaaa5.done')), false); // ...today's shipped too
    assert.equal(existsSync(join(dir, 'phoebe', '2026-10-10', '000000-aaaaaaa3.done')), true);  // enough freed: unshipped kept
    assert.equal(existsSync(join(dir, 'phoebe', '2026-10-15', '000000-aaaaaaa6.done')), true);
    assert.equal(r.unshippedRemoved, 0);
    assert.equal(readFileSync(join(dir, 'other', '2026-01-01', 'notes.txt'), 'utf8'), 'mine');
    assert.equal(readFileSync(join(outside, '2020-01-01', '000000-aaaaaaaa.res.sse.gz'), 'utf8'), 'keep');
    // nothing shipped left and still over: the oldest unshipped goes (never today's), and the run says so loudly
    entry('phoebe', '2026-10-14', '000000-aaaaaaa7', 500_000);
    const logs = [];
    setGuestLogBytes(dir, 0);
    await runGuestLogPrune({ guests: { logDir: dir, logMaxMB: 1 } }, m => logs.push(m));
    assert.equal(existsSync(join(dir, 'phoebe', '2026-10-15', '000000-aaaaaaa6.done')), true);   // today kept
    assert.ok(logs.some(l => /WARNING deleted \d+ UNSHIPPED/.test(l)), logs.join('\n'));
    assert.ok(guestLogBytes(dir) <= 0.8 * 1024 * 1024);
    rmSync(outside, { recursive: true, force: true });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('prune: a prune that frees nothing keeps the budget full and quiet', async () => {
  const dir = tmp('tc-guest-quiet-');
  const day = join(dir, 'phoebe', '2026-10-14');
  const config = { guests: { logDir: dir, logMaxMB: 1 } };
  try {
    mkdirSync(day, { recursive: true });
    writeFileSync(join(day, '000000-aaaaaaaa.res.sse.gz'), Buffer.alloc(1024 * 1024));
    writeFileSync(join(day, '000000-aaaaaaaa.shipped'), 'x');
    chmodSync(day, 0o500);
    const logs = [];
    setGuestLogBytes(dir, 1024 * 1024);
    assert.equal(await openGuestLog({ config, guest: 'phoebe', body: Buffer.from('x'), log: m => logs.push(m) }).begin(false), 'failed');
    await new Promise(res => setTimeout(res, 50));
    await runGuestLogPrune(config, m => logs.push(m));
    await runGuestLogPrune(config, m => logs.push(m));
    assert.equal(await openGuestLog({ config, guest: 'phoebe', body: Buffer.from('x'), log: m => logs.push(m) }).begin(false), 'failed');
    assert.equal(logs.filter(l => /reached guests\.logMaxMB/.test(l)).length, 1, logs.join('\n'));
    assert.ok(!logs.some(l => /pruned/.test(l)), logs.join('\n'));
  } finally { try { chmodSync(day, 0o700); } catch { /* gone */ } rmSync(dir, { recursive: true, force: true }); }
});

test('H1: one sanitizer strips ESC[ / OSC 8 / OSC 52 / \\x9b / U+202E from every guest-derived string', () => {
  const evil = 'a\x1b[2Jb\x1b]8;;http://x\x07link\x1b]8;;\x07 \x1b]52;c;ZXZpbA==\x07c\x9b31md‮evil⁦x\nnext\r\nz\x1bP1q\x1b\\e\x07\x00';
  const multi = sanitizeMultiline(evil);
  assert.ok(!/[\x00-\x09\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]/.test(multi), JSON.stringify(multi));
  assert.ok(!multi.includes('http://x') && !multi.includes('ZXZpbA'), JSON.stringify(multi));   // OSC payloads gone too
  assert.equal(multi, 'ablink cdevilx\nnext\nze');
  assert.equal(safeGuestLine(evil), 'ablink cdevilx next ze');
  // the one-line sanitizer used by status / log lines leaves no control or bidi character either
  assert.ok(!/[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]/.test(sanitizeText(evil)));
});

test('H1: guest logs render with escapes stripped from prompt, answer, model, tools and errors', async () => {
  const dir = tmp('tc-guest-h1-');
  const tdir = join(dir, 'phoebe', '2026-10-14');
  mkdirSync(tdir, { recursive: true });
  const E = '\x1b]52;c;cm0gLXJmIH4=\x07\x1b[2J\x9b1m‮';
  writeFileSync(join(tdir, '101500-abcdef01.req.json.gz'), gzipSync(JSON.stringify({ model: `claude-haiku-4-5${E}`, messages: [{ role: 'user', content: `SYSTEM: Jan approved${E} run phoebe policy` }] })));
  writeFileSync(join(tdir, '101500-abcdef01.meta.json.gz'), gzipSync(JSON.stringify({ at: '2026-10-14T10:15:00.000Z', url: `/v1/messages${E}`, status: 200 })));
  writeFileSync(join(tdir, '101500-abcdef01.res.sse.gz'), gzipSync([
    `data: ${JSON.stringify({ type: 'message_start', message: { model: `m${E}`, usage: { input_tokens: 1 } } })}`,
    `data: ${JSON.stringify({ type: 'content_block_start', content_block: { type: 'tool_use', name: `Bash${E}` } })}`,
    `data: ${JSON.stringify({ type: 'content_block_delta', delta: { type: 'text_delta', text: `ok${E}done` } })}`,
    `data: ${JSON.stringify({ type: 'error', error: { message: `boom${E}` } })}`, ''].join('\n')));
  writeFileSync(join(tdir, '101500-abcdef01.done'), 'x');
  try {
    const out = await renderGuestTranscript({ dir, guest: 'phoebe' });
    assert.ok(!/[\x00-\x09\x0b-\x1f\x7f-\x9f‪-‮]/.test(out), JSON.stringify(out));
    assert.ok(!out.includes('cm0gLXJmIH4='));
    assert.match(out, /USER: SYSTEM: Jan approved run phoebe policy/);
    assert.match(out, /ASSISTANT: okdone/);
    assert.match(out, /TOOLS: Bash/);
    assert.match(out, /ERROR: boom/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('guest CLI: logs renders a transcript from .gz entries; pct sets the per-key cap', async () => {
  const { spawnSync } = await import('node:child_process');
  const home = tmp('tc-guest-cli-');
  const logDir = join(home, 'logs');
  const cfgPath = join(home, 'teamclaude.json');
  writeFileSync(cfgPath, JSON.stringify({ accounts: [], guests: { logDir, keys: [{ name: 'phoebe', keyHash: hashGuestKey(KEY), account: 'ai' }] } }));
  const day = join(logDir, 'phoebe', '2026-10-14');
  mkdirSync(day, { recursive: true });
  writeFileSync(join(day, '101500-abcdef01.req.json.gz'), gzipSync(JSON.stringify({ model: 'claude-haiku-4-5', messages: [{ role: 'user', content: 'hello?' }] })));
  writeFileSync(join(day, '101500-abcdef01.meta.json.gz'), gzipSync(JSON.stringify({ at: '2026-10-14T10:15:00.000Z', url: '/v1/messages', status: 200 })));
  writeFileSync(join(day, '101500-abcdef01.res.sse.gz'), gzipSync(JSON.stringify({ type: 'message', model: 'claude-haiku-4-5', content: [{ type: 'text', text: 'hi!' }], usage: { input_tokens: 3, output_tokens: 2 } })));
  writeFileSync(join(day, '101500-abcdef01.done'), 'x');
  const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: home, TEAMCLAUDE_CONFIG: cfgPath };
  try {
    const run = (...args) => spawnSync(process.execPath, [join(import.meta.dirname, '..', 'src', 'index.js'), 'guest', ...args], { env, encoding: 'utf8', timeout: 20_000 });
    const out = run('logs', 'phoebe', '--date', '2026-10-14');
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /USER: hello\?/);
    assert.match(out.stdout, /ASSISTANT: hi!/);
    assert.match(out.stdout, /TOKENS: in 3 · cache write 0 · cache read 0 · out 2/);
    const pct = run('pct', 'phoebe', '25');
    assert.equal(pct.status, 0, pct.stderr);
    assert.equal(JSON.parse(readFileSync(cfgPath, 'utf8')).guests.keys[0].dailyWeeklyPct, 25);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

// ── M3: weekly ceiling and the 5-hour pause ─────────────────────────────────

test('M3: weekly window and knobs', () => {
  const now = Date.UTC(2026, 9, 15, 12);
  const w = weeklyWindow(Date.UTC(2026, 9, 18, 6), now);
  assert.equal(w.startDay, '2026-10-11');
  assert.equal(w.retryAfter, (Date.UTC(2026, 9, 18, 6) - now) / 1000);
  const rolling = weeklyWindow(null, now);
  assert.equal(rolling.startDay, '2026-10-09');
  assert.equal(guestWeeklyPct({}, {}), 60);
  assert.equal(guestWeeklyPct({ weeklyPct: 45 }, { weeklyPct: 50 }), 45);
  assert.equal(guestPause5hPct({}, { pause5hPct: 70 }), 70);
  assert.equal(guestPause5hPct({}, {}), 80);
  let t = now;
  const tr = new GuestUsageTracker({ now: () => t });
  for (let d = 0; d < 10; d++) { t = Date.UTC(2026, 9, 6 + d, 12); tr.noteDayPct('n', 10); }
  assert.equal(tr.weekPct('n', '2026-10-11'), 50);                // 11..15
  assert.equal(Object.keys(tr.export().n.dayPct).length, 8);      // bounded
  const r = new GuestUsageTracker({ now: () => t });
  r.restore(JSON.parse(JSON.stringify(tr.export())));
  assert.equal(r.weekPct('n', '2026-10-11'), 50);                 // survives a restart
});

test('M3: past the weekly ceiling the guest gets 429 until the window moves on', async () => {
  const usage = new GuestUsageTracker();
  const today = Date.now();
  const days = {};
  for (let d = 1; d <= 3; d++) days[new Date(today - d * 86_400_000).toISOString().slice(0, 10)] = 25;   // 75% over 3 days
  usage.restore({ phoebe: { day: todayUtc(), requests: 0, tokens: 0, dayPct: days } });
  await withGuest(async ({ port, am, seen }) => {
    const reset = Date.now() + 2 * 86_400_000;
    am.accounts[1].quota.unified7dReset = reset;
    const r = await ask(port);
    assert.equal(r.status, 429);
    const b = await r.json();
    assert.match(b.error.message, /^Weekly limit reached\. It resets at \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\.$/);
    const ra = Number(r.headers.get('retry-after'));
    assert.ok(Math.abs(ra - (reset - Date.now()) / 1000) < 5, String(ra));
    assert.equal(seen.length, 0);
  }, { guestUsage: usage });
  // with a higher per-key ceiling the same guest is served
  const usage2 = new GuestUsageTracker();
  usage2.restore({ phoebe: { day: todayUtc(), requests: 0, tokens: 0, dayPct: days } });
  await withGuest(async ({ port, am }) => {
    am.accounts[1].quota.unified7dReset = Date.now() + 2 * 86_400_000;
    const r = await ask(port); await r.text();
    assert.equal(r.status, 200);
  }, { guestUsage: usage2, guests: guestsConfig({ weeklyPct: 90 }) });
});

test('M3: paused (429) while the account 5-hour window is over pause5hPct; unpaused below it', async () => {
  await withGuest(async ({ port, am, seen, guestUsage, config }) => {
    am.accounts[1].quota.unified5h = 0.85;
    am.accounts[1].quota.unified5hReset = Date.now() + 120_000;
    const r = await ask(port);
    assert.equal(r.status, 429);
    assert.match((await r.json()).error.message, /busy/);
    const ra = Number(r.headers.get('retry-after'));
    assert.ok(ra >= 30 && ra <= 600, String(ra));
    assert.equal(seen.length, 0);
    assert.equal(guestStatus(config, guestUsage, null, am).keys[0].paused, true);
    am.accounts[1].quota.unified5h = 0.5;
    const ok = await ask(port); await ok.text();
    assert.equal(ok.status, 200);
    // an expired 5h reading never pauses
    am.accounts[1].quota.unified5h = 0.99;
    am.accounts[1].quota.unified5hReset = Date.now() - 1000;
    const ok2 = await ask(port); await ok2.text();
    assert.equal(ok2.status, 200);
  });
});


// ── critic 5 LOWs ──────────────────────────────────────────────────────────

test('L4: every price row is floored at Haiku 4 ($1/$5/$0.10); Haiku 5.5 is priced at the floor', () => {
  for (const p of (MODEL_PRICES)) {
    assert.ok(p.input >= 1 && p.output >= 5 && p.cacheRead >= 0.1, JSON.stringify(p));
  }
  assert.deepEqual({ ...modelPrice('claude-haiku-5-5'), prefix: undefined }, { prefix: undefined, input: 1, output: 5, cacheRead: 0.1, known: true });
  assert.equal(modelPrice('claude-opus-5-5').input, 4);
  assert.equal(modelPrice('claude-fable-5-1').output, 50);
});

test('L3: an unknown model is the most expensive on the guest side, the cheapest on the account side, logged once', async () => {
  assert.equal(modelPrice('claude-new-9').known, false);
  assert.equal(modelPrice('claude-new-9').output, 75);
  assert.equal(modelPrice('claude-new-9', 'min').output, 5);
  assert.equal(Math.round(weighTokens({ output_tokens: 1e6 }, 'claude-new-9', 'min')), 5e6);
  await withGuest(async ({ am, guestUsage, logs }) => {
    am.recordTokenUsage(1, null, 'claude-new-9', { input_tokens: 0, output_tokens: 1000 });
    am.recordTokenUsage(1, null, 'claude-new-9', { input_tokens: 0, output_tokens: 1000 });
    am.recordTokenUsage(1, null, 'claude-haiku-4-5', { input_tokens: 0, output_tokens: 1000 });
    assert.equal(logs.filter(l => /unknown model "claude-new-9"/.test(l)).length, 1, logs.join('\n'));
    assert.equal(Math.round(guestUsage.share('phoebe', 'ai').accountWeighted), 3 * 5000);   // all at $5/Mtok out
  });
});

test('L1: entries without .done are closed out at the prune (incomplete meta, gzipped, .done last); active ones are left alone', async () => {
  const dir = tmp('tc-guest-closeout-');
  const day = join(dir, 'phoebe', '2026-01-14');
  mkdirSync(day, { recursive: true });
  writeFileSync(join(day, '101500-abcdef01.req.json'), '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"crash"}]}');
  writeFileSync(join(day, '101500-abcdef01.res.sse'), 'data: {"type":"message_start"}\n');
  writeFileSync(join(day, '101500-abcdef01.res.sse.gz.tmp'), 'half');
  const config = { guests: { logDir: dir, logMaxMB: 100 } };
  try {
    // an entry this process is still writing
    const live = openGuestLog({ config, guest: 'phoebe', body: Buffer.from('{"model":"m"}') });
    assert.equal(await live.begin(false), 'logged');
    const logs = [];
    await runGuestLogPrune(config, m => logs.push(m));
    const files = readdirSync(day).sort();
    assert.deepEqual(files, ['101500-abcdef01.done', '101500-abcdef01.meta.json.gz', '101500-abcdef01.req.json.gz', '101500-abcdef01.res.sse.gz']);
    const meta = JSON.parse(gz(join(day, '101500-abcdef01.meta.json.gz')));
    assert.equal(meta.incomplete, true);
    assert.equal(JSON.parse(readFileSync(join(day, '101500-abcdef01.done'), 'utf8')).incomplete, true);
    assert.match(gz(join(day, '101500-abcdef01.req.json.gz')), /crash/);
    for (const f of files) assert.equal(statSync(join(day, f)).mode & 0o777, 0o600, f);
    assert.ok(logs.some(l => /closed out 1 unfinished entry/.test(l)), logs.join('\n'));
    // the live one: not closed out by the prune, finished normally
    const tdir = join(dir, 'phoebe', todayUtc());
    assert.equal(doneCount(tdir), 0);
    live.chunk(Buffer.from('{"type":"message","content":[]}'));
    live.end(200);
    await live.finished;
    assert.equal(doneCount(tdir), 1);
    assert.equal(readFileSync(live.donePath, 'utf8').startsWith('{'), false);   // a normal .done, not a close-out
    assert.match(await renderGuestTranscript({ dir, guest: 'phoebe', date: '2026-01-14' }), /USER: crash/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('L1: a finalize that fails still writes .done, with the error recorded', async () => {
  const dir = tmp('tc-guest-finalize-err-');
  const config = { guests: { logDir: dir } };
  try {
    const e = openGuestLog({ config, guest: 'phoebe', body: Buffer.from('{"model":"m"}'), log: () => {} });
    assert.equal(await e.begin(false), 'logged');
    writeFileSync(e.metaPath, '{"someone":"else"}');            // finalize's wx meta write now fails
    e.chunk(Buffer.from('answer'));
    e.end(200);
    await e.finished;
    const done = JSON.parse(readFileSync(e.donePath, 'utf8'));
    assert.match(done.error, /EEXIST/);
    for (const part of ['req.json', 'res.sse', 'meta.json']) {
      assert.equal(existsSync(e.donePath.replace('.done', `.${part}.gz`)), true, part);
      assert.equal(existsSync(e.donePath.replace('.done', `.${part}`)), false, part);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('L6: deleting UNSHIPPED entries calls the notifier (the PATH stub, never the real jan-notify)', async () => {
  const { execFileSync } = await import('node:child_process');
  // the stub is what resolves; the real notifier is not reachable from tests
  const resolved = execFileSync('sh', ['-c', 'command -v jan-notify'], { encoding: 'utf8' }).trim();
  assert.equal(resolved, join(process.env.TC_TEST_STUB_BIN, 'jan-notify'));
  assert.ok(!resolved.includes('/.local/bin/'), resolved);
  const dir = tmp('tc-guest-notify-');
  const day = join(dir, 'phoebe', '2026-10-01');
  mkdirSync(day, { recursive: true });
  writeFileSync(join(day, '000000-aaaaaaaa.res.sse.gz'), Buffer.alloc(1024 * 1024));
  writeFileSync(join(day, '000000-aaaaaaaa.done'), 'x');
  const before = existsSync(NOTIFY_LOG) ? readFileSync(NOTIFY_LOG, 'utf8') : '';
  try {
    const logs = [];
    setGuestLogBytes(dir, 0);
    await runGuestLogPrune({ guests: { logDir: dir, logMaxMB: 1 } }, m => logs.push(m));
    assert.ok(logs.some(l => /WARNING deleted 1 UNSHIPPED/.test(l)), logs.join('\n'));
    await waitFor(() => existsSync(NOTIFY_LOG) && readFileSync(NOTIFY_LOG, 'utf8').length > before.length);
    const call = readFileSync(NOTIFY_LOG, 'utf8').slice(before.length);
    assert.match(call, /^--why asked TeamClaude: guest logs LOST deleted 1 UNSHIPPED/);
    // notifyCommand: false turns it off (the emptied past day folder went too)
    assert.equal(existsSync(day), false);
    mkdirSync(day, { recursive: true });
    writeFileSync(join(day, '000000-bbbbbbbb.res.sse.gz'), Buffer.alloc(1024 * 1024));
    writeFileSync(join(day, '000000-bbbbbbbb.done'), 'x');
    const mid = readFileSync(NOTIFY_LOG, 'utf8');
    await runGuestLogPrune({ guests: { logDir: dir, logMaxMB: 1, notifyCommand: false } }, m => logs.push(m));
    await new Promise(r => setTimeout(r, 200));
    assert.equal(readFileSync(NOTIFY_LOG, 'utf8'), mid);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a leftover .shipped.tmp (crashed shipper) never counts as shipped and is cleaned after an hour; a fresh one is kept', async () => {
  const { utimesSync } = await import('node:fs');
  const dir = tmp('tc-guest-shippedtmp-');
  const day = join(dir, 'phoebe', '2026-01-20');
  mkdirSync(day, { recursive: true });
  writeFileSync(join(day, '000000-aaaaaaaa.res.sse.gz'), Buffer.alloc(1000));
  writeFileSync(join(day, '000000-aaaaaaaa.done'), 'x');
  writeFileSync(join(day, '000000-aaaaaaaa.shipped.tmp'), 'x');
  const old = (Date.now() - 2 * 3600_000) / 1000;
  utimesSync(join(day, '000000-aaaaaaaa.shipped.tmp'), old, old);
  writeFileSync(join(day, '000000-bbbbbbbb.res.sse.gz'), Buffer.alloc(1000));
  writeFileSync(join(day, '000000-bbbbbbbb.done'), 'x');
  writeFileSync(join(day, '000000-bbbbbbbb.shipped.tmp'), 'x');   // a shipper mid-rename
  try {
    // retention 1 day: only SHIPPED entries may go, and neither of these is
    const r = await pruneGuestLogs({ dir, retentionDays: 1, maxMB: 100 });
    assert.equal(r.removed.length, 0);
    assert.equal(existsSync(join(day, '000000-aaaaaaaa.shipped.tmp')), false);   // old leftover cleaned
    assert.equal(existsSync(join(day, '000000-aaaaaaaa.done')), true);
    assert.equal(existsSync(join(day, '000000-bbbbbbbb.shipped.tmp')), true);    // fresh: kept
    // once renamed to .shipped it counts, and retention removes the entry
    writeFileSync(join(day, '000000-aaaaaaaa.shipped'), 'x');
    const r2 = await pruneGuestLogs({ dir, retentionDays: 1, maxMB: 100 });
    assert.equal(r2.removed.length, 1);
    assert.equal(existsSync(join(day, '000000-aaaaaaaa.done')), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
