// Sticky sessions (KAN-2393): a running conversation stays on the account it
// started on until that account genuinely cannot serve (429 / exhausted /
// 100%). Priority changes (a manual switch) and window rollovers steer only NEW
// conversations.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AccountManager } from '../src/account-manager.js';
import { SessionTracker } from '../src/session-tracker.js';
import { createProxyServer } from '../src/server.js';

const H = 3600_000;
const WEEK = 7 * 24 * H;
const OPUS = 'claude-opus-5';
const ON = { enabled: true, preempt: true };

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't-' + name, refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

function fleet({ sticky = true, threshold = 1, tracker } = {}) {
  const am = new AccountManager([oauth('a', { priority: 0 }), oauth('b', { priority: 1 })], threshold, {
    distributeSessions: 'adaptive', expiryRouting: ON, stickySessions: sticky, sessionTracker: tracker,
  });
  for (const i of [0, 1]) {
    const q = am.accounts[i].quota;
    q.unified7d = 0.4; q.unified7dReset = Date.now() + 10 * H;
    q.unified5h = 0.1; q.unified5hReset = Date.now() + 2 * H;
    am.accounts[i].probing = false;
  }
  return am;
}

function serve(am, sid, { exclude = null } = {}) {
  am.beginSession(sid);
  const acc = am.getActiveAccount(exclude, OPUS, null, sid);
  if (acc) am.recordSession(sid, acc.index, OPUS);
  am.endSession(sid);
  return acc;
}

// Flip priorities the way a manual `teamclaude switch` does: b now outranks a.
function preferB(am) { am.accounts[0].priority = 1; am.accounts[1].priority = 0; }

test('control: without sticky, a priority change moves a running session', () => {
  const am = fleet({ sticky: false });
  assert.equal(serve(am, 's1').name, 'a');
  preferB(am);
  assert.equal(serve(am, 's1').name, 'b');
});

test('sticky: a priority change does NOT move a running session; new sessions follow it', () => {
  const am = fleet();
  assert.equal(serve(am, 's1').name, 'a');
  preferB(am);
  for (let i = 0; i < 5; i++) assert.equal(serve(am, 's1').name, 'a', `request ${i} moved`);
  assert.equal(serve(am, 's2').name, 'b', 'a new session should follow priority');
  assert.equal(am.getStatus().sessions.sticky, true);
});

test('sticky: a window rollover does NOT move a running session', () => {
  const am = fleet();
  am.accounts[1].priority = 0;            // one tier, so only the roll could move it
  assert.equal(serve(am, 's1').name, 'a');
  am.accounts[0].quota.unified7dReset += WEEK;
  am.accounts[0].quota.unified7d = 0;
  for (let i = 0; i < 3; i++) assert.equal(serve(am, 's1').name, 'a');
});

test('sticky: holds past a sub-100% switch threshold, releases at 100%', () => {
  const am = fleet({ threshold: 0.85 });
  assert.equal(serve(am, 's1').name, 'a');
  am.accounts[0].quota.unified5h = 0.95;
  assert.equal(serve(am, 's1').name, 'a', 'released below the hard wall');
  assert.equal(serve(am, 's-new').name, 'b', 'a new session should respect the switch threshold');
  am.accounts[0].quota.unified5h = 1;
  assert.equal(serve(am, 's1').name, 'b', 'held at 100%');
});

test('sticky: a 429-throttled pin fails over and re-sticks to the new account', () => {
  const am = fleet();
  assert.equal(serve(am, 's1').name, 'a');
  am.markRateLimited(0, 60);
  assert.equal(serve(am, 's1').name, 'b');
  // a recovers AND outranks b again — the session stays where its cache now is.
  am.accounts[0].status = 'active';
  am.accounts[0].rateLimitedUntil = null;
  for (let i = 0; i < 3; i++) assert.equal(serve(am, 's1').name, 'b');
});

test('sticky: an exclude (tried this request) is honoured', () => {
  const am = fleet();
  assert.equal(serve(am, 's1').name, 'a');
  assert.equal(serve(am, 's1', { exclude: new Set([0]) }).name, 'b');
});

test('sticky: an idle session expires and is placed as new', () => {
  let now = Date.now();
  const tracker = new SessionTracker({ knownTtlMs: H, now: () => now });
  const am = fleet({ tracker });
  assert.equal(serve(am, 's1').name, 'a');
  preferB(am);
  now += 30 * 60_000;
  assert.equal(serve(am, 's1').name, 'a', 'expired too early');
  now += 61 * 60_000;
  tracker.sweep(now);
  assert.equal(serve(am, 's1').name, 'b', 'an idle session should be new again');
});

// ---------------------------------------------------------------------------
// End to end through the proxy: a fake upstream forces a quota 429 on account a.
// ---------------------------------------------------------------------------

function listen(server) {
  return new Promise(r => server.listen(0, '127.0.0.1', () => r(server.address().port)));
}

test('e2e: forced 429 on the sticky account fails over, then the session stays on the new account', async () => {
  const hits = [];
  let rejectA = false;
  const upstream = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      const who = (req.headers.authorization || '').replace('Bearer t-', '');
      hits.push(who);
      if (who === 'a' && rejectA) {
        res.writeHead(429, {
          'content-type': 'application/json', 'retry-after': '600',
          'anthropic-ratelimit-unified-5h-status': 'rejected',
          'anthropic-ratelimit-unified-5h-utilization': '1.0',
        });
        res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'quota' } }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'm', type: 'message', role: 'assistant', content: [{ type: 'text', text: 'ok' }],
        model: OPUS, usage: { input_tokens: 1, output_tokens: 1 } }));
    });
  });
  const upstreamPort = await listen(upstream);
  const am = fleet();
  const proxy = createProxyServer(am, { proxy: { apiKey: 'k' }, upstream: `http://127.0.0.1:${upstreamPort}` });
  const proxyPort = await listen(proxy);
  const send = async () => {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'k', 'x-claude-code-session-id': 'sess-e2e' },
      body: JSON.stringify({ model: OPUS, max_tokens: 5, messages: [{ role: 'user', content: 'hi' }] }),
    });
    await res.text();
    return res.status;
  };
  try {
    assert.equal(await send(), 200);
    assert.equal(hits.at(-1), 'a');
    preferB(am);                          // a manual switch: session must not move
    assert.equal(await send(), 200);
    assert.equal(hits.at(-1), 'a', 'sticky session moved on a priority change');

    rejectA = true;                       // forced quota 429 on a
    hits.length = 0;
    assert.equal(await send(), 200, 'failover did not complete the request');
    assert.deepEqual(hits, ['a', 'b'], 'expected one 429 on a then success on b');
    assert.equal(am.accounts[0].status, 'throttled');

    // a comes back and outranks b again: the session keeps its new home.
    rejectA = false;
    am.accounts[0].status = 'active';
    am.accounts[0].rateLimitedUntil = null;
    am.accounts[0].quota.unified5h = 0.1;
    am.accounts[0].quota.unifiedStatus = null;
    am.accounts[0].priority = 0; am.accounts[1].priority = 1;
    hits.length = 0;
    assert.equal(await send(), 200);
    assert.deepEqual(hits, ['b'], 'session did not re-stick to the failover account');
  } finally {
    proxy.close();
    upstream.close();
  }
});
