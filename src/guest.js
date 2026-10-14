// Guest listener (config.guests): a second, deliberately tiny front door that
// lets someone OFF this machine spend ONE pinned account, and nothing else.
//
// The main listener cannot be that door. Besides inference it serves the
// CONNECT/MITM forward proxy (egress through this machine's IP), the control
// plane (/teamclaude/*: status, reload, switch, the dashboard), the OAuth and
// identity relays and event logging. A guest gets none of it:
//
//   - its own http server, on its own host:port, off unless configured;
//   - three routes: POST /v1/messages, POST /v1/messages/count_tokens,
//     GET /v1/models (+ /v1/models/<id>). Everything else is a 404, CONNECT and
//     upgrades are refused at the socket;
//   - a guest key (x-api-key or Authorization: Bearer) checked against a stored
//     sha256, constant-time; only the hash lives in teamclaude.json;
//   - a HARD pin to the key's account: the request goes through the normal
//     forwarding path with forcedPin, which never rotates, never hops and never
//     holds (see forwardRequest). An unavailable account is an error to the
//     guest, never another account;
//   - a per-key daily token cap (UTC day; input + output + cache tokens as the
//     responses report them). Checked before a request is sent, so the request
//     that crosses the cap finishes and the next one gets a 429.
//
// Config:
//   "guests": {
//     "listen": { "host": "100.99.200.17", "port": 3460 },
//     "keys": [{ "name": "nephew", "keyHash": "<sha256 hex>",
//                "account": "ai@example.com", "dailyTokenCap": 3000000,
//                "enabled": true }]
//   }
// `keys` is read live (a reload swaps it), `listen` at startup.

import http from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createProxyRequestListener, resolveAccountPin } from './server.js';

export const GUEST_KEY_PREFIX = 'tcg-';
export const GUEST_RETRY_BIND_MS = 10_000;
// Hosts a guest listener refuses to bind. The whole point of the guest door is
// that it opens on ONE interface; a wildcard would also open it on the LAN.
const WILDCARD_HOSTS = new Set(['', '0.0.0.0', '::', '[::]', '*']);

// Only the paths Claude Code needs for a session on an API key. Matched on the
// pathname exactly (the query string, e.g. `?beta=true`, is passed through).
const ALLOWED = [
  { method: 'POST', path: '/v1/messages' },
  { method: 'POST', path: '/v1/messages/count_tokens' },
  { method: 'GET', path: '/v1/models' },
];
const MODEL_ID_RE = /^\/v1\/models\/[A-Za-z0-9._:@-]{1,128}$/;

// Request headers that are a credential or steer this proxy. The guest's own
// key is ours, never upstream's; forwardRequest drops it too, this is the
// boundary saying so first.
const STRIPPED_REQUEST_HEADERS = ['authorization', 'x-api-key', 'proxy-authorization', 'cookie'];
// Response headers a guest has no business seeing.
const STRIPPED_RESPONSE_HEADERS = new Set(['set-cookie', 'authorization', 'x-api-key', 'proxy-authorization', 'www-authenticate']);

/** @param {string} key */
export function hashGuestKey(key) {
  return createHash('sha256').update(String(key), 'utf8').digest('hex');
}

export function newGuestKey() {
  return GUEST_KEY_PREFIX + randomBytes(24).toString('base64url');
}

/** @param {unknown} host */
export function isWildcardHost(host) {
  return WILDCARD_HOSTS.has(String(host ?? '').trim());
}

/** The configured keys that can authenticate: named, hashed, enabled. */
/** @param {any} guests @returns {any[]} */
export function usableGuestKeys(guests) {
  /** @type {any[]} */
  const keys = Array.isArray(guests?.keys) ? guests.keys : [];
  return keys.filter((/** @type {any} */ k) => k && typeof k.name === 'string' && k.name.trim()
    && typeof k.keyHash === 'string' && /^[0-9a-f]{64}$/i.test(k.keyHash)
    && typeof k.account === 'string' && k.account.trim()
    && k.enabled !== false);
}

/** The key a request presents: x-api-key, else a Bearer token. */
/** @param {Record<string, any>|undefined} headers @returns {string|null} */
export function presentedGuestKey(headers) {
  const x = headers?.['x-api-key'];
  if (typeof x === 'string' && x) return x;
  const auth = headers?.authorization;
  if (typeof auth === 'string') {
    const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
    if (m) return m[1].trim();
  }
  return null;
}

/**
 * Match a presented key against the configured hashes. Every candidate is
 * compared (constant time, fixed-length digests), so the scan leaks nothing
 * about which entry came close.
 */
/** @param {any} guests @param {string|null|undefined} presented @returns {any} */
export function resolveGuestKey(guests, presented) {
  if (!presented) return null;
  const digest = Buffer.from(hashGuestKey(presented), 'hex');
  let match = null;
  for (const entry of usableGuestKeys(guests)) {
    const stored = Buffer.from(entry.keyHash.toLowerCase(), 'hex');
    if (stored.length === digest.length && timingSafeEqual(stored, digest) && !match) match = entry;
  }
  return match;
}

/** @param {string|undefined} method @param {string|undefined} url */
export function isAllowedGuestRoute(method, url) {
  let pathname;
  try { pathname = new URL(url || '/', 'http://guest.invalid').pathname; } catch { return false; }
  // The raw url must start with the pathname the URL parser saw: a parser that
  // normalised `/v1/./messages` or `//v1/messages` into an allowed path must not
  // let the original through.
  if (!(url || '').startsWith(pathname)) return false;
  if (ALLOWED.some(r => r.method === method && r.path === pathname)) return true;
  return method === 'GET' && MODEL_ID_RE.test(pathname);
}

/** @param {number} [ms] */
export function utcDay(ms = Date.now()) {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * Per-guest counters. "Today" is the UTC day: a counter whose day is not today
 * reads as zero and restarts on its next use. Lifetime totals are kept beside
 * it so `status` can say what a guest has spent overall.
 */
export class GuestUsageTracker {
  constructor({ now = () => Date.now() } = {}) {
    this.now = now;
    /** @type {Map<string, {day: string, requestsToday: number, tokensToday: number, requests: number, tokens: number, lastSeen: number|null}>} */
    this.guests = new Map(); // name → { day, requestsToday, tokensToday, requests, tokens, lastSeen }
  }

  /** @param {string} name */
  _row(name) {
    const today = utcDay(this.now());
    let row = this.guests.get(name);
    if (!row) {
      row = { day: today, requestsToday: 0, tokensToday: 0, requests: 0, tokens: 0, lastSeen: null };
      this.guests.set(name, row);
    }
    if (row.day !== today) { row.day = today; row.requestsToday = 0; row.tokensToday = 0; }
    return row;
  }

  /** @param {string} name */
  recordRequest(name) {
    const row = this._row(name);
    row.requestsToday += 1;
    row.requests += 1;
    row.lastSeen = this.now();
  }

  /** @param {string} name @param {number} tokens */
  recordTokens(name, tokens) {
    const n = Number(tokens);
    if (!Number.isFinite(n) || n <= 0) return;
    const row = this._row(name);
    row.tokensToday += n;
    row.tokens += n;
  }

  /** @param {string} name */
  tokensToday(name) {
    const row = this.guests.get(name);
    return row && row.day === utcDay(this.now()) ? row.tokensToday : 0;
  }

  /** @param {string} name */
  get(name) {
    const row = this.guests.get(name);
    if (!row) return { requestsToday: 0, tokensToday: 0, requests: 0, tokens: 0, lastSeen: null };
    const today = row.day === utcDay(this.now());
    return {
      requestsToday: today ? row.requestsToday : 0,
      tokensToday: today ? row.tokensToday : 0,
      requests: row.requests,
      tokens: row.tokens,
      lastSeen: row.lastSeen ? new Date(row.lastSeen).toISOString() : null,
    };
  }

  export() {
    return Object.fromEntries([...this.guests].map(([k, v]) => [k, { ...v }]));
  }

  /** @param {any} saved */
  restore(saved) {
    if (!saved || typeof saved !== 'object') return;
    for (const [name, v] of Object.entries(saved)) {
      if (!v || typeof v !== 'object') continue;
      this.guests.set(name, {
        day: typeof v.day === 'string' ? v.day : utcDay(this.now()),
        requestsToday: Number(v.requestsToday) || 0,
        tokensToday: Number(v.tokensToday) || 0,
        requests: Number(v.requests) || 0,
        tokens: Number(v.tokens) || 0,
        lastSeen: Number(v.lastSeen) || null,
      });
    }
  }
}

/** What `teamclaude status` and the dashboard show per guest key. */
/** @param {any} config @param {GuestUsageTracker} guestUsage @param {any} [listening] */
export function guestStatus(config, guestUsage, listening = null) {
  /** @type {any[]} */
  const keys = Array.isArray(config?.guests?.keys) ? config.guests.keys : [];
  return {
    listen: config?.guests?.listen ? { host: config.guests.listen.host, port: config.guests.listen.port } : null,
    listening,
    keys: keys.filter((/** @type {any} */ k) => k && typeof k.name === 'string').map((/** @type {any} */ k) => ({
      name: k.name,
      account: k.account || null,
      enabled: k.enabled !== false,
      dailyTokenCap: Number(k.dailyTokenCap) || null,
      ...guestUsage.get(k.name),
    })),
  };
}

/** @param {any} res @param {number} status @param {string} type @param {string} message @param {Record<string, string>} [extra] */
function sendJson(res, status, type, message, extra = {}) {
  if (res.headersSent) { res.end(); return; }
  res.writeHead(status, { 'Content-Type': 'application/json', ...extra });
  res.end(JSON.stringify({ type: 'error', error: { type, message } }));
}

// Guarded response: filters credential headers out of anything the shared
// forwarding path writes back, whichever of setHeader / writeHead it uses.
/** @param {any} res */
function guardResponse(res) {
  const setHeader = res.setHeader.bind(res);
  res.setHeader = (/** @type {string} */ name, /** @type {any} */ value) => (STRIPPED_RESPONSE_HEADERS.has(String(name).toLowerCase()) ? res : setHeader(name, value));
  const writeHead = res.writeHead.bind(res);
  res.writeHead = (/** @type {number} */ status, /** @type {any[]} */ ...rest) => {
    const args = rest.map(a => {
      if (!a || typeof a !== 'object') return a;
      if (Array.isArray(a)) {
        const out = [];
        for (let i = 0; i + 1 < a.length; i += 2) {
          if (!STRIPPED_RESPONSE_HEADERS.has(String(a[i]).toLowerCase())) out.push(a[i], a[i + 1]);
        }
        return out;
      }
      return Object.fromEntries(Object.entries(a).filter(([k]) => !STRIPPED_RESPONSE_HEADERS.has(k.toLowerCase())));
    });
    for (const name of STRIPPED_RESPONSE_HEADERS) res.removeHeader(name);
    return writeHead(status, ...args);
  };
}

/**
 * The guest request handler. Exported apart from the server so tests can drive
 * it on an ephemeral loopback port.
 */
/** @param {{accountManager: any, config: any, hooks?: any, sx?: any, guestUsage: GuestUsageTracker, upstream?: string|null, log?: (m: string) => void}} opts */
export function createGuestRequestHandler({ accountManager, config, hooks = {}, sx = null, guestUsage, upstream = null, log = console.log }) {
  const listeners = new Map(); // "name\0pin" → forwarding listener
  // The shared config minus everything a guest must not steer: no proxy keys,
  // no usage dimensions read from the guest's headers, no quota hold. Other
  // fields (blockedModels, logging) are read through to the live config.
  const guestConfig = Object.create(config, {
    proxy: { value: {}, enumerable: true },
    holdSeconds: { value: 0, enumerable: true },
    eventLogging: { value: 'show', enumerable: true },
  });
  const forwarderFor = (/** @type {any} */ key) => {
    const pin = key.account.trim();
    const id = `${key.name.trim()}\0${pin}`;
    let fwd = listeners.get(id);
    if (!fwd) {
      fwd = createProxyRequestListener({
        accountManager,
        upstream: upstream || config.upstream || 'https://api.anthropic.com',
        logDir: config.logDir || null,
        hooks,
        sx,
        holdMs: 0,
        config: guestConfig,
        forcedPin: pin,
        // Names the guest in the activity log and the session readout.
        forcedClient: `guest:${key.name.trim()}`,
      });
      listeners.set(id, fwd);
    }
    return fwd;
  };

  return async (/** @type {any} */ req, /** @type {any} */ res) => {
    const remote = req.socket?.remoteAddress || '?';
    if (!isAllowedGuestRoute(req.method, req.url)) {
      sendJson(res, 404, 'not_found_error', 'Not found');
      return;
    }
    const key = resolveGuestKey(config.guests, presentedGuestKey(req.headers));
    if (!key) {
      log(`[TeamClaude] guest: refused ${req.method} ${req.url} from ${remote} (bad key)`);
      sendJson(res, 401, 'authentication_error', 'Invalid guest key.');
      return;
    }
    const name = key.name.trim();
    const cap = Number(key.dailyTokenCap) || 0;
    if (cap > 0 && guestUsage.tokensToday(name) >= cap) {
      log(`[TeamClaude] guest ${name}: daily cap ${cap} reached, 429`);
      sendJson(res, 429, 'rate_limit_error',
        `Daily limit reached (${cap.toLocaleString('en-US')} tokens). It resets at midnight UTC.`,
        { 'retry-after': String(secondsToUtcMidnight()) });
      return;
    }
    // The pin must name a configured account. resolveAccountPin is what the
    // forwarder resolves too; checking here keeps a typo from reaching the
    // forwarder's "unknown pin" message, which names the pin to the caller.
    if (resolveAccountPin(accountManager, key.account.trim()) == null) {
      log(`[TeamClaude] guest ${name}: pinned account "${key.account}" is not configured`);
      sendJson(res, 503, 'proxy_error', 'This guest key is not connected to an account right now.');
      return;
    }
    for (const h of STRIPPED_REQUEST_HEADERS) delete req.headers[h];
    guardResponse(res);
    guestUsage.recordRequest(name);
    req.tcGuest = name;
    // Tokens are booked to the guest through the same usage hook every
    // response path already feeds (stream and buffered alike).
    req.tcGuestUsage = (/** @type {number} */ input, /** @type {number} */ output, /** @type {number} */ cache) => guestUsage.recordTokens(name, (input || 0) + (output || 0) + (cache || 0));
    await forwarderFor(key)(req, res);
  };
}

/** @param {number} [ms] */
export function secondsToUtcMidnight(ms = Date.now()) {
  const d = new Date(ms);
  const next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - ms) / 1000));
}

/** @param {Parameters<typeof createGuestRequestHandler>[0]} opts */
export function createGuestServer(opts) {
  const server = http.createServer(createGuestRequestHandler(opts));
  // No forward proxying, no tunnels, no websockets: refuse at the socket.
  server.on('connect', (_req, socket) => {
    socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  server.on('upgrade', (_req, socket) => {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  server.on('clientError', (_err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });
  return server;
}

/**
 * Bind the guest server to config.guests.listen, retrying while the address is
 * not on this machine yet (a tailscale IP before tailscaled is up). Never falls
 * back to another address. Returns { server, state, stop }.
 */
/**
 * @param {Parameters<typeof createGuestRequestHandler>[0]} opts
 * @param {{retryMs?: number, log?: (m: string) => void}} [o]
 */
export function startGuestListener(opts, { retryMs = GUEST_RETRY_BIND_MS, log = console.log } = {}) {
  const listen = opts.config?.guests?.listen;
  /** @type {{listening: boolean, host: string|null, port: number|null, error: string|null}} */
  const state = { listening: false, host: listen?.host ?? null, port: listen?.port ?? null, error: null };
  if (!listen) return { server: null, state, stop: () => {} };
  const host = String(listen.host ?? '').trim();
  const port = Number(listen.port);
  if (isWildcardHost(host)) {
    state.error = `refusing wildcard host "${host}"`;
    log(`[TeamClaude] guest listener NOT started: guests.listen.host must be one address, not "${host}"`);
    return { server: null, state, stop: () => {} };
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    state.error = `bad port ${listen.port}`;
    log(`[TeamClaude] guest listener NOT started: bad guests.listen.port ${listen.port}`);
    return { server: null, state, stop: () => {} };
  }
  const server = createGuestServer({ ...opts, log });
  /** @type {ReturnType<typeof setTimeout>|null} */
  let timer = null;
  let stopped = false;
  const attempt = () => {
    if (stopped) return;
    const onError = (/** @type {any} */ err) => {
      server.removeListener('listening', onListening);
      state.error = err.code || err.message;
      log(`[TeamClaude] guest listener: cannot bind ${host}:${port} (${state.error}); retrying in ${Math.round(retryMs / 1000)}s`);
      timer = setTimeout(attempt, retryMs);
      timer.unref?.();
    };
    const onListening = () => {
      server.removeListener('error', onError);
      server.on('error', err => log(`[TeamClaude] guest listener error: ${err.message}`));
      state.listening = true;
      state.error = null;
      log(`[TeamClaude] guest listener on ${host}:${port} (${usableGuestKeys(opts.config.guests).length} enabled key(s))`);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  };
  attempt();
  return {
    server,
    state,
    stop: () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      server.closeAllConnections?.();
      server.close(() => {});
    },
  };
}
