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
//     responses report them), REQUIRED: a key without one is refused. Each
//     request reserves its worst case (prompt bytes/3 + max_tokens) before it
//     is sent and settles against real usage after, with at most 2 in flight
//     and 60 a minute per key, so parallel requests cannot overshoot it;
//   - bounded: 16 connections, 15 s for headers, 120 s for the request body,
//     32 MB bodies; error answers are scrubbed of account names, only an
//     allow-list of response headers passes; a guest's prompts are not written
//     to the request log (guests.logBodies: true opts in).
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
import net from 'node:net';
import { Readable } from 'node:stream';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createProxyRequestListener, resolveAccountPin } from './server.js';
import { safeLine } from './safe-text.js';

export const GUEST_KEY_PREFIX = 'tcg-';
export const GUEST_RETRY_BIND_MS = 10_000;
export const GUEST_DEFAULTS = {
  maxConcurrent: 2,          // per key, in flight at once
  requestsPerMinute: 60,     // per key, every allowed route (count_tokens too)
  maxBodyBytes: 32 * 1024 * 1024,
  maxConnections: 16,        // whole listener
  headersTimeoutMs: 15_000,
  requestTimeoutMs: 120_000, // receiving the request; a streamed answer may run longer
};

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
// Response headers a guest may see; everything else (organization ids, cookies,
// auth challenges, proxy diagnostics) is dropped.
const ALLOWED_RESPONSE_HEADERS = new Set(['content-type', 'content-length', 'content-encoding', 'cache-control',
  'date', 'request-id', 'x-request-id', 'retry-after']);
const isAllowedResponseHeader = (/** @type {string} */ name) => {
  const n = String(name).toLowerCase();
  // Not anthropic-ratelimit-*: those publish the pinned account's quota state.
  return ALLOWED_RESPONSE_HEADERS.has(n);
};
const GENERIC_ERROR = (/** @type {number} */ status) => `The relay could not serve this request (${status}). Try again in a bit; if it keeps happening, tell the person who gave you this key.`;

/** @param {string} key */
export function hashGuestKey(key) {
  return createHash('sha256').update(String(key), 'utf8').digest('hex');
}

export function newGuestKey() {
  return GUEST_KEY_PREFIX + randomBytes(24).toString('base64url');
}

/** @param {string} h an IPv6 literal (no brackets) @returns {number[]|null} 8 hextets */
function expandV6(h) {
  let s = h.toLowerCase();
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4) {
    const o = v4[1].split('.').map(Number);
    s = s.slice(0, -v4[1].length) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const parts = [...head, ...Array(Math.max(0, fill)).fill('0'), ...tail].map(x => parseInt(x, 16));
  return parts.length === 8 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? parts : null;
}

/**
 * Why `host` must not be the guest listener's address, or null when it may.
 * One literal IP only: the tailnet CGNAT range 100.64.0.0/10, Tailscale's IPv6
 * prefix fd7a:115c:a1e0::/48, or loopback (tests). Hostnames are refused (they
 * resolve at bind time to who knows what); every spelling of the unspecified
 * address (`0`, `::0`, `::ffff:0.0.0.0`, …) is refused because Node binds it to
 * every interface.
 * @param {unknown} host
 * @returns {string|null}
 */
export function guestHostProblem(host) {
  const h = String(host ?? '').trim().replace(/^\[(.*)\]$/, '$1');
  const kind = net.isIP(h);
  if (!kind) return `"${h}" is not an IP address (a hostname or wildcard is refused)`;
  /** @param {number[]} o */
  const v4ok = (o) => {
    if (o.every(x => x === 0)) return 'the unspecified address binds every interface';
    if (o[0] === 127) return null;
    if (o[0] === 100 && (o[1] & 0xc0) === 64) return null;
    return 'outside the tailnet range 100.64.0.0/10';
  };
  if (kind === 4) return v4ok(h.split('.').map(Number));
  const p = expandV6(h);
  if (!p) return `"${h}" is not an IP address`;
  if (p.every(x => x === 0)) return 'the unspecified address binds every interface';
  if (p.slice(0, 7).every(x => x === 0) && p[7] === 1) return null;              // ::1
  if (p.slice(0, 5).every(x => x === 0) && (p[5] === 0xffff || p[5] === 0)) {   // v4-mapped / -compatible
    return v4ok([p[6] >> 8, p[6] & 0xff, p[7] >> 8, p[7] & 0xff]);
  }
  if (p[0] === 0xfd7a && p[1] === 0x115c && p[2] === 0xa1e0) return null;
  return 'outside the tailnet range fd7a:115c:a1e0::/48';
}

/** Kept for callers that only need yes/no. @param {unknown} host */
export function isWildcardHost(host) {
  return guestHostProblem(host) != null;
}

/**
 * The key's daily cap: a positive number, Infinity for an explicit
 * "unlimited", or null when the entry has none (the key is then refused: a
 * forgotten cap must fail closed).
 * @param {any} key
 */
export function guestCap(key) {
  const v = key?.dailyTokenCap;
  if (v === 'unlimited') return Infinity;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/** @param {any} key @param {'maxConcurrent'|'requestsPerMinute'} field */
function keyLimit(key, field) {
  const n = Number(key?.[field]);
  return Number.isInteger(n) && n > 0 ? n : GUEST_DEFAULTS[field];
}

export const MAX_GUEST_MAX_TOKENS = 128_000;

/** A tool the CLIENT runs (name + input_schema, no type or type "custom"). @param {any} t */
function isCustomTool(t) {
  return t && typeof t === 'object' && (t.type == null || t.type === 'custom');
}

/**
 * Check a guest body before anything is reserved or sent, and work out its
 * worst case. Every way to make the estimate small without making the request
 * small is refused: a compressed body (the estimate would see the compressed
 * bytes), unparseable JSON, a missing / non-positive / absurd max_tokens, and
 * server-side tools or MCP servers (their input and cost never show up in the
 * figures the cap reads up front, and they spend the account's quota).
 * @param {string} pathname @param {Record<string, any>} headers @param {Buffer} body
 * @returns {{ ok: true, estimate: number, inputEstimate: number, maxTokens: number } | { ok: false, status: number, type: string, message: string }}
 */
export function checkGuestBody(pathname, headers, body) {
  const enc = String(headers?.['content-encoding'] ?? '').trim().toLowerCase();
  if (enc && enc !== 'identity') return { ok: false, status: 415, type: 'invalid_request_error', message: 'Compressed request bodies are not accepted here.' };
  if (pathname === '/v1/models' || pathname.startsWith('/v1/models/')) return { ok: true, estimate: 0, inputEstimate: 0, maxTokens: 0 };
  let json;
  try { json = JSON.parse(body.toString('utf8')); } catch { json = undefined; }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return { ok: false, status: 400, type: 'invalid_request_error', message: 'The request body must be a JSON object.' };
  if (Array.isArray(json.tools) && !json.tools.every(isCustomTool)) {
    return { ok: false, status: 400, type: 'invalid_request_error', message: 'Server-side tools (web search, web fetch, code execution, advisor) are not available through this relay.' };
  }
  if (json.tools != null && !Array.isArray(json.tools)) return { ok: false, status: 400, type: 'invalid_request_error', message: 'tools must be a list.' };
  if (json.mcp_servers != null && !(Array.isArray(json.mcp_servers) && json.mcp_servers.length === 0)) {
    return { ok: false, status: 400, type: 'invalid_request_error', message: 'MCP servers are not available through this relay.' };
  }
  const inputEstimate = Math.ceil(body.length / 3);
  if (pathname === '/v1/messages/count_tokens') return { ok: true, estimate: inputEstimate, inputEstimate, maxTokens: 0 };
  const m = json.max_tokens;
  if (!Number.isInteger(m) || m <= 0 || m > MAX_GUEST_MAX_TOKENS) {
    return { ok: false, status: 400, type: 'invalid_request_error', message: `max_tokens must be a whole number from 1 to ${MAX_GUEST_MAX_TOKENS}.` };
  }
  return { ok: true, estimate: inputEstimate + m, inputEstimate, maxTokens: m };
}

/**
 * Reserve-before-send estimate: prompt bytes/3 + max_tokens (see checkGuestBody).
 * @param {Buffer} body
 */
export function estimateRequestTokens(body) {
  const r = checkGuestBody('/v1/messages', {}, body);
  return r.ok ? r.estimate : Math.ceil(body.length / 3);
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
      dailyTokenCap: k.dailyTokenCap === 'unlimited' ? 'unlimited' : (Number(k.dailyTokenCap) || null),
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

/**
 * Guard a guest response: only allow-listed headers pass, and an error answer
 * (status >= 400) is buffered and scrubbed so it never names an account or
 * carries the proxy's own diagnostics.
 * @param {any} res
 * @param {() => string[]} identifiers account names/emails to keep out of error text
 */
function guardResponse(res, identifiers) {
  const setHeader = res.setHeader.bind(res);
  res.setHeader = (/** @type {string} */ name, /** @type {any} */ value) => (isAllowedResponseHeader(name) ? setHeader(name, value) : res);
  const writeHead = res.writeHead.bind(res);
  const write = res.write.bind(res);
  const end = res.end.bind(res);
  /** @type {Buffer[]|null} */
  let held = null;
  let heldBytes = 0;
  let status = 200;
  res.writeHead = (/** @type {number} */ code, /** @type {any[]} */ ...rest) => {
    status = code;
    const args = rest.map(a => {
      if (!a || typeof a !== 'object') return a;
      if (Array.isArray(a)) {
        const out = [];
        for (let i = 0; i + 1 < a.length; i += 2) if (isAllowedResponseHeader(a[i])) out.push(a[i], a[i + 1]);
        return out;
      }
      return Object.fromEntries(Object.entries(a).filter(([k]) => isAllowedResponseHeader(k)));
    });
    for (const name of res.getHeaderNames()) if (!isAllowedResponseHeader(name)) res.removeHeader(name);
    if (code >= 400) {
      held = [];
      // The scrubbed body has its own length.
      res.removeHeader('content-length');
      for (const a of args) {
        if (a && typeof a === 'object' && !Array.isArray(a)) {
          for (const k of Object.keys(a)) if (/^content-(length|encoding)$/i.test(k)) delete a[k];
        }
      }
    }
    return writeHead(code, ...args);
  };
  const hold = (/** @type {any} */ chunk, /** @type {any} */ enc) => {
    if (chunk == null || typeof chunk === 'function') return;
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), /** @type {BufferEncoding} */ (typeof enc === 'string' ? enc : 'utf8'));
    if (heldBytes < 256 * 1024) { held?.push(b); heldBytes += b.length; }
  };
  res.write = (/** @type {any} */ chunk, /** @type {any} */ enc, /** @type {any} */ cb) => {
    if (!held) return write(chunk, enc, cb);
    hold(chunk, enc);
    if (typeof enc === 'function') enc(); else if (typeof cb === 'function') cb();
    return true;
  };
  res.end = (/** @type {any} */ chunk, /** @type {any} */ enc, /** @type {any} */ cb) => {
    if (!held) return end(chunk, enc, cb);
    hold(chunk, enc);
    const text = Buffer.concat(held).toString('utf8');
    held = null;
    return end(scrubErrorBody(text, status, identifiers()), typeof cb === 'function' ? cb : (typeof enc === 'function' ? enc : undefined));
  };
}

/**
 * @param {string} text @param {number} status @param {string[]} identifiers
 * @returns {string}
 */
export function scrubErrorBody(text, status, identifiers) {
  const names = identifiers.filter(n => typeof n === 'string' && n.length >= 3);
  const named = (/** @type {string} */ t) => names.some(n => t.toLowerCase().includes(n.toLowerCase()));
  try {
    const json = JSON.parse(text);
    const err = json?.error;
    if (err && typeof err === 'object') {
      const msg = typeof err.message === 'string' ? err.message : '';
      if (err.type === 'proxy_error' || named(msg) || /teamclaude|pinned|account/i.test(msg)) {
        return JSON.stringify({ type: 'error', error: { type: err.type === 'proxy_error' ? 'api_error' : (err.type || 'api_error'), message: GENERIC_ERROR(status) } });
      }
      return JSON.stringify({ type: 'error', error: { type: err.type || 'api_error', message: msg } });
    }
  } catch { /* not JSON */ }
  return JSON.stringify({ type: 'error', error: { type: 'api_error', message: GENERIC_ERROR(status) } });
}

/**
 * Buffer a request body up to `limit` bytes. Resolves null when it is larger.
 * @param {any} req @param {number} limit
 * @returns {Promise<Buffer|null>}
 */
async function readBody(req, limit) {
  /** @type {Buffer[]} */
  const chunks = [];
  let n = 0;
  for await (const chunk of req) {
    n += chunk.length;
    if (n > limit) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/**
 * The guest request handler. Exported apart from the server so tests can drive
 * it on an ephemeral loopback port.
 * @param {{accountManager: any, config: any, hooks?: any, sx?: any, guestUsage: GuestUsageTracker, upstream?: string|null, log?: (m: string) => void}} opts
 */
export function createGuestRequestHandler({ accountManager, config, hooks = {}, sx = null, guestUsage, upstream = null, log = console.log }) {
  const listeners = new Map(); // "name\0pin" → forwarding listener
  /** @type {Map<string, {inflight: number, reserved: number, recent: number[]}>} */
  const live = new Map();
  /** @type {Map<string, {at: number, n: number}>} */
  const refusedLog = new Map();
  const liveOf = (/** @type {string} */ name) => {
    let l = live.get(name);
    if (!l) { l = { inflight: 0, reserved: 0, recent: [] }; live.set(name, l); }
    return l;
  };
  // The shared config minus everything a guest must not steer: no proxy keys,
  // no usage dimensions read from the guest's headers, no quota hold. Other
  // fields (blockedModels) are read through to the live config.
  const guestConfig = Object.create(config, {
    proxy: { value: {}, enumerable: true },
    holdSeconds: { value: 0, enumerable: true },
    eventLogging: { value: 'show', enumerable: true },
  });
  const identifiers = () => accountManager.accounts.flatMap((/** @type {any} */ a) => [a.name, a.email, a.accountUuid, a.orgUuid]).filter(Boolean);
  const forwarderFor = (/** @type {any} */ key) => {
    const pin = key.account.trim();
    const name = key.name.trim();
    const id = `${name}\0${pin}`;
    let fwd = listeners.get(id);
    if (!fwd) {
      fwd = createProxyRequestListener({
        accountManager,
        upstream: upstream || config.upstream || 'https://api.anthropic.com',
        // A guest's prompts stay out of the operator's request logs unless
        // guests.logBodies says otherwise.
        logDir: config.guests?.logBodies === true ? (config.logDir || null) : null,
        hooks,
        sx,
        holdMs: 0,
        config: guestConfig,
        forcedPin: pin,
        // Names the guest in the activity log and the session readout.
        forcedClient: `guest:${name}`,
        // A guest-chosen session id must never join one of the operator's.
        sessionPrefix: `guest:${name}:`,
      });
      listeners.set(id, fwd);
    }
    return fwd;
  };

  const handle = async (/** @type {any} */ req, /** @type {any} */ res) => {
    const remote = req.socket?.remoteAddress || '?';
    if (!isAllowedGuestRoute(req.method, req.url)) {
      sendJson(res, 404, 'not_found_error', 'Not found');
      return;
    }
    const key = resolveGuestKey(config.guests, presentedGuestKey(req.headers));
    if (!key) {
      // One line per remote per minute, however hard it knocks.
      const t = Date.now();
      const last = refusedLog.get(remote);
      if (!last || t - last.at >= 60_000) {
        log(`[TeamClaude] guest: refused ${safeLine(req.method)} ${safeLine(req.url)} from ${safeLine(remote)} (bad key)${last?.n ? `, +${last.n} more in the last minute` : ''}`);
        refusedLog.set(remote, { at: t, n: 0 });
        if (refusedLog.size > 1000) refusedLog.clear();
      } else last.n += 1;
      sendJson(res, 401, 'authentication_error', 'Invalid guest key.');
      return;
    }
    const name = key.name.trim();
    const cap = guestCap(key);
    if (cap == null) {
      log(`[TeamClaude] guest ${name}: refused, no dailyTokenCap configured (set a number or "unlimited")`);
      sendJson(res, 403, 'permission_error', 'This key has no daily limit set yet, so it is switched off.');
      return;
    }
    // The pin must name a configured account. Checked here so a typo never
    // reaches the forwarder's "unknown pin" message, which names the pin.
    if (resolveAccountPin(accountManager, key.account.trim()) == null) {
      log(`[TeamClaude] guest ${name}: pinned account "${key.account}" is not configured`);
      sendJson(res, 503, 'api_error', GENERIC_ERROR(503));
      return;
    }
    const state = liveOf(name);
    const now = Date.now();
    state.recent = state.recent.filter(t => now - t < 60_000);
    if (state.recent.length >= keyLimit(key, 'requestsPerMinute')) {
      sendJson(res, 429, 'rate_limit_error', 'Too many requests this minute. Wait a few seconds.', { 'retry-after': '10' });
      return;
    }
    if (state.inflight >= keyLimit(key, 'maxConcurrent')) {
      sendJson(res, 429, 'rate_limit_error', 'Too many requests at once. Wait for the current one to finish.', { 'retry-after': '2' });
      return;
    }
    state.recent.push(now);
    state.inflight += 1;
    let reservation = 0;
    let released = false;
    // What this request has booked so far, to settle a cut-short answer.
    const booked = { input: 0, output: 0, final: false, forwarded: false, maxTokens: 0, inputEstimate: 0, completion: false };
    const release = () => {
      if (released) return;
      released = true;
      state.inflight -= 1;
      state.reserved -= reservation;
      // A completion whose final usage never arrived (the guest hung up before
      // message_delta, the stream broke) is charged its worst case: whatever it
      // was allowed to produce and has not been booked, plus the prompt
      // estimate when even message_start never came. Conservative on purpose:
      // a guest who aborts while the request is still queued pays for it too.
      if (booked.forwarded && booked.completion && !booked.final && (res.statusCode || 200) < 400) {
        const shortfall = Math.max(0, booked.maxTokens - booked.output) + (booked.input > 0 ? 0 : booked.inputEstimate);
        if (shortfall > 0) {
          guestUsage.recordTokens(name, shortfall);
          log(`[TeamClaude] guest ${name}: answer cut short, booked ${shortfall} tokens (worst case)`);
        }
      }
    };
    res.once('close', release);
    try {
      const limit = Number(config.guests?.maxBodyBytes) > 0 ? Number(config.guests.maxBodyBytes) : GUEST_DEFAULTS.maxBodyBytes;
      const body = await readBody(req, limit);
      if (body == null) {
        sendJson(res, 413, 'request_too_large', 'Request too large.', { connection: 'close' });
        req.destroy?.();
        return;
      }
      const pathname = new URL(req.url, 'http://guest.invalid').pathname;
      const checked = checkGuestBody(pathname, req.headers, body);
      if (!checked.ok) {
        const bad = /** @type {{status: number, type: string, message: string}} */ (/** @type {unknown} */ (checked));
        sendJson(res, bad.status, bad.type, bad.message);
        return;
      }
      const good = /** @type {{estimate: number, inputEstimate: number, maxTokens: number}} */ (/** @type {unknown} */ (checked));
      booked.maxTokens = good.maxTokens;
      booked.inputEstimate = good.inputEstimate;
      booked.completion = pathname === '/v1/messages';
      // Reserve before sending: today's real usage + what is in flight + this
      // request's worst case must fit, so parallel requests cannot all slip in
      // under the cap and land far past it.
      reservation = Number.isFinite(cap) ? good.estimate : 0;
      if (Number.isFinite(cap) && guestUsage.tokensToday(name) + state.reserved + reservation > cap) {
        log(`[TeamClaude] guest ${name}: daily cap ${cap} reached (used ${guestUsage.tokensToday(name)}, in flight ${state.reserved}), 429`);
        reservation = 0;
        sendJson(res, 429, 'rate_limit_error',
          `Daily limit reached (${cap.toLocaleString('en-US')} tokens). It resets at midnight UTC.`,
          { 'retry-after': String(secondsToUtcMidnight()) });
        return;
      }
      state.reserved += reservation;
      for (const h of STRIPPED_REQUEST_HEADERS) delete req.headers[h];
      guardResponse(res, identifiers);
      guestUsage.recordRequest(name);
      // The body is already read; the forwarder reads it again from this copy.
      const replay = /** @type {any} */ (Readable.from(body.length ? [body] : []));
      replay.headers = req.headers;
      replay.rawHeaders = req.rawHeaders;
      replay.url = req.url;
      replay.method = req.method;
      replay.httpVersion = req.httpVersion;
      replay.socket = req.socket;
      replay.connection = req.socket;
      replay.tcGuest = name;
      // Tokens are booked to the guest through the same usage hook every
      // response path already feeds (stream and buffered alike).
      // message_start books input + cache; message_delta books output and may
      // carry a larger CUMULATIVE input (server-side tool rounds): the larger
      // figure wins, so input added after the start is booked too.
      replay.tcGuestUsage = (/** @type {number} */ input, /** @type {number} */ output, /** @type {number} */ cache, /** @type {any} */ cumulative) => {
        const fresh = (input || 0) + (cache || 0);
        let add = fresh + (output || 0);
        booked.input += fresh;
        booked.output += output || 0;
        // The figures that close a completion: message_delta (cumulative) or a
        // whole buffered body (input and output in one call).
        if (cumulative || (output || 0) > 0) booked.final = true;
        if (cumulative && typeof cumulative === 'object') {
          const total = (Number(cumulative.input_tokens) || 0) + (Number(cumulative.cache_creation_input_tokens) || 0) + (Number(cumulative.cache_read_input_tokens) || 0);
          if (total > booked.input) { add += total - booked.input; booked.input = total; }
        }
        guestUsage.recordTokens(name, add);
      };
      booked.forwarded = true;
      await forwarderFor(key)(replay, res);
    } finally {
      if (res.writableEnded || res.destroyed) release();
    }
  };

  // A throw in here must never escape: an unhandled rejection takes the whole
  // proxy (every one of the operator's sessions) down with it.
  return async (/** @type {any} */ req, /** @type {any} */ res) => {
    try {
      await handle(req, res);
    } catch (err) {
      log(`[TeamClaude] guest handler error: ${err instanceof Error ? err.message : String(err)}`);
      try {
        if (!res.headersSent) sendJson(res, 500, 'api_error', GENERIC_ERROR(500));
        else res.destroy();
      } catch { /* socket already gone */ }
    }
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
  const server = http.createServer({
    headersTimeout: GUEST_DEFAULTS.headersTimeoutMs,
    requestTimeout: GUEST_DEFAULTS.requestTimeoutMs,
  }, createGuestRequestHandler(opts));
  server.maxConnections = GUEST_DEFAULTS.maxConnections;
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
  const host = String(listen.host ?? '').trim().replace(/^\[(.*)\]$/, '$1');
  const port = Number(listen.port);
  const problem = guestHostProblem(host);
  if (problem) {
    state.error = `refusing host "${host}": ${problem}`;
    log(`[TeamClaude] guest listener NOT started: guests.listen.host ${problem}`);
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
