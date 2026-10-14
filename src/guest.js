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
//   - a usage-based daily lock: once the guest's share of the pinned
//     account's WEEKLY quota spent today (UTC) reaches guests.dailyWeeklyPct
//     (default 30, per-key override), the key is locked until 00:00 UTC. The
//     share is the account's weekly-utilization rise today × the guest's
//     fraction of the account's cost-weighted tokens today (GuestUsageTracker);
//   - a runaway backstop, dailyTokenCap (default 100M raw tokens, "unlimited"
//     accepted). Each request reserves its worst case (prompt bytes/3 +
//     max_tokens) against it before it is sent and settles against real usage
//     after, with at most 8 in flight and 240 a minute per key;
//   - bounded: 16 connections, 15 s for headers, 120 s for the request body,
//     8 MB bodies; error answers are scrubbed of account names, only an
//     allow-list of response headers passes. A guest's prompts never reach the
//     operator's request log; they go to the guest stream logs (guest-log.js,
//     guests.logBodies, default on).
//
// Config:
//   "guests": {
//     "listen": { "host": "100.99.200.17", "port": 3460 },
//     "dailyWeeklyPct": 30, "logBodies": true, "logRetentionDays": 90, "logMaxMB": 5000,
//     "keys": [{ "name": "nephew", "keyHash": "<sha256 hex>",
//                "account": "ai@example.com", "dailyWeeklyPct": 30,
//                "dailyTokenCap": 100000000, "enabled": true }]
//   }
// Everything but `listen` is read live (a reload swaps it), `listen` at startup.

import http from 'node:http';
import net from 'node:net';
import { Readable } from 'node:stream';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createProxyRequestListener, resolveAccountPin } from './server.js';
import { safeLine } from './safe-text.js';
import { openGuestLog, startGuestLogPruner } from './guest-log.js';

export const GUEST_KEY_PREFIX = 'tcg-';
export const GUEST_RETRY_BIND_MS = 10_000;
export const GUEST_DEFAULTS = {
  maxConcurrent: 8,          // per key, in flight at once
  requestsPerMinute: 240,    // per key, every allowed route (count_tokens too)
  dailyTokenCap: 100_000_000, // runaway backstop, raw tokens per UTC day
  dailyWeeklyPct: 30,        // the real limit: % of the pinned account's weekly quota per UTC day
  weeklyPct: 60,             // and per weekly window (the account's current 7 days)
  pause5hPct: 80,            // paused while the account's 5-hour window is past this
  weeklyStaleMs: 15 * 60_000, // an older weekly reading is not acted on (backstop only)
  maxBodyBytes: 8 * 1024 * 1024,
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
// No content-length / content-encoding: the forwarder hands over decompressed
// bytes, and the cache figures in them are rewritten (see guardResponse).
const ALLOWED_RESPONSE_HEADERS = new Set(['content-type', 'cache-control',
  'date', 'request-id', 'x-request-id', 'retry-after', 'x-should-retry']);
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
 * The key's runaway backstop in raw tokens per UTC day: its dailyTokenCap,
 * Infinity for "unlimited", the 100M default when absent or unusable. The
 * real limit is the usage share (guestPct); this only stops a runaway.
 * @param {any} key
 * @returns {number}
 */
export function guestCap(key) {
  const v = key?.dailyTokenCap;
  if (v === 'unlimited') return Infinity;
  const n = Number(v);
  return v != null && Number.isFinite(n) && n > 0 ? n : GUEST_DEFAULTS.dailyTokenCap;
}

/**
 * The share of the pinned account's weekly quota (in %) a key may use per UTC
 * day: the key's dailyWeeklyPct, else guests.dailyWeeklyPct, else 30.
 * @param {any} key @param {any} [guests]
 * @returns {number}
 */
export function guestPct(key, guests) {
  for (const v of [key?.dailyWeeklyPct, guests?.dailyWeeklyPct]) {
    const n = Number(v);
    if (v != null && Number.isFinite(n) && n > 0 && n <= 100) return n;
  }
  return GUEST_DEFAULTS.dailyWeeklyPct;
}

/**
 * A per-key % knob: the key's value, else guests.<field>, else the default.
 * @param {any} key @param {any} guests @param {'weeklyPct'|'pause5hPct'} field
 */
function pctKnob(key, guests, field) {
  for (const v of [key?.[field], guests?.[field]]) {
    const n = Number(v);
    if (v != null && Number.isFinite(n) && n > 0 && n <= 100) return n;
  }
  return GUEST_DEFAULTS[field];
}
/** % of the weekly quota a guest may use per weekly window. @param {any} key @param {any} [guests] */
export const guestWeeklyPct = (key, guests) => pctKnob(key, guests, 'weeklyPct');
/** The account 5-hour utilization (%) above which a guest is paused. @param {any} key @param {any} [guests] */
export const guestPause5hPct = (key, guests) => pctKnob(key, guests, 'pause5hPct');

/**
 * The weekly window a guest's ceiling is summed over: the account's current
 * 7 days when its weekly reset time is known and ahead, else the rolling last
 * 7 UTC days. startDay is the first UTC day counted; retryAfter is when the
 * window (or, rolling, its oldest day) moves on.
 * @param {unknown} resetAt ms @param {number} [now]
 */
export function weeklyWindow(resetAt, now = Date.now()) {
  const r = Number(resetAt);
  if (Number.isFinite(r) && r > now) {
    return { startDay: utcDay(r - 7 * 86_400_000), retryAfter: Math.max(1, Math.ceil((r - now) / 1000)),
      resetText: `at ${new Date(r).toISOString().slice(0, 16).replace('T', ' ')} UTC` };
  }
  return { startDay: utcDay(now - 6 * 86_400_000), retryAfter: secondsToUtcMidnight(now), resetText: 'at 00:00 UTC' };
}

/**
 * The ONE price table both sides of a guest's share are weighed with: US$
 * per million tokens (Anthropic API list prices, 2026-10): input, output,
 * cache read. Cache writes are 1.25 × input (2 × for 1h writes). Matched on
 * the model id's start, first match wins; an unknown model is priced as the
 * most expensive one, so a guest can never look cheaper than he is.
 */
export const MODEL_PRICES = [
  { prefix: 'claude-fable-', input: 10, output: 50, cacheRead: 0.25 },
  { prefix: 'claude-mythos-', input: 10, output: 50, cacheRead: 0.25 },
  { prefix: 'claude-opus-5-5', input: 4, output: 20, cacheRead: 0.2 },
  { prefix: 'claude-opus-5', input: 5, output: 25, cacheRead: 0.5 },
  { prefix: 'claude-opus-4-8', input: 5, output: 25, cacheRead: 0.5 },
  { prefix: 'claude-opus-4-7', input: 5, output: 25, cacheRead: 0.5 },
  { prefix: 'claude-opus-4-6', input: 5, output: 25, cacheRead: 0.5 },
  { prefix: 'claude-opus-4-5', input: 5, output: 25, cacheRead: 0.5 },
  { prefix: 'claude-opus-4', input: 15, output: 75, cacheRead: 1.5 },
  { prefix: 'claude-sonnet-5', input: 2, output: 10, cacheRead: 0.2 },
  { prefix: 'claude-sonnet-4', input: 3, output: 15, cacheRead: 0.3 },
  { prefix: 'claude-haiku-5', input: 0.1, output: 0.5, cacheRead: 0.01 },
  { prefix: 'claude-haiku-4', input: 1, output: 5, cacheRead: 0.1 },
  { prefix: 'claude-3-5-haiku', input: 0.8, output: 4, cacheRead: 0.08 },
];
const MOST_EXPENSIVE = MODEL_PRICES.reduce((a, b) => (b.output > a.output ? b : a));
// A web search is billed per request: $10 per 1000.
export const WEB_SEARCH_USD = 0.01;

/** @param {unknown} model */
export function modelPrice(model) {
  const id = String(model ?? '').toLowerCase().replace(/^.*\//, '').replace(/\[.*\]$/, '');
  return MODEL_PRICES.find(p => id.startsWith(p.prefix)) || MOST_EXPENSIVE;
}

/**
 * What one message's usage cost, in micro-US$ (Anthropic field names), priced
 * by its model, web searches included. Both sides of a guest's share use it.
 * @param {any} usage @param {unknown} [model]
 * @returns {number}
 */
export function weighTokens(usage, model) {
  if (!usage || typeof usage !== 'object') return 0;
  const n = (/** @type {unknown} */ v) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : 0);
  const p = modelPrice(model);
  const write = n(usage.cache_creation_input_tokens);
  const write1h = Math.min(write, n(usage.cache_creation?.ephemeral_1h_input_tokens));
  const usd = (n(usage.input_tokens) * p.input + (write - write1h) * p.input * 1.25 + write1h * p.input * 2
    + n(usage.cache_read_input_tokens) * p.cacheRead + n(usage.output_tokens) * p.output) / 1e6
    + n(usage.server_tool_use?.web_search_requests) * WEB_SEARCH_USD;
  return usd * 1e6;
}

/** @param {any} key @param {'maxConcurrent'|'requestsPerMinute'} field */
function keyLimit(key, field) {
  const n = Number(key?.[field]);
  return Number.isInteger(n) && n > 0 ? n : GUEST_DEFAULTS[field];
}

export const MAX_GUEST_MAX_TOKENS = 128_000;
export const IMAGE_MIN_TOKENS = 1600;
export const PDF_PAGE_TOKENS = 3000;
export const PDF_UNKNOWN_TOKENS = 100_000;

/**
 * A floor for what images and PDFs cost beyond their bytes: 1600 per image,
 * 3000 per PDF page (pages counted from the decoded PDF, 100k when unknown).
 * @param {unknown} node @param {number} [depth] @returns {number}
 */
export function mediaMinimum(node, depth = 0) {
  if (node == null || typeof node !== 'object' || depth > 64) return 0;
  if (Array.isArray(node)) return node.reduce((sum, x) => sum + mediaMinimum(x, depth + 1), 0);
  const o = /** @type {Record<string, any>} */ (node);
  let n = 0;
  if (o.type === 'image') n += IMAGE_MIN_TOKENS;
  if (o.type === 'document' && o.source?.media_type === 'application/pdf') {
    let pages = 0;
    if (typeof o.source.data === 'string') {
      try {
        const pdf = Buffer.from(o.source.data, 'base64').toString('latin1');
        // Pages inside compressed object streams cannot be counted from the
        // bytes: such a PDF gets the unknown-length floor.
        pages = /\/ObjStm\b/.test(pdf) ? 0 : (pdf.match(/\/Type\s*\/Page(?!s)/g) || []).length;
      } catch { pages = 0; }
    }
    n += pages > 0 ? pages * PDF_PAGE_TOKENS : PDF_UNKNOWN_TOKENS;
  }
  for (const [k, v] of Object.entries(o)) {
    if (k === 'input' && o.type === 'tool_use') continue;
    if (k === 'source') continue;
    if (v && typeof v === 'object') n += mediaMinimum(v, depth + 1);
  }
  return n;
}

/**
 * The first content block (at any depth, tool_result content included) whose
 * content lives somewhere else: a url or file source, or a file_id. Returns a
 * short description, or null.
 * @param {unknown} node @param {number} [depth]
 * @returns {string|null}
 */
export function findRemoteSource(node, depth = 0) {
  if (node == null || typeof node !== 'object' || depth > 64) return null;
  if (Array.isArray(node)) {
    for (const x of node) { const r = findRemoteSource(x, depth + 1); if (r) return r; }
    return null;
  }
  const o = /** @type {Record<string, any>} */ (node);
  if ('file_id' in o) return 'file_id';
  const src = o.source;
  if (src && typeof src === 'object' && !Array.isArray(src)) {
    const t = String(src.type ?? '');
    if (t !== 'base64' && t !== 'text' && t !== 'content') return `source type "${t || '?'}"`;
  }
  if (typeof o.type === 'string' && /^(container_upload|search_result_location|mcp_)/.test(o.type)) return `block type "${o.type}"`;
  for (const [k, v] of Object.entries(o)) {
    // A tool_use block's input is the model's own arguments (any shape at
    // all, a "source" field included), not content: not walked.
    if (k === 'input' && o.type === 'tool_use') continue;
    if (v && typeof v === 'object') { const r = findRemoteSource(v, depth + 1); if (r) return r; }
  }
  return null;
}

/**
 * Betas a guest may send: EXACT names, the ones the installed Claude Code
 * (2.1.29x, 2026-10) uses for an ordinary session. A new beta, even one
 * sharing a prefix with these, is dropped until it is added here. Dropped
 * on purpose: context-1m (the reservation is sized for the standard window),
 * files/MCP/threads/managed agents (input stored server-side), advisor, code
 * execution, cache keep-alive, fast mode, server-side fallbacks. Web search
 * and web fetch are allowed (Claude Code's WebSearch): what they spend shows
 * up in the weekly utilization the usage cap reads. Refresh: strings $(readlink -f $(which claude)) | grep -oE
 * '"[a-z0-9-]+-20[0-9]{2}-?[0-9]{2}-?[0-9]{2}"' | sort -u, then pick.
 */
export const GUEST_BETAS = new Set([
  'claude-code-20250219', 'oauth-2025-04-20', 'interleaved-thinking-2025-05-14', 'context-management-2025-06-27',
  'effort-2025-11-24', 'token-counting-2024-11-01', 'structured-outputs-2025-12-15', 'prompt-caching-scope-2026-01-05',
  'redact-thinking-2026-02-12', 'thinking-binding-controls-2026-08-01', 'thinking-display-updates-2026-08-18',
  'thinking-resumption-2026-07-17', 'thinking-token-count-2026-05-13', 'mid-conversation-system-2026-04-07',
  'mid-conversation-system-clear-at-2026-08-21', 'mid-conversation-tool-changes-2026-07-01', 'per-turn-control-2026-07-01',
  'timing-2026-09-09', 'inline-tools-2026-09-15', 'extended-cache-ttl-2025-04-11',
  'advanced-tool-use-2025-11-20', 'web-search-2025-03-05', 'web-fetch-2025-09-10',
]);

/**
 * The anthropic-beta value a guest request is forwarded with: only allow-listed
 * betas, plus the OAuth beta when the pinned account is a subscription (a
 * Claude Code on an API key never sends it, and upstream refuses an OAuth
 * bearer without it).
 * @param {unknown} value @param {{ oauth?: boolean }} [opts] @returns {string|undefined}
 */
export function guestBetas(value, { oauth = false } = {}) {
  const kept = String(value ?? '').split(',').map(x => x.trim().toLowerCase()).filter(x => GUEST_BETAS.has(x));
  if (oauth && !kept.includes(OAUTH_BETA)) kept.push(OAUTH_BETA);
  return kept.length ? [...new Set(kept)].join(',') : undefined;
}
export const OAUTH_BETA = 'oauth-2025-04-20';

/** Kept for callers: the allowlist, without the OAuth addition. @param {unknown} value */
export function stripLongContextBetas(value) {
  return guestBetas(value);
}

/** A tool the CLIENT runs (name + input_schema, no type or type "custom"). @param {any} t */
function isCustomTool(t) {
  return t && typeof t === 'object' && (t.type == null || t.type === 'custom');
}

// Server tools a guest may use: web search and web fetch (Claude Code's
// WebSearch sends web_search_<date>). Code execution, advisor, MCP and the
// rest stay refused: Claude Code does not send them in normal use.
const GUEST_SERVER_TOOL_RE = /^(web_search|web_fetch)_\d{8}$/;
/** @param {any} t */
export function isAllowedGuestTool(t) {
  return isCustomTool(t) || (t && typeof t === 'object' && GUEST_SERVER_TOOL_RE.test(String(t.type ?? '')));
}

/**
 * Check a guest body before anything is reserved or sent, and work out its
 * worst case. Every way to make the estimate small without making the request
 * small is refused: a compressed body (the estimate would see the compressed
 * bytes), unparseable JSON, a missing / non-positive / absurd max_tokens, and
 * server-side tools other than web search / fetch, or MCP servers.
 * @param {string} pathname @param {Record<string, any>} headers @param {Buffer} body
 * @returns {{ ok: true, estimate: number, inputEstimate: number, maxTokens: number, model?: string|null } | { ok: false, status: number, type: string, message: string }}
 */
export function checkGuestBody(pathname, headers, body) {
  const enc = String(headers?.['content-encoding'] ?? '').trim().toLowerCase();
  if (enc && enc !== 'identity') return { ok: false, status: 415, type: 'invalid_request_error', message: 'Compressed request bodies are not accepted here.' };
  if (pathname === '/v1/models' || pathname.startsWith('/v1/models/')) return { ok: true, estimate: 0, inputEstimate: 0, maxTokens: 0 };
  let json;
  try { json = JSON.parse(body.toString('utf8')); } catch { json = undefined; }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return { ok: false, status: 400, type: 'invalid_request_error', message: 'The request body must be a JSON object.' };
  if (Array.isArray(json.tools) && !json.tools.every(isAllowedGuestTool)) {
    return { ok: false, status: 400, type: 'invalid_request_error', message: 'Only web search and web fetch are available as server-side tools here (code execution, advisor and other server tools are not).' };
  }
  if (json.tools != null && !Array.isArray(json.tools)) return { ok: false, status: 400, type: 'invalid_request_error', message: 'tools must be a list.' };
  // Anything that makes the real input much bigger than the bytes sent: input
  // fetched or stored server-side is invisible to the bytes/3 estimate.
  // Server-side compaction runs an extra summarisation call billed in
  // usage.iterations[]; clearing edits (clear_*) cost nothing extra and stay.
  const edits = json.context_management?.edits;
  if (edits != null && (!Array.isArray(edits) || edits.some((/** @type {any} */ e) => /^compact/i.test(String(e?.type ?? ''))))) {
    return { ok: false, status: 400, type: 'invalid_request_error', message: 'Server-side compaction is not available through this relay.' };
  }
  for (const field of ['thread', 'container']) {
    if (json[field] != null) return { ok: false, status: 400, type: 'invalid_request_error', message: `"${field}" is not available through this relay.` };
  }
  const remote = findRemoteSource(json.messages) || findRemoteSource(json.system);
  if (remote) return { ok: false, status: 400, type: 'invalid_request_error', message: `Content by reference (${remote}) is not available through this relay: send the content itself.` };
  if (json.mcp_servers != null && !(Array.isArray(json.mcp_servers) && json.mcp_servers.length === 0)) {
    return { ok: false, status: 400, type: 'invalid_request_error', message: 'MCP servers are not available through this relay.' };
  }
  const inputEstimate = Math.ceil(body.length / 3) + mediaMinimum(json.messages) + mediaMinimum(json.system);
  const model = typeof json.model === 'string' ? json.model : null;
  if (pathname === '/v1/messages/count_tokens') return { ok: true, estimate: inputEstimate, inputEstimate, maxTokens: 0, model };
  const m = json.max_tokens;
  if (!Number.isInteger(m) || m <= 0 || m > MAX_GUEST_MAX_TOKENS) {
    return { ok: false, status: 400, type: 'invalid_request_error', message: `max_tokens must be a whole number from 1 to ${MAX_GUEST_MAX_TOKENS}.` };
  }
  return { ok: true, estimate: inputEstimate + m, inputEstimate, maxTokens: m, model };
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
 *
 * Beside the guests, one row per pinned ACCOUNT carries what the usage cap
 * needs: how far the account's weekly utilization rose today, and the
 * cost-weighted tokens the account (everyone on it, the guest included) spent
 * today. A guest's share of the weekly quota today =
 *   rise × guest weighted tokens today / account weighted tokens today.
 */
export class GuestUsageTracker {
  constructor({ now = () => Date.now(), staleMs = GUEST_DEFAULTS.weeklyStaleMs } = {}) {
    this.now = now;
    this.staleMs = staleMs;
    /** @type {Map<string, {day: string, requestsToday: number, tokensToday: number, weightedToday: number, lockedDay: string|null, requests: number, tokens: number, lastSeen: number|null, dayPct: Record<string, number>}>} */
    this.guests = new Map();
    /** @type {Map<string, {day: string, rise: number, weightedToday: number, lastUtil: number|null, lastResetAt: number|null, seenAt: number|null}>} */
    this.accounts = new Map();
  }

  /** @param {string} name */
  _row(name) {
    const today = utcDay(this.now());
    let row = this.guests.get(name);
    if (!row) {
      row = { day: today, requestsToday: 0, tokensToday: 0, weightedToday: 0, lockedDay: null, requests: 0, tokens: 0, lastSeen: null, dayPct: {} };
      this.guests.set(name, row);
    }
    if (row.day !== today) { row.day = today; row.requestsToday = 0; row.tokensToday = 0; row.weightedToday = 0; }
    return row;
  }

  /** @param {string} account */
  _account(account) {
    const today = utcDay(this.now());
    let row = this.accounts.get(account);
    if (!row) {
      row = { day: today, rise: 0, weightedToday: 0, lastUtil: null, lastResetAt: null, seenAt: null };
      this.accounts.set(account, row);
    }
    // A new day starts with no rise. Its baseline is the next reading unless
    // the last one is recent and from today (see observeWeekly).
    if (row.day !== today) { row.day = today; row.rise = 0; row.weightedToday = 0; }
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

  /** The guest's cost-weighted tokens (weighTokens). @param {string} name @param {number} w */
  recordGuestWeighted(name, w) {
    const n = Number(w);
    if (!Number.isFinite(n) || n <= 0) return;
    this._row(name).weightedToday += n;
  }

  /** Everyone's cost-weighted tokens on `account`. @param {string} account @param {number} w */
  recordAccountWeighted(account, w) {
    const n = Number(w);
    if (!Number.isFinite(n) || n <= 0) return;
    this._account(account).weightedToday += n;
  }

  /**
   * A weekly utilization reading (0-1) for `account`. The rise since the last
   * reading is today's; a weekly reset inside the day keeps what was risen
   * before it and counts the new window from 0.
   *
   * The rise is only booked between two readings close in time: when the
   * previous one is missing, older than staleMs, or from before today's 00:00
   * UTC, this reading is a fresh baseline and adds nothing. Otherwise a gap
   * (days of the guest switched off, a weekly reset in between) would land as
   * today's rise and lock the guest at once.
   * @param {string} account @param {number|null|undefined} util @param {number|null|undefined} resetAt @param {number|null|undefined} seenAt
   */
  observeWeekly(account, util, resetAt, seenAt) {
    const u = Number(util);
    if (util == null || !Number.isFinite(u) || u < 0) return;
    const seen = Number(seenAt) || null;
    const row = this._account(account);
    if (seen != null && row.seenAt != null && seen < row.seenAt) return;
    const reset = Number(resetAt) || null;
    const at = seen ?? this.now();
    const dayStart = Date.parse(`${utcDay(this.now())}T00:00:00Z`);
    const gap = row.lastUtil == null || row.seenAt == null || at - row.seenAt > this.staleMs || row.seenAt < dayStart;
    if (gap) {
      row.lastUtil = u;
    } else {
      const last = /** @type {number} */ (row.lastUtil);
      // A reset is the reset time moving on, or a drop once the old reset
      // time has passed. A drop with the old window still running is a
      // lagging reading (probe vs headers): ignored.
      const moved = reset != null && row.lastResetAt != null && reset > row.lastResetAt + 3_600_000;
      const due = row.lastResetAt != null && at >= row.lastResetAt;
      const rolled = moved || (u < last - 0.02 && due);
      if (rolled) { row.rise += u; row.lastUtil = u; }
      else if (u > last) { row.rise += u - last; row.lastUtil = u; }
    }
    if (reset != null) row.lastResetAt = reset;
    if (seen != null) row.seenAt = seen;
  }

  /**
   * The guest's share of `account`'s weekly quota used today, in %. `pct` is
   * null when the account's weekly reading is missing or older than staleMs:
   * then only the backstop applies.
   * @param {string} name @param {string} account
   * @returns {{pct: number|null, stale: boolean, risePct: number, guestWeighted: number, accountWeighted: number}}
   */
  share(name, account) {
    const today = utcDay(this.now());
    const g = this.guests.get(name);
    const a = this.accounts.get(account);
    const guestWeighted = g && g.day === today ? g.weightedToday : 0;
    const accountWeighted = a && a.day === today ? a.weightedToday : 0;
    const rise = a && a.day === today ? a.rise : 0;
    const stale = !a || a.seenAt == null || this.now() - a.seenAt > this.staleMs;
    const fraction = accountWeighted > 0 ? Math.min(1, guestWeighted / accountWeighted) : 0;
    return { pct: stale ? null : rise * 100 * fraction, stale, risePct: rise * 100, guestWeighted, accountWeighted };
  }

  /**
   * Remember today's share % (the latest figure wins), for the weekly
   * ceiling. Only the last 8 days are kept.
   * @param {string} name @param {number} pct
   */
  noteDayPct(name, pct) {
    const n = Number(pct);
    if (!Number.isFinite(n) || n < 0) return;
    const row = this._row(name);
    row.dayPct[utcDay(this.now())] = n;
    const days = Object.keys(row.dayPct).sort();
    for (const d of days.slice(0, Math.max(0, days.length - 8))) delete row.dayPct[d];
  }

  /** The guest's share % summed over the UTC days from startDay on. @param {string} name @param {string} startDay */
  weekPct(name, startDay) {
    const row = this.guests.get(name);
    if (!row) return 0;
    return Object.entries(row.dayPct).reduce((s, [d, v]) => (d >= startDay ? s + v : s), 0);
  }

  /** Lock the guest for the rest of today (UTC). @param {string} name */
  lock(name) { this._row(name).lockedDay = utcDay(this.now()); }

  /** @param {string} name */
  lockedToday(name) {
    return this.guests.get(name)?.lockedDay === utcDay(this.now());
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
    return Object.fromEntries([...this.guests].map(([k, v]) => [k, { ...v, dayPct: { ...v.dayPct } }]));
  }

  exportAccounts() {
    return Object.fromEntries([...this.accounts].map(([k, v]) => [k, { ...v }]));
  }

  /** @param {any} saved @param {any} [savedAccounts] */
  restore(saved, savedAccounts) {
    const num = (/** @type {any} */ v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
    if (saved && typeof saved === 'object') {
      for (const [name, v] of Object.entries(saved)) {
        if (!v || typeof v !== 'object') continue;
        this.guests.set(name, {
          day: typeof v.day === 'string' ? v.day : utcDay(this.now()),
          requestsToday: num(v.requestsToday),
          tokensToday: num(v.tokensToday),
          weightedToday: num(v.weightedToday),
          lockedDay: typeof v.lockedDay === 'string' ? v.lockedDay : null,
          dayPct: v.dayPct && typeof v.dayPct === 'object'
            ? Object.fromEntries(Object.entries(v.dayPct).filter(([d, x]) => /^\d{4}-\d{2}-\d{2}$/.test(d) && Number.isFinite(Number(x))).map(([d, x]) => [d, Number(x)]))
            : {},
          requests: num(v.requests),
          tokens: num(v.tokens),
          lastSeen: Number(v.lastSeen) || null,
        });
      }
    }
    if (savedAccounts && typeof savedAccounts === 'object') {
      for (const [account, v] of Object.entries(savedAccounts)) {
        if (!v || typeof v !== 'object' || typeof v.day !== 'string') continue;
        this.accounts.set(account, {
          day: v.day,
          rise: num(v.rise),
          weightedToday: num(v.weightedToday),
          lastUtil: v.lastUtil == null ? null : num(v.lastUtil),
          lastResetAt: Number(v.lastResetAt) || null,
          seenAt: Number(v.seenAt) || null,
        });
      }
    }
  }
}

/**
 * Feed `guestUsage` the pinned account's current weekly reading.
 * @param {any} accountManager @param {GuestUsageTracker} guestUsage @param {number} index
 */
export function sampleWeekly(accountManager, guestUsage, index) {
  const a = accountManager?.accounts?.[index];
  if (!a?.quota) return;
  guestUsage.observeWeekly(a.name, a.quota.unified7d, a.quota.unified7dReset, a.quota.unified7dSeenAt);
}

/** What `teamclaude status` and the dashboard show per guest key. */
/** @param {any} config @param {GuestUsageTracker} guestUsage @param {any} [listening] @param {any} [accountManager] */
export function guestStatus(config, guestUsage, listening = null, accountManager = null) {
  /** @type {any[]} */
  const keys = Array.isArray(config?.guests?.keys) ? config.guests.keys : [];
  return {
    listen: config?.guests?.listen ? { host: config.guests.listen.host, port: config.guests.listen.port } : null,
    listening,
    keys: keys.filter((/** @type {any} */ k) => k && typeof k.name === 'string').map((/** @type {any} */ k) => {
      const idx = accountManager && typeof k.account === 'string' ? resolveAccountPin(accountManager, k.account.trim()) : null;
      if (idx != null) sampleWeekly(accountManager, guestUsage, idx);
      const accountName = idx != null ? accountManager.accounts[idx].name : (k.account || '');
      const sh = guestUsage.share(k.name.trim(), accountName);
      if (sh.pct != null) guestUsage.noteDayPct(k.name.trim(), sh.pct);
      const quota = idx != null ? (accountManager.accounts[idx].quota || {}) : {};
      const win = weeklyWindow(quota.unified7dReset);
      const wk = guestUsage.weekPct(k.name.trim(), win.startDay);
      const u5 = Number(quota.unified5h);
      const r5 = Number(quota.unified5hReset) || null;
      const p5 = guestPause5hPct(k, config?.guests);
      const cap = guestCap(k);
      return {
        name: k.name,
        account: k.account || null,
        enabled: k.enabled !== false,
        dailyTokenCap: cap === Infinity ? 'unlimited' : cap,
        sharePct: sh.pct == null ? null : Math.round(sh.pct * 100) / 100,
        shareStale: sh.stale,
        capPct: guestPct(k, config?.guests),
        locked: guestUsage.lockedToday(k.name.trim()),
        weekSharePct: Math.round(wk * 100) / 100,
        weeklyCapPct: guestWeeklyPct(k, config?.guests),
        weeklyLocked: wk >= guestWeeklyPct(k, config?.guests),
        pause5hPct: p5,
        paused: quota.unified5h != null && Number.isFinite(u5) && (r5 == null || Date.now() < r5) && u5 * 100 > p5,
        ...guestUsage.get(k.name.trim()),
      };
    }),
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
 * @param {((b: Buffer) => void)|null} [tap] sees every body byte as the forwarder wrote it (the guest stream log)
 */
function guardResponse(res, identifiers, tap = null) {
  const setHeader = res.setHeader.bind(res);
  res.setHeader = (/** @type {string} */ name, /** @type {any} */ value) => (isAllowedResponseHeader(name) ? setHeader(name, value) : res);
  const writeHead = res.writeHead.bind(res);
  const write = res.write.bind(res);
  const end = res.end.bind(res);
  /** @type {Buffer[]|null} */
  let held = null;
  let heldBytes = 0;
  let status = 200;
  // A success body is passed through line by line (whole lines only, so a
  // figure is never split) with its prompt-cache figures zeroed: the account's
  // cache is shared with its owner, and a cache hit would tell the guest that a
  // guessed prefix matches the owner's prompts. Booked before this, unchanged.
  /** @type {Buffer} */
  let carry = Buffer.alloc(0);
  const passOn = (/** @type {Buffer} */ b, /** @type {boolean} */ last) => {
    const all = carry.length ? Buffer.concat([carry, b]) : b;
    const cut = last ? all.length : all.lastIndexOf(0x0a) + 1;
    carry = all.subarray(cut);
    return cut ? zeroCacheFigures(all.subarray(0, cut).toString('utf8')) : '';
  };
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
    if (code >= 400) held = [];
    return writeHead(code, ...args);
  };
  const hold = (/** @type {any} */ chunk, /** @type {any} */ enc) => {
    if (chunk == null || typeof chunk === 'function') return;
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), /** @type {BufferEncoding} */ (typeof enc === 'string' ? enc : 'utf8'));
    if (heldBytes < 256 * 1024) { held?.push(b); heldBytes += b.length; }
  };
  const asBuffer = (/** @type {any} */ chunk, /** @type {any} */ enc) => (Buffer.isBuffer(chunk) ? chunk
    : Buffer.from(String(chunk), /** @type {BufferEncoding} */ (typeof enc === 'string' ? enc : 'utf8')));
  const tapped = (/** @type {any} */ chunk, /** @type {any} */ enc) => {
    if (!tap || chunk == null || typeof chunk === 'function') return;
    try { tap(asBuffer(chunk, enc)); } catch { /* logging never fails a request */ }
  };
  res.write = (/** @type {any} */ chunk, /** @type {any} */ enc, /** @type {any} */ cb) => {
    tapped(chunk, enc);
    if (!held) {
      if (chunk == null || typeof chunk === 'function') return write(chunk, enc, cb);
      const out = passOn(asBuffer(chunk, enc), false);
      const done = typeof enc === 'function' ? enc : cb;
      if (!out) { if (typeof done === 'function') done(); return true; }
      return write(out, typeof done === 'function' ? done : undefined);
    }
    hold(chunk, enc);
    if (typeof enc === 'function') enc(); else if (typeof cb === 'function') cb();
    return true;
  };
  res.end = (/** @type {any} */ chunk, /** @type {any} */ enc, /** @type {any} */ cb) => {
    tapped(chunk, enc);
    if (!held) {
      const done = typeof chunk === 'function' ? chunk : typeof enc === 'function' ? enc : cb;
      const tail = passOn(chunk == null || typeof chunk === 'function' ? Buffer.alloc(0) : asBuffer(chunk, enc), true);
      return end(tail || undefined, typeof done === 'function' ? done : undefined);
    }
    hold(chunk, enc);
    const text = Buffer.concat(held).toString('utf8');
    held = null;
    return end(scrubErrorBody(text, status, identifiers()), typeof cb === 'function' ? cb : (typeof enc === 'function' ? enc : undefined));
  };
}

const CACHE_FIGURE_RE = /"(cache_read_input_tokens|cache_creation_input_tokens|cache_missed_input_tokens|ephemeral_5m_input_tokens|ephemeral_1h_input_tokens)"(\s*):(\s*)\d+/g;
/** @param {string} text */
export function zeroCacheFigures(text) {
  return text.replace(CACHE_FIGURE_RE, '"$1"$2:$30');
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
 * @param {{accountManager: any, config: any, hooks?: any, sx?: any, guestUsage: GuestUsageTracker, upstream?: string|null, log?: (m: string) => void, persist?: (() => unknown)|null}} opts
 */
export function createGuestRequestHandler({ accountManager, config, hooks = {}, sx = null, guestUsage, upstream = null, log = console.log, persist = null }) {
  let lastPersist = 0;
  const persistNow = () => {
    if (!persist) return;
    lastPersist = Date.now();
    try { Promise.resolve(persist()).catch(() => {}); } catch { /* best effort */ }
  };
  // Usage near the cap is saved at once (at most every 10 s), so a crash
  // cannot hand back up to a minute of spend.
  const persistNearCap = (/** @type {string} */ name, /** @type {number} */ cap) => {
    if (!persist || !Number.isFinite(cap) || guestUsage.tokensToday(name) < 0.9 * cap) return;
    if (Date.now() - lastPersist < 10_000) return;
    persistNow();
  };
  // Every account's spend today, cost-weighted: the denominator of a guest's
  // share. Fed by the same per-message usage every listener records, and the
  // weekly reading sampled at the same moment (its headers came first).
  const unsubscribe = typeof accountManager?.onTokenUsage === 'function'
    ? accountManager.onTokenUsage((/** @type {number} */ idx, /** @type {any} */ usage, /** @type {any} */ model) => {
      const a = accountManager.accounts[idx];
      if (!a) return;
      sampleWeekly(accountManager, guestUsage, idx);
      guestUsage.recordAccountWeighted(a.name, weighTokens(usage, model));
    })
    : () => {};
  /** @type {Map<string, number>} guests whose weekly reading is stale → when that was last logged (once an hour) */
  const staleLogged = new Map();
  /** @type {Map<string, number>} guests at their weekly ceiling → when that was last logged (once an hour) */
  const weeklyLogged = new Map();
  let lastLogFailLine = 0;
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
        // A guest's prompts never reach the operator's request log: they go
        // to the guest stream logs (guest-log.js) instead.
        logDir: null,
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
    // The pin must name a configured account. Checked here so a typo never
    // reaches the forwarder's "unknown pin" message, which names the pin.
    const pinIndex = resolveAccountPin(accountManager, key.account.trim());
    if (pinIndex == null) {
      log(`[TeamClaude] guest ${name}: pinned account "${key.account}" is not configured`);
      sendJson(res, 503, 'api_error', GENERIC_ERROR(503));
      return;
    }
    const lockedOut = () => {
      sendJson(res, 429, 'rate_limit_error', DAILY_LIMIT_MESSAGE,
        { 'retry-after': String(secondsToUtcMidnight()), connection: 'close' });
      req.resume?.();
    };
    // The usage cap: the guest's share of the pinned account's weekly quota
    // spent today. Once reached the key stays locked until 00:00 UTC.
    if (guestUsage.lockedToday(name)) { lockedOut(); return; }
    sampleWeekly(accountManager, guestUsage, pinIndex);
    const sh = guestUsage.share(name, accountManager.accounts[pinIndex].name);
    const pct = guestPct(key, config.guests);
    if (sh.pct != null && sh.pct >= pct) {
      guestUsage.lock(name);
      log(`[TeamClaude] guest ${name}: daily usage cap reached (${sh.pct.toFixed(1)}% of the weekly quota today, cap ${pct}%), locked until 00:00 UTC`);
      persistNow();
      lockedOut();
      return;
    }
    // The weekly ceiling: the guest's share of the weekly quota summed over
    // the account's current 7-day window (rolling 7 days when its reset time
    // is unknown). Not a lock: it lifts as the window moves on.
    if (sh.pct != null) guestUsage.noteDayPct(name, sh.pct);
    const quota = accountManager.accounts[pinIndex].quota || {};
    const win = weeklyWindow(quota.unified7dReset);
    const wk = guestUsage.weekPct(name, win.startDay);
    const wkCap = guestWeeklyPct(key, config.guests);
    if (wk >= wkCap) {
      if (Date.now() - (weeklyLogged.get(name) ?? -Infinity) >= 3_600_000) {
        weeklyLogged.set(name, Date.now());
        log(`[TeamClaude] guest ${name}: weekly ceiling reached (${wk.toFixed(1)}% of the weekly quota this window, cap ${wkCap}%), refused until the window moves on`);
      }
      sendJson(res, 429, 'rate_limit_error', `Weekly limit reached. It resets ${win.resetText}.`,
        { 'retry-after': String(win.retryAfter), connection: 'close' });
      req.resume?.();
      return;
    }
    // The pause: while the account's 5-hour window is past pause5hPct, the
    // guest waits so the owner's own work keeps the room. Lifts by itself.
    const p5 = guestPause5hPct(key, config.guests);
    const u5 = Number(quota.unified5h);
    const r5 = Number(quota.unified5hReset) || null;
    if (quota.unified5h != null && Number.isFinite(u5) && (r5 == null || Date.now() < r5) && u5 * 100 > p5) {
      const wait = r5 ? Math.min(600, Math.max(30, Math.ceil((r5 - Date.now()) / 1000))) : 300;
      sendJson(res, 429, 'rate_limit_error', 'The shared account is busy right now. Try again in a few minutes.',
        { 'retry-after': String(wait), connection: 'close' });
      req.resume?.();
      return;
    }
    if (sh.stale) {
      if (Date.now() - (staleLogged.get(name) ?? -Infinity) >= 3_600_000) {
        staleLogged.set(name, Date.now());
        log(`[TeamClaude] guest ${name}: no fresh weekly reading for the pinned account, only the ${Number.isFinite(cap) ? cap.toLocaleString('en-US') + '-token' : 'unlimited'} backstop applies until one arrives`);
      }
    } else staleLogged.delete(name);
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
    // Already at the backstop (counting what is in flight): refuse before
    // reading a single body byte, so a capped-out key costs this process nothing.
    if (Number.isFinite(cap) && guestUsage.tokensToday(name) + state.reserved >= cap) {
      lockedOut();
      return;
    }
    state.recent.push(now);
    state.inflight += 1;
    let reservation = 0;
    let released = false;
    // What this request has booked so far, to settle a cut-short answer.
    const booked = { input: 0, output: 0, extra: 0, final: false, forwarded: false, maxTokens: 0, inputEstimate: 0, completion: false, weighted: 0, model: /** @type {string|null} */ (null) };
    /** @type {Record<string, any>} the message's usage so far, merged the way server.js merges it */
    const merged = {};
    /** @type {ReturnType<typeof openGuestLog>} */
    let entry = null;
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
    // The log entry is closed (gzipped, marked .done) when the answer ends.
    res.once('close', () => entry?.end(res.statusCode));
    /** A refusal after the body was read: answered, and kept (under the unbilled cap) in the stream log. */
    const refuse = (/** @type {number} */ status, /** @type {string} */ type, /** @type {string} */ message, /** @type {Record<string, string>} */ extra = {}) => {
      entry?.begin(true);
      entry?.chunk(Buffer.from(JSON.stringify({ type: 'error', error: { type, message } })));
      sendJson(res, status, type, message, extra);
    };
    try {
      const limit = Number(config.guests?.maxBodyBytes) > 0 ? Number(config.guests.maxBodyBytes) : GUEST_DEFAULTS.maxBodyBytes;
      const body = await readBody(req, limit);
      if (body == null) {
        sendJson(res, 413, 'request_too_large', 'Request too large.', { connection: 'close' });
        req.destroy?.();
        return;
      }
      // The request and, below, the answer as received (guest-log.js). A
      // billed completion is logged in full; anything unbilled (refused here,
      // count_tokens, models) under the unbilled cap. Logging fails CLOSED:
      // a request that cannot be logged is refused before it is forwarded.
      entry = openGuestLog({ config, guest: name, method: req.method, url: req.url, headers: req.headers,
        body, presentedKey: presentedGuestKey(req.headers), log });
      const pathname = new URL(req.url, 'http://guest.invalid').pathname;
      const checked = checkGuestBody(pathname, req.headers, body);
      if (!checked.ok) {
        const bad = /** @type {{status: number, type: string, message: string}} */ (/** @type {unknown} */ (checked));
        refuse(bad.status, bad.type, bad.message);
        return;
      }
      const good = /** @type {{estimate: number, inputEstimate: number, maxTokens: number, model?: string|null}} */ (/** @type {unknown} */ (checked));
      booked.model = good.model ?? null;
      booked.maxTokens = good.maxTokens;
      booked.inputEstimate = good.inputEstimate;
      booked.completion = pathname === '/v1/messages';
      // Reserve before sending: today's real usage + what is in flight + this
      // request's worst case must fit, so parallel requests cannot all slip in
      // under the cap and land far past it.
      reservation = Number.isFinite(cap) ? good.estimate : 0;
      if (Number.isFinite(cap) && guestUsage.tokensToday(name) + state.reserved + reservation > cap) {
        log(`[TeamClaude] guest ${name}: token backstop ${cap} reached (used ${guestUsage.tokensToday(name)}, in flight ${state.reserved}), 429`);
        reservation = 0;
        refuse(429, 'rate_limit_error', DAILY_LIMIT_MESSAGE, { 'retry-after': String(secondsToUtcMidnight()) });
        return;
      }
      state.reserved += reservation;
      if (entry) {
        const logged = await entry.begin(!booked.completion);
        if (logged === 'failed') {
          if (Date.now() - lastLogFailLine >= 60_000) {
            lastLogFailLine = Date.now();
            log(`[TeamClaude] guest ${name}: request refused, it could not be logged (log budget spent or not writable)`);
          }
          sendJson(res, 503, 'api_error', 'Logging unavailable. Try again later.', { 'retry-after': '60' });
          return;
        }
      }
      for (const h of STRIPPED_REQUEST_HEADERS) delete req.headers[h];
      const pinned = accountManager.accounts[/** @type {number} */ (resolveAccountPin(accountManager, key.account.trim()))];
      const beta = guestBetas(req.headers['anthropic-beta'], { oauth: pinned?.type === 'oauth' });
      if (beta === undefined) delete req.headers['anthropic-beta'];
      else req.headers['anthropic-beta'] = beta;
      const log1 = entry;
      guardResponse(res, identifiers, log1 ? (b) => log1.chunk(b) : null);
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
      replay.tcGuestUsage = (/** @type {number} */ input, /** @type {number} */ output, /** @type {number} */ cache, /** @type {any} */ cumulative, /** @type {any} */ raw) => {
        // Cost-weighted, from the merged figures: the same weighing the
        // account's side of the share gets (weighTokens).
        const report = raw && typeof raw === 'object' ? raw : (cumulative && typeof cumulative === 'object' ? cumulative : null);
        if (report) {
          Object.assign(merged, report);
          const w = weighTokens(merged, booked.model);
          if (w > booked.weighted) { guestUsage.recordGuestWeighted(name, w - booked.weighted); booked.weighted = w; }
        }
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
          // Server-side iterations (e.g. compaction) are billed per iteration:
          // when their sum is larger than everything booked, book the rest.
          if (Array.isArray(cumulative.iterations)) {
            const it = cumulative.iterations.reduce((/** @type {number} */ sum, /** @type {any} */ x) => sum + (Number(x?.input_tokens) || 0) + (Number(x?.output_tokens) || 0)
              + (Number(x?.cache_creation_input_tokens) || 0) + (Number(x?.cache_read_input_tokens) || 0), 0);
            const have = booked.input + booked.output + booked.extra;   // everything booked, this call included
            if (it > have) { add += it - have; booked.extra += it - have; }
          }
        }
        guestUsage.recordTokens(name, add);
        persistNearCap(name, cap);
      };
      booked.forwarded = true;
      await forwarderFor(key)(replay, res);
    } finally {
      if (res.writableEnded || res.destroyed) release();
    }
  };

  // A throw in here must never escape: an unhandled rejection takes the whole
  // proxy (every one of the operator's sessions) down with it.
  const handler = async (/** @type {any} */ req, /** @type {any} */ res) => {
    try {
      await handle(req, res);
    } catch (err) {
      log(`[TeamClaude] guest handler error: ${safeLine(err instanceof Error ? err.message : String(err), 300)}`);
      try {
        if (!res.headersSent) sendJson(res, 500, 'api_error', GENERIC_ERROR(500));
        else res.destroy();
      } catch { /* socket already gone */ }
    }
  };
  return Object.assign(handler, { dispose: unsubscribe });
}

export const DAILY_LIMIT_MESSAGE = 'Daily limit reached. It resets at 00:00 UTC.';

/** @param {number} [ms] */
export function secondsToUtcMidnight(ms = Date.now()) {
  const d = new Date(ms);
  const next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - ms) / 1000));
}

/** @param {Parameters<typeof createGuestRequestHandler>[0]} opts */
export function createGuestServer(opts) {
  const handler = createGuestRequestHandler(opts);
  const server = http.createServer({
    headersTimeout: GUEST_DEFAULTS.headersTimeoutMs,
    requestTimeout: GUEST_DEFAULTS.requestTimeoutMs,
  }, handler);
  server.on('close', () => handler.dispose());
  /** @type {any} */ (server).disposeGuest = handler.dispose;
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
  // Guest stream logs: pruned now and once a day (retention + size backstop).
  const stopPruner = startGuestLogPruner({ config: opts.config, log });
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
      stopPruner();
      /** @type {any} */ (server).disposeGuest?.();
      server.closeAllConnections?.();
      server.close(() => {});
    },
  };
}
