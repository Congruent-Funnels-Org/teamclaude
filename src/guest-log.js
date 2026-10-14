// Guest stream logs (config.guests.logBodies, default on): the FULL request
// and the FULL answer, as received from upstream, of every guest request that
// got as far as a body, so the operator can see what a guest does.
//
//   <logDir>/<guest>/<YYYY-MM-DD>/<HHMMSS>-<reqid>.req.json   method, url, headers (auth stripped), body
//   <logDir>/<guest>/<YYYY-MM-DD>/<HHMMSS>-<reqid>.res.sse    the response body bytes, SSE or JSON
//
// logDir defaults to ~/.local/share/teamclaude/guest-logs (guests.logDir).
// Dirs 0700, files 0600. No credential is written: the guest's key, any auth
// header and cookies are stripped, and account tokens never pass through here
// (they are added by the forwarder, after this sees the request).
//
// Logging never blocks or fails a request: every write is async, and a write
// error is one log line, the request goes on. Retention: guests.logRetentionDays
// (default 90) and a size backstop guests.logMaxMB (default 5000, oldest days
// first), pruned at start and once a day.

import { createWriteStream } from 'node:fs';
import { mkdir, writeFile, readdir, readFile, stat, rm } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

export const GUEST_LOG_DEFAULTS = {
  retentionDays: 90,
  maxMB: 5000,
  pruneEveryMs: 24 * 3600_000,
  maxQueuedBytes: 64 * 1024 * 1024, // held while the file opens; more is dropped
};

const SECRET_HEADERS = new Set(['authorization', 'x-api-key', 'proxy-authorization', 'cookie', 'set-cookie']);
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/** @param {any} config */
export function guestLogDir(config) {
  const d = config?.guests?.logDir;
  if (typeof d === 'string' && d.trim()) return d.trim();
  return join(process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'teamclaude', 'guest-logs');
}

/** @param {any} config */
export function guestLogsEnabled(config) {
  return config?.guests?.logBodies !== false;
}

/** A guest name as one safe path segment. @param {string} name */
export function guestDirName(name) {
  const s = String(name).trim().replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
  return !s || /^\.+$/.test(s) ? '_' : s;
}

/**
 * The request headers minus every credential: auth headers, cookies, and any
 * header that carries the presented guest key.
 * @param {Record<string, any>|undefined} headers @param {string|null} [presentedKey]
 */
export function sanitizeHeaders(headers, presentedKey = null) {
  /** @type {Record<string, any>} */
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const name = k.toLowerCase();
    if (SECRET_HEADERS.has(name)) continue;
    if (presentedKey && String(v).includes(presentedKey)) continue;
    out[name] = v;
  }
  return out;
}

let lastFailLog = 0;

/**
 * Start the log of one guest request. Returns null when logging is off.
 * `chunk` takes response bytes as they arrive, `end` closes the file.
 * @param {{config: any, guest: string, method?: string, url?: string, headers?: Record<string, any>, body: Buffer,
 *   presentedKey?: string|null, log?: (m: string) => void, now?: number, reqId?: string}} o
 * @returns {{chunk: (b: Buffer) => void, end: () => void, reqPath: string, resPath: string}|null}
 */
export function openGuestLog({ config, guest, method = 'POST', url = '', headers = {}, body, presentedKey = null, log = console.log, now = Date.now(), reqId }) {
  if (!guestLogsEnabled(config)) return null;
  const at = new Date(now);
  const iso = at.toISOString();
  const day = iso.slice(0, 10);
  const id = reqId || randomBytes(4).toString('hex');
  const stem = `${iso.slice(11, 19).replace(/:/g, '')}-${id}`;
  const dir = join(guestLogDir(config), guestDirName(guest), day);
  const reqPath = join(dir, `${stem}.req.json`);
  const resPath = join(dir, `${stem}.res.sse`);

  let failed = false;
  const fail = (/** @type {any} */ err) => {
    if (failed) return;
    failed = true;
    // One line per failing request, and at most one a minute overall.
    const t = Date.now();
    if (t - lastFailLog < 60_000) return;
    lastFailLog = t;
    try { log(`[TeamClaude] guest ${guest}: stream log write failed (${err?.code || err?.message || err}); the request goes on`); } catch { /* nothing */ }
  };

  /** @type {Buffer[]} */
  let queue = [];
  let queued = 0;
  let ended = false;
  /** @type {import('node:fs').WriteStream|null} */
  let stream = null;

  let parsed;
  try { parsed = JSON.parse(body.toString('utf8')); } catch { parsed = body.toString('utf8'); }
  const reqDoc = JSON.stringify({ at: iso, reqId: id, guest, method, url, headers: sanitizeHeaders(headers, presentedKey), body: parsed }, null, 1);

  mkdir(dir, { recursive: true, mode: 0o700 })
    .then(() => writeFile(reqPath, reqDoc, { mode: 0o600, flag: 'wx' }))
    .then(() => {
      if (failed) return;
      stream = createWriteStream(resPath, { mode: 0o600, flags: 'wx' });
      stream.on('error', fail);
      for (const b of queue) stream.write(b);
      queue = [];
      if (ended) stream.end();
    })
    .catch(fail);

  return {
    reqPath,
    resPath,
    chunk(b) {
      if (failed || ended || !b?.length) return;
      if (stream) { stream.write(b); return; }
      if (queued + b.length > GUEST_LOG_DEFAULTS.maxQueuedBytes) return;
      queue.push(Buffer.from(b));
      queued += b.length;
    },
    end() {
      if (ended) return;
      ended = true;
      if (stream) stream.end();
    },
  };
}

/** @param {string} p @returns {Promise<number>} */
async function dirBytes(p) {
  let n = 0;
  let entries;
  try { entries = await readdir(p, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const f = join(p, e.name);
    if (e.isDirectory()) n += await dirBytes(f);
    else { try { n += (await stat(f)).size; } catch { /* gone */ } }
  }
  return n;
}

/**
 * Remove day folders older than retentionDays, then, while the whole log is
 * over maxMB, the oldest remaining days (today last).
 * @param {{dir: string, retentionDays?: number, maxMB?: number, now?: number}} o
 * @returns {Promise<{removed: string[], bytes: number}>}
 */
export async function pruneGuestLogs({ dir, retentionDays = GUEST_LOG_DEFAULTS.retentionDays, maxMB = GUEST_LOG_DEFAULTS.maxMB, now = Date.now() }) {
  /** @type {string[]} */
  const removed = [];
  /** @type {{path: string, day: string, bytes: number}[]} */
  const days = [];
  let guests;
  try { guests = await readdir(dir, { withFileTypes: true }); } catch { return { removed, bytes: 0 }; }
  const cutoff = new Date(now - retentionDays * 86_400_000).toISOString().slice(0, 10);
  for (const g of guests) {
    if (!g.isDirectory()) continue;
    let ds;
    try { ds = await readdir(join(dir, g.name), { withFileTypes: true }); } catch { continue; }
    for (const d of ds) {
      if (!d.isDirectory() || !DAY_RE.test(d.name)) continue;
      const path = join(dir, g.name, d.name);
      if (d.name < cutoff) { await rm(path, { recursive: true, force: true }); removed.push(path); continue; }
      days.push({ path, day: d.name, bytes: await dirBytes(path) });
    }
  }
  let bytes = days.reduce((s, d) => s + d.bytes, 0);
  const limit = maxMB * 1024 * 1024;
  days.sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
  for (const d of days) {
    if (bytes <= limit) break;
    await rm(d.path, { recursive: true, force: true });
    removed.push(d.path);
    bytes -= d.bytes;
  }
  return { removed, bytes };
}

/**
 * Prune now and once a day. Settings are read from the live config each run.
 * @param {{config: any, log?: (m: string) => void, everyMs?: number}} o
 * @returns {() => void} stop
 */
export function startGuestLogPruner({ config, log = console.log, everyMs = GUEST_LOG_DEFAULTS.pruneEveryMs }) {
  const run = () => {
    if (!guestLogsEnabled(config)) return;
    const g = config?.guests || {};
    const days = Number(g.logRetentionDays) > 0 ? Number(g.logRetentionDays) : GUEST_LOG_DEFAULTS.retentionDays;
    const mb = Number(g.logMaxMB) > 0 ? Number(g.logMaxMB) : GUEST_LOG_DEFAULTS.maxMB;
    pruneGuestLogs({ dir: guestLogDir(config), retentionDays: days, maxMB: mb })
      .then(r => { if (r.removed.length) log(`[TeamClaude] guest logs: pruned ${r.removed.length} day folder(s)`); })
      .catch(err => log(`[TeamClaude] guest logs: prune failed (${err?.message || err})`));
  };
  run();
  const t = setInterval(run, everyMs);
  t.unref?.();
  return () => clearInterval(t);
}

// ── reading them back: `teamclaude guest logs <name>` ───────────────────────

/** @param {unknown} content @returns {string} */
function textOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.map((/** @type {any} */ b) => {
    if (b?.type === 'text') return b.text;
    if (b?.type === 'tool_result') return `[tool result${b.is_error ? ', error' : ''}]`;
    if (b?.type === 'image') return '[image]';
    if (b?.type === 'document') return '[document]';
    return '';
  }).filter(Boolean).join('\n');
}

/** @param {string} s @param {number} n */
function clip(s, n) {
  const t = String(s).trim();
  return t.length > n ? `${t.slice(0, n)}… (+${t.length - n} chars)` : t;
}

/**
 * Parse one answer (SSE or a JSON body) into text, tool calls, usage, error.
 * @param {string} raw
 */
export function parseGuestAnswer(raw) {
  let text = '';
  /** @type {string[]} */
  const tools = [];
  /** @type {Record<string, any>} */
  const usage = {};
  let model = null;
  let error = null;
  const take = (/** @type {any} */ d) => {
    if (!d || typeof d !== 'object') return;
    if (d.type === 'error') error = d.error?.message || 'error';
    else if (d.type === 'message_start') { model = d.message?.model || model; Object.assign(usage, d.message?.usage || {}); }
    else if (d.type === 'message_delta') Object.assign(usage, d.usage || {});
    else if (d.type === 'content_block_start') {
      const b = d.content_block;
      if (b?.type === 'tool_use' || b?.type === 'server_tool_use') tools.push(b.name || b.type);
    } else if (d.type === 'content_block_delta' && d.delta?.type === 'text_delta') text += d.delta.text || '';
    else if (d.type === 'message' || Array.isArray(d.content)) {
      model = d.model || model;
      Object.assign(usage, d.usage || {});
      for (const b of d.content || []) {
        if (b?.type === 'text') text += b.text || '';
        else if (b?.type === 'tool_use' || b?.type === 'server_tool_use') tools.push(b.name || b.type);
      }
    } else if (typeof d.input_tokens === 'number' && Object.keys(d).length === 1) usage.input_tokens = d.input_tokens;
  };
  if (/^\s*(event|data):/m.test(raw)) {
    for (const line of raw.split('\n')) if (line.startsWith('data: ')) { try { take(JSON.parse(line.slice(6))); } catch { /* partial */ } }
  } else {
    try { take(JSON.parse(raw)); } catch { if (raw.trim()) error = 'unreadable answer'; }
  }
  return { text, tools, usage, model, error };
}

/**
 * A readable transcript of one guest's day, oldest request first.
 * @param {{dir: string, guest: string, date?: string|null}} o
 * @returns {Promise<string>}
 */
export async function renderGuestTranscript({ dir, guest, date = null }) {
  const gdir = join(dir, guestDirName(guest));
  let days;
  try { days = (await readdir(gdir)).filter(d => DAY_RE.test(d)).sort(); } catch { days = []; }
  if (!days.length) return `No logs for guest "${guest}" in ${gdir}.`;
  const day = date || days[days.length - 1];
  if (!days.includes(day)) return `No logs for guest "${guest}" on ${day}. Days with logs: ${days.slice(-10).join(', ')}`;
  const files = (await readdir(join(gdir, day))).filter(f => f.endsWith('.req.json')).sort();
  const n = (/** @type {any} */ v) => Number(v || 0).toLocaleString('en-US');
  const out = [`Guest "${guest}", ${day} (UTC): ${files.length} request(s)`];
  for (const f of files) {
    const stem = f.slice(0, -'.req.json'.length);
    let req = null;
    try { req = JSON.parse(await readFile(join(gdir, day, f), 'utf8')); } catch { /* unreadable */ }
    let raw = '';
    try { raw = await readFile(join(gdir, day, `${stem}.res.sse`), 'utf8'); } catch { /* none */ }
    const body = req?.body && typeof req.body === 'object' ? req.body : {};
    const a = parseGuestAnswer(raw);
    const time = (req?.at || '').slice(11, 19) || stem.slice(0, 6);
    const route = String(req?.url || '').split('?')[0];
    out.push('', `── ${time}  ${route}  ${a.model || body.model || '?'}  (${stem.split('-').pop()})`);
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    const lastUser = [...msgs].reverse().find((/** @type {any} */ m) => m?.role === 'user');
    if (lastUser) out.push(`USER: ${clip(textOf(lastUser.content), 2000) || '(no text)'}`);
    if (a.error) out.push(`ERROR: ${clip(a.error, 500)}`);
    if (a.text) out.push(`ASSISTANT: ${clip(a.text, 4000)}`);
    if (a.tools.length) out.push(`TOOLS: ${a.tools.join(', ')}`);
    const u = a.usage;
    if (Object.keys(u).length) {
      out.push(`TOKENS: in ${n(u.input_tokens)} · cache write ${n(u.cache_creation_input_tokens)} · cache read ${n(u.cache_read_input_tokens)} · out ${n(u.output_tokens)}`
        + (u.server_tool_use?.web_search_requests ? ` · web searches ${u.server_tool_use.web_search_requests}` : ''));
    }
  }
  return out.join('\n');
}
