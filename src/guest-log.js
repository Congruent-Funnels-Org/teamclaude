// Guest stream logs (config.guests.logBodies, default on): the FULL request
// and the FULL answer, as received from upstream, of every guest request that
// got as far as a body, so the operator can see what a guest does.
//
//   <logDir>/<guest>/<YYYY-MM-DD>/<HHMMSS>-<reqid>.req.json   the request body, raw bytes as received
//   <logDir>/<guest>/<YYYY-MM-DD>/<HHMMSS>-<reqid>.meta.json  time, method, url, headers (auth stripped)
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
// first, freeing down to 80% once past 90%), pruned at start and once a day.
// Between prunes a running byte count (seeded by each prune) stops all writing
// once logMaxMB is reached, with one log line, and asks for a prune, which
// frees room so logging resumes.

import { createWriteStream } from 'node:fs';
import { mkdir, writeFile, readdir, readFile, stat, rm, rmdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

export const GUEST_LOG_DEFAULTS = {
  retentionDays: 90,
  maxMB: 5000,
  pruneEveryMs: 24 * 3600_000,
  maxQueuedBytes: 64 * 1024 * 1024, // held while the file opens; more is dropped
};

// Only files this module writes are ever deleted.
const LOG_FILE_RE = /^\d{6}-[0-9a-f]{8}\.(req\.json|meta\.json|res\.sse)$/;
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

/** @param {any} config */
function maxBytesOf(config) {
  const mb = Number(config?.guests?.logMaxMB);
  return (mb > 0 ? mb : GUEST_LOG_DEFAULTS.maxMB) * 1024 * 1024;
}

/**
 * The running byte count per log dir: set from disk by each prune, raised by
 * every write. Past logMaxMB nothing more is written until a prune makes room.
 * @type {Map<string, {bytes: number, full: boolean, lastKick: number}>}
 */
const budgets = new Map();
/** @param {string} dir */
function budgetOf(dir) {
  let b = budgets.get(dir);
  if (!b) { b = { bytes: 0, full: false, lastKick: 0 }; budgets.set(dir, b); }
  return b;
}
/**
 * For tests and the pruner: what the log under `dir` holds now. `keepFull`
 * leaves a "full" state (and so its one log line) alone: a prune that freed
 * nothing must not re-announce it.
 * @param {string} dir @param {number} bytes @param {{keepFull?: boolean}} [o]
 */
export function setGuestLogBytes(dir, bytes, { keepFull = false } = {}) {
  const b = budgetOf(dir);
  b.bytes = Math.max(0, Number(bytes) || 0);
  if (!keepFull) b.full = false;
}
/** @param {string} dir */
export function guestLogBytes(dir) {
  return budgetOf(dir).bytes;
}

/**
 * Count `n` bytes against the dir's budget. False (and, once, a log line and a
 * prune request) when the budget is spent.
 * @param {any} config @param {string} dir @param {number} n @param {(m: string) => void} log
 */
function spend(config, dir, n, log) {
  const b = budgetOf(dir);
  if (b.bytes + n > maxBytesOf(config)) {
    if (!b.full) {
      b.full = true;
      try { log(`[TeamClaude] guest logs: ${dir} reached guests.logMaxMB (${Math.round(maxBytesOf(config) / 1048576)} MB); not logging until a prune makes room`); } catch { /* nothing */ }
    }
    const t = Date.now();
    if (t - b.lastKick >= 60_000) { b.lastKick = t; runGuestLogPrune(config, log); }
    return false;
  }
  b.bytes += n;
  return true;
}

/**
 * Start the log of one guest request. Returns null when logging is off or the
 * size budget is spent. `chunk` takes response bytes as they arrive, `end`
 * closes the file. The body is written as the raw bytes received.
 * @param {{config: any, guest: string, method?: string, url?: string, headers?: Record<string, any>, body: Buffer,
 *   truncatedFrom?: number|null, presentedKey?: string|null, log?: (m: string) => void, now?: number, reqId?: string}} o
 * @returns {{chunk: (b: Buffer) => void, end: () => void, reqPath: string, resPath: string, metaPath: string}|null}
 */
export function openGuestLog({ config, guest, method = 'POST', url = '', headers = {}, body, truncatedFrom = null, presentedKey = null, log = console.log, now = Date.now(), reqId }) {
  if (!guestLogsEnabled(config)) return null;
  const base = guestLogDir(config);
  const at = new Date(now);
  const iso = at.toISOString();
  const day = iso.slice(0, 10);
  const id = reqId || randomBytes(4).toString('hex');
  const stem = `${iso.slice(11, 19).replace(/:/g, '')}-${id}`;
  const dir = join(base, guestDirName(guest), day);
  const reqPath = join(dir, `${stem}.req.json`);
  const metaPath = join(dir, `${stem}.meta.json`);
  const resPath = join(dir, `${stem}.res.sse`);
  const meta = JSON.stringify({ at: iso, reqId: id, guest, method, url,
    ...(truncatedFrom ? { bodyTruncatedFrom: truncatedFrom } : {}), headers: sanitizeHeaders(headers, presentedKey) });
  if (!spend(config, base, body.length + meta.length, log)) return null;

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
  let full = false;
  /** @type {import('node:fs').WriteStream|null} */
  let stream = null;

  mkdir(dir, { recursive: true, mode: 0o700 })
    .then(() => writeFile(metaPath, meta, { mode: 0o600, flag: 'wx' }))
    .then(() => writeFile(reqPath, body, { mode: 0o600, flag: 'wx' }))
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
    metaPath,
    chunk(b) {
      if (failed || ended || full || !b?.length) return;
      // The answer counts against the budget too; past it the file stops here.
      if (!spend(config, base, b.length, log)) { full = true; return; }
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
    if (e.isFile() && LOG_FILE_RE.test(e.name)) { try { n += (await stat(f)).size; } catch { /* gone */ } }
  }
  return n;
}

/**
 * Delete this module's files in one day folder, then the folder if empty.
 * Nothing else in it (or anywhere) is touched.
 * @param {string} path
 */
async function removeDay(path) {
  let entries;
  try { entries = await readdir(path, { withFileTypes: true }); } catch { return; }
  for (const e of entries) if (e.isFile() && LOG_FILE_RE.test(e.name)) await rm(join(path, e.name), { force: true });
  try { await rmdir(path); } catch { /* not empty: foreign files stay */ }
}

// Size backstop with a gap: past HIGH of logMaxMB a prune frees down to LOW,
// so the running count has room again and logging resumes (the budget never
// lets the total pass logMaxMB, so pruning only "while over" would free nothing).
export const PRUNE_HIGH = 0.9;
export const PRUNE_LOW = 0.8;

/**
 * Remove day folders older than retentionDays; then, when the whole log is
 * over 90% of maxMB, the oldest days until it is at most 80% (other days
 * first, today's last). Only folders named as guestDirName names them (a
 * removed guest's too), only YYYY-MM-DD folders in them, only this module's
 * own files, never through a symlink, so a mistaken logDir (~, /) can never
 * lose anything else.
 * @param {{dir: string, retentionDays?: number, maxMB?: number, now?: number}} o
 * @returns {Promise<{removed: string[], bytes: number}>}
 */
export async function pruneGuestLogs({ dir, retentionDays = GUEST_LOG_DEFAULTS.retentionDays, maxMB = GUEST_LOG_DEFAULTS.maxMB, now = Date.now() }) {
  /** @type {string[]} */
  const removed = [];
  /** @type {{path: string, day: string, bytes: number}[]} */
  const days = [];
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return { removed, bytes: 0 }; }
  const cutoff = new Date(now - retentionDays * 86_400_000).toISOString().slice(0, 10);
  for (const g of entries) {
    if (!g.isDirectory() || guestDirName(g.name) !== g.name) continue;
    let ds;
    try { ds = await readdir(join(dir, g.name), { withFileTypes: true }); } catch { continue; }
    for (const d of ds) {
      if (!d.isDirectory() || !DAY_RE.test(d.name)) continue;
      const path = join(dir, g.name, d.name);
      if (d.name < cutoff) { await removeDay(path); removed.push(path); continue; }
      days.push({ path, day: d.name, bytes: await dirBytes(path) });
    }
  }
  let bytes = days.reduce((s, d) => s + d.bytes, 0);
  const limit = maxMB * 1024 * 1024;
  if (bytes > limit * PRUNE_HIGH) {
    const today = new Date(now).toISOString().slice(0, 10);
    // Oldest first, today's folders after every older one.
    days.sort((a, b) => ((a.day === today) - (b.day === today)) || (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
    for (const d of days) {
      if (bytes <= limit * PRUNE_LOW) break;
      await removeDay(d.path);
      removed.push(d.path);
      bytes -= d.bytes;
    }
  }
  return { removed, bytes };
}

/** @type {Set<string>} dirs with a prune running */
const pruning = new Set();

/**
 * One prune with the live settings; afterwards the running byte count is what
 * is left on disk. Never throws.
 * @param {any} config @param {(m: string) => void} [log]
 * @returns {Promise<void>}
 */
export function runGuestLogPrune(config, log = console.log) {
  if (!guestLogsEnabled(config)) return Promise.resolve();
  const dir = guestLogDir(config);
  if (pruning.has(dir)) return Promise.resolve();
  pruning.add(dir);
  const g = config?.guests || {};
  const days = Number(g.logRetentionDays) > 0 ? Number(g.logRetentionDays) : GUEST_LOG_DEFAULTS.retentionDays;
  return pruneGuestLogs({ dir, retentionDays: days, maxMB: maxBytesOf(config) / 1048576 })
    .then(r => {
      // Still full after a prune that freed nothing: stay quiet about it.
      setGuestLogBytes(dir, r.bytes, { keepFull: r.removed.length === 0 && r.bytes >= maxBytesOf(config) * PRUNE_HIGH });
      if (r.removed.length) log(`[TeamClaude] guest logs: pruned ${r.removed.length} day folder(s)`);
    })
    .catch(err => { try { log(`[TeamClaude] guest logs: prune failed (${err?.message || err})`); } catch { /* nothing */ } })
    .finally(() => pruning.delete(dir));
}

/**
 * Prune now and once a day. Settings are read from the live config each run.
 * @param {{config: any, log?: (m: string) => void, everyMs?: number}} o
 * @returns {() => void} stop
 */
export function startGuestLogPruner({ config, log = console.log, everyMs = GUEST_LOG_DEFAULTS.pruneEveryMs }) {
  const run = () => { runGuestLogPrune(config, log); };
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
    /** @type {any} */
    let req = null;
    try { req = JSON.parse(await readFile(join(gdir, day, `${stem}.meta.json`), 'utf8')); } catch { /* none */ }
    /** @type {any} */
    let body = {};
    try { body = JSON.parse(await readFile(join(gdir, day, f), 'utf8')); } catch { body = {}; }
    if (!body || typeof body !== 'object') body = {};
    let raw = '';
    try { raw = await readFile(join(gdir, day, `${stem}.res.sse`), 'utf8'); } catch { /* none */ }
    const a = parseGuestAnswer(raw);
    const time = (req?.at || '').slice(11, 19) || stem.slice(0, 6);
    const route = String(req?.url || '').split('?')[0];
    out.push('', `── ${time}  ${route}  ${a.model || body.model || '?'}  (${stem.split('-').pop()})`);
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    const lastUser = [...msgs].reverse().find((/** @type {any} */ m) => m?.role === 'user');
    if (lastUser) out.push(`USER: ${clip(textOf(lastUser.content), 2000) || '(no text)'}`);
    if (req?.bodyTruncatedFrom) out.push(`(refused body, ${n(req.bodyTruncatedFrom)} bytes, first 64 KB kept)`);
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
