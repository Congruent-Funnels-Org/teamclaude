// Guest stream logs (config.guests.logBodies, default on): the request and
// the answer, as received from upstream, of every guest request that got as
// far as a body, so the operator can see what a guest does. Kept for good
// (company data): local files go only once SHIPPED, or when the local disk
// budget forces it.
//
//   <logDir>/<guest>/<YYYY-MM-DD>/<HHMMSS>-<reqid>.req.json   the request body, raw bytes as received
//   <logDir>/<guest>/<YYYY-MM-DD>/<HHMMSS>-<reqid>.res.sse    the response body bytes, SSE or JSON
//   <logDir>/<guest>/<YYYY-MM-DD>/<HHMMSS>-<reqid>.meta.json  time, method, url, status, headers (auth stripped)
//
// While a request runs those are plain files. When it ends each is gzipped to
// `<file>.gz` (0600) and the plain one removed, then `<HHMMSS>-<reqid>.done`
// is written LAST (atomic rename): an entry with `.done` is complete. A
// shipper uploads complete entries and writes `<HHMMSS>-<reqid>.shipped` next
// to them; the prune treats shipped entries as safe to delete. `day.json` in
// each day folder holds that guest-day's logging counters (local accounting).
//
// logDir defaults to ~/.local/share/teamclaude/guest-logs (guests.logDir).
// Dirs 0700, files 0600. No credential is written: the guest's key, any auth
// header and cookies are stripped, and account tokens never pass through here
// (they are added by the forwarder, after this sees the request).
//
// Logging FAILS CLOSED: a request that cannot be logged (the guest's daily
// byte budget, guests.logGuestMBPerDay, default 500, or the global one
// spent; the folder or file cannot be written) is refused before it is
// forwarded (begin() answers 'failed'). An unbilled request (refused, an
// upstream error, count_tokens, models) keeps 64 KB of its body and only the
// first 200 / 16 MB of them per guest per UTC day; past that it is counted
// ('counted') and still served. Writing the answer is async and never fails
// the request; an error there is one log line.
//
// Local size backstop guests.logMaxMB (default 5000): past 90% a prune frees
// down to 80%, shipped entries first (oldest first, any day), then unshipped
// ones (oldest first, never today's unless today alone is over the cap) with
// a loud log line. Shipped entries older than guests.logRetentionDays (90)
// go too. Pruned at start, once a day and when the budget fills.

import { createWriteStream, createReadStream } from 'node:fs';
import { mkdir, writeFile, readdir, readFile, stat, rm, rmdir, rename } from 'node:fs/promises';
import { once } from 'node:events';
import { pipeline } from 'node:stream/promises';
import { createGzip, gunzipSync } from 'node:zlib';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { sanitizeMultiline, safeGuestLine } from './safe-text.js';

export const GUEST_LOG_DEFAULTS = {
  retentionDays: 90,              // for SHIPPED entries only
  maxMB: 5000,                    // local disk budget, all guests
  guestMBPerDay: 500,             // per guest per UTC day
  pruneEveryMs: 24 * 3600_000,
  maxQueuedBytes: 64 * 1024 * 1024, // held while the file opens; more is dropped
  // An unbilled request (refused, an upstream error, count_tokens, models)
  // costs the guest nothing, so its logging is capped per guest per UTC day:
  // past either limit it is only counted (day.json notLogged).
  unbilledPerDay: 200,
  unbilledBytesPerDay: 16 * 1024 * 1024,
  unbilledBodyBytes: 64 * 1024,
};

const STEM = '\\d{6}-[0-9a-f]{8}';
// Only files this module (or the shipper, .shipped) writes are ever deleted.
const LOG_FILE_RE = new RegExp(`^(${STEM}\\.((req\\.json|meta\\.json|res\\.sse)(\\.gz)?|done|done\\.tmp|shipped)|day\\.json)$`);
const STEM_RE = new RegExp(`^(${STEM})\\.`);
export const DAY_FILE = 'day.json';
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

/** @param {any} config */
function guestMaxBytesOf(config) {
  const mb = Number(config?.guests?.logGuestMBPerDay);
  return (mb > 0 ? mb : GUEST_LOG_DEFAULTS.guestMBPerDay) * 1024 * 1024;
}

/**
 * One guest's logging counters for one UTC day, seeded from the day folder's
 * day.json so a restart keeps every cap: allBytes (the guest's daily budget),
 * unbilledEntries / unbilledBytes (the unbilled cap), notLogged.
 * @typedef {{day: string, dir: string, allBytes: number, unbilledEntries: number, unbilledBytes: number, notLogged: number, timer: any, ready: Promise<void>, fullLogged: boolean}} DayCounters
 * @type {Map<string, DayCounters>}
 */
const guestDays = new Map();

/** @param {string} dir the day folder @param {string} day @returns {DayCounters} */
function dayOf(dir, day) {
  let q = guestDays.get(dir);
  if (!q) {
    for (const [k, v] of guestDays) if (v.day !== day) { if (v.timer) clearTimeout(v.timer); guestDays.delete(k); }
    /** @type {DayCounters} */
    const nq = { day, dir, allBytes: 0, unbilledEntries: 0, unbilledBytes: 0, notLogged: 0, timer: null, ready: Promise.resolve(), fullLogged: false };
    nq.ready = readFile(join(dir, DAY_FILE), 'utf8').then(t => {
      const d = JSON.parse(t) || {};
      nq.allBytes += Number(d.allBytes) || 0;
      nq.unbilledEntries += Number(d.unbilledEntries) || 0;
      nq.unbilledBytes += Number(d.unbilledBytes) || 0;
      nq.notLogged += Number(d.notLogged) || 0;
    }).catch(() => {});
    guestDays.set(dir, nq);
    q = nq;
  }
  return q;
}

/** Save a guest-day's counters, at most every 2 s. @param {DayCounters} q */
function saveDay(q) {
  if (q.timer) return;
  q.timer = setTimeout(() => {
    q.timer = null;
    q.ready
      .then(() => mkdir(q.dir, { recursive: true, mode: 0o700 }))
      .then(() => writeFile(join(q.dir, DAY_FILE), JSON.stringify({ allBytes: q.allBytes, unbilledEntries: q.unbilledEntries, unbilledBytes: q.unbilledBytes, notLogged: q.notLogged }), { mode: 0o600 }))
      .catch(() => {});
  }, 2000);
  q.timer.unref?.();
}

/** For tests: forget the per-day counters (as a restart would). */
export function resetGuestLogDays() {
  for (const v of guestDays.values()) if (v.timer) clearTimeout(v.timer);
  guestDays.clear();
}

/** For tests: a guest-day's counters once loaded. @param {string} dayDir */
export async function guestLogDay(dayDir) {
  const q = guestDays.get(dayDir);
  if (!q) return null;
  await q.ready;
  return { allBytes: q.allBytes, unbilledEntries: q.unbilledEntries, unbilledBytes: q.unbilledBytes, notLogged: q.notLogged };
}

/** gzip `p` to `p.gz` (0600), then remove `p`. @param {string} p */
async function gzipFile(p) {
  await pipeline(createReadStream(p), createGzip(), createWriteStream(`${p}.gz`, { mode: 0o600, flags: 'wx' }));
  await rm(p);
}

/**
 * Start the log of one guest request. Returns null when logging is off.
 * Nothing is written until `begin(unbilled)`, which the caller awaits BEFORE
 * forwarding: 'logged' (go on), 'counted' (an unbilled request over its daily
 * cap: only counted, go on) or 'failed' (cannot be logged: refuse it). A
 * billed completion keeps its whole body; an unbilled one (refused here,
 * count_tokens, models) its first 64 KB. `chunk` takes response bytes,
 * `end(status)` closes the entry: meta written, every file gzipped, `.done`
 * last. `finished` settles when that is done (or given up).
 * @param {{config: any, guest: string, method?: string, url?: string, headers?: Record<string, any>, body: Buffer,
 *   presentedKey?: string|null, log?: (m: string) => void, now?: number, reqId?: string}} o
 * @returns {{begin: (unbilled: boolean) => Promise<'logged'|'counted'|'failed'>, chunk: (b: Buffer) => void, end: (status?: number) => void, finished: Promise<void>, reqPath: string, resPath: string, metaPath: string, donePath: string}|null}
 */
export function openGuestLog({ config, guest, method = 'POST', url = '', headers = {}, body, presentedKey = null, log = console.log, now = Date.now(), reqId }) {
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
  const donePath = join(dir, `${stem}.done`);
  const cleanHeaders = sanitizeHeaders(headers, presentedKey);
  const guestMax = guestMaxBytesOf(config);

  let failed = false;
  const fail = (/** @type {any} */ err) => {
    if (failed) return;
    failed = true;
    // One line per failing request, and at most one a minute overall.
    const t = Date.now();
    if (t - lastFailLog < 60_000) return;
    lastFailLog = t;
    try { log(`[TeamClaude] guest ${guest}: stream log write failed (${err?.code || err?.message || err})`); } catch { /* nothing */ }
  };

  /** @type {Buffer[]} */
  let queue = [];
  let queued = 0;
  let dead = false;      // nothing more is written (a budget ran out, a write failed)
  let ended = false;
  /** @type {string|null} why the answer was cut short in the log */
  let cutShort = null;
  let isUnbilled = false;
  let truncatedFrom = 0;
  /** @type {number|undefined} */
  let endStatus;
  /** @type {DayCounters|null} */
  let q = null;
  /** @type {import('node:fs').WriteStream|null} */
  let stream = null;
  /** @type {Promise<'logged'|'counted'|'failed'>|null} */
  let begun = null;
  /** @type {(v?: any) => void} */
  let settle = () => {};
  const finished = new Promise(r => { settle = r; });

  const write = (/** @type {Buffer} */ b) => {
    if (dead || !q) return;
    if (q.allBytes + b.length > guestMax) { cutShort = 'guest daily log budget'; dead = true; return; }
    if (isUnbilled && q.unbilledBytes + b.length > GUEST_LOG_DEFAULTS.unbilledBytesPerDay) { cutShort = 'unbilled daily cap'; dead = true; return; }
    if (!spend(config, base, b.length, log)) { cutShort = 'logMaxMB'; dead = true; return; }
    q.allBytes += b.length;
    if (isUnbilled) q.unbilledBytes += b.length;
    saveDay(q);
    stream?.write(b);
  };

  const finalize = async () => {
    try {
      if (stream) { stream.end(); if (!stream.closed) await once(stream, 'close'); }
      if (failed) return;
      const meta = JSON.stringify({ at: iso, reqId: id, guest, method, url, status: endStatus ?? null,
        ...(isUnbilled || Number(endStatus) >= 400 ? { unbilled: true } : {}),
        ...(truncatedFrom ? { bodyTruncatedFrom: truncatedFrom } : {}),
        ...(cutShort ? { answerCutShort: cutShort } : {}),
        headers: cleanHeaders });
      await writeFile(metaPath, meta, { mode: 0o600, flag: 'wx' });
      for (const p of [reqPath, resPath, metaPath]) await gzipFile(p);
      await writeFile(`${donePath}.tmp`, `${new Date().toISOString()}\n`, { mode: 0o600 });
      await rename(`${donePath}.tmp`, donePath);
    } catch (err) { fail(err); } finally { settle(); }
  };

  const begin = (/** @type {boolean} */ unbilled) => {
    if (begun) return begun;
    begun = (async () => {
      q = dayOf(dir, day);
      await q.ready;
      isUnbilled = unbilled;
      const cut = unbilled && body.length > GUEST_LOG_DEFAULTS.unbilledBodyBytes;
      const reqBody = cut ? body.subarray(0, GUEST_LOG_DEFAULTS.unbilledBodyBytes) : body;
      if (cut) truncatedFrom = body.length;
      const size = reqBody.length + 4096;   // + the meta written at the end
      if (unbilled && (q.unbilledEntries >= GUEST_LOG_DEFAULTS.unbilledPerDay || q.unbilledBytes + size > GUEST_LOG_DEFAULTS.unbilledBytesPerDay)) {
        q.notLogged += 1;
        saveDay(q);
        dead = true;
        settle();
        return 'counted';
      }
      if (q.allBytes + size > guestMax) {
        if (!q.fullLogged) {
          q.fullLogged = true;
          try { log(`[TeamClaude] guest ${guest}: daily log budget (guests.logGuestMBPerDay, ${Math.round(guestMax / 1048576)} MB) spent; its requests are refused until 00:00 UTC`); } catch { /* nothing */ }
        }
        dead = true; settle(); return 'failed';
      }
      if (!spend(config, base, size, log)) { dead = true; settle(); return 'failed'; }
      q.allBytes += size;
      if (unbilled) { q.unbilledEntries += 1; q.unbilledBytes += size; }
      saveDay(q);
      try {
        await mkdir(dir, { recursive: true, mode: 0o700 });
        await writeFile(reqPath, reqBody, { mode: 0o600, flag: 'wx' });
        const ws = createWriteStream(resPath, { mode: 0o600, flags: 'wx' });
        await once(ws, 'open');
        ws.on('error', fail);
        stream = ws;
      } catch (err) {
        fail(err);
        dead = true;
        settle();
        return 'failed';
      }
      // Bytes that came while the file was opening: booked and written now.
      const held = queue;
      queue = []; queued = 0;
      for (const b of held) write(b);
      return 'logged';
    })();
    return begun;
  };

  return {
    reqPath,
    resPath,
    metaPath,
    donePath,
    finished,
    begin,
    chunk(b) {
      if (failed || ended || dead || !b?.length) return;
      if (!stream) {
        // Not open yet: held (bounded) until begin settles.
        if (queued + b.length > GUEST_LOG_DEFAULTS.maxQueuedBytes) return;
        queue.push(Buffer.from(b));
        queued += b.length;
        return;
      }
      write(Buffer.from(b));
    },
    end(status) {
      if (ended) return;
      ended = true;
      endStatus = status;
      if (!begun) { settle(); return; }
      begun.then(r => { if (r === 'logged' && stream) finalize(); });
    },
  };
}

/**
 * The entries of one day folder: this module's files grouped by stem, with
 * their size and whether the shipper has marked them shipped. day.json and
 * anything foreign are not entries.
 * @param {string} path
 * @returns {Promise<{entries: {stem: string, files: string[], bytes: number, shipped: boolean}[], dayFileBytes: number}>}
 */
async function scanDay(path) {
  /** @type {Map<string, {stem: string, files: string[], bytes: number, shipped: boolean}>} */
  const by = new Map();
  let dayFileBytes = 0;
  let list;
  try { list = await readdir(path, { withFileTypes: true }); } catch { return { entries: [], dayFileBytes }; }
  for (const e of list) {
    if (!e.isFile() || !LOG_FILE_RE.test(e.name)) continue;
    let size = 0;
    try { size = (await stat(join(path, e.name))).size; } catch { continue; }
    if (e.name === DAY_FILE) { dayFileBytes = size; continue; }
    const stem = /** @type {RegExpExecArray} */ (STEM_RE.exec(e.name))[1];
    let en = by.get(stem);
    if (!en) { en = { stem, files: [], bytes: 0, shipped: false }; by.set(stem, en); }
    en.files.push(e.name);
    en.bytes += size;
    if (e.name.endsWith('.shipped')) en.shipped = true;
  }
  return { entries: [...by.values()], dayFileBytes };
}

/** Delete one entry's files: the bytes that went, and whether all did. @param {string} path @param {{files: string[]}} en */
async function removeEntry(path, en) {
  let freed = 0;
  let all = true;
  for (const f of en.files) {
    const p = join(path, f);
    try { const size = (await stat(p)).size; await rm(p); freed += size; } catch { all = false; /* could not remove it */ }
  }
  return { freed, all };
}

// Size backstop with a gap: past HIGH of logMaxMB a prune frees down to LOW,
// so the running count has room again and logging resumes (the budget never
// lets the total pass logMaxMB, so pruning only "while over" would free nothing).
export const PRUNE_HIGH = 0.9;
export const PRUNE_LOW = 0.8;

/**
 * Free local space. Shipped entries older than retentionDays go. Then, when
 * the whole log is over 90% of maxMB, entries until it is at most 80%:
 * shipped ones first (oldest first, any day), then unshipped ones (oldest
 * first; today's only when today alone is over maxMB), which the caller
 * reports loudly. A past day left with no entries loses its day.json and
 * folder. Only folders named as guestDirName names them (a removed guest's
 * too), only YYYY-MM-DD folders in them, only this module's own files (and
 * the shipper's .shipped), never through a symlink, so a mistaken logDir (~,
 * /) can never lose anything else.
 * @param {{dir: string, retentionDays?: number, maxMB?: number, now?: number}} o
 * @returns {Promise<{removed: string[], unshippedRemoved: number, bytes: number, freed: number}>}
 */
export async function pruneGuestLogs({ dir, retentionDays = GUEST_LOG_DEFAULTS.retentionDays, maxMB = GUEST_LOG_DEFAULTS.maxMB, now = Date.now() }) {
  /** @type {string[]} */
  const removed = [];
  let unshippedRemoved = 0;
  let freed = 0;
  /** @type {{path: string, day: string, en: {stem: string, files: string[], bytes: number, shipped: boolean}}[]} */
  const all = [];
  /** @type {{path: string, day: string}[]} */
  const dayDirs = [];
  let bytes = 0;
  let guests;
  try { guests = await readdir(dir, { withFileTypes: true }); } catch { return { removed, unshippedRemoved, bytes: 0, freed }; }
  const today = new Date(now).toISOString().slice(0, 10);
  const cutoff = new Date(now - retentionDays * 86_400_000).toISOString().slice(0, 10);
  for (const g of guests) {
    if (!g.isDirectory() || guestDirName(g.name) !== g.name) continue;
    let ds;
    try { ds = await readdir(join(dir, g.name), { withFileTypes: true }); } catch { continue; }
    for (const d of ds) {
      if (!d.isDirectory() || !DAY_RE.test(d.name)) continue;
      const path = join(dir, g.name, d.name);
      dayDirs.push({ path, day: d.name });
      const { entries, dayFileBytes } = await scanDay(path);
      bytes += dayFileBytes;
      for (const en of entries) all.push({ path, day: d.name, en });
    }
  }
  const drop = async (/** @type {typeof all[number]} */ x) => {
    const r = await removeEntry(x.path, x.en);
    freed += r.freed;
    bytes -= r.freed;
    // Listed (and reported) only when it really went.
    if (r.all) {
      removed.push(join(x.path, x.en.stem));
      if (!x.en.shipped) unshippedRemoved += 1;
      x.en.files = [];
    }
  };
  const byAge = (/** @type {typeof all[number]} */ a, /** @type {typeof all[number]} */ b) =>
    (a.day < b.day ? -1 : a.day > b.day ? 1 : a.en.stem < b.en.stem ? -1 : a.en.stem > b.en.stem ? 1 : 0);
  /** @type {typeof all} */
  const kept = [];
  for (const x of all) {
    if (x.en.shipped && x.day < cutoff) { bytes += x.en.bytes; await drop(x); } else { bytes += x.en.bytes; kept.push(x); }
  }
  const limit = maxMB * 1024 * 1024;
  if (bytes > limit * PRUNE_HIGH) {
    const shipped = kept.filter(x => x.en.shipped).sort(byAge);
    for (const x of shipped) { if (bytes <= limit * PRUNE_LOW) break; await drop(x); }
    if (bytes > limit * PRUNE_LOW) {
      const todayBytes = kept.filter(x => x.day >= today && x.en.files.length).reduce((s, x) => s + x.en.bytes, 0);
      const unshipped = kept.filter(x => !x.en.shipped && x.en.files.length && (x.day < today || todayBytes > limit)).sort(byAge);
      for (const x of unshipped) { if (bytes <= limit * PRUNE_LOW) break; await drop(x); }
    }
  }
  // A past day with no entries left: its counters and folder go too.
  for (const d of dayDirs) {
    if (d.day >= today) continue;
    const { entries, dayFileBytes } = await scanDay(d.path);
    if (entries.length) continue;
    if (dayFileBytes) { try { await rm(join(d.path, DAY_FILE)); bytes -= dayFileBytes; freed += dayFileBytes; } catch { /* gone */ } }
    try { await rmdir(d.path); } catch { /* foreign files stay */ }
  }
  return { removed, unshippedRemoved, bytes: Math.max(0, bytes), freed };
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
      setGuestLogBytes(dir, r.bytes, { keepFull: r.freed === 0 && r.bytes >= maxBytesOf(config) * PRUNE_HIGH });
      const shippedGone = r.removed.length - r.unshippedRemoved;
      if (shippedGone) log(`[TeamClaude] guest logs: pruned ${shippedGone} shipped entr${shippedGone === 1 ? 'y' : 'ies'}`);
      if (r.unshippedRemoved) {
        log(`[TeamClaude] guest logs: WARNING deleted ${r.unshippedRemoved} UNSHIPPED entr${r.unshippedRemoved === 1 ? 'y' : 'ies'} (oldest first) to stay under guests.logMaxMB: the shipper is behind or not running, those logs are gone`);
      }
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

/** A log file's text, from `<p>.gz` or plain `<p>` (an entry still running). @param {string} p */
async function readLogText(p) {
  try { return gunzipSync(await readFile(`${p}.gz`)).toString('utf8'); } catch { /* not gzipped (yet) */ }
  try { return await readFile(p, 'utf8'); } catch { return ''; }
}

/**
 * A readable transcript of one guest's day, oldest request first. Everything
 * in it came from the guest or the model, so every field is stripped of
 * escape sequences and control / bidi characters (sanitizeMultiline) before
 * it reaches a terminal or an agent.
 * @param {{dir: string, guest: string, date?: string|null}} o
 * @returns {Promise<string>}
 */
export async function renderGuestTranscript({ dir, guest, date = null }) {
  const name = safeGuestLine(guest, 64);
  const gdir = join(dir, guestDirName(guest));
  let days;
  try { days = (await readdir(gdir)).filter(d => DAY_RE.test(d)).sort(); } catch { days = []; }
  if (!days.length) return `No logs for guest "${name}" in ${safeGuestLine(gdir, 300)}.`;
  const day = date || days[days.length - 1];
  if (!days.includes(day)) return `No logs for guest "${name}" on ${safeGuestLine(day, 10)}. Days with logs: ${days.slice(-10).join(', ')}`;
  const stems = [...new Set((await readdir(join(gdir, day))).filter(f => /\.req\.json(\.gz)?$/.test(f) && STEM_RE.test(f))
    .map(f => /** @type {RegExpExecArray} */ (STEM_RE.exec(f))[1]))].sort();
  const n = (/** @type {any} */ v) => Number(v || 0).toLocaleString('en-US');
  const one = (/** @type {unknown} */ v, /** @type {number} */ max = 200) => safeGuestLine(String(v ?? ''), max);
  const multi = (/** @type {unknown} */ v, /** @type {number} */ max) => clip(sanitizeMultiline(String(v ?? '')), max);
  const out = [`Guest "${name}", ${day} (UTC): ${stems.length} request(s)`];
  try {
    const skipped = Number(JSON.parse(await readFile(join(gdir, day, DAY_FILE), 'utf8'))?.notLogged) || 0;
    if (skipped) out.push(`${n(skipped)} unbilled request(s) (refusals, errors, count_tokens) not logged (over the daily cap)`);
  } catch { /* none */ }
  for (const stem of stems) {
    const p = (/** @type {string} */ ext) => join(gdir, day, `${stem}.${ext}`);
    /** @type {any} */
    let req = null;
    try { req = JSON.parse(await readLogText(p('meta.json'))); } catch { /* none (still running) */ }
    /** @type {any} */
    let body = {};
    try { body = JSON.parse(await readLogText(p('req.json'))); } catch { body = {}; }
    if (!body || typeof body !== 'object') body = {};
    const a = parseGuestAnswer(await readLogText(p('res.sse')));
    const time = one((req?.at || '').slice(11, 19) || stem.slice(0, 6), 8);
    const route = one(String(req?.url || '').split('?')[0], 80);
    out.push('', `── ${time}  ${route}  ${one(a.model || body.model || '?', 80)}${req?.status ? `  ${one(req.status, 3)}` : ''}  (${stem.split('-').pop()})`);
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    const lastUser = [...msgs].reverse().find((/** @type {any} */ m) => m?.role === 'user');
    if (lastUser) out.push(`USER: ${multi(textOf(lastUser.content), 2000) || '(no text)'}`);
    if (req?.bodyTruncatedFrom) out.push(`(unbilled request, body ${n(req.bodyTruncatedFrom)} bytes, first 64 KB kept)`);
    if (req?.answerCutShort) out.push(`(answer log cut short: ${one(req.answerCutShort, 40)})`);
    if (a.error) out.push(`ERROR: ${multi(a.error, 500)}`);
    if (a.text) out.push(`ASSISTANT: ${multi(a.text, 4000)}`);
    if (a.tools.length) out.push(`TOOLS: ${a.tools.map(t => one(t, 64)).join(', ')}`);
    const u = a.usage;
    if (Object.keys(u).length) {
      out.push(`TOKENS: in ${n(u.input_tokens)} · cache write ${n(u.cache_creation_input_tokens)} · cache read ${n(u.cache_read_input_tokens)} · out ${n(u.output_tokens)}`
        + (u.server_tool_use?.web_search_requests ? ` · web searches ${n(u.server_tool_use.web_search_requests)}` : ''));
    }
  }
  return out.join('\n');
}
