// `teamclaude guest …` — manage guest keys (config.guests, see guest.js).
//
// Every write goes through atomicConfigUpdate (locked read-modify-write), then
// the running server is told to reload; keys are read per request, so add,
// rotate, enable and disable take effect without a restart. A listen change
// needs one (it is a socket).
//
// A new key is shown ONCE (or written to --key-file, mode 600) and only its
// sha256 is stored.

import { open } from 'node:fs/promises';
import { atomicConfigUpdate, loadConfig } from './config.js';
import { hashGuestKey, newGuestKey, guestHostProblem, guestCap, guestPct, GUEST_DEFAULTS } from './guest.js';
import { guestLogDir, renderGuestTranscript } from './guest-log.js';
import { safeLine } from './safe-text.js';

export const GUEST_USAGE = `Usage:
  teamclaude guest list [--json]
  teamclaude guest add <name> --account <account> [--pct <percent>] [--cap <tokens/day|unlimited>] [--key-file <path>]
  teamclaude guest rotate <name> [--key-file <path>]
  teamclaude guest enable <name> | disable <name> [--rotate]
  teamclaude guest pct <name> <percent|default>
  teamclaude guest cap <name> <tokens/day|unlimited>
  teamclaude guest logs <name> [--date YYYY-MM-DD]
  teamclaude guest remove <name>
  teamclaude guest listen <host> <port> | listen off
Guest keys reach ONE pinned account on a separate listener (config.guests).
The daily limit is usage-based: a guest locks until 00:00 UTC once its share of the
pinned account's WEEKLY quota used today reaches its % (pct; default ${GUEST_DEFAULTS.dailyWeeklyPct},
guests.dailyWeeklyPct). cap is only a runaway backstop in raw tokens (default 100M).
logs prints a guest's saved requests and answers for one day (default: the latest).`;

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** @param {string[]} argv */
function parseFlags(argv) {
  /** @type {string[]} */
  const pos = [];
  /** @type {Record<string, any>} */
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json' || a === '--rotate') flags[a.slice(2)] = true;
    else if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else flags[a.slice(2)] = argv[++i];
    } else pos.push(a);
  }
  return { pos, flags };
}

/** @param {string} msg */
function fail(msg) {
  console.error(msg);
  process.exitCode = 1;
}

/** @param {unknown} v @returns {number} */
function parsePct(v) {
  const n = Number(String(v).replace(/%$/, ''));
  if (!Number.isFinite(n) || n <= 0 || n > 100) throw new Error(`Bad percent "${v}": a number above 0 and at most 100 (30 = 30% of the weekly quota per day).`);
  return n;
}

/** @param {unknown} v @returns {number|'unlimited'} */
function parseCap(v) {
  if (v === undefined || v === true) throw new Error('A cap needs a value: <tokens/day> (e.g. 100000000) or unlimited.');
  if (String(v) === 'unlimited') return 'unlimited';
  const n = Number(String(v).replace(/[_,]/g, ''));
  if (!Number.isInteger(n) || n <= 0) throw new Error(`Bad cap "${v}": a whole number of tokens per day above 0, or "unlimited".`);
  return n;
}

/** @param {string} key @param {string|undefined} keyFile @param {string} what */
async function deliverKey(key, keyFile, what) {
  if (keyFile) {
    // 0600 from creation, never a moment world-readable.
    const fh = await open(keyFile, 'w', 0o600);
    try { await fh.writeFile(key + '\n'); await fh.chmod(0o600); } finally { await fh.close(); }
    console.log(`${what}: key written to ${keyFile} (mode 600). It is not stored anywhere else.`);
  } else {
    console.log(`${what}. The key (shown once, only its hash is stored):`);
    console.log(key);
  }
}

/**
 * Tell the running server to reload. A server that is not running is fine (the
 * change applies when it starts); one that IS running and refuses or fails the
 * reload is an error: the command exits non-zero so a caller (`nephew off`)
 * never believes a key is off while the server still honours it.
 * @param {any} config
 * @returns {Promise<'reloaded'|'no-server'|'failed'>}
 */
async function notifyRunningServer(config) {
  const port = config?.proxy?.port;
  if (!port) return 'no-server';
  let res;
  try {
    res = await fetch(`http://127.0.0.1:${port}/teamclaude/reload`, {
      method: 'POST',
      headers: { 'x-api-key': config.proxy?.apiKey || '' },
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    const code = /** @type {any} */ (err)?.cause?.code;
    if (code === 'ECONNREFUSED') { console.log('No server running: the change applies when it starts.'); return 'no-server'; }
    fail(`The running server could not be reached to reload (${code || (err instanceof Error ? err.message : String(err))}). The config is saved but NOT live yet: run 'teamclaude service restart' or retry.`);
    return 'failed';
  }
  if (res.ok) { console.log('Reloaded running server.'); return 'reloaded'; }
  fail(`The running server refused the reload (HTTP ${res.status}). The config is saved but NOT live yet.`);
  return 'failed';
}

/** @param {any} config @returns {Promise<any>} */
async function fetchLiveGuests(config) {
  const port = config?.proxy?.port;
  if (!port) return null;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/teamclaude/status`, {
      headers: { 'x-api-key': config.proxy?.apiKey || '' },
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return null;
    return (await res.json())?.guests ?? null;
  } catch { return null; }
}

/**
 * After a reload, check what the RUNNING server now does for `name` (its
 * /teamclaude/status), not what the config file says: `want` is the state it
 * must report ('disabled', 'enabled' or 'absent'). A server that is running but
 * cannot show it, or shows something else, is a failure (exit 1).
 * @param {any} config @param {string} name @param {'disabled'|'enabled'|'absent'} want
 * @param {'reloaded'|'no-server'|'failed'} reload
 */
async function confirmLive(config, name, want, reload) {
  if (reload !== 'reloaded') return;
  const live = await fetchLiveGuests(config);
  if (!live || !Array.isArray(live.keys)) {
    fail(`The running server did not report its guest keys after the reload: "${name}" is NOT confirmed ${want}. Run 'teamclaude guest list' or restart the service.`);
    return;
  }
  const k = live.keys.find((/** @type {any} */ x) => x?.name === name);
  const got = !k ? 'absent' : k.enabled === false ? 'disabled' : 'enabled';
  if (got !== want && !(want === 'disabled' && got === 'absent')) {
    fail(`The running server still reports guest "${name}" as ${got} (wanted ${want}). It is NOT off/changed yet: restart the service.`);
    return;
  }
  console.log(`Confirmed on the running server: "${name}" is ${got}.`);
}

/** @param {any} config @param {string} name @returns {any} */
function findKey(config, name) {
  return (config.guests?.keys || []).find((/** @type {any} */ k) => k?.name === name) || null;
}

/** One update that must find the named key; returns false (and fails) when absent. */
/** @param {string} name @param {(k: any, c: any) => void} fn */
async function updateKey(name, fn) {
  let found = false;
  const config = await atomicConfigUpdate((/** @type {any} */ c) => {
    const k = findKey(c, name);
    if (!k) return;
    found = true;
    fn(k, c);
  });
  if (!found) { fail(`No guest key named "${name}".`); return null; }
  return config;
}

/** @param {string[]} argv */
export async function guestCommand(argv) {
  const [sub, ...rest] = argv;
  const { pos, flags } = parseFlags(rest);
  const name = pos[0];
  try {
    switch (sub) {
      case undefined:
      case 'list': {
        const config = await loadConfig() || {};
        const live = await fetchLiveGuests(config);
        const rows = (config.guests?.keys || []).map((/** @type {any} */ k) => {
          const u = live?.keys?.find((/** @type {any} */ l) => l.name === k.name) || {};
          const cap = guestCap(k);
          return {
            // The running server's view when it answers (L2), else the file.
            name: k.name, account: k.account, enabled: typeof u.enabled === 'boolean' ? u.enabled : k.enabled !== false,
            weekSharePct: u.weekSharePct ?? null, weeklyCapPct: u.weeklyCapPct ?? null, weeklyLocked: u.weeklyLocked ?? null,
            paused: u.paused ?? null, pause5hPct: u.pause5hPct ?? null,
            dailyTokenCap: cap === Infinity ? 'unlimited' : cap,
            capPct: guestPct(k, config.guests),
            sharePct: u.sharePct ?? null, shareStale: u.shareStale ?? null, locked: u.locked ?? null,
            tokensToday: u.tokensToday ?? null, requestsToday: u.requestsToday ?? null, lastSeen: u.lastSeen ?? null,
          };
        });
        const listen = config.guests?.listen || null;
        if (flags.json) {
          console.log(JSON.stringify({ listen, listening: live?.listening?.listening ?? null, error: live?.listening?.error ?? null, keys: rows }, null, 2));
          return;
        }
        const st = live?.listening;
        const state = !live ? '' : st?.listening ? ' (listening)' : ` (not listening${st?.error ? ': ' + st.error : ''})`;
        console.log(`Guest listener: ${listen ? `${listen.host}:${listen.port}` : 'off'}${listen ? state : ''}`);
        if (!rows.length) { console.log('No guest keys.'); return; }
        for (const r of rows) {
          const backstop = r.dailyTokenCap === 'unlimited' ? 'unlimited' : Number(r.dailyTokenCap).toLocaleString('en-US');
          const share = r.tokensToday == null ? '?' : r.sharePct == null ? 'n/a (no fresh weekly reading)' : `${r.sharePct.toFixed(1)}%`;
          const today = r.tokensToday == null ? 'server not reachable' : `${r.tokensToday.toLocaleString('en-US')}/${backstop} backstop tokens, ${r.requestsToday} req today`;
          const locked = r.locked == null ? '?' : r.locked ? 'LOCKED until 00:00 UTC' : 'no';
          const week = r.weekSharePct == null ? '?' : `${Number(r.weekSharePct).toFixed(1)}% / cap ${r.weeklyCapPct}%${r.weeklyLocked ? ' (LIMIT REACHED)' : ''}`;
          console.log(`  ${safeLine(r.name, 64)}  ${r.enabled ? 'enabled ' : 'DISABLED'}  → ${safeLine(r.account, 120)}`);
          console.log(`      share today ${share} of weekly / cap ${r.capPct}%   locked ${locked}`);
          console.log(`      this weekly window ${week}   ${r.paused ? `PAUSED (account 5h over ${r.pause5hPct}%)` : 'not paused'}`);
          console.log(`      ${today}   last seen ${r.lastSeen || 'never'}`);
        }
        return;
      }
      case 'add': {
        if (!name || !NAME_RE.test(name)) return fail(GUEST_USAGE);
        const account = flags.account;
        if (!account) return fail('add needs --account <account name or email> (the one account this key may use).');
        const cap = flags.cap === undefined ? undefined : parseCap(flags.cap);
        const pct = flags.pct === undefined ? undefined : parsePct(flags.pct);
        const key = newGuestKey();
        let exists = false;
        const config = await atomicConfigUpdate((/** @type {any} */ c) => {
          if (findKey(c, name)) { exists = true; return; }
          c.guests ??= {};
          c.guests.keys ??= [];
          c.guests.keys.push({ name, keyHash: hashGuestKey(key), account,
            ...(pct !== undefined ? { dailyWeeklyPct: pct } : {}),
            ...(cap !== undefined ? { dailyTokenCap: cap } : {}), enabled: true });
        });
        if (exists) return fail(`A guest key named "${name}" exists; use rotate.`);
        if (!(config.accounts || []).some((/** @type {any} */ a) => a?.name === account || a?.email === account)) {
          console.error(`Warning: no configured account is named "${account}"; the key will be refused until one is.`);
        }
        await deliverKey(key, flags['key-file'], `Added guest "${name}" pinned to ${account}`);
        await notifyRunningServer(config);
        return;
      }
      case 'rotate': {
        if (!name) return fail(GUEST_USAGE);
        const key = newGuestKey();
        const config = await updateKey(name, (/** @type {any} */ k) => { k.keyHash = hashGuestKey(key); });
        if (!config) return;
        await deliverKey(key, flags['key-file'], `Rotated guest "${name}" (old key no longer works)`);
        await notifyRunningServer(config);
        return;
      }
      case 'enable':
      case 'disable': {
        if (!name) return fail(GUEST_USAGE);
        const config = await updateKey(name, (/** @type {any} */ k) => {
          k.enabled = sub === 'enable';
          // --rotate: the old key's hash is replaced by one nobody holds, so
          // re-enabling later can never revive a key that was handed out.
          if (flags.rotate) k.keyHash = hashGuestKey(newGuestKey());
        });
        if (!config) return;
        console.log(`Guest "${name}" ${sub}d${flags.rotate ? ' and its key destroyed' : ''}.`);
        await confirmLive(config, name, sub === 'enable' ? 'enabled' : 'disabled', await notifyRunningServer(config));
        return;
      }
      case 'cap': {
        if (!name || pos[1] === undefined) return fail(GUEST_USAGE);
        const cap = parseCap(pos[1]);
        const config = await updateKey(name, (/** @type {any} */ k) => { k.dailyTokenCap = cap; });
        if (!config) return;
        console.log(`Guest "${name}" token backstop: ${cap === 'unlimited' ? 'unlimited' : cap.toLocaleString('en-US') + ' tokens'}.`);
        await notifyRunningServer(config);
        return;
      }
      case 'pct': {
        if (!name || pos[1] === undefined) return fail(GUEST_USAGE);
        const pct = pos[1] === 'default' ? null : parsePct(pos[1]);
        const config = await updateKey(name, (/** @type {any} */ k) => {
          if (pct == null) delete k.dailyWeeklyPct; else k.dailyWeeklyPct = pct;
        });
        if (!config) return;
        console.log(`Guest "${name}" daily limit: ${guestPct(findKey(config, name), config.guests)}% of the weekly quota${pct == null ? ' (the default)' : ''}.`);
        await notifyRunningServer(config);
        return;
      }
      case 'logs': {
        if (!name) return fail(GUEST_USAGE);
        const date = flags.date;
        if (date !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(String(date))) return fail('--date wants YYYY-MM-DD (UTC).');
        const config = await loadConfig() || {};
        console.log(await renderGuestTranscript({ dir: guestLogDir(config), guest: name, date: date ?? null }));
        return;
      }
      case 'remove': {
        if (!name) return fail(GUEST_USAGE);
        let found = false;
        const config = await atomicConfigUpdate((/** @type {any} */ c) => {
          const keys = c.guests?.keys || [];
          const next = keys.filter((/** @type {any} */ k) => k?.name !== name);
          found = next.length !== keys.length;
          if (found) c.guests.keys = next;
        });
        if (!found) return fail(`No guest key named "${name}".`);
        console.log(`Removed guest "${name}".`);
        await confirmLive(config, name, 'absent', await notifyRunningServer(config));
        return;
      }
      case 'listen': {
        if (pos[0] === 'off') {
          await atomicConfigUpdate((/** @type {any} */ c) => { if (c.guests) delete c.guests.listen; });
          console.log('Guest listener off (takes effect on the next server restart).');
          return;
        }
        const [host, portStr] = pos;
        const port = Number(portStr);
        if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return fail(GUEST_USAGE);
        const problem = guestHostProblem(host);
        if (problem) return fail(`Refusing "${host}": ${problem}. Use this machine's tailscale IP (tailscale ip -4).`);
        await atomicConfigUpdate((/** @type {any} */ c) => { c.guests ??= {}; c.guests.keys ??= []; c.guests.listen = { host, port }; });
        console.log(`Guest listener set to ${host}:${port} (takes effect on the next server restart).`);
        return;
      }
      default:
        return fail(GUEST_USAGE);
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
}
