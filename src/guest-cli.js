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
import { hashGuestKey, newGuestKey, isWildcardHost } from './guest.js';

export const GUEST_USAGE = `Usage:
  teamclaude guest list [--json]
  teamclaude guest add <name> --account <account> [--cap <tokens/day>] [--key-file <path>]
  teamclaude guest rotate <name> [--key-file <path>]
  teamclaude guest enable <name> | disable <name> [--rotate]
  teamclaude guest cap <name> <tokens/day|0>
  teamclaude guest remove <name>
  teamclaude guest listen <host> <port> | listen off
Guest keys reach ONE pinned account on a separate listener (config.guests).
The daily cap is per UTC day, counting input + output + cache tokens.`;

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

/** @param {unknown} v */
function parseCap(v) {
  if (v === undefined) return undefined;
  const n = Number(String(v).replace(/[_,]/g, ''));
  if (!Number.isInteger(n) || n < 0) throw new Error(`Bad cap "${v}": a whole number of tokens per day (0 = no cap).`);
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

/** @param {any} config */
async function notifyRunningServer(config) {
  const port = config?.proxy?.port;
  if (!port) return;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/teamclaude/reload`, {
      method: 'POST',
      headers: { 'x-api-key': config.proxy?.apiKey || '' },
    });
    if (res.ok) console.log('Reloaded running server.');
  } catch { /* no server running */ }
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
          return {
            name: k.name, account: k.account, enabled: k.enabled !== false,
            dailyTokenCap: k.dailyTokenCap ?? null,
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
          const cap = r.dailyTokenCap ? r.dailyTokenCap.toLocaleString('en-US') : 'no cap';
          const today = r.tokensToday == null ? 'server not reachable' : `${r.tokensToday.toLocaleString('en-US')} tokens / ${r.requestsToday} req today`;
          console.log(`  ${r.name}  ${r.enabled ? 'enabled ' : 'DISABLED'}  → ${r.account}  cap ${cap}  ${today}  last seen ${r.lastSeen || 'never'}`);
        }
        return;
      }
      case 'add': {
        if (!name || !NAME_RE.test(name)) return fail(GUEST_USAGE);
        const account = flags.account;
        if (!account) return fail('add needs --account <account name or email> (the one account this key may use).');
        const cap = parseCap(flags.cap);
        const key = newGuestKey();
        let exists = false;
        const config = await atomicConfigUpdate((/** @type {any} */ c) => {
          if (findKey(c, name)) { exists = true; return; }
          c.guests ??= {};
          c.guests.keys ??= [];
          c.guests.keys.push({ name, keyHash: hashGuestKey(key), account, dailyTokenCap: cap ?? 0, enabled: true });
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
        await notifyRunningServer(config);
        return;
      }
      case 'cap': {
        if (!name || pos[1] === undefined) return fail(GUEST_USAGE);
        const cap = parseCap(pos[1]);
        const config = await updateKey(name, (/** @type {any} */ k) => { k.dailyTokenCap = cap; });
        if (!config) return;
        console.log(`Guest "${name}" daily cap: ${cap ? cap.toLocaleString('en-US') + ' tokens' : 'none'}.`);
        await notifyRunningServer(config);
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
        await notifyRunningServer(config);
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
        if (isWildcardHost(host)) return fail(`Refusing "${host}": the guest listener binds ONE address (e.g. this machine's tailscale IP).`);
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
