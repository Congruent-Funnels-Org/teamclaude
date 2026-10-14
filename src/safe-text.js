// One decision about what may reach an operator's terminal or a log file.
//
// Not every value that ends up there is ours. A pin segment is percent-encoded
// by the client and decoded here; an account name comes from an OAuth payload;
// a session title is read out of a transcript on disk. A control character in
// any of them is not cosmetic:
//
//   - an escape sequence repositions, colours, or clears the operator's
//     terminal when the value is rendered or the log is `cat`ed;
//   - a newline forges a whole log line. That is the one that matters, because
//     the activity log is what a deployment joins against to attribute traffic
//     to a person — a line an attacker can write is a line that can name
//     somebody else.
//
// So it is stripped once at the boundary, rather than at each interpolation
// where the next new field will forget to.

// SGR is only one of the escape forms: `\x1b[2J` (erase) and `\x1b[1;1H`
// (cursor home) are CSI sequences with a final byte outside `m`, so a
// colour-only strip lets them through. `\p{C}` then covers the rest —
// C0/C1 controls (including \n and \r), and format characters such as U+202E.
const CONTROL = /\x1b\[[0-?]*[ -/]*[@-~]|\p{C}/gu;
// Whole escape sequences, so their payload goes too: OSC (ESC ] … BEL/ST, e.g.
// OSC 8 links and OSC 52 clipboard writes), DCS/SOS/PM/APC strings, CSI in
// both its ESC [ and 8-bit \x9b forms, the 8-bit OSC \x9d, and two-byte ESC X.
const ESCAPES = /\x1b\][\s\S]*?(?:\x07|\x1b\\|\x9c|$)|\x1b[P^_X][\s\S]*?(?:\x1b\\|\x9c|$)|\x9d[\s\S]*?(?:\x07|\x1b\\|\x9c|$)|[\x90\x98\x9e\x9f][\s\S]*?(?:\x1b\\|\x9c|$)|\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~]|\x1b[@-_]/g;

/**
 * Strip escape sequences and control characters, collapsing the whitespace they
 * leave behind so a stripped value cannot pad a column or split a line.
 * @param {unknown} value
 */
export function sanitizeText(value) {
  return String(value).replace(CONTROL, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * The same strip for text that is shown over several lines (a guest's prompt
 * or a model's answer in `teamclaude guest logs`): escape sequences with
 * their payload, every control and format character (C0, C1, bidi overrides
 * such as U+202E, zero-width marks) except the newline. Tabs become two
 * spaces, CR and the Unicode line/paragraph separators become newlines.
 * @param {unknown} value
 */
export function sanitizeMultiline(value) {
  return String(value)
    .replace(ESCAPES, '')
    .replace(/\r\n?|[\u2028\u2029]/g, '\n')
    .replace(/\t/g, '  ')
    .replace(/\p{C}/gu, c => (c === '\n' ? '\n' : ''));
}

/**
 * sanitizeMultiline on one line, bounded: for a guest-derived value shown in
 * a single field (a model name, a tool name, a route).
 * @param {unknown} value @param {number} [max]
 */
export function safeGuestLine(value, max = 120) {
  const s = sanitizeMultiline(value).replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max) : s;
}

/**
 * sanitizeText, bounded — for a value rendered into a fixed-width column.
 *
 * @param {unknown} value
 * @param {number} [max]
 */
export function safeLine(value, max = 120) {
  const cleaned = sanitizeText(value);
  return cleaned.length > max ? cleaned.slice(0, max) : cleaned;
}
