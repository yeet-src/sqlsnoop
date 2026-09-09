// Pure presentation helpers — strings and color, no signals or BPF.

// `String.repeat` throws RangeError on a negative count, and several callers
// compute a width by subtraction (`stmtW - verbW - 1`). Today every one of
// those is protected by a `Math.max` floor, so this is latent rather than
// live — but a layout constant changing by a few columns is all it would take,
// and a RangeError inside a render thunk paints an exception over the UI.
// Clamping here costs nothing and removes the class of bug.
export const pad = (s, n) => {
  const w = Math.max(0, n | 0);
  return (`${s}` + " ".repeat(w)).slice(0, w);
};
export const lpad = (s, n) => {
  const w = Math.max(0, n | 0);
  return (" ".repeat(w) + `${s}`).slice(-w || undefined);
};

// Truncate with an ellipsis so a long statement never wraps a table row.
export const clip = (s, n) => {
  const t = `${s}`;
  if (t.length <= n) return pad(t, n);
  if (n <= 1) return t.slice(0, n);
  return `${t.slice(0, n - 1)}…`;
};

// A rate as a short human string: 12, 4.2K, 1.1M.
export const fmtRate = (perSec) => {
  if (perSec < 1) return perSec > 0 ? perSec.toFixed(1) : "0";
  if (perSec < 1000) return `${Math.round(perSec)}`;
  if (perSec < 1e6) return `${(perSec / 1e3).toFixed(1)}K`;
  return `${(perSec / 1e6).toFixed(1)}M`;
};

// A count, shortened the same way.
export const fmtCount = (n) => {
  if (n < 1000) return `${n}`;
  if (n < 1e6) return `${(n / 1e3).toFixed(1)}K`;
  return `${(n / 1e6).toFixed(1)}M`;
};

// A microsecond latency as µs / ms / s. `null` means we never paired a reply,
// which is rendered as an explicit dash rather than a zero — a zero would
// read as "instant" when the truth is "unknown".
export const fmtLat = (us) => {
  if (us == null) return "—";
  if (us < 1000) return `${Math.round(us)}µs`;
  if (us < 1e6) return `${(us / 1000).toFixed(us < 10_000 ? 2 : 1)}ms`;
  return `${(us / 1e6).toFixed(2)}s`;
};

export const fmtBytes = (n) => {
  if (n == null) return "—";
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
};

// Wall-clock time of day, to the millisecond. A feed without timestamps cannot
// be lined up against an application log, which is the first thing anyone does
// with a slow request. No `Intl` in this runtime, so hand-rolled.
export function clockMs(ms) {
  const d = new Date(ms);
  const p2 = (n) => (n < 10 ? `0${n}` : `${n}`);
  const p3 = (n) => (n < 10 ? `00${n}` : n < 100 ? `0${n}` : `${n}`);
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}.${p3(d.getMilliseconds())}`;
}

// The values column: `42, pending` rather than `$1=42  $2='pending'`.
//
// Positional `$n=` labels cost half the column's width to restate what the
// statement's own `?` placeholders already say by position. Dropping them fits
// roughly twice the actual data in the same space, and the detail pane still
// shows the full indexed form for anyone who needs to be sure which is which.
export function valuesInline(values, width) {
  if (!values?.length) return "";
  const parts = values.map((v) => {
    // Strip the SQL quoting for the compact column; it is noise at this size
    // and the detail pane keeps the copyable, quoted form.
    const t = `${v.text}`.replace(/^'(.*)'$/s, "$1");
    return v.certain === false ? `${t}?` : t;
  });
  let out = parts.join(", ");
  if (out.length > width) out = `${out.slice(0, Math.max(1, width - 1))}…`;
  return out;
}

// A bar for the aggregate view's share-of-total-time column.
const BLOCKS = "▏▎▍▌▋▊▉█";
export function bar(frac, width) {
  const f = Math.max(0, Math.min(1, frac || 0));
  const cells = f * width;
  const full = Math.floor(cells);
  const rem = cells - full;
  let s = "█".repeat(Math.min(full, width));
  if (full < width && rem > 0.06) s += BLOCKS[Math.min(BLOCKS.length - 1, Math.floor(rem * BLOCKS.length))];
  return pad(s, width);
}

// The statement with its parameter values substituted back in, ready to paste
// into a psql or mysql prompt.
//
// This is the realistic next step after finding a slow query: run `EXPLAIN` on
// it. Without this you have a template and a separate list of values and have
// to reassemble them by hand, counting placeholders, which is exactly the
// tedious step the tool should absorb.
//
// Returns null rather than a best guess when any value is uncertain. A
// statement that looks runnable but carries a mis-decoded value is worse than
// no statement: it either fails with a type error or, much worse, runs against
// the wrong row. The `certain === false` flag exists precisely so this can
// refuse.
export function explainable(sql, values) {
  if (!sql || !values?.length) return null;
  if (values.some((v) => v.certain === false)) return null;

  // Postgres numbers its placeholders ($1, $2), MySQL and most ORMs use a
  // positional `?`. Handle both, and require the count to line up — a
  // mismatch means we are not looking at the values for this statement.
  const byIndex = new Map(values.map((v) => [v.index, v.text]));

  if (/\$\d/.test(sql)) {
    const wanted = new Set([...sql.matchAll(/\$(\d+)/g)].map((m) => Number(m[1])));
    for (const n of wanted) if (!byIndex.has(n)) return null;
    return sql.replace(/\$(\d+)/g, (_, n) => byIndex.get(Number(n)));
  }

  const holes = (sql.match(/\?/g) ?? []).length;
  if (holes === 0 || holes !== values.length) return null;
  let k = 0;
  return sql.replace(/\?/g, () => values[k++].text);
}
