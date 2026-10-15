// The palette, and the colour decisions that depend on it.
//
// Split out of `format.js` so that module stays PURE TEXT with no runtime
// import. `idx()` comes from `yeet:tui`, which only exists inside the yeet
// isolate, so anything importing it cannot be loaded by Node — and that made
// the string formatters untestable purely because they shared a file with the
// colours. Presentation logic that needs the runtime lives here; formatting
// that needs nothing lives there.
import { idx } from "yeet:tui";

// ── palette ─────────────────────────────────────────────────────────────────
//
// Built monochrome-first: strip every color below and the layout still reads,
// because structure and the dim tier carry it. Color is then added back only
// where it changes a decision.
//
// The budget, and it is a budget: roughly 85% of the screen is `text` or
// dimmer. One accent (`glyph`) leads the eye. Red is reserved for a real
// problem and never appears on healthy traffic. Two verb colors survive
// because read-vs-write is a genuine at-a-glance distinction when you are
// scanning for the statement that changed something.
//
// Deliberately NOT colored any more: latency below 100ms (it was tinted on
// every row, which taught the eye to ignore the tint), footgun text (the mark
// is in the gutter, the explanation is in the detail pane), and the per-row
// process name (it left the row entirely).
export const C = {
  rail: idx(235), // status/hint bar background
  cap: idx(238), // key-cap tile
  glyph: idx(222), // the one accent: active tab, selected row, live values
  text: idx(252), // primary text — statements, the thing you came to read
  dim: idx(245), // secondary: labels, units, timestamps
  faint: idx(240), // tertiary: separators, empty markers, ornament
  read: idx(74), // SELECT and friends — calm blue
  write: idx(215), // INSERT/UPDATE/DELETE — amber, because they change things
  ddl: idx(176), // CREATE/ALTER/DROP — violet, rarer and louder
  noise: idx(240), // session upkeep, when shown: as quiet as ornament
  warn: idx(214), // footgun, and only in the gutter
  error: idx(203), // an error reply, or a latency past a second
  ok: idx(114), // healthy
  value: idx(108), // decoded parameter values — muted green, not a highlight
  sel: idx(24), // selected-row background
  tls: idx(140), // read inside TLS
};

// Verb → color. Read vs write is the distinction worth keeping in color: it is
// what you scan for when something changed and you need to know which
// statement did it.
const DDL = new Set(["CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE"]);
export const verbColor = (verb, isWrite) => {
  if (DDL.has(verb)) return C.ddl;
  return isWrite ? C.write : C.read;
};

// Latency → color, in three bands and no more.
//
// Everything under 100ms is DIM, deliberately. The previous version tinted
// four bands starting at 10ms, so on healthy local traffic every single row
// carried a color and the eye learned the color meant nothing. A database call
// over 100ms is worth a look; over a second is worth a fix; below that is
// simply normal and should look it.
export const latColor = (us) => {
  if (us == null) return C.faint;
  if (us >= 1e6) return C.error;
  if (us >= 100_000) return C.warn;
  return C.dim;
};
