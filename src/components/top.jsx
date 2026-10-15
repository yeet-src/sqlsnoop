// The aggregate: the same traffic collapsed by statement shape and ranked.
//
// This answers "what is hammering this database" — the question
// pg_stat_statements answers, except nothing had to be enabled on the server
// and the client process is included, which the server-side view cannot see.
//
// Ranked by TOTAL time, not average or max. A 2ms query run four thousand
// times costs more than a 900ms query run twice, and total is the only column
// that says so. The feed already surfaces the individually slow one.
//
// This is where the share bar belongs, and why it is here and not in the feed:
// these rows are SORTED BY COST, so the bars descend monotonically and read as
// one shape the eye can take in at a glance. In a time-ordered feed the same
// bars zigzag and become noise. Same primitive, opposite effect, decided by
// whether the sort order supports the comparison.
//
// One line per shape, like the feed. A footgun is a gutter mark; its sentence
// is in the context line under the table.
import { Box, Text } from "yeet:tui";
import { bar, clip, fmtCount, fmtLat, lpad, pad } from "@/lib/format.js";
import { C, verbColor } from "@/lib/theme.js";

const W_GUTTER = 2;
const W_CALLS = 6;
const W_TOTAL = 8;
const W_AVG = 8;
const W_MAX = 8;
const W_BAR = 8; // the share bar itself
const W_PCT = 5; // and its percentage
const W_MARK = 3; // ⚠ / ✗

// One definition of the non-statement width, shared by the header and the
// rows so the columns cannot drift. The feed carries the same pattern for the
// same reason.
const CHROME = W_GUTTER + 1 + W_CALLS + 1 + W_TOTAL + 1 + W_AVG + 1 + W_MAX + 2 + W_BAR + W_PCT + W_MARK + 1;
const stmtWidth = (totalCols) => Math.max(20, totalCols - CHROME - 2);

export default function Top({ shapes, showNoise, selected, height, cols }) {
  return (
    <Box height="1fr" overflow="hidden">
      <Text height="1" fg={C.faint}>
        {() => {
          const stmtW = stmtWidth(cols?.get?.() ?? 120);
          return (
            `${" ".repeat(W_GUTTER)} ${lpad("CALLS", W_CALLS)} ${lpad("TOTAL", W_TOTAL)} ` +
            `${lpad("AVG", W_AVG)} ${lpad("MAX", W_MAX)}  ${pad("SHARE", W_BAR + W_PCT)}` +
            `${" ".repeat(W_MARK)} ${pad("STATEMENT", stmtW)}`
          );
        }}
      </Text>
      {() => {
        const all = shapes.get();
        const rows = showNoise.get() ? all : all.filter((r) => !r.isNoise);
        if (!rows.length) {
          return (
            <Text height="1" fg={C.faint}>
              {"  waiting for SQL traffic — run a query against Postgres or MySQL"}
            </Text>
          );
        }
        // Share is of the captured window's total time, so the bars sum to the
        // whole and the top row is the biggest cost.
        const grand = rows.reduce((s, r) => s + r.totalUs, 0) || 1;
        const stmtW = stmtWidth(cols?.get?.() ?? 120);
        const sel = selected.get();
        const h = Math.max(1, (height?.get?.() ?? 20) - 1);

        return rows.slice(0, h).map((r, i) => {
          const isSel = i === sel;
          const bg = isSel ? C.sel : undefined;
          const share = r.totalUs / grand;
          const mark = r.errors ? "✗" : r.footgun ? "⚠" : " ";
          const markFg = r.errors ? C.error : C.warn;

          const body = r.shape.slice(r.verb.length).trim();
          const verbW = Math.min(r.verb.length, 7);

          return (
            <Text height="1" bg={bg} break="none">
              <Text fg={isSel ? C.glyph : C.faint}>{isSel ? " ▸" : "  "}</Text>
              <Text bold fg={C.text}>{` ${lpad(fmtCount(r.calls), W_CALLS)}`}</Text>
              <Text fg={C.glyph}>{` ${lpad(fmtLat(r.totalUs), W_TOTAL)}`}</Text>
              <Text fg={C.dim}>{` ${lpad(fmtLat(r.avgUs), W_AVG)}`}</Text>
              <Text fg={C.dim}>{` ${lpad(fmtLat(r.maxUs || null), W_MAX)}`}</Text>
              <Text fg={C.faint}>{"  "}</Text>
              {/* The bar is the accent here; it is the column doing the work. */}
              <Text fg={C.glyph}>{bar(share, W_BAR)}</Text>
              <Text fg={C.faint}>{lpad(`${Math.round(share * 100)}%`, W_PCT)}</Text>
              <Text fg={markFg}>{` ${mark} `}</Text>
              <Text fg={r.isNoise ? C.noise : verbColor(r.verb, r.isWrite)}>{pad(r.verb, verbW)}</Text>
              <Text fg={r.isNoise ? C.noise : C.text}>{` ${clip(body, stmtW - verbW - 1)}`}</Text>
            </Text>
          );
        });
      }}
    </Box>
  );
}
