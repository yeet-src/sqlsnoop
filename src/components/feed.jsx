// The feed: every statement as it completed, newest first.
//
// This view answers "what is my app doing right now, and why did that request
// take three seconds". It is an append-only log — a row never mutates once it
// lands — which is what makes a repeated query read as repetition, and that is
// how an N+1 becomes visible rather than something you have to infer.
//
// STRICTLY ONE LINE PER STATEMENT. That constraint is the whole design, and it
// replaced a version that spent up to three lines on a row (one for the
// statement, one for its values, one for a footgun). Variable row height is
// what made the old feed unreadable: with rows 1, 2 or 3 lines tall the eye
// can't establish a rhythm, so it re-parses every row from scratch instead of
// scanning down a column. Everything below follows from holding that line:
//
//   * parameter values move INTO the row, in their own right-hand column
//   * a footgun becomes a one-character mark in a left gutter; the sentence
//     explaining it lives in the detail pane, where there is room for it
//   * a repeated shape becomes an `×141` badge rather than a summary line
//   * the process name left the row entirely (it was 18 identical columns
//     down the left edge) and is reported once in the status line
//
// The columns are fixed-width and left-aligned to a grid so the whole view
// reads as a table: time, latency, rows, statement, values. Numeric columns
// are right-aligned so magnitudes line up as digits.
import { Box, Text } from "yeet:tui";
import { clip, clockMs, fmtCount, fmtLat, lpad, pad, valuesInline } from "@/lib/format.js";
import { C, latColor, verbColor } from "@/lib/theme.js";
import { foldRuns } from "@/lib/fold.js";

// Column widths. Time and the numerics are fixed; the statement takes what is
// left after the values column is reserved, so the values stay in a true
// column instead of ragging along behind statements of different lengths.
const W_GUTTER = 2; // selection caret
const W_TIME = 12; // 15:42:01.203
const W_LAT = 8; //     1.02ms
const W_ROWS = 4; //      312
const W_MARK = 3; // ⚠ / ✗, in its own column
const W_VALUES = 20; // 42, pending
const W_BADGE = 6; // ×141

// Everything that is not the statement text. Kept in one place because the
// header and the rows have to agree exactly or the columns drift apart, and
// they drifted the first time this was written in two places.
const CHROME = W_GUTTER + 1 + W_TIME + 1 + W_LAT + 1 + W_ROWS + W_MARK + 1 + W_VALUES + 2 + W_BADGE;

// The statement column, capped rather than greedy. Letting it absorb all the
// slack on a wide terminal pushed the values 60 columns away from the text
// they belong to, which broke the association the single-line layout exists
// to create.
const stmtWidth = (totalCols) => Math.max(20, Math.min(76, totalCols - CHROME));

export default function Feed({ statements, showNoise, selected, height, cols }) {
  return (
    <Box height="1fr" overflow="hidden">
      <Text height="1" fg={C.faint}>
        {() => {
          const stmtW = stmtWidth(cols?.get?.() ?? 120);
          return (
            `${" ".repeat(W_GUTTER)} ${pad("TIME", W_TIME)} ${lpad("LATENCY", W_LAT)} ${lpad("ROWS", W_ROWS)}` +
            `${" ".repeat(W_MARK)} ${pad("STATEMENT", stmtW)}  ${pad("VALUES", W_VALUES)}`
          );
        }}
      </Text>
      {() => {
        const rows = foldRuns(statements.get(), showNoise.get());
        if (!rows.length) {
          return (
            <Text height="1" fg={C.faint}>
              {"  waiting for SQL traffic — run a query against Postgres or MySQL"}
            </Text>
          );
        }
        const stmtW = stmtWidth(cols?.get?.() ?? 120);
        const sel = selected.get();
        const h = Math.max(1, (height?.get?.() ?? 20) - 1);

        return rows.slice(0, h).map((r, i) => {
          const isSel = i === sel;
          const bg = isSel ? C.sel : undefined;

          // The gutter carries at most one mark, worst-first: an error reply
          // beats a footgun. One character, so a row is never widened by a
          // signal and the marks form a scannable column of their own.
          const mark = r.error ? "✗" : r.footgun ? "⚠" : " ";
          const markFg = r.error ? C.error : C.warn;

          // The statement text without its leading verb, which is rendered
          // separately in the verb's own color. Read and write stay visually
          // distinct because that is what you scan for when something changed.
          const body = r.shape.slice(r.verb.length).trim();
          const verbW = Math.min(r.verb.length, 7);

          return (
            <Text height="1" bg={bg} break="none">
              <Text fg={isSel ? C.glyph : C.faint}>{isSel ? " ▸" : "  "}</Text>
              <Text fg={C.faint}>{` ${pad(r.at ? clockMs(r.at) : "", W_TIME)}`}</Text>
              <Text fg={latColor(r.latUs)} bold={r.latUs != null && r.latUs >= 100_000}>
                {` ${lpad(fmtLat(r.latUs), W_LAT)}`}
              </Text>
              <Text fg={C.faint}>{` ${lpad(r.rows == null ? "·" : fmtCount(r.rows), W_ROWS)}`}</Text>
              <Text fg={markFg}>{` ${mark} `}</Text>
              <Text fg={r.isNoise ? C.noise : verbColor(r.verb, r.isWrite)}>{pad(r.verb, verbW)}</Text>
              <Text fg={r.isNoise ? C.noise : C.text}>{` ${clip(body, stmtW - verbW - 1)}`}</Text>
              <Text fg={C.value}>{`  ${pad(valuesInline(r.values, W_VALUES), W_VALUES)}`}</Text>
              {r.runCount ? (
                // The N+1 badge. A count alone is the signal; the burst's
                // total time is in the detail pane rather than spending a
                // second line here to restate it.
                <Text bold fg={C.warn}>{lpad(`×${fmtCount(r.runCount)}`, W_BADGE)}</Text>
              ) : (
                <Text>{" ".repeat(W_BADGE)}</Text>
              )}
            </Text>
          );
        });
      }}
    </Box>
  );
}
