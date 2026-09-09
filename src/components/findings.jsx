// The findings view: what the tool noticed, ranked by what it costs.
//
// This is what opens first, and that ordering is the point. The feed is a
// firehose by nature — 22 rows of routine lookups with one real problem
// somewhere in them — and asking a reader to spot the problem is work the tool
// should do itself. Opening on the findings means the first screen answers
// "what is wrong here", and the feed becomes the place you go for context once
// you know what you are looking for.
//
// Statements get full width here, which is why this is a view rather than a
// side pane. At three panes across a normal terminal each column truncates to
// about thirty characters, and `SELECT count(*) FROM orders WHERE customer_id
// = ?` is indistinguishable from `SELECT count(*) FROM orders WHERE status =
// ?` at that width — the layout would defeat the thing it was arranging.
import { Box, Text } from "yeet:tui";
import { clip, clockMs, fmtCount, fmtLat, lpad, pad } from "@/lib/format.js";
import { C } from "@/lib/theme.js";
import { KIND_LABEL } from "@/lib/findings.js";

const W_GUTTER = 2;
const W_WHEN = 8; // 11:47:40
const W_KIND = 6; // n+1 / slow / check / error
const W_WHAT = 30; // ×29 in one burst
const W_COST = 8;

const CHROME = W_GUTTER + 1 + W_WHEN + 1 + W_KIND + 1 + W_WHAT + 1 + W_COST + 2;

// A finding's type colour. Errors are the only red on this screen, and an
// `n+1` gets the accent because it is the finding this tool exists to produce.
const kindColor = (kind) => {
  if (kind === "error") return C.error;
  if (kind === "n+1") return C.glyph;
  if (kind === "slow") return C.warn;
  return C.dim; // footgun checks
};

export default function Findings({ findings, selected, height, cols, stats }) {
  return (
    <Box height="1fr" overflow="hidden">
      <Text height="1" fg={C.faint}>
        {() => {
          const stmtW = Math.max(20, (cols?.get?.() ?? 120) - CHROME);
          return (
            `${" ".repeat(W_GUTTER)} ${pad("WHEN", W_WHEN)} ${pad("", W_KIND)} ${pad("WHAT", W_WHAT)} ` +
            `${lpad("COST", W_COST)}  ${pad("STATEMENT", stmtW)}`
          );
        }}
      </Text>
      {() => {
        const rows = findings.get();
        const seen = stats?.get?.()?.tracked ?? 0;

        if (!rows.length) {
          // An empty findings list is a RESULT, not a blank screen, so it says
          // what it looked at. "Nothing found in 1,284 statements" is
          // information; an empty pane reads as a broken tool.
          return [
            <Text height="1" fg={C.ok}>
              {seen > 0 ? "  nothing worth flagging yet" : "  waiting for SQL traffic"}
            </Text>,
            <Text height="1" fg={C.faint}>
              {seen > 0
                ? `  ${fmtCount(seen)} statements seen — no N+1 bursts, no errors, no statements worth a second look`
                : "  run a query against Postgres or MySQL"}
            </Text>,
          ];
        }

        const stmtW = Math.max(20, (cols?.get?.() ?? 120) - CHROME);
        const sel = selected.get();
        const h = Math.max(1, (height?.get?.() ?? 20) - 1);

        return rows.slice(0, h).map((f, i) => {
          const isSel = i === sel;
          const bg = isSel ? C.sel : undefined;
          const r = f.row;
          const body = r.shape.slice(r.verb.length).trim();

          return (
            <Text height="1" bg={bg} break="none">
              <Text fg={isSel ? C.glyph : C.faint}>{isSel ? " ▸" : "  "}</Text>
              <Text fg={C.faint}>{` ${pad(f.at ? clockMs(f.at).slice(0, 8) : "", W_WHEN)}`}</Text>
              <Text bold fg={kindColor(f.kind)}>{` ${pad(KIND_LABEL[f.kind] ?? f.kind, W_KIND)}`}</Text>
              <Text fg={C.text}>{` ${pad(clip(f.label, W_WHAT), W_WHAT)}`}</Text>
              {/* Cost is what the ranking is built on, so it carries weight. */}
              <Text fg={C.dim}>{` ${lpad(f.costUs ? fmtLat(f.costUs) : "—", W_COST)}`}</Text>
              <Text fg={C.faint}>{"  "}</Text>
              <Text fg={C.dim}>{pad(r.verb, Math.min(r.verb.length, 7))}</Text>
              <Text fg={C.text}>{` ${clip(body, stmtW - Math.min(r.verb.length, 7) - 1)}`}</Text>
            </Text>
          );
        });
      }}
    </Box>
  );
}
