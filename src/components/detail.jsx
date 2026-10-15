// The detail pane: one statement, in full, with everything we actually know
// about it and explicitly nothing we don't.
//
// Two rules shape what is on screen.
//
// HONESTY. A latency we never paired reads "not paired", not zero. A row count
// Postgres put past the capture window reads "not stated", not zero rows. A
// parameter we could not decode with certainty is marked. A confident wrong
// number costs more trust than an admitted gap, and this tool is only useful
// if it is believed.
//
// RELEVANCE. The facts block used to print eight lines on every row, six of
// which were identical every time (dialect, plaintext, byte counts) on a
// single-database local run. Metadata that never varies is not information, it
// is furniture between the reader and the thing they opened the pane for. So a
// fact appears when it is worth reading: the dialect when more than one is in
// play, the observation path when it is TLS, the byte counts only when they
// are large enough to matter.
//
// For a folded N+1 row the pane leads with THE EXECUTIONS, because that is the
// diagnosis. `×28` tells you a shape repeated; only the values tell you
// whether it repeated over different rows (a loop) or the same one (a cache
// that isn't working), and that is the whole question.
import { Box, Text } from "yeet:tui";
import { clip, clockMs, explainable, fmtBytes, fmtCount, fmtLat, lpad, pad, valuesInline } from "@/lib/format.js";
import { C } from "@/lib/theme.js";

const Row = ({ k, v, fg }) => (
  <Text height="1" break="none">
    <Text fg={C.faint}>{`  ${pad(k, 13)}`}</Text>
    <Text fg={fg}>{v}</Text>
  </Text>
);

// Wrap the statement across lines so a long one is fully readable rather than
// clipped. This pane is where you come to read the whole thing.
const wrap = (s, width, maxLines) => {
  const out = [];
  let line = "";
  for (const word of `${s}`.split(/\s+/)) {
    if (!line.length) line = word;
    else if (line.length + 1 + word.length <= width) line += ` ${word}`;
    else {
      out.push(line);
      line = word;
    }
    if (out.length >= maxLines) break;
  }
  if (line.length && out.length < maxLines) out.push(line);
  return out;
};

export default function Detail({ record, cols, rows }) {
  return (
    <Box height="1fr" width="100%" overflow="hidden">
      {() => {
        const r = record.get();
        if (!r) {
          return <Text height="1" fg={C.faint}>{"  select a row to inspect it"}</Text>;
        }
        const width = Math.max(40, (cols?.get?.() ?? 120) - 8);
        // Lines available, minus the rule this pane opens with.
        const budget = Math.max(5, (rows?.get?.() ?? 18) - 1);
        const out = [];
        const line = (el) => {
          if (out.length < budget) out.push(el);
        };

        // A rule instead of a `border` box.
        //
        // The bordered version drew its bottom rule one column wider than the
        // pane, which wrapped and put `─┘` on the footer's line. Rather than
        // fight the layout engine over how a border measures itself, the
        // separator is plain text: it is clipped to the box like any other
        // content, so it cannot overflow, and one horizontal rule reads more
        // quietly than a full box anyway.
        line(<Text height="1" fg={C.faint}>{"─".repeat(Math.max(10, (cols?.get?.() ?? 120)))}</Text>);

        // ── the executions, when this row is a folded burst ────────────────
        //
        // Leads the pane, because for the row a developer is most likely to
        // open, this is the answer.
        if (r.runMembers?.length > 1) {
          const shown = Math.min(r.runMembers.length, Math.max(3, budget - 12));
          line(
            <Text height="1" break="none">
              <Text bold fg={C.glyph}>{`  ${r.runCount} executions`}</Text>
              <Text fg={C.dim}>{`  ${fmtLat(r.runTotalUs)} total`}</Text>
              {r.runTimed < r.runCount ? <Text fg={C.faint}>{`  (${r.runTimed} timed)`}</Text> : null}
            </Text>,
          );
          for (const m of r.runMembers.slice(0, shown)) {
            line(
              <Text height="1" break="none">
                <Text fg={C.faint}>{`    ${pad(m.at ? clockMs(m.at) : "", 13)}`}</Text>
                <Text fg={C.value}>{pad(valuesInline(m.values, 30), 31)}</Text>
                <Text fg={C.dim}>{lpad(fmtLat(m.latUs), 8)}</Text>
                <Text fg={C.faint}>{lpad(m.rows == null ? "·" : `${fmtCount(m.rows)} rows`, 10)}</Text>
              </Text>,
            );
          }
          if (r.runMembers.length > shown) {
            // Counted against what was RETAINED, not the burst total. The
            // executions list is capped (64), so subtracting from `runCount`
            // claimed "… 194 more" for a 200-execution burst when only 58
            // more were ever kept — a number the pane could not have shown.
            const held = r.runMembers.length - shown;
            const beyond = r.runCount - r.runMembers.length;
            line(
              <Text height="1" fg={C.faint}>
                {beyond > 0
                  ? `    … ${held} more retained, ${beyond} beyond the capture window`
                  : `    … ${held} more`}
              </Text>,
            );
          }
          line(<Text height="1">{" "}</Text>);
        }

        // ── the statement ─────────────────────────────────────────────────
        line(
          <Text height="1" break="none">
            <Text bold fg={C.glyph}>{"  statement"}</Text>
            <Text fg={C.faint}>{r.truncated ? "   (cut at the capture window)" : ""}</Text>
          </Text>,
        );

        // Prefer the runnable form: the statement with its values substituted,
        // which is what you paste into a prompt to run EXPLAIN. Falls back to
        // the template plus a separate parameter list when substitution can't
        // be done safely (see `explainable`).
        const runnable = explainable(r.sql, r.values);
        for (const l of wrap(runnable ?? r.sql, width, 5)) {
          line(<Text height="1"><Text fg={C.faint}>{"    "}</Text><Text fg={C.text}>{l}</Text></Text>);
        }
        if (runnable) {
          line(<Text height="1" fg={C.faint}>{"    values substituted — ready to paste into psql or EXPLAIN"}</Text>);
        }
        line(<Text height="1">{" "}</Text>);

        // ── parameters, only when they add something ──────────────────────
        //
        // Skipped entirely when the runnable form above already shows every
        // value inline and none is uncertain; repeating them is the kind of
        // padding this pane was guilty of.
        if (r.values?.length && !runnable) {
          line(<Text height="1" bold fg={C.glyph}>{"  parameters"}</Text>);
          for (const v of r.values) {
            line(
              <Text height="1" break="none">
                <Text fg={C.faint}>{`    $${v.index} = `}</Text>
                <Text fg={C.value}>{v.text}</Text>
                {v.certain === false ? <Text fg={C.warn}>{`   (${v.note ?? "uncertain"})`}</Text> : null}
              </Text>,
            );
          }
          if (r.valuesTruncated) {
            line(<Text height="1" fg={C.faint}>{"    (more parameters than the capture window held)"}</Text>);
          }
          if (r.shapeAmbiguous) {
            line(
              <Text height="1" fg={C.warn}>
                {"    ⚠ matched by parameter count, not by name — may belong to another statement"}
              </Text>,
            );
          }
          line(<Text height="1">{" "}</Text>);
        } else if (!r.values?.length && r.shape.includes("?")) {
          line(
            <Text height="1" fg={C.faint}>
              {r.valuesNote ? `  ${r.valuesNote}` : "  values were sent inline in the statement text"}
            </Text>,
          );
          line(<Text height="1">{" "}</Text>);
        }

        // ── the footgun, in words ─────────────────────────────────────────
        if (r.footgun) {
          line(
            <Text height="1" break="none">
              <Text fg={C.warn}>{"  ⚠  "}</Text>
              <Text fg={C.warn}>{clip(r.footgun, width)}</Text>
            </Text>,
          );
          line(
            <Text height="1" fg={C.faint}>
              {"     read off the statement itself, not a claim about the query plan"}
            </Text>,
          );
          line(<Text height="1">{" "}</Text>);
        }

        // ── facts, filtered to what varies ────────────────────────────────
        line(<Text height="1" bold fg={C.glyph}>{"  facts"}</Text>);
        line(<Row k="client" v={`${r.comm} (pid ${r.pid})`} fg={C.dim} />);
        line(
          <Row
            k="latency"
            v={r.latUs == null ? "not paired to a reply" : `${fmtLat(r.latUs)}  (socket-paired round trip)`}
            fg={r.latUs == null ? C.faint : C.dim}
          />,
        );
        line(
          <Row
            k="rows"
            v={r.rows == null ? "not stated in the captured reply" : `${r.rows}`}
            fg={r.rows == null ? C.faint : C.dim}
          />,
        );
        // Only when it is not the ordinary case. On a plaintext single-dialect
        // host these three said the same thing on every row forever.
        if (r.isTls) line(<Row k="observed" v="inside TLS (SSL_write/SSL_read)" fg={C.tls} />);
        if (r.dialectName !== "postgres") line(<Row k="dialect" v={r.dialectName} fg={C.dim} />);
        if (r.respBytes != null && r.respBytes >= 64 * 1024) {
          line(<Row k="reply size" v={fmtBytes(r.respBytes)} fg={C.dim} />);
        }
        if (r.error) line(<Row k="result" v="the server replied with an error" fg={C.error} />);

        return out;
      }}
    </Box>
  );
}
