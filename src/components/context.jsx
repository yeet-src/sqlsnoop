// The context line: one row, directly under the feed, describing the SELECTED
// statement.
//
// It exists because holding the feed to one line per statement moved three
// things out of the rows, and they still have to be somewhere:
//
//   * the process, which was 18 identical columns down the left edge
//   * the footgun sentence, which was an amber line under a third of rows
//   * the N+1 burst's total time, which was a summary line of its own
//
// Putting them here trades repetition for a single line that changes as you
// move the selection. That is a real trade rather than a free win: you see the
// process for one row instead of all of them. It is the right trade because
// the process is nearly always the same for every row on screen, and when it
// isn't, moving the selection tells you immediately.
//
// Not a replacement for the detail pane. This is the one-line version, always
// visible; `enter` opens the full record.
import { Box, Text } from "yeet:tui";
import { clip, fmtLat } from "@/lib/format.js";
import { C } from "@/lib/theme.js";

const sep = () => <Text fg={C.faint}>{" · "}</Text>;

export default function Context({ record, cols }) {
  return (
    <Box height="1" direction="row">
      <Text break="none">
        {() => {
          const r = record.get();
          if (!r) return <Text fg={C.faint}>{"  ↑/↓ select · enter for detail"}</Text>;

          const width = Math.max(40, (cols?.get?.() ?? 120) - 4);
          const bits = [<Text>{"  "}</Text>];

          // Who ran it. The thing the rows gave up.
          //
          // A feed row is one statement and names its own process; an
          // aggregate row is a shape that several processes may share, so it
          // names them all (bounded) instead. Same line, both views.
          if (r.comms) {
            const shown = r.comms.slice(0, 3).join(", ");
            bits.push(<Text fg={C.dim}>{shown + (r.comms.length > 3 ? ` +${r.comms.length - 3}` : "")}</Text>);
          } else {
            bits.push(<Text fg={C.dim}>{`${r.comm}/${r.pid}`}</Text>);
          }
          bits.push(sep(), <Text fg={C.dim}>{r.dialectName}</Text>);
          if (r.isTls || r.anyTls) bits.push(sep(), <Text fg={C.tls}>{"inside TLS"}</Text>);

          // The burst's cost, which the `×N` badge in the row deliberately
          // doesn't carry.
          if (r.runCount) {
            bits.push(
              sep(),
              <Text bold fg={C.warn}>{`×${r.runCount}`}</Text>,
              <Text fg={C.dim}>{` in a burst, ${fmtLat(r.runTotalUs)} total`}</Text>,
            );
          }

          // The footgun, in words. In the row it is a single `⚠`; this is
          // where the sentence lives, and it only costs a line when the
          // selected row actually has one.
          if (r.footgun) {
            const used = 30 + (r.runCount ? 30 : 0);
            bits.push(sep(), <Text fg={C.warn}>{clip(r.footgun, Math.max(20, width - used))}</Text>);
          } else if (r.error) {
            bits.push(sep(), <Text fg={C.error}>{"the server replied with an error"}</Text>);
          } else if (r.errors) {
            bits.push(sep(), <Text fg={C.error}>{`${r.errors} error${r.errors > 1 ? "s" : ""}`}</Text>);
          }

          return bits;
        }}
      </Text>
    </Box>
  );
}
