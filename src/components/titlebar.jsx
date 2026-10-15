// Status rail: what you're looking at, how fast it's arriving, and where it
// came from.
//
// Rebuilt around a hierarchy, because the previous version was seven segments
// separated by `▏` with every one at the same weight — the query rate and
// `tls: libssl.so` competed equally, so nothing led. Now there are three
// tiers:
//
//   1. identity and the active view      (bold, the one accent)
//   2. the rate, which is the live number you actually watch   (bold)
//   3. everything else, dim, and only when it has something to say
//
// Tier 3 is conditional on purpose. A zero read/write split, a TLS target with
// no TLS traffic on it, and a slow-floor of zero are all defaults, and a
// default rendered on screen is noise pretending to be information. They
// appear when they become true.
import { Box, Text } from "yeet:tui";
import { fmtLat, fmtRate } from "@/lib/format.js";
import { C } from "@/lib/theme.js";

const gap = () => <Text>{"    "}</Text>;

// `statements` is passed in and READ, deliberately, even though the title bar
// shows nothing from it directly.
//
// `stats` is published by the `statements` producer, and a `from()` producer
// only runs while its own signal is watched. The aggregate view watches
// `shapes`, not `statements`, so switching to it used to tear the feed
// producer down and freeze every rate at zero. Reading `statements` here keeps
// one permanent watcher on the capture for as long as the title bar is
// mounted, which is the whole session.
export default ({ stats, status, minLatency, tlsTargets, showNoise, statements, isFrozen, bufferedCount }) => (
  <Box height="1" direction="row">
    <Text break="none">
      {() => {
        statements?.get?.(); // keeps the capture producer alive — see above
        const s = stats.get();
        const st = status.get();

        // No brand and no tabs here: both moved to the tabs row above, which
        // owns "where am I". This row owns "what is happening", which is a
        // different question and reads better without a selector competing in
        // the same line.
        const bits = [<Text>{" "}</Text>];

        // Attach state leads when it isn't healthy: a probe that failed is the
        // only thing on this line worth reading.
        if (st !== "tracing") {
          bits.push(<Text bold fg={C.error}>{st}</Text>);
          return bits;
        }

        // Paused says so LOUDLY, and says what is being held back.
        //
        // A frozen view that looks live is the worst outcome here: the reader
        // concludes the database went quiet, or that the tool broke. Naming
        // the buffered count turns the pause into an obvious, reversible state
        // rather than an ambiguous one.
        if (isFrozen?.get?.()) {
          const held = bufferedCount?.get?.() ?? 0;
          bits.push(<Text bold fg={C.glyph}>{"⏸ paused"}</Text>);
          if (held > 0) {
            bits.push(<Text fg={C.dim}>{`  ${fmtRate(held)} new`}</Text>);
          }
          bits.push(<Text fg={C.faint}>{"   g resume"}</Text>, gap());
        }

        // The live number.
        bits.push(<Text bold fg={C.text}>{fmtRate(s.qps)}</Text>, <Text fg={C.dim}>{" q/s"}</Text>);

        // Which dialects are actually arriving, named rather than counted.
        // Two zeroed counters ("pg 0  mysql 0") told you nothing; the names of
        // what is live tell you the tool is pointed at the right server.
        const live = [];
        if (s.pgRate > 0) live.push("postgres");
        if (s.myRate > 0) live.push("mysql");
        if (live.length) {
          bits.push(gap(), <Text fg={C.dim}>{live.join(" + ")}</Text>);
        }

        // The write share, only once there are writes to speak of.
        if (s.writeRate > 0) {
          bits.push(
            gap(),
            <Text fg={C.write}>{fmtRate(s.writeRate)}</Text>,
            <Text fg={C.dim}>{" writes/s"}</Text>,
          );
        }

        // TLS, only when something was actually read inside it. A configured
        // target that never fired is not news.
        if (s.tlsRate > 0) {
          bits.push(gap(), <Text fg={C.tls}>{`${fmtRate(s.tlsRate)} in TLS`}</Text>);
        }

        // The kernel-side floor, only when it has been raised off zero.
        const floor = minLatency.get() || 0;
        if (floor > 0) {
          bits.push(gap(), <Text fg={C.dim}>{"≥ "}</Text>, <Text fg={C.text}>{fmtLat(floor)}</Text>);
        }

        if (showNoise.get()) {
          bits.push(gap(), <Text fg={C.noise}>{"+ session chatter"}</Text>);
        }

        return bits;
      }}
    </Text>
  </Box>
);
