// Key hints, one dim row.
//
// Plain dim text rather than the raised key-cap tiles this had before. The
// tiles put a background swatch behind every key, which made the bottom of the
// screen the highest-contrast thing on it — competing with the data for
// attention, at the one place where nothing needs attention. Convention here
// is bottom's and btop's: dim hints, and the key itself is the only part with
// any weight.
import { Box, Text } from "yeet:tui";
import { C } from "@/lib/theme.js";

const hint = (keys, label) => [
  <Text fg={C.dim}>{keys}</Text>,
  <Text fg={C.faint}>{` ${label}`}</Text>,
  <Text fg={C.faint}>{"   "}</Text>,
];

export default ({ view, isFrozen }) => (
  <Box height="1" direction="row" bg={C.rail}>
    <Text break="none">
      {() => {
        // The hints change with the state, so the one that matters right now
        // is present rather than buried in a fixed list. While paused, the way
        // back to live is the thing you want to be told.
        const paused = isFrozen?.get?.();
        return [
          "  ",
          ...hint("tab", "next view"),
          ...hint("1/2/3", "findings · feed · top"),
          ...hint("↑↓", paused ? "move" : "select, pauses feed"),
          ...(paused ? hint("g", "resume live") : []),
          ...hint("enter", "detail"),
          ...hint("n", "chatter"),
          ...hint("+/-", "slow floor"),
          ...hint("q", "quit"),
        ];
      }}
    </Text>
  </Box>
);
