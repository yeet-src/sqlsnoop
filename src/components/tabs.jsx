// The view selector, drawn as real folder tabs.
//
// Three rows, because a box has three edges you can see from the front:
//
//   ╭──────────╮                    the active tab's top and sides
//   │ findings │  feed   top        the labels
//   ╯          ╰────────────────    the rule, broken where the tab attaches
//
// The point of the middle row's box is that the active tab is *connected* to
// the content below it: the rule closes around every inactive tab and opens
// under the active one, so the label and the panel read as one object. That is
// structure rather than emphasis, which is why it survives being looked at
// sideways in a way that bold-versus-dim does not. Before this the active view
// was distinguished only by weight and colour, which is easy to miss on a
// screen that already uses colour for six other things.
//
// It costs two rows beyond the status line it absorbs. On a 44-row terminal
// that is about 5% of the feed, spent so nobody has to wonder which view they
// are in.
import { Box, Text } from "yeet:tui";
import { C } from "@/lib/theme.js";

// One horizontal run of the rule, and the corner pieces that join a tab to
// it. Kept as named constants because getting these characters right is the
// whole trick and a stray box-drawing glyph is invisible in a diff.
const H = "─";
const TL = "╭";
const TR = "╮";
const V = "│";
const JOIN_L = "╯"; // rule arriving from the left, turning up into the tab
const JOIN_R = "╰"; // rule leaving to the right, turning down from the tab

// Label text for a view, including the findings count. The count lives on the
// tab because it is what tells you whether to switch: you can work in the feed
// and still see that something is waiting.
const labelFor = (v, nf) => {
  // The count shows whether or not the tab is active. Dropping it when
  // inactive defeats the point: the reason to put a count on a tab is so you
  // can work in the feed and still see that something is waiting.
  if (v === "findings") return nf > 0 ? `findings ${nf}` : "findings";
  return v;
};

export default function Tabs({ views, view, findings, cols, status }) {
  return (
    <Box height="3">
      {() => {
        const active = view.get();
        const nf = findings?.get?.()?.length ?? 0;
        const total = cols?.get?.() ?? 120;

        const LEAD = 11; // " sqlsnoop  " — the brand sits left of the tabs
        const GAP = 2; // spaces between tabs

        // Measure first, draw second. Each tab's on-screen width has to be
        // known by all three rows, and computing it twice is how the rows end
        // up disagreeing by a character.
        const items = views.map((v) => {
          const text = labelFor(v, nf);
          return { v, text, inner: text.length + 2 }; // one space either side
        });

        // ── row 1: the active tab's top edge, nothing else ────────────────
        let top = " ".repeat(LEAD);
        for (const it of items) {
          if (it.v === active) top += TL + H.repeat(it.inner) + TR;
          else top += " ".repeat(it.inner + 2);
          top += " ".repeat(GAP);
        }

        // ── row 2: the labels ─────────────────────────────────────────────
        const mid = [<Text bold fg={C.write}>{" sqlsnoop  "}</Text>];
        for (const it of items) {
          const on = it.v === active;
          if (on) {
            mid.push(
              <Text fg={C.faint}>{V}</Text>,
              <Text bold fg={C.glyph}>{` ${it.text} `}</Text>,
              <Text fg={C.faint}>{V}</Text>,
            );
          } else {
            // Inactive tabs are plain text at the SAME width as an active one
            // (two extra columns for where the borders would be), so
            // switching never shifts the row. A findings count on an inactive
            // tab keeps its warning colour, since that is the thing telling
            // you to switch.
            const [head, count] = it.v === "findings" && nf > 0
              ? [it.text.replace(/ \d+$/, ""), ` ${nf}`]
              : [it.text, ""];
            mid.push(<Text>{" "}</Text>, <Text fg={C.dim}>{head}</Text>);
            if (count) mid.push(<Text bold fg={C.warn}>{count}</Text>);
            mid.push(<Text>{"   "}</Text>);
          }
          mid.push(<Text>{" ".repeat(GAP)}</Text>);
        }

        // ── row 3: the rule, opening under the active tab ─────────────────
        //
        // This is the row that does the work. It runs the full width, closing
        // around inactive tabs and breaking where the active one attaches, so
        // the tab and the panel below are visibly the same object.
        let rule = H.repeat(LEAD);
        for (const it of items) {
          if (it.v === active) rule += JOIN_L + " ".repeat(it.inner) + JOIN_R;
          else rule += H.repeat(it.inner + 2);
          rule += H.repeat(GAP);
        }
        // Run it to the full terminal width. Padding to `total` and then
        // slicing left the rule short of the edge, which read as an unfinished
        // line rather than a frame; the tab needs the rule to reach the screen
        // edge for the "attached to the panel" effect to work at all.
        while (rule.length < total) rule += H;

        // The status line rides on the top row, to the right of the active
        // tab's upper edge. That row is otherwise blank, and a status line of
        // its own was another near-empty row; merged, the chrome is three rows
        // instead of four.
        return [
          <Box height="1" direction="row">
            <Text fg={C.faint} break="none">{top}</Text>
            <Box width="1fr">{status}</Box>
          </Box>,
          <Text height="1" break="none">{mid}</Text>,
          <Text height="1" fg={C.faint}>{rule.slice(0, total)}</Text>,
        ];
      }}
    </Box>
  );
}
