/* sqlsnoop — a live trace of SQL statements, read off the wire.
 *
 * Every statement any process on the box sends Postgres or MySQL, with the
 * parameter values the client actually bound, the round-trip latency, and
 * the shape it collapses to. Nothing is installed in the application,
 * nothing changes on the database, and neither one knows it's happening.
 *
 * Two views over the same capture, because they answer different questions:
 *
 *   feed  — every statement as it completed, newest first. "What is my app
 *           doing right now, and why did that request take three seconds."
 *           An append-only log, so a repeated query reads as repetition —
 *           which is how an N+1 becomes visible instead of inferrable.
 *   top   — the same traffic collapsed by shape and ranked by total time.
 *           "What is hammering this database." A pg_stat_statements you
 *           didn't have to enable, that also knows which process it was.
 *
 * Layout: probes/ (BPF-aware) → components/ (pure UI) → lib/ (pure helpers).
 */
import { Box, Text, computed, mount, signal } from "yeet:tui";
import {
  bufferedCount,
  isFrozen,
  minLatency,
  setFrozen,
  setMinLatency,
  shapes,
  statements,
  stats,
  status,
  tlsTargets,
} from "@/probes/sql.js";
import { C } from "@/lib/theme.js";
import { foldRuns } from "@/lib/fold.js";
import { findingsFrom } from "@/lib/findings.js";
import TitleBar from "@/components/titlebar.jsx";
import Tabs from "@/components/tabs.jsx";
import Feed from "@/components/feed.jsx";
import Findings from "@/components/findings.jsx";
import Top from "@/components/top.jsx";
import Detail from "@/components/detail.jsx";
import Context from "@/components/context.jsx";
import Footer from "@/components/footer.jsx";

// Three views, and findings opens FIRST.
//
// The feed used to open, which meant the tool's first screen was a firehose
// that asked the reader to find the problem in it. Opening on the findings
// means the first screen is the answer: a short ranked list of what the tool
// noticed. The feed is still there, as the place you go for surrounding
// context once you know what you are looking for.
const VIEWS = ["findings", "feed", "top"];
const view = signal("findings");
const selected = signal(0);

// Selecting a row FREEZES the feed; returning to the newest row resumes it.
//
// At 140 statements a second the list is replaced every 250ms, so without
// this, "row 4" is a different statement every frame: the highlight slides
// onto rows you did not choose and the detail pane describes a moving target.
// You cannot read the row you just decided to look at.
//
// Tying the freeze to the selection rather than to a separate key means there
// is nothing extra to learn and nothing to leave switched on by accident. The
// intent is unambiguous — you only move the selection when you want to
// inspect something, and you only return to the top when you are done.
//
// The aggregate view is not frozen by selection: its rows are a ranking, not
// a stream, so they do not slide out from under a selection the way feed rows
// do. Freezing there would stop the ranking updating for no benefit.
const select = (i) => {
  const next = Math.max(0, i);
  selected.set(next);
  // Only the feed slides out from under a selection, so only the feed
  // freezes. A findings list and a ranking are stable enough to point at.
  if (view.get() === "feed") setFrozen(next > 0);
  else setFrozen(false);
};
const showNoise = signal(false); // session upkeep hidden by default
const showDetail = signal(false);

// `tty` only exists when there IS a terminal. Piping the output (into `tee`
// while recording a demo, or into a file) leaves it undefined, and reading
// `tty.size()` at module scope then throws before anything renders —
// "ReferenceError: tty is not defined", with no hint that a pipe caused it.
// So every terminal interaction goes through these guards, and a headless run
// degrades to a fixed viewport instead of crashing.
const TTY = typeof tty === "undefined" ? null : tty;
const viewport = signal(TTY?.size?.() ?? { rows: 40, cols: 120 });

TTY?.on?.("resize", (s) => viewport.set(s));
const cols = computed(() => viewport.get().cols);
// Rows available to the list: total minus title, footer, and the header row.
// What the tool noticed, derived from the same statement log the other two
// views read, so the three can never disagree about what was captured.
const findings = computed(() => findingsFrom(statements.get()));

// The detail pane's height, shared by the pane (to budget its lines) and the
// layout (to size the box), so the two cannot disagree.
const detailRows = computed(() => Math.min(20, Math.floor(viewport.get().rows / 2)));

const listRows = computed(() => {
  const rows = viewport.get().rows;
  const detail = showDetail.get() ? detailRows.get() : 0;
  // tabs(3, status folded in) + context + footer = 5 chrome rows, plus the
  // table's own header row.
  return Math.max(3, rows - 5 - detail);
});

// The selected row, as the row's own type. The context line wants the
// aggregate's shape-level fields (which processes ran it, how many errors),
// so it gets the shape rather than a sample statement.
const currentRow = computed(() => {
  const i = selected.get();
  const v = view.get();
  if (v === "findings") {
    // A finding carries the statement it was found on, so the detail pane and
    // context line work unchanged.
    return findings.get()[i]?.row ?? null;
  }
  if (v === "feed") {
    // Resolved against the FOLDED list, which is what the feed actually
    // renders. Reading the raw statements here made row N mean two different
    // things depending on who was asking, and the detail pane lost the
    // burst's executions because an unfolded row has none.
    const rows = foldRuns(statements.get(), showNoise.get());
    return rows[i] ?? null;
  }
  const rows = shapes.get().filter((r) => showNoise.get() || !r.isNoise);
  return rows[i] ?? null;
});

// What the DETAIL pane describes. Here an aggregate row resolves to a concrete
// example statement, because the pane shows one statement's full text, values
// and facts — an abstraction has none of those.
const current = computed(() => {
  const r = currentRow.get();
  if (!r) return null;
  return r.sample ?? r;
});

const LAT_STEPS = [0, 1000, 5000, 10_000, 50_000, 100_000, 500_000, 1_000_000];
const stepLatency = (dir) => {
  const cur = minLatency.get();
  if (dir > 0) {
    const next = LAT_STEPS.find((s) => s > cur);
    setMinLatency(next ?? LAT_STEPS[LAT_STEPS.length - 1]);
  } else {
    const below = LAT_STEPS.filter((s) => s < cur);
    setMinLatency(below.length ? below[below.length - 1] : 0);
  }
};

TTY?.on?.("keydown", (e) => {
  const code = e.code;
  const k = (e.key ?? "").toLowerCase();
  if (code === "Escape") {
    // Unwind one layer at a time: the detail pane, then the freeze, then quit.
    // Escape never quits out from under someone who is mid-inspection.
    if (showDetail.get()) return showDetail.set(false);
    if (isFrozen.get()) return select(0);
    return yeet.exit();
  }
  if (k === "q") return yeet.exit();
  if (code === "Tab") {
    const i = VIEWS.indexOf(view.get());
    view.set(VIEWS[(i + 1 + VIEWS.length) % VIEWS.length]);
    select(0); // resets the selection, which also resumes the feed
    return;
  }
  // Direct access, so a reader who knows where they are going does not have
  // to cycle. Matches the order in the title bar.
  if (k === "1") { view.set("findings"); return select(0); }
  if (k === "2") { view.set("feed"); return select(0); }
  if (k === "3") { view.set("top"); return select(0); }
  if (code === "ArrowUp" || k === "k") return select(selected.get() - 1);
  if (code === "ArrowDown" || k === "j") return select(selected.get() + 1);
  if (code === "PageUp") return select(selected.get() - 10);
  if (code === "PageDown") return select(selected.get() + 10);
  // An explicit way back to live, for when you have scrolled a long way down.
  if (code === "Home" || k === "g") return select(0);
  if (code === "Enter") return showDetail.set(!showDetail.get());
  if (k === "n") return showNoise.set(!showNoise.get());
  if (k === "+" || k === "=") return stepLatency(1);
  if (k === "-" || k === "_") return stepLatency(-1);
});

TTY?.enableMouse?.();
TTY?.on?.("wheel", (e) => select(selected.get() + (e.deltaY > 0 ? 3 : -3)));

const Root = () => (
  <Box>
    {/* The view selector, drawn as real folder tabs attached to the panel
        below, with the status line riding on its top row.
        
        Folding the two together matters: the tab's top row is empty except
        for one tab's upper edge, and the status line was a nearly empty row
        of its own. Merged, the chrome costs three rows instead of four and
        the live numbers sit in space that was already blank. */}
    <Tabs
      views={VIEWS}
      view={view}
      findings={findings}
      cols={cols}
      status={
        <TitleBar
          stats={stats}
          status={status}
          minLatency={minLatency}
          tlsTargets={tlsTargets}
          showNoise={showNoise}
          statements={statements}
          isFrozen={isFrozen}
          bufferedCount={bufferedCount}
        />
      }
    />
    <Box height="1fr" overflow="hidden">
      {() => {
        switch (view.get()) {
          case "findings":
            return <Findings findings={findings} selected={selected} height={listRows} cols={cols} stats={stats} />;
          case "feed":
            return <Feed statements={statements} showNoise={showNoise} selected={selected} height={listRows} cols={cols} />;
          default:
            return <Top shapes={shapes} showNoise={showNoise} selected={selected} height={listRows} cols={cols} />;
        }
      }}
    </Box>
    {/* One line describing the selection: the process, and the footgun in
        words. Both left the rows so every row could stay one line tall. */}
    <Context record={currentRow} cols={cols} />
    {() =>
      showDetail.get() ? (
        // `width="100%"` explicitly, and `overflow="hidden"` on both boxes.
        // A bordered box left to size itself drew a rule exactly as wide as
        // the terminal, which wrapped by one character and pushed the bottom
        // border onto the footer's line.
        <Box height={`${detailRows.get()}`} width="100%" overflow="hidden">
          <Detail record={current} cols={cols} rows={detailRows} />
        </Box>
      ) : null
    }
    <Footer view={view} isFrozen={isFrozen} />
  </Box>
);

const Bsod = ({ error }) => {
  const lines = String(error?.stack ?? error?.message ?? error).split("\n");
  return (
    <Box bg={C.sel} width="1fr" height="1fr" padding={2}>
      <Text height="1" bold>{":(  sqlsnoop hit an error"}</Text>
      <Text height="1">{" "}</Text>
      {lines.map((l) => (
        <Text height="1">{l}</Text>
      ))}
      <Text height="1">{" "}</Text>
      <Text height="1" fg={C.dim}>{"press q to quit"}</Text>
    </Box>
  );
};

// A TUI needs a terminal. `mount()` reaches for `tty` internally, so a run
// whose output is piped or redirected cannot render at all — and the raw
// failure is an unhelpful "ReferenceError: tty is not defined" from inside
// the runtime. Say what actually happened, and point at the probe module,
// which is the line-mode path built for exactly this case.
if (!TTY) {
  console.log("sqlsnoop needs a terminal: its output is a live TUI, and this run has no TTY");
  console.log("(output is piped or redirected — run it directly, or record with script/asciinema)");
  console.log("");
  console.log("For a pipeable, line-at-a-time stream of the same capture, run the probe instead:");
  console.log("  yeet run src/probes/sql.js");
  yeet.exit();
}

try {
  mount(Root);
} catch (e) {
  mount(() => <Bsod error={e} />);
}
await new Promise(() => {});
