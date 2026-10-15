// Burst folding: collapsing a repeated statement shape into one row.
//
// Lives in lib/ rather than in the feed component because TWO callers have to
// agree on it. The feed renders folded rows, and the detail pane has to
// resolve the selected row back to the same folded object so it can list the
// burst's executions. When the fold lived in the component, the pane received
// the raw unfolded statement instead and the executions were simply absent —
// the selection and the display disagreed about what a row was.
// Relative, not `@/`: the alias is resolved by esbuild at bundle time, so a
// module importing through it cannot be loaded directly by Node and cannot be
// unit tested. Within lib/ the alias buys nothing anyway.
import { NPLUSONE_MIN } from "./footguns.js";

// Fold repeated shapes onto one row carrying the burst's stats.
//
// NOT a consecutive-run fold, which is what this was first and why it never
// fired on real traffic. A genuine N+1 rarely arrives as a clean run: the loop
// body issues other statements too, so the feed interleaves
//
//   lookup(1)  aggregate  lookup(2)  aggregate  lookup(3)  …
//
// and a consecutive check sees runs of length one throughout. What identifies
// an N+1 is the same shape repeating MANY times in a SHORT window, whatever
// ran between the repeats.
export function foldRuns(rows, showNoise) {
  const visible = showNoise ? rows : rows.filter((r) => !r.isNoise);

  // Only the recent head of the log is a burst candidate. Further back,
  // repetition is ordinary traffic over time rather than one request fanning
  // out, and folding it would overstate the problem.
  const WINDOW = 240;
  const head = visible.slice(0, WINDOW);

  const groups = new Map();
  for (let i = 0; i < head.length; i++) {
    const r = head[i];
    const key = `${r.pid}${r.shape}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = []));
    g.push(i);
  }

  const folded = new Set();
  const summary = new Map();
  for (const all of groups.values()) {
    // Split occurrences into clusters separated by a real gap, so two distinct
    // bursts of the same shape (two requests that each fan out) stay two rows
    // rather than merging into one inflated count.
    const clusters = [];
    let cur = [all[0]];
    for (let k = 1; k < all.length; k++) {
      if (all[k] - all[k - 1] <= 12) cur.push(all[k]);
      else {
        clusters.push(cur);
        cur = [all[k]];
      }
    }
    clusters.push(cur);

    for (const idxs of clusters) {
      if (idxs.length < NPLUSONE_MIN) continue;

      // The burst must be tight to be one fan-out rather than steady load.
      const span = idxs[idxs.length - 1] - idxs[0];
      if (span > idxs.length * 3) continue;

      const anchor = idxs[0]; // the newest occurrence anchors the fold
      const members = idxs.map((i) => head[i]);
      const timed = members.filter((r) => r.latUs != null);
      summary.set(anchor, {
        runCount: idxs.length,
        runTotalUs: timed.reduce((s, r) => s + r.latUs, 0),
        runMaxUs: timed.reduce((s, r) => Math.max(s, r.latUs), 0),
        runTimed: timed.length,
        // The folded executions themselves, oldest first, kept so the detail
        // pane can list them.
        //
        // This is the payoff the fold was previously throwing away. `×28` says
        // a shape repeated; only the executions say whether the VALUES
        // differed, and that distinction is the entire diagnosis: 41, 42, 43
        // is a loop over rows, while 41, 41, 41 is a cache that isn't working.
        // Bounded, because a burst can run into the hundreds and the pane can
        // only show a screenful.
        runMembers: members.slice(0, 64).reverse(),
      });
      for (let k = 1; k < idxs.length; k++) folded.add(idxs[k]);
    }
  }

  const out = [];
  for (let i = 0; i < head.length; i++) {
    if (folded.has(i)) continue;
    const s = summary.get(i);
    out.push(s ? { ...head[i], ...s } : head[i]);
  }
  for (let i = WINDOW; i < visible.length; i++) out.push(visible[i]);
  return out;
}

