// Findings: turning a stream of statements into a short list of things worth
// looking at.
//
// This is the view the tool opens on, and the reason is the feed's own
// weakness. A feed at 40 statements a second is 22 rows of routine lookups
// with one real problem somewhere in it, and spotting that problem is work the
// tool should be doing rather than delegating to whoever is watching. The
// aggregate view answers "what costs the most", which is adjacent but not the
// same question: a cheap `DELETE` with no `WHERE` never ranks by cost and is
// the single most alarming thing this tool can see.
//
// WHAT COUNTS AS A FINDING. Only things read off the captured statements, with
// no guessing about the server:
//
//   n+1        one shape repeated in a tight burst, from one process
//   footgun    a property of the statement text (no WHERE, SELECT *, …)
//   error      the server replied with an error
//   slow       an execution far slower than that same shape's own median
//
// The `slow` check is the only one that needs a baseline, and it deliberately
// compares a shape against ITSELF rather than against a fixed threshold. A
// 40ms statement is unremarkable for a heavy aggregate and alarming for a
// primary-key lookup, so a global "slower than X" line either floods on one
// workload or stays silent on another. Comparing against the shape's own
// median asks the only question that generalises: is this execution unusual
// for this query.
//
// DELIBERATELY NOT INCLUDED: any severity scale. Ranking is by measured cost,
// which is a real number. Calling one finding "high" and another "medium"
// would be a judgment the wire cannot support, and the tool's credibility
// rests on not making those.
// Relative, not `@/`: the alias is resolved by esbuild at bundle time, so a
// module importing through it cannot be loaded directly by Node and cannot be
// unit tested. Within lib/ the alias buys nothing anyway.
import { NPLUSONE_MIN } from "./footguns.js";

// A shape's median latency, used as its own baseline for the `slow` check.
// Median rather than mean because one 5-second outlier should not raise the
// bar that detects outliers.
const fmtUs = (us) => (us >= 1000 ? `${(us / 1000).toFixed(1)}ms` : `${Math.round(us)}µs`);

function medianOf(list) {
  if (!list.length) return null;
  const s = [...list].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

// How much slower than its shape's median an execution has to be before it is
// worth surfacing. Generous on purpose: normal variance on a loaded host is
// easily 3-4x, and a finding that fires on ordinary jitter trains people to
// ignore the list.
// Deliberately strict. At 8x/5ms this fired on ordinary jitter and produced
// ten near-identical rows that buried the three real problems — a findings
// list that needs skimming has failed at its job. A statement has to be both
// a big multiple of its own median AND slow enough that a person would notice
// it in a request.
const SLOW_FACTOR = 20;
const SLOW_FLOOR_US = 50_000; // 50ms: perceptible inside a web request

// Group the log by (pid, shape) so both the burst detection and the per-shape
// baseline read from the same grouping.
function groupByShape(rows) {
  const groups = new Map();
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const key = `${r.pid}${r.shape}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { rows: [], idxs: [] }));
    g.rows.push(r);
    g.idxs.push(i);
  }
  return groups;
}

export function findingsFrom(statements) {
  // Findings are about the application's own traffic. Session chatter has no
  // findings worth reporting: a `BEGIN` is never an N+1 and never a footgun,
  // and including it would pad the list with noise.
  const rows = statements.filter((r) => !r.isNoise);
  if (!rows.length) return [];

  const out = [];
  const groups = groupByShape(rows);

  for (const g of groups.values()) {
    const timed = g.rows.filter((r) => r.latUs != null).map((r) => r.latUs);
    const median = medianOf(timed);

    // ── n+1 ──────────────────────────────────────────────────────────────
    //
    // Clustered the same way the feed folds, so the two views never disagree
    // about what counts as a burst: occurrences adjacent in the log, split on
    // a real gap.
    let cluster = [g.idxs[0]];
    const clusters = [];
    for (let k = 1; k < g.idxs.length; k++) {
      if (g.idxs[k] - g.idxs[k - 1] <= 12) cluster.push(g.idxs[k]);
      else {
        clusters.push(cluster);
        cluster = [g.idxs[k]];
      }
    }
    clusters.push(cluster);

    // Every qualifying burst of this shape, collapsed into ONE finding
    // below. Six bursts of the same query is one bug that happened six
    // times, not six findings — reporting each separately reproduced the
    // firehose this view exists to replace, with 24 rows where there were
    // three real problems.
    const bursts = [];
    for (const c of clusters) {
      if (c.length < NPLUSONE_MIN) continue;
      const span = c[c.length - 1] - c[0];
      if (span > c.length * 3) continue;

      const members = c.map((i) => rows[i]);
      const mtimed = members.filter((r) => r.latUs != null);
      const total = mtimed.reduce((s, r) => s + r.latUs, 0);
      const head = members[0]; // newest in the burst

      // Did the values actually differ? That is what separates a loop over
      // rows from a repeated identical query, and it is the first thing
      // anyone asks about an N+1. Compared as rendered text, which is what
      // the reader would compare by eye.
      const seen = new Set(members.map((m) => (m.values ?? []).map((v) => v.text).join("")));
      const distinct = seen.size;

      // TWO GUARDS against calling coincidence an N+1. With several
      // connections working concurrently, ten executions of a common lookup
      // land adjacent in the log purely by chance, and the first version of
      // this reported `SELECT count(*)` and a primary-key lookup as N+1s
      // alongside the real one. A false finding in a list this short is
      // expensive: it is a third of the screen, and it teaches the reader to
      // doubt the other rows.
      //
      //   1. It has to come from ONE THREAD. A real N+1 is a loop inside one
      //      request, so every execution shares a tid. Interleaved traffic
      //      from several workers does not.
      //   2. It has to be TIGHT IN TIME. A loop issues its queries within
      //      milliseconds; coincidental adjacency spans far longer.
      const tids = new Set(members.map((m) => m.tid));
      if (tids.size > 1) continue;

      const times = members.map((m) => m.at ?? 0).filter(Boolean);
      if (times.length >= 2) {
        const spanMs = Math.max(...times) - Math.min(...times);
        // Generous per execution (a slow loop is still a loop) but bounded,
        // so a shape trickling all day never qualifies.
        if (spanMs > Math.max(250, c.length * 40)) continue;
      }

      bursts.push({ n: c.length, total, head, members, mtimed: mtimed.length, distinct });
    }

    if (bursts.length) {
      // Rank by the worst single burst, but report the whole picture: the
      // biggest one is what you would reproduce, the total is what fixing it
      // saves, and the occurrence count says whether it is systemic.
      const worst = bursts.reduce((a, b) => (b.n > a.n ? b : a));
      const grandTotal = bursts.reduce((sum, b) => sum + b.total, 0);
      const calls = bursts.reduce((sum, b) => sum + b.n, 0);
      const anyDistinct = bursts.some((b) => b.distinct > 1);

      out.push({
        kind: "n+1",
        label: bursts.length > 1 ? `×${worst.n} worst of ${bursts.length} bursts` : `×${worst.n} in one burst`,
        detail: anyDistinct ? "different parameters each time — a loop over rows" : "same parameters every time",
        costUs: grandTotal,
        count: calls,
        occurrences: bursts.length,
        at: worst.head.at,
        row: {
          ...worst.head,
          runCount: worst.n,
          runTotalUs: worst.total,
          runTimed: worst.mtimed,
          runMembers: worst.members.slice(0, 64).reverse(),
        },
        subtype: anyDistinct ? "loop over rows" : "repeated identical query",
      });
    }

    // ── slow, relative to this shape's own median ───────────────────────
    if (median != null && timed.length >= 4) {
      // The single worst outlier for this shape, not every one over the bar.
      // Five slow executions of one query is one thing to investigate.
      let worst = null;
      let overBar = 0;
      for (const r of g.rows) {
        if (r.latUs == null) continue;
        if (r.latUs < SLOW_FLOOR_US) continue;
        if (r.latUs < median * SLOW_FACTOR) continue;
        overBar++;
        if (!worst || r.latUs > worst.latUs) worst = r;
      }
      if (worst) {
        out.push({
          kind: "slow",
          label: `${Math.round(worst.latUs / median)}× this shape's median`,
          detail: overBar > 1
            ? `${overBar} slow runs, median ${fmtUs(median)} over ${timed.length}`
            : `median ${fmtUs(median)} over ${timed.length} runs`,
          costUs: worst.latUs,
          count: overBar,
          at: worst.at,
          row: worst,
        });
      }
    }
  }

  // ── footguns and errors, one finding per shape rather than per execution ─
  //
  // A `SELECT *` that runs 200 times is one problem, not 200 findings. The
  // cost is summed across its executions so it ranks against everything else
  // by what it actually costs.
  const byShape = new Map();
  for (const r of rows) {
    if (!r.footgun && !r.error) continue;
    const key = `${r.error ? "e" : "f"}${r.pid}${r.shape}`;
    let e = byShape.get(key);
    if (!e) byShape.set(key, (e = { r, n: 0, cost: 0, at: r.at }));
    e.n++;
    e.cost += r.latUs ?? 0;
    if ((r.at ?? 0) > (e.at ?? 0)) {
      e.at = r.at;
      e.r = r; // report the most recent example
    }
  }
  for (const e of byShape.values()) {
    out.push({
      kind: e.r.error ? "error" : "footgun",
      label: e.r.error ? "the server replied with an error" : e.r.footgun,
      detail: e.n > 1 ? `${e.n} times` : "",
      costUs: e.cost,
      count: e.n,
      at: e.at,
      row: e.r,
    });
  }

  // Ranked by measured cost. An N+1 whose 29 calls total 6ms outranks a lone
  // 2ms statement, which is the correct ordering: the total is what you would
  // save by fixing it.
  //
  // The one exception is a finding with no cost at all — an error reply has no
  // latency to speak of — which would otherwise sort last despite being the
  // most actionable thing on the list. Errors are pinned above the cost
  // ranking for that reason.
  out.sort((a, b) => {
    const ea = a.kind === "error" ? 1 : 0;
    const eb = b.kind === "error" ? 1 : 0;
    if (ea !== eb) return eb - ea;
    return b.costUs - a.costUs || (b.at ?? 0) - (a.at ?? 0);
  });

  return out;
}

// Short type labels, fixed width so the column aligns.
export const KIND_LABEL = {
  "n+1": "n+1",
  slow: "slow",
  footgun: "check",
  error: "error",
};
