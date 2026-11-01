// A one-shot report for agents, CI jobs and pipes: capture for a fixed window,
// print ONE JSON object, exit.
//
//   yeet run . -- --report --seconds 30                  # through the main entry
//   yeet run . -- --report --seconds 30 --tls-binary libssl.so
//   yeet run . -- --report --seconds 30 --values         # include bound values
//   yeet run src/report.js -- --seconds 30               # unbundled, same report
//
// The TUI needs a terminal, and the raw probe dump (`yeet run
// src/probes/sql.js`) prints wire events that a reader has to stitch back
// together: a prepared statement's executions arrive as bare parameter blocks,
// and pairing them by "the last statement on this socket" attributes them to
// the wrong query as soon as a connection prepares two. This reads the joined
// model the TUI reads, so the attribution, the per-shape totals and the
// findings are the ones the findings view would show.
//
// Parameter values, and the raw statement text that can carry them inline,
// are left out unless `--values` is passed. A shape, a count and a latency
// answer every question this report exists for, and bound values are
// routinely customer data that has no business in an agent's transcript by
// default.

// Relative, not `@/`: this also runs unbundled, like probes/sql.js.
import { Signal } from "yeet:signal";
import { statements, stats, status, tlsTargets } from "./probes/sql.js";
import { findingsFrom } from "./lib/findings.js";

const ms = (us) => (us == null ? null : Math.round(Number(us) / 10) / 100);
const proc = (r) => `${r.comm}/${r.pid}`;

function shapesOf(rows) {
  const byShape = new Map();
  for (const st of rows) {
    let r = byShape.get(st.shape);
    if (!r) {
      r = {
        shape: st.shape,
        verb: st.verb,
        dialect: st.dialectName,
        calls: 0,
        totalUs: 0,
        maxUs: 0,
        timed: 0,
        errors: 0,
        tls: false,
        byCount: 0,
        truncated: false,
        processes: new Set(),
        footgun: st.footgun ?? null,
      };
      byShape.set(st.shape, r);
    }
    r.calls++;
    if (st.latUs != null) {
      const us = Number(st.latUs);
      r.totalUs += us;
      r.timed++;
      if (us > r.maxUs) r.maxUs = us;
    }
    if (st.error) r.errors++;
    if (st.isTls) r.tls = true;
    if (st.shapeAmbiguous) r.byCount++;
    if (st.truncated) r.truncated = true;
    r.processes.add(proc(st));
  }
  // Ranked by total time, as the aggregate view ranks: a fast query run 2,000
  // times outranks a slow one run twice.
  return [...byShape.values()]
    .sort((a, b) => b.totalUs - a.totalUs || b.calls - a.calls)
    .map((r) => ({
      shape: r.shape,
      verb: r.verb,
      dialect: r.dialect,
      calls: r.calls,
      total_ms: ms(r.totalUs),
      avg_ms: r.timed ? ms(r.totalUs / r.timed) : null,
      max_ms: r.timed ? ms(r.maxUs) : null,
      // Calls with a paired reply. Fewer than `calls` means some latencies are
      // unknown (see the README's "Why does the latency say —"), not zero.
      timed: r.timed,
      errors: r.errors,
      tls: r.tls,
      processes: [...r.processes],
      footgun: r.footgun,
      // Executions matched to this shape by placeholder count (the only
      // statement prepared on that connection with that many) rather than by
      // the statement name the protocol carries. Ties are dropped upstream, so
      // this is an inference, not a coin-flip, and it is counted, not hidden.
      matched_by_count: r.byCount,
      truncated: r.truncated,
    }));
}

function findingOf(f, withValues) {
  const r = f.row ?? {};
  const out = {
    kind: f.kind,
    label: f.label,
    detail: f.detail ?? null,
    subtype: f.subtype ?? null,
    cost_ms: ms(f.costUs),
    executions: f.count ?? null,
    occurrences: f.occurrences ?? null,
    // For an N+1, the size of the largest burst: the per-request count when
    // one request runs one loop, which is the number people ask for first.
    largest_burst: r.runCount ?? null,
    verb: r.verb ?? null,
    shape: r.shape ?? null,
    process: r.comm ? proc(r) : null,
    tid: r.tid ?? null,
  };
  // The raw statement text only with --values: a driver that inlines its
  // values (psycopg2, any simple-protocol client) carries them in the SQL
  // itself, so the text is as sensitive as the bound values are.
  if (withValues) {
    out.sql = r.sql ?? null;
    if (r.valuesText) out.values = r.valuesText;
  }
  return out;
}

function notesFor(rows, app, tls) {
  const notes = [];
  if (rows.length && !app.length) {
    // Measured, not hypothetical: a pooled client that prepared its
    // statements before the capture began sends only Binds that cite names
    // this run never saw parsed, and those are dropped rather than guessed,
    // so all that is left to attribute is BEGIN/COMMIT.
    notes.push(
      "Only session chatter (BEGIN/COMMIT and the like) was attributed. The usual cause is long-lived " +
        "connections that prepared their statements before the capture started: their executions cite " +
        "statements this run never saw, so they are dropped rather than guessed. Restart the client, or " +
        "capture across a deploy or pool recycle, so connections open while the capture is running.",
    );
  }
  if (!rows.length) {
    notes.push(
      "No SQL was seen in the window. In the order it actually happens: the client is on a Unix socket " +
        "(invisible; it must connect over TCP), the workload did not run during the window, or the " +
        "connections are encrypted and the TLS probes target the wrong binary (see tls_targets and --tls-binary).",
    );
  }
  if (!tls.length) notes.push("TLS probes did not attach, so only plaintext connections were read.");
  if (rows.length >= 2000) {
    notes.push("The 2,000-statement log filled, so the analysis covers the most recent 2,000. Use a shorter --seconds.");
  }
  return notes;
}

export function runReport(args = yeet.args ?? {}) {
  const secs = Math.max(1, Number(args.seconds ?? args.secs ?? 30) || 30);
  const top = Math.max(1, Number(args.top ?? 20) | 0);
  const withValues = !!args.values;

  // The producer behind `statements` only runs while something watches it;
  // with no UI, a bare watcher is that something. It never needs to re-arm:
  // the log is a State, so a plain read at the end returns whatever was last
  // published.
  const watcher = new Signal.subtle.Watcher(() => {});
  watcher.watch(statements);

  setTimeout(() => {
    const rows = statements.get();
    const app = rows.filter((r) => !r.isNoise);
    const tls = tlsTargets.get();
    const s = stats.get();
    const report = {
      tool: "sqlsnoop",
      status: status.get(),
      window_s: secs,
      tls_targets: tls,
      statements_seen: s.tracked,
      statements_analyzed: rows.length,
      session_chatter: rows.length - app.length,
      unpaired_replies: s.unpaired,
      findings: findingsFrom(rows).map((f) => findingOf(f, withValues)),
      shapes: shapesOf(app).slice(0, top),
      notes: notesFor(rows, app, tls),
    };
    watcher.unwatch(statements);
    console.log(JSON.stringify(report, (_k, v) => (typeof v === "bigint" ? Number(v) : v)));
    // Let the line reach the client before the isolate goes away.
    setTimeout(() => yeet.exit(), 200);
  }, secs * 1000 + 600);
}

// Run when this file is the entry, by the same two-part guard as
// probes/sql.js: in the bundle `import.meta.main` is true for every inlined
// module, and unbundled the path alone is true whoever imports this.
if (import.meta.main && /report\.js$/.test(import.meta.url ?? "")) runReport();
