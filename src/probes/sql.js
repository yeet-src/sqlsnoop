// BPF data layer for sqlsnoop — the only BPF-aware module.
//
// It loads bin/probe.bpf.o, attaches the socket kprobes (and the TLS uprobes
// where a target is given), and folds three kinds of raw event into one
// append-only log of completed statements. The UI reads plain signals:
//   statements — array of finished statements, newest first, each frozen
//                once it lands (never mutates)
//   shapes     — the same traffic collapsed by normalized shape, for the
//                aggregate view
//   stats      — rolling totals + per-second rates for the title bar
//   status     — attach state, surfaced in the title bar instead of thrown
//
// THE STITCHING PROBLEM, which is most of what this module is.
//
// One logical "a query happened" is up to three ring-buffer events, and they
// do not arrive in a tidy order:
//
//   KIND_QUERY  → statement text (Postgres 'Q'/'P', MySQL COM_QUERY/PREPARE)
//   KIND_PARAMS → parameter values (Postgres Bind, MySQL COM_STMT_EXECUTE)
//   KIND_REPLY  → the reply landed; carries the measured latency
//
// Three facts about real client behaviour drive the design, and each one was
// found by running against actual traffic rather than reading the specs:
//
//   1. A client PREPARES ONCE AND EXECUTES MANY TIMES. Most executions carry
//      no statement text at all — just values. A workload issuing 84 lookups
//      sent 36 statements and 99 parameter blocks. So the socket keeps a
//      registry of statements prepared on it, and an execution is attributed
//      back to one by the prepared-statement NAME the protocol puts in the
//      Bind message. Those unattributed executions ARE the N+1; a model that
//      needs a statement per execution cannot see the thing it exists to find.
//
//   2. A client DOES NOT WAIT for a reply before sending the next statement.
//      So both the kernel and this module keep a per-socket FIFO rather than
//      one slot, and replies pop the oldest outstanding send. With one slot,
//      120 of 135 replies had no timestamp to pair against.
//
//   3. A pipelining client can send VALUES BEFORE their statement, putting
//      the next Bind in the same write as the previous statement's Sync. An
//      orphaned parameter block is therefore held briefly for the statement
//      about to arrive, guarded on placeholder count and freshness.
//
// Everything here keys on the socket, because neither protocol carries a
// request id the way MongoDB's does. That is the load-bearing assumption and
// the documented limit: replies are ordered per connection, which makes FIFO
// pairing correct, but a genuinely concurrent multiplexer over one socket
// would defeat it. See the PAIRING note in sql.bpf.c.
//
// Run standalone to eyeball the raw events (needs the daemon; BPF load is
// privileged and handled by yeetd):
//   yeet run src/probes/sql.js
// then generate traffic, e.g.  psql -h 127.0.0.1 -c 'select 1'
import { BpfObject, DataSec, RingBuf } from "yeet:bpf";
import { computed, from, signal } from "yeet:tui";

// Relative, not `@/`: the alias is bundle-time only, and this module must
// also run standalone via `yeet run src/probes/sql.js`.
import { normalize, verbOf, isWrite, isNoise, isRealStatement, summarize } from "../lib/normalize.js";
import { decodePgBind, decodeMysqlExecute, paramCountOf, renderValues } from "../lib/params.js";
import { footgunOf } from "../lib/footguns.js";

// ── constants shared with sql.bpf.c ─────────────────────────────────────────
const KIND = { QUERY: 1, PARAMS: 2, REPLY: 3 };
const DIALECT = { PG: 1, MYSQL: 2 };

const CAP = 2000; // most-recent statements retained (scrollback depth)
const WINDOW_MS = 250; // snapshot cadence — one re-render per window, not per event
const PENDING_TTL_MS = 30_000; // drop a statement whose reply never came
// How long an orphaned parameter block can wait for its statement. It belongs
// to the statement immediately following it, so this is deliberately tight —
// a stale orphan captioning an unrelated statement is the worst failure this
// module has, being confidently wrong rather than merely incomplete.
const ORPHAN_TTL_MS = 500;

// The exe path is relative to the *running module's* dir, and that dir
// differs between the two ways this module runs:
//
//   bundled     `yeet run .`                 → src/index.jsx  → ../bin
//   standalone  `yeet run src/probes/sql.js` → src/probes/    → ../../bin
//
// `import.meta.main` is not reliable here (esbuild keeps the expression live
// in the bundle, so it stays truthy), so try both depths and keep whichever
// opens. Same fix mongosnoop carries.
const CANDIDATES = ["../bin/probe.bpf.o", "../../bin/probe.bpf.o"];

export const tlsTargets = signal([]);
export const status = signal("starting…");
export const stats = signal({
  tracked: 0,
  qps: 0,
  readRate: 0,
  writeRate: 0,
  slowest: 0,
  pgRate: 0,
  myRate: 0,
  tlsRate: 0,
  unpaired: 0,
});

// Kernel-side slow-statement floor, in microseconds. Patched live into the
// BPF program's .data so filtering happens before the ring buffer rather
// than after the fact in JS.
export const minLatency = signal(0);

let knobs = null;
export function setMinLatency(us) {
  us = Math.max(0, us);
  minLatency.set(us);
  try {
    knobs?.patch({ min_latency_us: BigInt(us) });
  } catch {
    // A failed patch leaves the kernel filtering at the old floor; the UI
    // value would then lie, so put it back.
    minLatency.set(Number(knobs?.read?.("min_latency_us") ?? 0));
  }
}

// Binaries worth trying for a TLS attach, discovered from the running
// process list rather than hardcoded — a virtualenv's python, a bundled
// node, or a distro psql are all found the same way.
const discoverTlsBinaries = async () => {
  const found = new Map();
  try {
    const { data } = await yeet.graph.query(`{ procs { exe stat { comm } } }`);
    for (const p of data?.procs ?? []) {
      const exe = p?.exe ?? "";
      const comm = p?.stat?.comm ?? "";
      if (!exe) continue;
      // Runtimes that either link libssl or bundle their own TLS and talk to
      // databases. Matched on name or path so a bundled binary reporting its
      // own name is still found.
      if (!/(^|\/)(node|bun|deno|python|python3|psql|mysql|ruby|java|dotnet)/i.test(comm) &&
          !/(^|\/)(node|bun|deno|python|python3|psql|mysql|ruby|java|dotnet)/i.test(exe)) continue;
      found.set(exe, true);
    }
  } catch {
    // No graph, no discovery — the libssl attach still covers dynamic clients.
  }
  return [...found.keys()];
};

const load = async () => {
  let lastErr;
  for (const exe of CANDIDATES) {
    try {
      let b = new BpfObject({ exe, base: import.meta.dirname })
        .bind("sql_events", { kind: "ringbuf", btf_struct: "sql_event" })
        .bind("probe.data", { kind: "data" });

      // A BPF program attaches ONCE, so the three TLS programs get one target
      // each. `libssl.so` covers every dynamically-linked client at once,
      // which is most database clients including psql and Python's. A
      // statically-linked runtime needs its own binary named explicitly.
      //
      // Off by default: attaching a uprobe to a library that isn't there
      // fails, and the plaintext path is what most local setups use. The arg
      // parser normalises dashes to underscores, so accept both spellings.
      // Every program in the object must be given attach opts, including the
      // TLS ones we may not want — the loader rejects the object outright if
      // one is left unattached ("No attach opts provided"). So the default is
      // still an attach, just to `libssl.so`, which is present on essentially
      // every Linux host and covers the dynamically-linked clients (psql,
      // Python's _ssl, distro Node) at once. `--tls-binary` overrides the
      // target; the attach itself is not optional.
      const want = yeet.args?.tls_binary ?? yeet.args?.["tls-binary"];
      const attached = [];
      {
        let target = !want || want === true ? "libssl.so" : want;
        if (target === "auto") {
          const found = await discoverTlsBinaries();
          target = found[0] ?? "libssl.so";
        }
        try {
          b = b
            .attach("on_ssl_write", { kind: "uprobe", binary: target, symbol: "SSL_write" })
            // kind is always "uprobe"; the program's SEC() name decides entry
            // vs return, so on_ssl_read_ret shares this spec shape.
            .attach("on_ssl_read", { kind: "uprobe", binary: target, symbol: "SSL_read" })
            .attach("on_ssl_read_ret", { kind: "uprobe", binary: target, symbol: "SSL_read" });
          attached.push(target);
        } catch {
          // No SSL symbols there (stripped build, or no libssl on the box).
          // The plaintext path still works, so degrade to wire-only rather
          // than failing the load.
        }
      }

      const ctl = await b.start();
      knobs = new DataSec(ctl, "probe.data");
      tlsTargets.set(attached);
      return ctl;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
};

// A char[]/u8[] field arrives as an array-like; normalise to Uint8Array so
// the parameter decoders can subarray it.
const bytes = (v) => {
  if (!v) return new Uint8Array(0);
  if (v instanceof Uint8Array) return v;
  return Uint8Array.from(v);
};

// Decode a NUL-terminated char[] to JS text. No TextDecoder in bare V8.
const cstr = (v) => {
  if (typeof v === "string") return v.replace(/\0.*$/s, "");
  if (!v) return "";
  let s = "";
  for (const b of v) {
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s;
};

// Statement text out of the kernel's window. The window is raw bytes and may
// end mid-token; anything unprintable terminates it, which keeps a binary
// tail out of the display.
//
// `skipName` handles the Postgres Parse ('P') frame, whose window starts with
// a prepared-statement NAME cstring before the SQL. The kernel deliberately
// does not find that boundary — scanning a variable-length cstring is the
// unbounded walk it refuses to do (see the 'P' comment in sql.bpf.c) — so the
// split happens here, where a NUL scan is one line. The name is empty for the
// unnamed prepares every pooled client sends, so this is usually a single
// leading zero byte; a named one is skipped correctly too.
const sqlText = (v, len, skipName = false) => {
  const b = bytes(v);
  const n = Math.min(len ?? b.length, b.length);
  let i = 0;
  if (skipName) {
    while (i < n && b[i] !== 0) i++; // the name
    i++; // its terminator
  }
  let s = "";
  for (; i < n; i++) {
    const c = b[i];
    if (c === 0) break;
    // Tab/newline become spaces; other control bytes end the text.
    if (c === 9 || c === 10 || c === 13) {
      s += " ";
      continue;
    }
    if (c < 0x20 || c >= 0x7f) break;
    s += String.fromCharCode(c);
  }
  return s;
};

// The prepared-statement name from a Postgres Parse frame's window. The
// window starts with that name as a cstring, and it is the protocol's own
// identifier for the statement — which is what later Bind messages carry to
// say which statement they are executing. Empty for an unnamed prepare.
const parseName = (v, len) => {
  const b = bytes(v);
  const n = Math.min(len ?? b.length, b.length);
  let s = "";
  for (let i = 0; i < n; i++) {
    const c = b[i];
    if (c === 0) break;
    if (c < 0x20 || c >= 0x7f) return "";
    s += String.fromCharCode(c);
  }
  return s;
};

const unwrap = (w) => w?.sql_event ?? w; // ring-buffer events wrap the struct

// Postgres states its row count in the CommandComplete frame as ASCII —
// "SELECT 42", "UPDATE 3", "INSERT 0 5". That is a string parse, hence JS
// and not the kernel. Returns null when the reply head doesn't carry one,
// which is common: the count arrives after the data rows, so a large result
// puts it past the captured window.
function pgRowsFromReply(buf, len) {
  const b = bytes(buf);
  const end = Math.min(len ?? b.length, b.length);
  let i = 0;
  // Walk the reply's frames looking for 'C' (CommandComplete) or 'E' (error).
  for (let f = 0; f < 16 && i + 5 <= end; f++) {
    const tag = b[i];
    const flen = ((b[i + 1] << 24) | (b[i + 2] << 16) | (b[i + 3] << 8) | b[i + 4]) >>> 0;
    if (flen < 4 || flen > 1 << 24) break;
    if (tag === 0x43) {
      // 'C' — the tag string, e.g. "SELECT 42"
      let s = "";
      for (let k = i + 5; k < end && b[k] !== 0; k++) s += String.fromCharCode(b[k]);
      const m = s.match(/(\d+)\s*$/);
      return { rows: m ? Number(m[1]) : null, error: false };
    }
    if (tag === 0x45) return { rows: null, error: true }; // 'E' — ErrorResponse
    i += 1 + flen;
  }
  return { rows: null, error: false };
}

// MySQL's OK packet states affected rows as a length-encoded integer; a
// result set instead starts with a column count, and the real row count only
// arrives at the end. So this reports affected-rows for writes and leaves
// reads to the row counter below.
function mysqlRowsFromReply(buf, len) {
  const b = bytes(buf);
  const end = Math.min(len ?? b.length, b.length);
  if (end < 5) return { rows: null, error: false };
  const first = b[4];
  if (first === 0xff) return { rows: null, error: true }; // ERR packet
  if (first === 0x00) {
    // OK packet: affected rows, length-encoded, right after the header.
    const f = b[5];
    if (f === undefined) return { rows: null, error: false };
    if (f < 0xfb) return { rows: f, error: false };
    if (f === 0xfc && end > 7) return { rows: b[6] | (b[7] << 8), error: false };
    return { rows: null, error: false };
  }
  return { rows: null, error: false };
}

// ── the joined model ────────────────────────────────────────────────────────

// Statements awaiting their parameters and/or reply, keyed by socket. Bounded
// by TTL rather than count: a socket that goes quiet mid-statement (client
// killed, connection dropped) would otherwise hold its slot forever.
const pending = new Map();

// Parameter values that arrived BEFORE the statement they belong to, keyed by
// socket. A pipelining client (psycopg3, observed) puts the next Bind in the
// same write as the previous statement's Sync, so the values genuinely reach
// us one event early. The next statement on that socket claims them.
const orphanParams = new Map();

// Executions of an already-prepared statement that are waiting for their
// reply, keyed by socket, oldest first. A client that prepares once and
// executes many times (every ORM) sends only a Bind per execution, so these
// are the rows an N+1 is made of — each gets its own latency when its reply
// pops it off the front.
const execQueue = new Map();

// Statements prepared on each socket, oldest first, most-recently-used last.
// A client prepares once and then sends only parameter values per execution,
// so without this registry every execution after the first is unattributable
// — and those executions are precisely what an N+1 consists of.
const preparedBySock = new Map();

// Map key for a MySQL statement's learned parameter count. A plain separator
// rather than a NUL, so the source file stays text.
const mysqlKey = (pid) => `my:${pid}`;

// Parameter counts learned per (pid, MySQL statement id). MySQL's execute
// message doesn't carry the count, so it has to come from the prepare — see
// the note in lib/params.js. Learned from the prepared statement's text.
const mysqlParamCounts = new Map();

const sweepPending = (now) => {
  for (const [k, p] of pending) {
    if (now - p.wallMs > PENDING_TTL_MS) pending.delete(k);
  }
  // A socket that went quiet mid-burst (client killed, connection dropped)
  // leaves queued executions whose replies will never come. Drop them rather
  // than hold the memory; they are already counted in the totals.
  for (const [k, q] of execQueue) {
    if (q.length && now - q[q.length - 1].wallMs > PENDING_TTL_MS) execQueue.delete(k);
  }
  for (const [k, o] of orphanParams) {
    if (now - o.wallMs > ORPHAN_TTL_MS * 4) orphanParams.delete(k);
  }
  // Registries for sockets that have gone quiet. Bounded by count rather than
  // age, since a long-lived pooled connection legitimately keeps its prepared
  // statements for hours.
  if (preparedBySock.size > 4096) preparedBySock.clear();
  // Keyed per pid and never deleted, so on a host churning short-lived MySQL
  // clients this was the only structure here that grew for the life of the
  // run. Bounded crudely: it refills from the next prepare, so dropping it
  // costs at most one execute's values.
  if (mysqlParamCounts.size > 4096) mysqlParamCounts.clear();
};

// Build the display record for a completed statement.
function finish(p, reply) {
  const shape = p.shape;
  const verb = p.verb;
  return Object.freeze({
    pid: p.pid,
    tid: p.tid,
    comm: p.comm,
    dialect: p.dialect,
    dialectName: p.dialect === DIALECT.MYSQL ? "mysql" : "postgres",
    isTls: p.isTls,
    sql: p.sql,
    shape,
    verb,
    label: summarize(shape, verb),
    values: p.values ?? [],
    valuesText: p.values?.length ? renderValues(p.values) : "",
    valuesTruncated: !!p.valuesTruncated,
    valuesNote: p.valuesNote ?? "",
    // True when this execution was matched to its statement by placeholder
    // count rather than by the protocol's own statement name, and more than
    // one candidate fit. Surfaced in the UI: an unshown uncertainty flag is
    // worse than none, since it makes a guess look like an observation.
    shapeAmbiguous: !!p.shapeAmbiguous,
    valuesReordered: !!p.valuesReordered,
    isPrepare: p.isPrepare,
    isWrite: isWrite(verb),
    isNoise: isNoise(shape),
    // The raw SQL as well as the shape: one check needs to see the literal
    // pattern that normalization strips (see footgunOf).
    footgun: footgunOf(shape, verb, p.sql),
    truncated: p.truncated,
    latUs: reply?.latUs ?? null,
    rows: reply?.rows ?? null,
    error: !!reply?.error,
    // Wall clock of the send, so a feed row can be lined up against an
    // application log. The kernel gives a monotonic latency, not a date, so
    // this is stamped in userspace when the statement was first seen.
    at: p.wallMs,
    reqBytes: p.bytes,
    respBytes: reply?.bytes ?? null,
    sock: p.sock,
  });
}

// ── the rate window, at MODULE scope ────────────────────────────────────────
//
// These counters and the interval that publishes them deliberately live out
// here rather than inside the `statements` producer below, and that placement
// is load-bearing.
//
// A `from()` producer is torn down and rebuilt whenever its watcher set goes
// empty, and that is far easier to trigger than it looks. A `computed` that
// reads the signal re-evaluates whenever anything else it depends on changes
// (the selected row, the noise toggle), and each re-evaluation rebuilds its
// dependency set. With the rate window living inside the producer, every one
// of those rebuilds reset it: the counters climbed to about sixteen, restarted
// at zero, and the 250ms publisher never survived long enough to fire once.
// The title bar sat at a flat `0 q/s` while the feed filled with hundreds of
// rows, and nothing anywhere threw an error.
//
// Out here there is exactly one window for the life of the script, and it does
// not care who is watching what.
const win = { q: 0, reads: 0, writes: 0, slowest: 0, pg: 0, my: 0, tls: 0 };
let cumulative = 0; // every statement seen, never reset
let unpairedTotal = 0;

// ── freeze ──────────────────────────────────────────────────────────────────
//
// Freezing stops PUBLISHING, never capturing. The kernel keeps delivering and
// the log keeps growing; the UI just holds the snapshot it already has.
//
// These live at module scope alongside the rate window, and for the same
// reason: the producer they belong to is torn down and rebuilt whenever its
// watcher set changes, and freeze state surviving that is the difference
// between a working pause and one that silently releases itself.
let frozen = false;
let frozenAtCount = 0;
let pendingWhileFrozen = 0;
let freezeHook = null; // installed by the producer below

export const isFrozen = signal(false);
export const bufferedCount = signal(0);
const frozenSig = isFrozen;
const bufferedSig = bufferedCount;

// Freeze or resume the feed. Called from the UI, which owns the policy for
// WHEN to freeze (selecting a row does it) but not the mechanism.
export function setFrozen(want) {
  if (freezeHook) freezeHook(!!want);
  else {
    // The producer has not started yet (nothing is watching the feed). Record
    // the intent so it takes effect when it does.
    frozen = !!want;
    isFrozen.set(frozen);
  }
}

// Report the buffered count on the same cadence as the rates, so a paused
// header can say "340 new" and the reader knows nothing was dropped.
setInterval(() => {
  if (frozen) bufferedCount.set(pendingWhileFrozen);
}, WINDOW_MS);

function countStatement(rec) {
  cumulative++;
  if (rec.isNoise) return;
  win.q++;
  if (rec.dialect === DIALECT.MYSQL) win.my++;
  else win.pg++;
  if (rec.isTls) win.tls++;
  if (rec.isWrite) win.writes++;
  else win.reads++;
  if (rec.latUs > win.slowest) win.slowest = rec.latUs;
}

// Rates are smoothed across a rolling second instead of reported from a single
// 250ms window. One window is a small sample: on bursty traffic it swings
// wildly, and the moment a burst pauses it reads a flat zero while the screen
// is still full of statements from an instant ago.
{
  const secs = WINDOW_MS / 1000;
  const HISTORY = 4; // 4 × 250ms = one second
  const history = [];
  setInterval(() => {
    history.push({ ...win });
    if (history.length > HISTORY) history.shift();
    win.q = win.reads = win.writes = win.slowest = win.pg = win.my = win.tls = 0;

    const span = history.length * secs;
    const sum = (f) => history.reduce((a, w) => a + f(w), 0);
    stats.set({
      tracked: cumulative,
      qps: sum((w) => w.q) / span,
      readRate: sum((w) => w.reads) / span,
      writeRate: sum((w) => w.writes) / span,
      // The slowest in the whole smoothing window, so a spike stays on screen
      // long enough to actually read.
      slowest: history.reduce((a, w) => Math.max(a, w.slowest), 0),
      pgRate: sum((w) => w.pg) / span,
      myRate: sum((w) => w.my) / span,
      tlsRate: sum((w) => w.tls) / span,
      unpaired: unpairedTotal,
    });
  }, WINDOW_MS);
}

export const statements = from((state) => {
  const log = []; // completed statements, newest first — immutable once pushed
  let logId = 0;
  let dirty = false;

  const push = (rec) => {
    // Insert by SEND time, not arrival time.
    //
    // A row is published when its REPLY lands, and replies do not come back in
    // send order once a client pipelines or a slow statement sits behind a
    // fast one. Pushing to the head in arrival order therefore produced a feed
    // whose timestamps went backwards mid-screen, which is both wrong and
    // visibly wrong now that rows carry a clock.
    //
    // Reordering is bounded to a short prefix, so this is a handful of
    // comparisons rather than a sort of the log, and rows below that prefix
    // are settled and never move — which is what keeps the feed stable to read
    // while it streams.
    const at = rec.at ?? 0;
    let i = 0;
    const LOOKBACK = 32;
    while (i < log.length && i < LOOKBACK && (log[i].at ?? 0) > at) i++;
    log.splice(i, 0, { id: ++logId, ...rec });
    if (log.length > CAP) log.length = CAP;
    dirty = true;
    countStatement(rec); // the rate window lives at module scope, see above
  };

  const sub = load()
    .then((ctl) => {
      status.set("tracing");
      return new RingBuf(ctl, "sql_events").subscribe((w) => {
        const ev = unwrap(w);
        const sock = String(ev.sock);
        const now = Date.now();

        if (ev.kind === KIND.QUERY) {
          // A Parse frame's window leads with the statement-name cstring.
          const sql = sqlText(ev.sql, ev.sql_len, ev.tag === 0x50);
          if (!sql) return;
          const shape = normalize(sql);
          const verb = verbOf(shape);
          // Drop anything whose verb we couldn't name — an empty row is
          // worse than no row.
          if (!isRealStatement(verb)) return;

          // A statement already pending on this socket moves to the
          // outstanding QUEUE rather than being published untimed.
          //
          // This is the same lesson as the re-execution path, one level up. A
          // client does not wait for a reply before sending the next
          // statement: psycopg3 in autocommit mode puts several statements on
          // the wire back to back, and a one-slot-per-socket model evicts each
          // one before its reply lands — every row then reads "—" for latency
          // while the unpaired counter climbs. Since replies come back in the
          // order the statements were sent, a FIFO queue per socket pairs
          // them correctly, and the depth of that queue is exactly how far
          // ahead the client is running.
          const prev = pending.get(sock);
          if (prev) {
            const q = execQueue.get(sock) ?? [];
            q.push(prev);
            // Bound it: a client pipelining far ahead of its replies would
            // otherwise grow this without limit. The oldest are the least
            // likely to still be answered, so they go first.
            while (q.length > 64) {
              unpairedTotal++;
              push(finish(q.shift(), null));
            }
            execQueue.set(sock, q);
          }

          const rec = {
            pid: ev.pid,
            tid: ev.tid,
            comm: cstr(ev.comm),
            dialect: ev.dialect,
            isTls: ev.source === 1,
            sql,
            shape,
            verb,
            isPrepare: !!ev.is_prepare,
            truncated: !!ev.truncated,
            bytes: ev.bytes,
            sock,
            wallMs: now,
            values: [],
            // Postgres names the statement a Parse creates; later Binds cite
            // that name. This is the exact key that attributes an execution
            // to its SQL, so it beats any heuristic.
            stmtName: ev.dialect === DIALECT.PG && ev.tag === 0x50 ? parseName(ev.sql, ev.sql_len) : "",
          };

          // Claim parameter values that arrived BEFORE their statement.
          //
          // Observed against psycopg3: a pipelining client sends the Bind for
          // the next execution in the same write as the previous statement's
          // Sync, so the values reach us one event ahead of the Parse they
          // belong to. Buffering the orphan on the socket and letting the
          // next statement claim it is what puts them back together.
          //
          // The claim is GUARDED on two things, because an unguarded one is
          // worse than no values at all — it captions a statement with
          // another statement's data, which is the most misleading thing this
          // tool could do:
          //
          //   1. The placeholder count must match. A Bind carrying two values
          //      cannot belong to a statement with three `?`s.
          //   2. The orphan must be fresh. It belongs to the statement that
          //      follows it immediately, so anything older than one publish
          //      window is a leftover from a sequence we lost track of.
          //
          // A rejected orphan is dropped rather than held for the next
          // candidate: if we cannot say which statement it belongs to, the
          // honest answer is to show no values.
          const orphan = orphanParams.get(sock);
          if (orphan) {
            orphanParams.delete(sock);
            const want = paramCountOf(shape);
            const fresh = now - orphan.wallMs <= ORPHAN_TTL_MS;
            if (fresh && want > 0 && orphan.values.length === want) {
              rec.values = orphan.values;
              rec.valuesTruncated = orphan.truncated;
              rec.valuesNote = orphan.note ?? "";
              rec.valuesReordered = true; // the UI notes the arrival order
            }
          }

          pending.set(sock, rec);

          // Register it as prepared on this socket, so later Binds that carry
          // only values can be matched back to it. This is what makes an N+1
          // countable at all — see the attribution note in the PARAMS branch.
          {
            const reg = preparedBySock.get(sock) ?? [];
            // Deduplicate by NAME where the protocol gave one (a client
            // re-preparing under the same name replaces it), otherwise by
            // shape.
            const at = rec.stmtName
              ? reg.findIndex((x) => x.stmtName === rec.stmtName)
              : reg.findIndex((x) => x.shape === rec.shape);
            if (at >= 0) reg.splice(at, 1);
            reg.push(rec);
            // Bound per socket. A connection with hundreds of distinct
            // prepared statements is real, but the oldest are the least
            // likely to be executed again.
            while (reg.length > 64) reg.shift();
            preparedBySock.set(sock, reg);
          }

          // Remember the placeholder count so a later MySQL execute on this
          // statement can be decoded. Keyed per pid so two processes don't
          // share ids.
          if (ev.dialect === DIALECT.MYSQL && ev.is_prepare) {
            mysqlParamCounts.set(mysqlKey(ev.pid), paramCountOf(shape));
          }
          if (pending.size > 4096) sweepPending(now);
          return;
        }

        if (ev.kind === KIND.PARAMS) {
          // Decode the values first — who they belong to is a separate
          // question, and a harder one.
          const prepared = preparedBySock.get(sock) ?? [];
          const p = pending.get(sock);

          let r;
          if (ev.dialect === DIALECT.PG) {
            r = decodePgBind(bytes(ev.params), ev.param_len);
          } else {
            // MySQL: the count comes from the prepared statement's text,
            // because the execute message does not carry it. Try the pending
            // statement, then anything prepared on this socket.
            const n =
              (p ? paramCountOf(p.shape) : 0) ||
              prepared.map((x) => paramCountOf(x.shape)).find((c) => c > 0) ||
              mysqlParamCounts.get(mysqlKey(ev.pid)) ||
              0;
            r = decodeMysqlExecute(bytes(ev.params), ev.param_len, n);
          }

          if (!r.values.length) return;
          const got = r.values.length;

          // WHICH statement is this an execution of?
          //
          // A client prepares each statement ONCE and then sends only a Bind
          // per execution, so the overwhelming majority of executions arrive
          // with no statement text attached to them at all. The workload
          // that exposed this sent 36 statements and 99 parameter blocks: the
          // 78 extra executions are the N+1, and a model that needs a
          // statement event per execution simply cannot see them.
          //
          // So the socket keeps a registry of the statements prepared on it,
          // and a Bind is matched to one by PLACEHOLDER COUNT — the only
          // discriminator the Bind message carries. When exactly one prepared
          // statement takes this many parameters the match is unambiguous;
          // when several do, the most recently used one wins, which is right
          // for a loop and a coin-flip otherwise. An ambiguous match is
          // marked on the row (`shapeAmbiguous`) rather than presented as
          // certain.
          let owner = null;
          let ambiguous = false;

          // 1. By NAME, when the Bind cited one and we saw that Parse. This
          //    is the protocol telling us the answer, so it is exact.
          const named = r.stmtName ? prepared.find((x) => x.stmtName === r.stmtName) : null;
          if (named) {
            owner = named;
          } else if (p && paramCountOf(p.shape) === got) {
            // 2. The statement still pending on THIS socket, when its
            //    placeholder count matches.
            //
            //    Same socket is a much stronger signal than same count: a
            //    Bind arriving on a connection whose last statement is still
            //    unanswered almost certainly belongs to it, because a
            //    connection processes its messages in order. The count has to
            //    agree as well, so a mismatch falls through rather than
            //    captioning the pending statement with values that are not
            //    its own.
            //
            //    The old version also accepted a pending statement with ZERO
            //    placeholders, which was simply wrong: a statement with no
            //    `?` cannot be the target of a Bind carrying values.
            owner = p;
          } else {
            // 3. Fall back to placeholder count — but only when it is
            //    UNAMBIGUOUS.
            //
            //    This used to take the most-recently-used candidate whenever
            //    several fit, marking the row ambiguous. That was too
            //    generous, and concurrent traffic showed why: an inventory
            //    write's `sku-1354` was captioned onto an orders lookup,
            //    because both take two parameters. The row carried a `~`
            //    marker, but a values line under the wrong SQL is misleading
            //    whatever marker it wears — someone reading the feed sees a
            //    concrete value under a concrete statement and believes it.
            //
            //    So a tie now yields NO owner and the values are dropped. The
            //    cost is a statement occasionally shown without its values;
            //    the alternative is showing it with someone else's, which is
            //    worse. This branch is only reached for unnamed prepares
            //    whose Parse we missed (attached mid-connection), since
            //    Postgres names the statements it prepares and MySQL carries
            //    a statement id.
            const fits = prepared.filter((x) => paramCountOf(x.shape) === got);
            if (fits.length === 1) {
              owner = fits[0];
              ambiguous = true; // matched by shape, not by the protocol's name
            }
          }

          if (!owner) {
            // Values with no statement we can attribute them to. Hold them
            // briefly for a statement that may be about to arrive; otherwise
            // they are dropped rather than captioned onto a guess.
            orphanParams.set(sock, { values: r.values, truncated: r.truncated, note: r.note, wallMs: now });
            if (orphanParams.size > 4096) {
              for (const [k, o] of orphanParams) {
                if (now - o.wallMs > ORPHAN_TTL_MS * 4) orphanParams.delete(k);
              }
            }
            return;
          }

          // The statement currently pending, still without values, is this
          // execution itself rather than a re-execution of something.
          if (owner === p && !p.values?.length) {
            p.values = r.values;
            p.valuesTruncated = r.truncated;
            p.valuesNote = r.note ?? "";
            p.shapeAmbiguous = ambiguous;
            return;
          }

          // Otherwise this is a fresh EXECUTION of an already-prepared
          // statement. Queue it in send order so the reply that follows times
          // it, mirroring the kernel's per-socket FIFO of send timestamps
          // (INFLIGHT_RING in sql.bpf.c). The two queues have to agree about
          // ordering or latencies land on the wrong executions.
          const exec = {
            ...owner,
            values: r.values,
            valuesTruncated: r.truncated,
            valuesNote: r.note ?? "",
            shapeAmbiguous: ambiguous,
            wallMs: now,
            reexecuted: true,
          };
          const q = execQueue.get(sock) ?? [];
          q.push(exec);
          // Bound it: a client pipelining far ahead of its replies would grow
          // this without limit. The oldest are least likely to still be
          // answered, so they go first, published untimed.
          while (q.length > 64) {
            unpairedTotal++;
            push(finish(q.shift(), null));
          }
          execQueue.set(sock, q);

          // Keep the registry ordered by recency of use, so the "most
          // recently used wins" tiebreak above means what it says.
          const reg = preparedBySock.get(sock);
          if (reg) {
            const at = reg.indexOf(owner);
            if (at >= 0 && at !== reg.length - 1) {
              reg.splice(at, 1);
              reg.push(owner);
            }
          }
          return;
        }

        if (ev.kind === KIND.REPLY) {
          // A queued re-execution is answered first: in a
          // prepare-once/execute-many chain the replies arrive in the order
          // the executions were sent, so the oldest outstanding one owns this
          // reply. Only when the queue is empty does the reply belong to the
          // statement currently pending.
          const q = execQueue.get(sock);
          let target;
          if (q?.length) {
            target = q.shift();
            if (!q.length) execQueue.delete(sock);
          } else {
            target = pending.get(sock);
            if (!target) return; // a reply we have no statement for
            pending.delete(sock);
          }

          const raw = ev.dialect === DIALECT.PG
            ? pgRowsFromReply(ev.params, ev.param_len)
            : mysqlRowsFromReply(ev.params, ev.param_len);

          push(finish(target, { latUs: ev.lat_us, rows: raw.rows, error: raw.error, bytes: ev.bytes }));
        }
      });
    })
    .catch((e) => status.set(`probe failed: ${e?.message ?? e}`));

  // The producer publishes only the LOG snapshot. Rates are owned at module
  // scope so they survive this producer being restarted by a watcher change.
  //
  // While FROZEN it stops publishing but keeps capturing. That distinction is
  // the whole point: the rows on screen hold still so they can be read, and
  // nothing is lost, because the log behind them keeps filling. Unfreezing
  // publishes the current log, so you rejoin the live stream rather than
  // replaying a backlog.
  //
  // Freezing is what makes selection mean anything. Without it the list is
  // replaced every 250ms, so "row 4" is a different statement each frame and
  // the detail pane describes a moving target — you cannot read the row you
  // just decided to look at.
  const publish = () => {
    sweepPending(Date.now());
    if (frozen) {
      // Count what the reader is not seeing, so the UI can say so instead of
      // looking stalled.
      pendingWhileFrozen = Math.max(0, cumulative - frozenAtCount);
      return;
    }
    if (!dirty) return;
    state.set(log.slice(0, CAP));
    dirty = false;
  };
  const h = setInterval(publish, WINDOW_MS);

  // Publishing is driven by the interval above, so freezing only has to flip
  // a flag; the next tick does the right thing. Exposed through the module's
  // `setFrozen` rather than directly, because the UI must not reach into the
  // producer's closure.
  freezeHook = (want) => {
    if (want === frozen) return;
    frozen = want;
    if (frozen) {
      frozenAtCount = cumulative;
      pendingWhileFrozen = 0;
    } else {
      // Rejoin live immediately rather than waiting up to a window for the
      // next tick, so resuming feels instant.
      pendingWhileFrozen = 0;
      state.set(log.slice(0, CAP));
      dirty = false;
    }
    frozenSig.set(frozen);
    bufferedSig.set(0);
  };

  return () => {
    clearInterval(h);
    sub.then((s) => s?.unsubscribe());
  };
}, []);

// ── the aggregate model ─────────────────────────────────────────────────────
//
// The same traffic, collapsed by normalized shape. This answers a different
// question from the feed: the feed says "what is happening right now", the
// aggregate says "what is hammering this database" — a pg_stat_statements you
// never had to enable, and one that includes the client process, which the
// server-side view cannot see.
//
// Derived from the feed rather than accumulated separately, so the two views
// can never disagree about what was captured. That costs a pass over the log
// per publish window, which at CAP=2000 is trivial and buys the guarantee.
export const shapes = computed(() => {
  // A COMPUTED over `statements`, not a second `from()` with its own timer.
  //
  // The first version was a `from()` whose producer read `statements.get()`
  // from inside a `setInterval`. A read in a bare callback is not a reactive
  // read: it registers no dependency, so the aggregate view kept no watcher on
  // the capture and the feed producer was started and torn down underneath it.
  //
  // A computed declares the dependency properly. There is one capture
  // producer, alive while anything reads either signal, and this recomputes
  // when the feed actually changes rather than on a timer — strictly less
  // work, and no lifecycle surprises.
  const rows = new Map();
  for (const st of statements.get()) {
    let r = rows.get(st.shape);
    if (!r) {
      r = {
        shape: st.shape,
        label: st.label,
        verb: st.verb,
        dialectName: st.dialectName,
        calls: 0,
        totalUs: 0,
        maxUs: 0,
        rows: 0,
        rowsKnown: 0,
        errors: 0,
        timed: 0, // calls we have a latency for; the average divides by this
        comms: new Set(),
        isWrite: st.isWrite,
        isNoise: st.isNoise,
        footgun: st.footgun,
        anyTls: false,
        sample: st, // a concrete example, for the detail pane
      };
      rows.set(st.shape, r);
    }
    r.calls++;
    if (st.latUs != null) {
      r.totalUs += st.latUs;
      r.timed++;
      if (st.latUs > r.maxUs) r.maxUs = st.latUs;
    }
    if (st.rows != null) {
      r.rows += st.rows;
      r.rowsKnown++;
    }
    if (st.error) r.errors++;
    if (st.isTls) r.anyTls = true;
    r.comms.add(st.comm);
  }

  const out = [...rows.values()].map((r) => ({
    ...r,
    comms: [...r.comms],
    avgUs: r.timed ? r.totalUs / r.timed : null,
    // Only claim a row total when every call reported one; a partial sum
    // reads as a fact and would be wrong.
    rowsTotal: r.rowsKnown === r.calls ? r.rows : null,
  }));
  // Ranked by total time, which is the number that identifies the query
  // actually costing you something — a fast query run 10,000 times beats a
  // slow one run twice, and the feed already surfaces the individually slow.
  out.sort((a, b) => b.totalUs - a.totalUs || b.calls - a.calls);
  // Ranked by total time, which is the number identifying the query that
  // actually costs something: a fast query run 10,000 times beats a slow one
  // run twice, and the feed already surfaces the individually slow.
  out.sort((a, b) => b.totalUs - a.totalUs || b.calls - a.calls);
  return out;
});

// Standalone correctness probe: dump raw joined statements so field names and
// types are verifiable before any UI exists.
//
// Guarded on this module being the entry BY PATH, not on `import.meta.main`:
// the bundle inlines this module into src/index.jsx, and there `import.meta`
// belongs to the bundle — which IS the entry — so an `import.meta.main` guard
// runs the dump loop instead of the TUI.
const isEntry = /probes\/sql\.js$/.test(import.meta.url ?? "");

if (isEntry) {
  const ctl = await load();
  const rb = new RingBuf(ctl, "sql_events");
  const kindName = { 1: "QUERY", 2: "PARAMS", 3: "REPLY" };
  console.log("[sql] attached tcp_sendmsg/tcp_recvmsg — waiting for SQL traffic…");
  console.log(`[sql] tls targets: ${tlsTargets.get().join(", ") || "(none — plaintext only)"}`);

  const pend = new Map();
  const orphans = new Map();
  rb.subscribe((w) => {
    const ev = unwrap(w);
    const sock = String(ev.sock);
    const dia = ev.dialect === DIALECT.MYSQL ? "mysql" : "pg";
    const src = ev.source === 1 ? "TLS " : "wire";

    if (ev.kind === KIND.QUERY) {
      const sql = sqlText(ev.sql, ev.sql_len, ev.tag === 0x50);
      const shape = normalize(sql);
      const held = orphans.get(sock);
      orphans.delete(sock);
      console.log(
        `[QUERY] ${src} ${dia} ${cstr(ev.comm)}/${ev.pid} sock=${sock} ` +
          `tag=${String.fromCharCode(ev.tag)} prep=${ev.is_prepare} ${ev.bytes}B${ev.truncated ? " TRUNC" : ""}`,
      );
      console.log(`   sql   ${sql || "(empty)"}`);
      console.log(`   shape ${shape}   verb=${verbOf(shape)}  params=${paramCountOf(shape)}`);
      if (held) console.log(`   vals  ${renderValues(held)}   (arrived before this statement)`);
      pend.set(sock, { shape, pid: ev.pid, dialect: ev.dialect });
    } else if (ev.kind === KIND.PARAMS) {
      const p = pend.get(sock);
      const r = ev.dialect === DIALECT.PG
        ? decodePgBind(bytes(ev.params), ev.param_len)
        : decodeMysqlExecute(bytes(ev.params), ev.param_len, p ? paramCountOf(p.shape) : 0);
      if (r.values.length && !p) {
        // Held for the statement that is about to arrive — the pipelining
        // case the joined model handles the same way.
        orphans.set(sock, r.values);
        console.log(`[PARAMS] ${src} ${dia} sock=${sock} ${ev.param_len}B → ${renderValues(r.values)} (held, no statement yet)`);
      } else {
        console.log(`[PARAMS] ${src} ${dia} sock=${sock} ${ev.param_len}B → ${renderValues(r.values) || "(none)"}${r.truncated ? " TRUNC" : ""}${r.note ? ` (${r.note})` : ""}`);
      }
    } else if (ev.kind === KIND.REPLY) {
      const raw = ev.dialect === DIALECT.PG
        ? pgRowsFromReply(ev.params, ev.param_len)
        : mysqlRowsFromReply(ev.params, ev.param_len);
      console.log(
        `[REPLY]  ${src} ${dia} sock=${sock} lat=${(ev.lat_us / 1000).toFixed(2)}ms ` +
          `rows=${raw.rows ?? "-"}${raw.error ? " ERROR" : ""} ${ev.bytes}B`,
      );
    }
  });
  await new Promise(() => {});
}
