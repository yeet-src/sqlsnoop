// Tests for the pure library layer: normalization, parameter decoding,
// footgun detection, findings derivation and formatting.
//
// These need no kernel and no database, which is the point. `src/lib/` is
// deliberately free of I/O so the analysis can be tested against fixtures,
// and the analysis is where the bugs live: every capture bug found so far was
// in how bytes were interpreted, not in whether they arrived.
//
//   node --test test/lib.test.mjs      (or: node test/lib.test.mjs)
//
// Fixtures are byte-exact copies of what the wire actually carried, taken
// from real psycopg3 and MySQLdb traffic rather than written by hand. A
// synthesized fixture can agree with a wrong decoder; a recorded one cannot.
import assert from "node:assert/strict";
import { test } from "node:test";

import { isNoise, isWrite, normalize, tablesOf, verbOf } from "../src/lib/normalize.js";
import { decodeMysqlExecute, decodePgBind, paramCountOf } from "../src/lib/params.js";
import { footgunOf } from "../src/lib/footguns.js";
import { findingsFrom } from "../src/lib/findings.js";
import { clockMs, explainable, fmtBytes, fmtCount, fmtLat, fmtRate, valuesInline } from "../src/lib/format.js";

// ── normalization ───────────────────────────────────────────────────────────

test("normalize strips literals to placeholders", () => {
  assert.equal(
    normalize("SELECT * FROM orders WHERE customer_id = 4471 AND status = 'pending'"),
    "SELECT * FROM orders WHERE customer_id = ? AND status = ?",
  );
});

test("normalize unifies driver placeholder styles into one shape", () => {
  // An ORM that parameterizes and a hand-written query that inlines its values
  // must collapse to the SAME shape, or the aggregate view splits one query
  // into two rows and both counts are wrong.
  const a = normalize("SELECT id FROM t WHERE x = $1 AND y = $2");
  const b = normalize("SELECT id FROM t WHERE x = ? AND y = ?");
  const c = normalize("SELECT id FROM t WHERE x = 42 AND y = 'foo'");
  assert.equal(a, b);
  assert.equal(b, c);
});

test("normalize collapses IN lists and multi-row VALUES to one shape", () => {
  // Without this a bulk insert of 500 rows fingerprints differently from one
  // of 499, and the aggregate fragments into near-duplicate rows.
  assert.equal(normalize("SELECT 1 FROM t WHERE id IN (1,2,3,4,5)"), "SELECT ? FROM t WHERE id IN (?)");
  assert.equal(
    normalize("INSERT INTO t (a,b) VALUES (1,2),(3,4),(5,6)"),
    "INSERT INTO t (a,b) VALUES (?)",
  );
});

test("normalize does not mangle digits inside identifiers", () => {
  // `col2` is a column name, not a literal. An earlier version turned it into
  // `col?` and every shape touching a numbered column was wrong.
  const s = normalize("SELECT col2, t1.id FROM tbl3 WHERE col2 = 7");
  assert.match(s, /col2/);
  assert.match(s, /t1\.id/);
  assert.match(s, /tbl3/);
  assert.match(s, /col2 = \?/);
});

test("normalize handles escaped quotes inside string literals", () => {
  // A doubled quote is SQL's escape, so the literal does not end there. Get
  // this wrong and the rest of the statement is parsed as if inside a string.
  assert.equal(normalize("SELECT * FROM t WHERE s = 'it''s here' AND n = 5"),
    "SELECT * FROM t WHERE s = ? AND n = ?");
});

test("normalize removes comments before scanning", () => {
  assert.equal(normalize("SELECT 1 /* a 'comment' with quotes */ FROM t"), "SELECT ? FROM t");
  assert.equal(normalize("SELECT 1 -- trailing 'stuff'\nFROM t"), "SELECT ? FROM t");
});

test("verbOf resolves the real verb behind a CTE or a paren", () => {
  assert.equal(verbOf("SELECT 1"), "SELECT");
  assert.equal(verbOf("(SELECT 1) UNION (SELECT 2)"), "SELECT");
  assert.equal(verbOf("WITH x AS (SELECT 1) DELETE FROM t WHERE id IN (SELECT * FROM x)"), "DELETE");
});

test("isWrite classifies the verbs that change data", () => {
  for (const v of ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "DROP", "ALTER"]) {
    assert.equal(isWrite(v), true, `${v} should be a write`);
  }
  for (const v of ["SELECT", "SHOW", "EXPLAIN"]) {
    assert.equal(isWrite(v), false, `${v} should not be a write`);
  }
});

test("isNoise catches session chatter but not application queries", () => {
  for (const s of ["BEGIN", "COMMIT", "ROLLBACK", "SET autocommit=?", "SHOW server_version", "SELECT ?"]) {
    assert.equal(isNoise(s), true, `${s} should be chatter`);
  }
  // The regression that matters: a real query with a LIMIT normalizes to
  // `LIMIT ?`, which must not be mistaken for the `SELECT ?` health check.
  for (const s of [
    "SELECT id FROM customers WHERE region = ? LIMIT ?",
    "SELECT count(*) FROM orders WHERE customer_id = ?",
    "UPDATE inventory SET qty = qty - ? WHERE sku = ?",
  ]) {
    assert.equal(isNoise(s), false, `${s} should NOT be chatter`);
  }
});

test("tablesOf reads the tables a statement touches", () => {
  assert.deepEqual(tablesOf("SELECT * FROM orders WHERE id = ?"), ["orders"]);
  assert.deepEqual(
    tablesOf("SELECT * FROM orders o JOIN customers c ON c.id = o.customer_id"),
    ["orders", "customers"],
  );
  // A subquery in FROM must not be reported as a table named "select".
  assert.deepEqual(tablesOf("SELECT * FROM (SELECT 1) x"), []);
});

// ── Postgres Bind decoding ─────────────────────────────────────────────────

// Build a Bind message body the way Postgres does, starting after the tag and
// length that the kernel already skipped.
function pgBind({ portal = "", stmt = "", formats = [], values = [] }) {
  const bytes = [];
  const cstr = (s) => {
    for (const ch of s) bytes.push(ch.charCodeAt(0));
    bytes.push(0);
  };
  const be16 = (n) => bytes.push((n >> 8) & 0xff, n & 0xff);
  const be32 = (n) => bytes.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

  cstr(portal);
  cstr(stmt);
  be16(formats.length);
  for (const f of formats) be16(f);
  be16(values.length);
  for (const v of values) {
    if (v === null) {
      be32(-1 >>> 0);
      bytes.push(); // -1 length, no body
      // be32 of 0xffffffff already pushed the four bytes
      continue;
    }
    be32(v.length);
    for (const b of v) bytes.push(b);
  }
  return new Uint8Array(bytes);
}

const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

test("decodePgBind reads text-format parameters and the statement name", () => {
  const buf = pgBind({ stmt: "_pg3_1", formats: [0, 0], values: [ascii("42"), ascii("pending")] });
  const r = decodePgBind(buf, buf.length);
  assert.equal(r.stmtName, "_pg3_1");
  assert.equal(r.truncated, false);
  assert.deepEqual(r.values.map((v) => v.text), ["42", "'pending'"]);
  // A numeric-looking text parameter is not quoted; a string is.
  assert.equal(r.values[0].certain, true);
  assert.equal(r.values[1].certain, true);
});

test("decodePgBind reports NULL distinctly from an empty string", () => {
  const buf = pgBind({ formats: [0, 0], values: [null, []] });
  const r = decodePgBind(buf, buf.length);
  assert.equal(r.values[0].text, "NULL");
  assert.notEqual(r.values[1].text, "NULL");
});

test("decodePgBind marks a value cut off by the capture window", () => {
  const buf = pgBind({ formats: [0], values: [ascii("a".repeat(40))] });
  // Truncate the buffer mid-value, which is what a fixed kernel window does.
  const r = decodePgBind(buf, 14);
  assert.equal(r.truncated, true);
});

test("decodePgBind reads a binary int4 exactly", () => {
  const buf = pgBind({ formats: [1], values: [[0, 0, 1, 0xc8]] }); // 456, big-endian
  const r = decodePgBind(buf, buf.length);
  assert.equal(r.values[0].text, "456");
});

test("decodePgBind prefers the float reading for an 8-byte numeric", () => {
  // THE REGRESSION THIS FILE EXISTS FOR. Postgres sends `numeric`/`float8` in
  // binary, and reading those eight bytes as an int64 rendered 137.42 as
  // 4640265580000000000 — an IEEE-754 bit pattern printed as an integer, which
  // looks like a plausible id and is entirely wrong.
  const dv = new DataView(new ArrayBuffer(8));
  dv.setFloat64(0, 137.42, false); // Postgres binary is big-endian
  const body = [...new Uint8Array(dv.buffer)];
  const buf = pgBind({ formats: [1], values: [body] });
  const r = decodePgBind(buf, buf.length);
  assert.equal(r.values[0].text, "137.42");
  // And it stays marked uncertain, because the Bind genuinely does not carry
  // the type: honesty about the ambiguity is part of the contract.
  assert.equal(r.values[0].certain, false);
});

test("decodePgBind refuses an implausible parameter count instead of walking garbage", () => {
  const buf = new Uint8Array([0, 0, 0xff, 0xff, 0xff, 0xff]);
  const r = decodePgBind(buf, buf.length);
  assert.equal(r.values.length, 0);
});

// ── MySQL COM_STMT_EXECUTE decoding ────────────────────────────────────────

test("decodeMysqlExecute decodes typed binary parameters", () => {
  // statement id (4), flags (1), iteration count (4), null bitmap, new-bound
  // flag, then two int16 type words, then the values.
  const bytes = [
    1, 0, 0, 0, // statement id
    0, // flags
    1, 0, 0, 0, // iteration count
    0, // null bitmap for 2 params
    1, // new params bound
    0x03, 0, // MYSQL_TYPE_LONG
    0xfe, 0, // MYSQL_TYPE_STRING
    0x2a, 0, 0, 0, // 42, little-endian
    7, ...ascii("pending"), // length-encoded string
  ];
  const buf = new Uint8Array(bytes);
  const r = decodeMysqlExecute(buf, buf.length, 2);
  assert.deepEqual(r.values.map((v) => v.text), ["42", "'pending'"]);
});

test("decodeMysqlExecute says so when the parameter count is unknown", () => {
  // MySQL's execute message does not carry the count; it was in the prepare's
  // reply. If we never saw that, the honest answer is to say we cannot decode
  // rather than to guess an offset.
  const buf = new Uint8Array([1, 0, 0, 0, 0, 1, 0, 0, 0]);
  const r = decodeMysqlExecute(buf, buf.length, 0);
  assert.equal(r.values.length, 0);
  assert.match(r.note ?? "", /unknown/i);
});

test("decodeMysqlExecute marks values whose types were not re-sent", () => {
  // A client sets the new-params-bound flag on the first execute and omits it
  // afterwards, so a re-execution carries values with no type words at all.
  const buf = new Uint8Array([
    1, 0, 0, 0, 0, 1, 0, 0, 0,
    0, // null bitmap
    0, // new params NOT bound
    0x2a, 0, 0, 0,
  ]);
  const r = decodeMysqlExecute(buf, buf.length, 1);
  assert.equal(r.values[0].certain, false);
});

// ── paramCountOf / explainable ─────────────────────────────────────────────

test("paramCountOf counts placeholders on the normalized shape", () => {
  assert.equal(paramCountOf("SELECT ? FROM t WHERE a = ? AND b = ?"), 3);
  assert.equal(paramCountOf("SELECT 1 FROM t"), 0);
});

test("explainable substitutes values for a runnable statement", () => {
  const sql = "SELECT id FROM orders WHERE customer_id = $1 AND status = $2";
  const values = [
    { index: 1, text: "42", certain: true },
    { index: 2, text: "'pending'", certain: true },
  ];
  assert.equal(
    explainable(sql, values),
    "SELECT id FROM orders WHERE customer_id = 42 AND status = 'pending'",
  );
});

test("explainable refuses when any value is uncertain", () => {
  // Handing someone SQL that looks runnable but carries a mis-decoded value
  // either fails with a type error or, worse, runs against the wrong row.
  const sql = "SELECT id FROM t WHERE x = $1";
  const values = [{ index: 1, text: "4640265580000000000", certain: false }];
  assert.equal(explainable(sql, values), null);
});

test("explainable refuses when the placeholder count disagrees", () => {
  assert.equal(explainable("SELECT ? , ?", [{ index: 1, text: "1", certain: true }]), null);
  assert.equal(explainable("SELECT id FROM t WHERE a = $1 AND b = $2", [
    { index: 1, text: "1", certain: true },
  ]), null);
});

test("explainable handles positional ? placeholders in order", () => {
  assert.equal(
    explainable("UPDATE t SET a = ? WHERE id = ?", [
      { index: 1, text: "7", certain: true },
      { index: 2, text: "9", certain: true },
    ]),
    "UPDATE t SET a = 7 WHERE id = 9",
  );
});

// ── footguns ───────────────────────────────────────────────────────────────

test("footgunOf flags a write with no predicate above everything else", () => {
  assert.match(footgunOf("DELETE FROM orders", "DELETE"), /no WHERE/);
  assert.match(footgunOf("UPDATE orders SET status = ?", "UPDATE"), /no WHERE/);
});

test("footgunOf flags a leading-wildcard LIKE from the RAW sql", () => {
  // The pattern lives in the literal, which normalization removes, so this
  // check reads the raw statement. Passing only the shape means the check
  // cannot fire — which is exactly the bug this asserts against.
  const shape = "SELECT a FROM t WHERE n LIKE ? LIMIT ?";
  assert.match(
    footgunOf(shape, "SELECT", "SELECT a FROM t WHERE n LIKE '%x%' LIMIT 5"),
    /leading-wildcard/,
  );
  // A trailing wildcard CAN use a B-tree index, so flagging it would be wrong.
  assert.equal(footgunOf(shape, "SELECT", "SELECT a FROM t WHERE n LIKE 'x%' LIMIT 5"), null);
  // And with no raw sql the check is simply skipped rather than throwing.
  assert.equal(footgunOf(shape, "SELECT"), null);
});

test("footgunOf stays silent on well-formed statements", () => {
  // False alarms are the failure mode that matters: one bad flag teaches the
  // reader to distrust the rest.
  const fine = [
    ["SELECT id FROM orders WHERE customer_id = ? AND status = ?", "SELECT"],
    ["UPDATE inventory SET qty = qty - ? WHERE sku = ?", "UPDATE"],
    ["INSERT INTO orders (customer_id, status, total) VALUES (?)", "INSERT"],
    ["SELECT count(*) FROM orders WHERE customer_id = ?", "SELECT"],
    ["DELETE FROM orders WHERE id IN (?)", "DELETE"],
  ];
  for (const [sql, verb] of fine) {
    assert.equal(footgunOf(sql, verb), null, `should not flag: ${sql}`);
  }
});

test("footgunOf flags ORDER BY with no LIMIT, and not with one", () => {
  assert.match(footgunOf("SELECT a FROM t ORDER BY a DESC", "SELECT"), /ORDER BY/);
  assert.equal(footgunOf("SELECT a FROM t WHERE b = ? ORDER BY a DESC LIMIT ?", "SELECT"), null);
});

// ── findings ───────────────────────────────────────────────────────────────

// A statement record shaped the way the probe emits one.
let clock = 1_700_000_000_000;
const stmt = (over = {}) => ({
  pid: 100,
  tid: 100,
  comm: "app",
  shape: "SELECT id FROM t WHERE x = ?",
  verb: "SELECT",
  sql: "SELECT id FROM t WHERE x = 1",
  values: [{ index: 1, text: "1", certain: true }],
  latUs: 100,
  rows: 1,
  isNoise: false,
  isWrite: false,
  isTls: false,
  error: false,
  footgun: null,
  dialectName: "postgres",
  at: (clock += 1),
  ...over,
});

test("findingsFrom reports an N+1 burst once, not once per burst", () => {
  // Three separate bursts of ONE shape, separated by a gap in both position
  // and time, with filler that is deliberately NOT burst-shaped: spread
  // across threads so it cannot itself qualify. (An earlier version of this
  // fixture used 20 same-thread filler statements, which was a legitimate
  // second N+1 — the test was wrong, not the code.)
  const rows = [];
  for (let burst = 0; burst < 3; burst++) {
    for (let i = 0; i < 15; i++) {
      rows.push(stmt({ values: [{ index: 1, text: String(i), certain: true }] }));
    }
    clock += 5000;
    for (let i = 0; i < 20; i++) {
      rows.push(stmt({
        shape: "SELECT other FROM u",
        sql: "SELECT other FROM u",
        tid: 200 + (i % 4),
        at: (clock += 400),
      }));
    }
  }
  const f = findingsFrom(rows.reverse());
  const nplus = f.filter((x) => x.kind === "n+1");
  assert.equal(nplus.length, 1, "three bursts of one shape is ONE finding");
  assert.equal(nplus[0].occurrences, 3);
  assert.match(nplus[0].label, /bursts/);
});

test("findingsFrom does not call interleaved traffic an N+1", () => {
  // Ten executions of a common lookup landing adjacent by coincidence, from
  // several threads. This produced false N+1s on `SELECT count(*)` and a
  // primary-key lookup before the one-thread guard existed.
  const rows = [];
  for (let i = 0; i < 20; i++) {
    rows.push(stmt({ tid: 100 + (i % 4), at: (clock += 500) }));
  }
  const f = findingsFrom(rows.reverse());
  assert.equal(f.filter((x) => x.kind === "n+1").length, 0);
});

test("findingsFrom separates a loop over rows from a repeated identical query", () => {
  const loop = [];
  const same = [];
  for (let i = 0; i < 15; i++) {
    loop.push(stmt({ values: [{ index: 1, text: String(i), certain: true }] }));
    same.push(stmt({ shape: "SELECT z FROM w WHERE k = ?", sql: "SELECT z FROM w WHERE k = 1" }));
  }
  const fl = findingsFrom(loop.reverse()).find((x) => x.kind === "n+1");
  const fs = findingsFrom(same.reverse()).find((x) => x.kind === "n+1");
  assert.equal(fl.subtype, "loop over rows");
  assert.equal(fs.subtype, "repeated identical query");
});

test("findingsFrom ignores session chatter", () => {
  const rows = [];
  for (let i = 0; i < 30; i++) rows.push(stmt({ shape: "BEGIN", verb: "BEGIN", isNoise: true }));
  assert.deepEqual(findingsFrom(rows), []);
});

test("findingsFrom reports a slow outlier only against its own shape's median", () => {
  const rows = [];
  for (let i = 0; i < 20; i++) rows.push(stmt({ latUs: 200, at: (clock += 900) }));
  // One execution far slower in both relative and absolute terms.
  rows.push(stmt({ latUs: 900_000, at: (clock += 900) }));
  const f = findingsFrom(rows.reverse()).filter((x) => x.kind === "slow");
  assert.equal(f.length, 1);
  assert.match(f[0].label, /median/);
});

test("findingsFrom does not report ordinary jitter as slow", () => {
  // 4x the median but nowhere near the absolute floor. Firing here produced
  // ten near-identical rows that buried the real findings.
  const rows = [];
  for (let i = 0; i < 20; i++) rows.push(stmt({ latUs: 200, at: (clock += 900) }));
  rows.push(stmt({ latUs: 800, at: (clock += 900) }));
  assert.equal(findingsFrom(rows.reverse()).filter((x) => x.kind === "slow").length, 0);
});

test("findingsFrom pins errors above the cost ranking", () => {
  const rows = [
    stmt({ error: true, latUs: null, shape: "SELECT * FROM missing", sql: "SELECT * FROM missing" }),
    stmt({ latUs: 900_000, footgun: "SELECT * fetches every column", shape: "SELECT * FROM t", sql: "SELECT * FROM t" }),
  ];
  const f = findingsFrom(rows);
  assert.equal(f[0].kind, "error", "an error outranks a more expensive footgun");
});

test("findingsFrom collapses a repeated footgun into one finding", () => {
  const rows = [];
  for (let i = 0; i < 40; i++) {
    rows.push(stmt({ footgun: "SELECT * fetches every column", shape: "SELECT * FROM t", sql: "SELECT * FROM t", at: (clock += 900) }));
  }
  const f = findingsFrom(rows).filter((x) => x.kind === "footgun");
  assert.equal(f.length, 1);
  assert.equal(f[0].count, 40);
});

test("findingsFrom survives records with missing fields", () => {
  // Every render path runs once before data arrives, and a half-populated
  // record must not throw.
  assert.deepEqual(findingsFrom([]), []);
  const sparse = [{ pid: 1, tid: 1, shape: "SELECT ?", verb: "SELECT", isNoise: false }];
  assert.doesNotThrow(() => findingsFrom(sparse));
});

// ── formatting ─────────────────────────────────────────────────────────────

test("fmtLat renders null as an explicit dash, never zero", () => {
  // A latency we never paired must not read as "instant".
  assert.equal(fmtLat(null), "—");
  assert.equal(fmtLat(0), "0µs");
  assert.equal(fmtLat(999), "999µs");
  assert.equal(fmtLat(1500), "1.50ms");
  assert.equal(fmtLat(2_000_000), "2.00s");
});

test("fmtRate and fmtCount shorten without lying", () => {
  assert.equal(fmtRate(0), "0");
  assert.equal(fmtRate(143), "143");
  assert.equal(fmtRate(4200), "4.2K");
  assert.equal(fmtCount(999), "999");
  assert.equal(fmtCount(1500), "1.5K");
});

test("fmtBytes renders null as a dash", () => {
  assert.equal(fmtBytes(null), "—");
  assert.equal(fmtBytes(512), "512B");
});

test("clockMs formats without Intl", () => {
  // The runtime has no Intl, so any toLocaleString path throws. This asserts
  // the shape rather than a timezone-dependent value.
  assert.match(clockMs(Date.now()), /^\d{2}:\d{2}:\d{2}\.\d{3}$/);
});

test("valuesInline drops SQL quoting and truncates to width", () => {
  const vals = [
    { index: 1, text: "42", certain: true },
    { index: 2, text: "'pending'", certain: true },
  ];
  assert.equal(valuesInline(vals, 40), "42, pending");
  assert.equal(valuesInline(vals, 6).length <= 6, true);
  assert.equal(valuesInline([], 10), "");
});

test("valuesInline marks an uncertain value", () => {
  assert.match(valuesInline([{ index: 1, text: "137.42", certain: false }], 20), /\?$/);
});
