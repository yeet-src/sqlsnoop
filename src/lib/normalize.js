// Statement normalization — turning a concrete statement into a SHAPE.
//
// This is the analysis that makes the tool worth running. A slow-query log
// tells you a statement was slow; it cannot easily tell you the same
// statement ran two hundred times in one request. Stripping the literals out
// collapses those two hundred rows into one shape with a count, and an N+1
// stops being something you have to notice and becomes one thing happening
// two hundred times.
//
//   SELECT * FROM orders WHERE customer_id = 4471 AND status = 'pending'
//   → SELECT * FROM orders WHERE customer_id = ? AND status = ?
//
// Pure string work, no signals, no BPF. Deliberately a LEXER, not a SQL
// parser: we need to know where the literals are, not what the query means,
// and a real parser would be a per-dialect grammar plus a maintenance
// burden for no gain here.

// Collapse a statement to its shape. Order matters: strings and comments go
// first, because a number inside a string literal ('id 42') must not be
// treated as a number, and a keyword inside a comment must not be counted.
export function normalize(sql) {
  if (!sql) return "";
  let s = sql;

  // Comments first — they can contain anything, including quotes that would
  // otherwise unbalance the string scanner below.
  s = s.replace(/\/\*[\s\S]*?\*\//g, " "); // /* block */
  s = s.replace(/--[^\n]*/g, " "); // -- line
  s = s.replace(/#[^\n]*/g, " "); // MySQL's # line comment

  // TYPED string literals BEFORE plain ones. Postgres escape strings (E'…'),
  // bit strings (B'0101') and hex strings (X'ff') carry a prefix letter, and
  // the general rule below consumes only the quoted part — leaving the prefix
  // behind as a bare identifier, so `E'a'` normalized to `E?` rather than `?`.
  // Ordering is the entire fix, and it is why these three sit here rather
  // than after.
  s = s.replace(/\bE'(?:[^']|'')*'/gi, "?"); // Postgres escape strings
  s = s.replace(/\bB'[01]*'/gi, "?"); // bit strings
  s = s.replace(/\bX'[0-9a-f]*'/gi, "?"); // hex strings

  // Then plain string literals. SQL escapes a quote by doubling it ('it''s'),
  // so the body of a literal is "not-a-quote, or two quotes in a row".
  s = s.replace(/'(?:[^']|'')*'/g, "?");
  // Postgres double quotes are IDENTIFIERS ("my table"), so they survive.
  s = s.replace(/\b0x[0-9a-f]+\b/gi, "?"); // MySQL hex literals

  // Placeholders the client already used, unified so a prepared statement and
  // a literal one collapse to the SAME shape. That is the point: an ORM that
  // parameterizes and a hand-written query that doesn't are the same shape,
  // and should aggregate together.
  s = s.replace(/\$\d+/g, "?"); // Postgres $1, $2
  s = s.replace(/:\w+/g, "?"); // named binds
  s = s.replace(/\?/g, "?"); // already a placeholder

  // Numeric literals, but NOT digits that are part of an identifier
  // (`col2`, `t1.id`). The leading boundary check is what prevents that.
  s = s.replace(/(^|[^\w.$])[-+]?\d+(\.\d+)?([eE][-+]?\d+)?\b/g, "$1?");

  // An IN list of any length is one shape. Without this, `IN (?, ?, ?)` and
  // `IN (?, ?)` are different shapes and the aggregate view fragments into
  // near-duplicates that are really the same query.
  s = s.replace(/\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)/gi, "IN (?)");

  // A multi-row VALUES clause, same reasoning — a bulk insert of 500 rows is
  // one statement shape, not a 500-tuple fingerprint.
  s = s.replace(/\bVALUES\s*\(\s*\?(?:\s*,\s*\?)*\s*\)(\s*,\s*\(\s*\?(?:\s*,\s*\?)*\s*\))+/gi, "VALUES (?)");

  // Whitespace last, so every substitution above has already run.
  s = s.replace(/\s+/g, " ").trim();
  return s;
}

// The leading verb, uppercased. Used for read/write classification and for
// coloring the feed. Handles a leading paren (`(SELECT …) UNION …`) and a
// leading CTE (`WITH x AS (…) SELECT …`), both of which would otherwise
// report the wrong verb.
export function verbOf(sql) {
  if (!sql) return "";
  const s = sql.replace(/^[\s(]+/, "");
  const first = (s.match(/^[a-z_]+/i) ?? [""])[0].toUpperCase();
  if (first !== "WITH") return first;

  // A CTE's real verb is the one AFTER the last CTE definition, and getting
  // this wrong is a correctness bug rather than a cosmetic one: a
  // `WITH … DELETE` read as a SELECT is classified as a read, so it is never
  // footgun-checked and never counted as a write.
  //
  // The previous version scanned for the first verb NOT followed by another
  // `AS (`, which picked the SELECT inside the CTE body whenever the outer
  // statement had no further `AS (` after it. Balancing the parens is the
  // only way to be right: walk from the first `(`, and the verb is the first
  // keyword at depth zero after the definitions close.
  let depth = 0;
  let i = s.indexOf("(");
  if (i < 0) return "WITH";
  for (; i < s.length; i++) {
    const c = s[i];
    if (c === "'") {
      // Skip a string literal so a paren inside it does not move the depth.
      i++;
      while (i < s.length && !(s[i] === "'" && s[i + 1] !== "'")) i += s[i] === "'" ? 2 : 1;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) {
        // A comma here means another CTE definition follows; anything else
        // means the outer statement starts.
        const rest = s.slice(i + 1);
        const m = rest.match(/^\s*,/);
        if (m) continue;
        const verb = rest.match(/^\s*([a-z_]+)/i);
        return verb ? verb[1].toUpperCase() : "WITH";
      }
    }
  }
  return "WITH";
}


// Statements that change data. Everything else is treated as a read.
const WRITE_VERBS = new Set([
  "INSERT",
  "UPDATE",
  "DELETE",
  "REPLACE",
  "MERGE",
  "UPSERT",
  "TRUNCATE",
  "CREATE",
  "ALTER",
  "DROP",
  "GRANT",
  "REVOKE",
]);

export const isWrite = (verb) => WRITE_VERBS.has(verb);

// Connection and session upkeep that clients do on their own. These say
// nothing about what the application is doing and, on a pooled connection,
// can easily outnumber the real traffic — a health check every second per
// connection buries an app that queries every few seconds. Hidden by
// default, toggleable, never dropped.
const NOISE_RX = [
  /^SET\b/i,
  /^SHOW\b/i,
  /^BEGIN\b/i,
  /^COMMIT\b/i,
  /^ROLLBACK\b/i,
  /^SAVEPOINT\b/i,
  /^RELEASE\b/i,
  /^DISCARD\b/i,
  /^DEALLOCATE\b/i,
  /^SELECT\s+\?$/i, // SELECT 1 — the canonical health check
  /^SELECT\s+VERSION\(\)/i,
  /^SELECT\s+CURRENT_SCHEMA/i,
  /^SELECT\s+pg_backend_pid/i,
  /^START\s+TRANSACTION/i,
  /\bpg_catalog\b/i, // driver metadata introspection
  /\binformation_schema\b/i,
  /^SELECT\s+@@/i, // MySQL session variables
];

export const isNoise = (shape) => NOISE_RX.some((rx) => rx.test(shape));

// A shape is worth showing if it has a plausible verb. Anything the lexer
// couldn't name is dropped rather than shown as an empty row.
export const isRealStatement = (verb) => /^[A-Z][A-Z_]*$/.test(verb ?? "");

// The table(s) a statement touches, for the feed's compact form. A lexical
// guess, and labelled as one — it reads the token after FROM / JOIN / INTO /
// UPDATE, which is right for the overwhelming majority of statements and
// gives up rather than guessing on the rest.
export function tablesOf(sql) {
  if (!sql) return [];
  const out = [];
  const rx = /\b(?:FROM|JOIN|INTO|UPDATE)\s+([`"\[]?[\w.$]+[`"\]]?)/gi;
  let m;
  while ((m = rx.exec(sql)) !== null) {
    const t = m[1].replace(/[`"\[\]]/g, "");
    // Skip a subquery (FROM (SELECT …)) and the SET keyword after UPDATE.
    if (!t || /^(select|set)$/i.test(t)) continue;
    if (!out.includes(t)) out.push(t);
    if (out.length >= 4) break;
  }
  return out;
}

// A short label for the feed: the verb plus the tables it touches. Falls back
// to the shape itself when no table could be read, so a row is never blank.
export function summarize(shape, verb) {
  const tables = tablesOf(shape);
  if (!tables.length) return shape;
  return `${verb} ${tables.join(", ")}`;
}
