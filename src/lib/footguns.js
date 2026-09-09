// Footguns: things visible in the statement itself that reliably cause pain.
//
// Held to the same bar as redissnoop's and mongosnoop's: a false alarm
// erodes trust faster than a missed one. Every check below is a property of
// the statement AS CAPTURED, not a guess about the server's execution plan.
//
// Deliberately NOT included: "this query has no index", "this will be slow",
// "this needs a covering index". We read the wire, not the planner — none of
// that is visible from here, and claiming it would be the kind of overreach
// that makes an engineer stop believing the flags that ARE sound. If you
// want the plan, the statement is right there to copy into EXPLAIN.
//
// Takes the NORMALIZED shape for structural checks, so a check cannot be
// fooled by a value that happens to contain a keyword, PLUS the raw SQL for
// the one check that needs to see a literal (a leading-wildcard LIKE, whose
// whole signal is the `%` that normalization removes). `raw` is optional: a
// caller without it simply loses that one check rather than throwing.

// Ordered by severity — the first hit wins, so the worst thing about a
// statement is what gets surfaced.
export function footgunOf(shape, verb, raw) {
  if (!shape) return null;
  const s = shape;

  // A write with no predicate hits every row in the table. This is the one
  // that ruins someone's afternoon, so it leads.
  if (verb === "DELETE" && !/\bWHERE\b/i.test(s)) {
    return "DELETE with no WHERE — matches every row";
  }
  if (verb === "UPDATE" && !/\bWHERE\b/i.test(s)) {
    return "UPDATE with no WHERE — matches every row";
  }

  // A leading-wildcard LIKE cannot use a B-tree index, by definition rather
  // than by plan choice. A trailing wildcard ('foo%') can, which is why only
  // the leading form is worth flagging.
  //
  // This is checked against the RAW SQL, not the shape, and that is the whole
  // reason it works. `normalize()` turns every literal into `?`, so by the
  // time a statement reaches the shape the pattern is gone and
  // `LIKE '%foo'` is indistinguishable from `LIKE 'foo%'`. The previous
  // version tested the shape and could therefore never fire — and its
  // condition was `A || (B && A)`, which is just `A`, so the second half was
  // dead code hiding the fact that the first half never matched.
  if (raw && /\bLIKE\s+(?:E?'%|"%)/i.test(raw)) {
    return "leading-wildcard LIKE can't use an index";
  }

  // A cartesian product: multiple tables in FROM with no join predicate.
  // Counted on commas at the top level of the FROM clause, which is the old
  // implicit-join style where this mistake actually happens.
  const fromCommas = (s.match(/\bFROM\s+[\w.`"]+(\s*,\s*[\w.`"]+)+/i) ?? [])[0];
  if (fromCommas && !/\bWHERE\b/i.test(s)) {
    return "comma join with no WHERE — cartesian product";
  }

  // ORDER BY with no LIMIT sorts the entire result set to throw most of it
  // away. Common in code that paginates in the application instead.
  if (/\bORDER\s+BY\b/i.test(s) && !/\bLIMIT\b/i.test(s) && !/\bFETCH\s+FIRST\b/i.test(s) && !/\bTOP\s+\?/i.test(s)) {
    return "ORDER BY with no LIMIT — sorts the whole result";
  }

  // SELECT * pulls every column, including the large ones nobody asked for,
  // and defeats covering indexes. Only flagged on a real table read, not on
  // a COUNT(*) or an EXISTS subquery.
  if (/^SELECT\s+\*/i.test(s) && /\bFROM\b/i.test(s)) {
    return "SELECT * fetches every column";
  }

  // An unbounded read of a table with no predicate at all.
  if (verb === "SELECT" && !/\bWHERE\b/i.test(s) && !/\bLIMIT\b/i.test(s) && /\bFROM\b/i.test(s) && !/\bCOUNT\s*\(/i.test(s)) {
    return "no WHERE and no LIMIT — reads the whole table";
  }

  // A subquery in the SELECT list runs once per output row.
  if (/\bSELECT\b[\s\S]*?\(\s*SELECT\b/i.test(s) && /\bFROM\b/i.test(s)) {
    const head = s.slice(0, s.search(/\bFROM\b/i));
    if (/\(\s*SELECT\b/i.test(head)) return "correlated subquery in the SELECT list runs per row";
  }

  // OR across different columns often defeats a single-column index. Stated
  // as "often", and only flagged when it's an OR between two distinct
  // column comparisons rather than a repeated one.
  const ors = s.match(/\b([\w.]+)\s*=\s*\?\s+OR\s+([\w.]+)\s*=\s*\?/i);
  if (ors && ors[1].toLowerCase() !== ors[2].toLowerCase()) {
    return "OR across columns often can't use one index";
  }

  // A function wrapped around a column in the predicate makes it
  // unsargable — the index on the bare column can't be used.
  if (/\bWHERE\b[\s\S]*\b(LOWER|UPPER|DATE|CAST|COALESCE|SUBSTRING|TRIM)\s*\(\s*[\w.]+\s*\)\s*(=|<|>|LIKE|IN)/i.test(s)) {
    return "function on a column in WHERE defeats its index";
  }

  // A NOT IN with a subquery has surprising NULL semantics and is usually
  // slower than the NOT EXISTS form.
  if (/\bNOT\s+IN\s*\(\s*SELECT\b/i.test(s)) {
    return "NOT IN (SELECT …) — NULL-sensitive and usually slower than NOT EXISTS";
  }

  return null;
}

// Is this statement one of a repeated run — the N+1 signal? Not a property
// of a single statement, so it lives in the aggregate view rather than here;
// this is the threshold that view uses, kept next to the other judgment
// calls so there's one place to argue with them.
export const NPLUSONE_MIN = 10; // identical shapes in a burst before we say it
export const NPLUSONE_WINDOW_MS = 2000; // how close together they have to be
