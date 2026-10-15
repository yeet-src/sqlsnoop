// Parameter decoding — putting the VALUES back next to the statement.
//
// Neither protocol sends a finished SQL string when a client uses prepared
// statements (which every ORM and most hand-written clients do). It sends a
// template with holes and, in a SEPARATE wire message, the values for those
// holes:
//
//   Parse:  SELECT * FROM orders WHERE customer_id = $1 AND status = $2
//   Bind:   $1 = 4471   $2 = "pending"
//
// The kernel copies both windows and hands them here. This module walks the
// parameter block and produces display strings, so the feed can show what
// actually got substituted rather than a row of `$1`s. Without it you can
// see that a statement ran 200 times; with it you can see it ran with 200
// different ids, which is the difference between "something is repeating"
// and "this is a loop over rows".
//
// Both decoders are DELIBERATELY partial and say so. A parameter block is
// variable-length and the kernel's window is fixed, so a long block is cut
// off; and MySQL's binary protocol only makes sense with the type metadata
// from the earlier prepare, which may have happened before we attached.
// Every value that can't be decoded with certainty is reported as unknown
// rather than guessed at — an invented value in a debugging tool is worse
// than a missing one.

// Printable-ASCII test for deciding whether a byte run is text.
const isPrint = (b) => b >= 0x20 && b < 0x7f;

// Turn a byte range into a string, refusing if it isn't plausibly text.
const asText = (b, from, to) => {
  let s = "";
  for (let i = from; i < to && i < b.length; i++) {
    if (!isPrint(b[i])) return null;
    s += String.fromCharCode(b[i]);
  }
  return s;
};

const be16 = (b, i) => (b[i] << 8) | b[i + 1];
const be32 = (b, i) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
const be32s = (b, i) => (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]; // signed
const le16 = (b, i) => b[i] | (b[i + 1] << 8);
const le32 = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;

// Quote a decoded value the way it would appear in SQL, so a value can be
// copied straight into a psql/mysql prompt.
const quote = (v) => (typeof v === "string" ? `'${v.replace(/'/g, "''")}'` : String(v));

// ── Postgres: the Bind message ──────────────────────────────────────────────
//
// Layout after the tag and length, which the kernel already skipped:
//
//   cstring  portal name           (usually empty)
//   cstring  prepared stmt name    (usually empty)
//   int16    number of format codes
//   int16[]  format codes          0 = text, 1 = binary
//   int16    number of parameters
//   for each: int32 length (-1 = NULL), then that many bytes
//
// The format code decides everything: a text parameter is ASCII and can be
// shown as-is, while a binary one needs its column type to interpret — and
// the type is NOT in this message, it was in the Parse. So binary parameters
// are decoded only where the byte length makes the intent unambiguous (4
// bytes = int32, 8 = int64/float8) and reported as raw bytes otherwise.
export function decodePgBind(buf, len) {
  const b = buf;
  const end = Math.min(len, b.length);
  let i = 0;

  // The two leading cstrings are the portal name and — the useful one — the
  // PREPARED STATEMENT NAME. That name is the protocol's own identifier for
  // which statement is being executed, so it is what attributes an execution
  // to its SQL text. Guessing by parameter count instead mis-attributes every
  // execution whenever two prepared statements take the same number of
  // parameters, which is common (two `WHERE x = ? AND y = ?` queries) and
  // silently wrong.
  let portal = "";
  while (i < end && b[i] !== 0) {
    portal += String.fromCharCode(b[i]);
    i++;
  }
  i++; // portal terminator
  let stmtName = "";
  while (i < end && b[i] !== 0) {
    stmtName += String.fromCharCode(b[i]);
    i++;
  }
  i++; // statement-name terminator
  if (i > end) return { values: [], truncated: true, stmtName: "" };

  if (i + 2 > end) return { values: [], truncated: true, stmtName };
  const nFormats = be16(b, i);
  i += 2;
  // A sane Bind has few format codes; a wild count means we've lost the
  // frame and should stop rather than walk garbage.
  if (nFormats > 64) return { values: [], truncated: true, stmtName };

  const formats = [];
  for (let k = 0; k < nFormats; k++) {
    if (i + 2 > end) return { values: [], truncated: true, stmtName };
    formats.push(be16(b, i));
    i += 2;
  }

  if (i + 2 > end) return { values: [], truncated: true, stmtName };
  const nParams = be16(b, i);
  i += 2;
  if (nParams > 128) return { values: [], truncated: true, stmtName };

  const values = [];
  let truncated = false;

  for (let k = 0; k < nParams; k++) {
    if (i + 4 > end) {
      truncated = true;
      break;
    }
    const plen = be32s(b, i);
    i += 4;

    if (plen === -1) {
      values.push({ index: k + 1, text: "NULL", certain: true });
      continue;
    }
    if (plen < 0 || plen > 1 << 20) {
      truncated = true;
      break;
    }
    // The value runs past what the kernel copied — say so rather than
    // showing a half-decoded value.
    if (i + plen > end) {
      values.push({ index: k + 1, text: "…", certain: false, note: "beyond capture window" });
      truncated = true;
      break;
    }

    // Format 0 means the client sent this parameter as text, which is the
    // common case for most drivers and is directly readable.
    const fmt = nFormats === 0 ? 0 : formats[Math.min(k, nFormats - 1)];

    if (fmt === 0) {
      const t = asText(b, i, i + plen);
      if (t === null) {
        values.push({ index: k + 1, text: hex(b, i, Math.min(plen, 8)), certain: false, note: "not text" });
      } else {
        // A text parameter is a string on the wire even when it's a number,
        // so quote only what isn't numeric — a value should read the way it
        // would be typed.
        values.push({ index: k + 1, text: /^-?\d+(\.\d+)?$/.test(t) ? t : quote(t), certain: true });
      }
    } else {
      values.push({ index: k + 1, ...decodePgBinary(b, i, plen) });
    }
    i += plen;
  }

  return { values, truncated, stmtName };
}

// A binary Postgres parameter, decoded only where the length pins the type.
// Postgres binary format is big-endian and fixed-width per type, so the
// length is a genuine signal — but it does NOT distinguish an int8 from a
// float8, both being 8 bytes. Where it's ambiguous the integer reading is
// shown and marked uncertain, because an integer key is what a debugging
// session is usually chasing.
function decodePgBinary(b, off, len) {
  if (len === 0) return { text: "''", certain: true };
  if (len === 1) return { text: b[off] === 0 ? "false" : b[off] === 1 ? "true" : String(b[off]), certain: b[off] < 2 };
  if (len === 2) return { text: String((be16(b, off) << 16) >> 16), certain: true };
  if (len === 4) return { text: String(be32s(b, off)), certain: true };
  if (len === 8) {
    // Eight bytes is ambiguous: int8, float8, timestamp and money all fit,
    // and the Bind message does not carry the type (that was in the Parse).
    //
    // Reading it as an int64 unconditionally was actively misleading. A
    // `numeric` column compared against 137.42 rendered as
    // `4640265580000000000` — the IEEE-754 bit pattern printed as an integer,
    // which looks like a plausible id and is completely wrong. A confident
    // wrong value is the worst thing this module can produce, so both
    // readings are computed and the plausible one wins.
    let iv = 0n;
    for (let k = 0; k < 8; k++) iv = (iv << 8n) | BigInt(b[off + k]);
    if (iv >= 1n << 63n) iv -= 1n << 64n;

    const dv = new DataView(new Uint8Array(b.subarray(off, off + 8)).buffer);
    const fv = dv.getFloat64(0, false); // Postgres binary is big-endian

    // A float reading is preferred when it is finite and lands in a range a
    // person would recognise, while the integer reading is absurdly large.
    // Real int8 keys are nowhere near 2^53, and real float8 values are not
    // astronomically large, so the two rarely both look sane.
    const intLooksAbsurd = iv > 4_000_000_000_000_000n || iv < -4_000_000_000_000_000n;
    const floatLooksSane = Number.isFinite(fv) && Math.abs(fv) < 1e15;

    if (intLooksAbsurd && floatLooksSane) {
      // Trim float noise (0.1 + 0.2 style tails) without inventing precision.
      const text = String(Number(fv.toFixed(6)));
      return { text, certain: false, note: "8 bytes, read as float8" };
    }
    return { text: String(iv), certain: false, note: "8 bytes, read as int8" };
  }
  // Anything else is very likely text sent in binary format.
  const t = asText(b, off, off + len);
  if (t !== null) return { text: quote(t), certain: true };
  return { text: hex(b, off, Math.min(len, 8)), certain: false, note: "binary" };
}

// ── MySQL: COM_STMT_EXECUTE ────────────────────────────────────────────────
//
// Layout after the command byte, which the kernel already skipped:
//
//   int32    statement id
//   int8     flags
//   int32    iteration count (always 1)
//   if num_params > 0:
//     bitmap  NULL bitmap, (num_params + 7) / 8 bytes
//     int8    new-params-bound flag
//     if 1:   int16[] type per parameter, then the values
//
// THE CATCH: `num_params` is not in this message. It was in the server's
// reply to COM_STMT_PREPARE, so a decoder needs state from an earlier
// exchange. When the prepare happened while we were attached, probes/sql.js
// hands us the parameter count it learned from the statement text; when it
// happened before we attached, we don't know it and say so.
//
// The type bytes are only present when the new-params-bound flag is set,
// which a client sets on the first execute and then omits for subsequent
// ones. So a re-executed statement carries values with NO types at all. That
// is a real hole in what the wire tells us and it is reported, not papered
// over.
export function decodeMysqlExecute(buf, len, nParams) {
  const b = buf;
  const end = Math.min(len, b.length);

  if (end < 9) return { values: [], truncated: true, stmtId: 0 };
  const stmtId = le32(b, 0);
  let i = 4 + 1 + 4; // statement id, flags, iteration count

  if (!nParams || nParams < 0) {
    return { values: [], truncated: false, stmtId, note: "parameter count unknown — prepare not observed" };
  }
  if (nParams > 128) return { values: [], truncated: true, stmtId };

  const bitmapLen = (nParams + 7) >> 3;
  if (i + bitmapLen + 1 > end) return { values: [], truncated: true, stmtId };
  const nullBitmap = b.subarray(i, i + bitmapLen);
  i += bitmapLen;

  const newBound = b[i];
  i += 1;

  const types = [];
  if (newBound === 1) {
    for (let k = 0; k < nParams; k++) {
      if (i + 2 > end) return { values: [], truncated: true, stmtId };
      types.push(le16(b, i) & 0xff); // low byte is the type; high bit is unsigned
      i += 2;
    }
  }

  const values = [];
  let truncated = false;

  for (let k = 0; k < nParams; k++) {
    const isNull = (nullBitmap[k >> 3] >> (k & 7)) & 1;
    if (isNull) {
      values.push({ index: k + 1, text: "NULL", certain: true });
      continue;
    }
    if (!types.length) {
      values.push({ index: k + 1, text: "?", certain: false, note: "types not re-sent on this execute" });
      continue;
    }
    if (i >= end) {
      truncated = true;
      break;
    }
    const r = decodeMysqlValue(b, i, end, types[k]);
    if (!r) {
      truncated = true;
      break;
    }
    values.push({ index: k + 1, text: r.text, certain: r.certain, note: r.note });
    i += r.size;
  }

  return { values, truncated, stmtId };
}

// MySQL binary protocol value types, the subset that actually shows up in
// application traffic. Little-endian, fixed-width for numerics; strings are
// length-encoded.
const MY = {
  TINY: 0x01,
  SHORT: 0x02,
  LONG: 0x03,
  FLOAT: 0x04,
  DOUBLE: 0x05,
  NULL: 0x06,
  TIMESTAMP: 0x07,
  LONGLONG: 0x08,
  INT24: 0x09,
  DATE: 0x0a,
  TIME: 0x0b,
  DATETIME: 0x0c,
  NEWDECIMAL: 0xf6,
  BLOB: 0xfc,
  VAR_STRING: 0xfd,
  STRING: 0xfe,
};

function decodeMysqlValue(b, off, end, type) {
  switch (type) {
    case MY.TINY:
      if (off + 1 > end) return null;
      return { text: String((b[off] << 24) >> 24), size: 1, certain: true };
    case MY.SHORT:
    case MY.INT24:
      if (off + 2 > end) return null;
      return { text: String((le16(b, off) << 16) >> 16), size: 2, certain: true };
    case MY.LONG:
      if (off + 4 > end) return null;
      return { text: String(le32(b, off) | 0), size: 4, certain: true };
    case MY.LONGLONG: {
      if (off + 8 > end) return null;
      let v = 0n;
      for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(b[off + k]);
      if (v >= 1n << 63n) v -= 1n << 64n;
      return { text: String(v), size: 8, certain: true };
    }
    case MY.FLOAT:
    case MY.DOUBLE: {
      const w = type === MY.FLOAT ? 4 : 8;
      if (off + w > end) return null;
      // No DataView guarantee in bare V8 for a subarray view, so build one.
      const dv = new DataView(new Uint8Array(b.subarray(off, off + w)).buffer);
      const n = w === 4 ? dv.getFloat32(0, true) : dv.getFloat64(0, true);
      return { text: String(Number(n.toFixed(6))), size: w, certain: true };
    }
    case MY.DATE:
    case MY.DATETIME:
    case MY.TIMESTAMP: {
      if (off + 1 > end) return null;
      const n = b[off];
      if (off + 1 + n > end) return null;
      if (n === 0) return { text: "'0000-00-00'", size: 1, certain: true };
      const y = le16(b, off + 1);
      const mo = b[off + 3];
      const d = b[off + 4];
      let s = `${y}-${String(mo).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      if (n >= 7) {
        s += ` ${String(b[off + 5]).padStart(2, "0")}:${String(b[off + 6]).padStart(2, "0")}:${String(b[off + 7]).padStart(2, "0")}`;
      }
      return { text: `'${s}'`, size: 1 + n, certain: true };
    }
    case MY.TIME: {
      if (off + 1 > end) return null;
      const n = b[off];
      if (off + 1 + n > end) return null;
      if (n === 0) return { text: "'00:00:00'", size: 1, certain: true };
      const neg = b[off + 1] ? "-" : "";
      const days = le32(b, off + 2);
      const h = b[off + 6] + days * 24;
      const s = `${neg}${String(h).padStart(2, "0")}:${String(b[off + 7]).padStart(2, "0")}:${String(b[off + 8]).padStart(2, "0")}`;
      return { text: `'${s}'`, size: 1 + n, certain: true };
    }
    default: {
      // Everything else (strings, blobs, decimals) is length-encoded: a
      // length prefix that is itself variable-width.
      const li = lenenc(b, off, end);
      if (!li) return null;
      const from = off + li.size;
      const to = from + li.value;
      if (to > end) return { text: "…", size: end - off, certain: false, note: "beyond capture window" };
      const t = asText(b, from, to);
      if (t === null) return { text: hex(b, from, Math.min(li.value, 8)), size: li.size + li.value, certain: false, note: "binary" };
      return { text: quote(t), size: li.size + li.value, certain: true };
    }
  }
}

// MySQL's length-encoded integer: one byte under 0xfb, otherwise a marker
// byte naming the width of what follows.
function lenenc(b, off, end) {
  if (off >= end) return null;
  const f = b[off];
  if (f < 0xfb) return { value: f, size: 1 };
  if (f === 0xfc) {
    if (off + 3 > end) return null;
    return { value: le16(b, off + 1), size: 3 };
  }
  if (f === 0xfd) {
    if (off + 4 > end) return null;
    return { value: b[off + 1] | (b[off + 2] << 8) | (b[off + 3] << 16), size: 4 };
  }
  if (f === 0xfe) {
    if (off + 9 > end) return null;
    return { value: le32(b, off + 1), size: 9 }; // high 4 bytes ignored; >4GB isn't a parameter
  }
  return null;
}

const HEXD = "0123456789abcdef";
function hex(b, off, n) {
  let s = "0x";
  for (let i = off; i < off + n && i < b.length; i++) s += HEXD[b[i] >> 4] + HEXD[b[i] & 15];
  return s;
}

// How many placeholders a statement has, counted from its text. This is what
// lets the MySQL execute decoder work at all: the count belongs to the
// prepare's reply, which we may not have seen, but the statement text tells
// us the same thing and we DO have that.
//
// Counted on the normalized shape, where every literal has already become a
// `?`, so it must be given the shape and not the raw SQL.
export const paramCountOf = (shape) => (shape.match(/\?/g) ?? []).length;

// Merge decoded values into a display string: `id=4471  status='pending'`.
// Uses the statement's placeholder positions when names can be recovered,
// falling back to positional `$n` labels.
export function renderValues(values) {
  return values.map((v) => `$${v.index}=${v.text}${v.certain === false ? "?" : ""}`).join("  ");
}
