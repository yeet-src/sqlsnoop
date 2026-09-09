// sqlsnoop — a live trace of SQL statements, read off the wire.
//
// Two wire protocols, one capture layer. Postgres and MySQL frame their
// messages differently, but both are length-prefixed and tag-then-payload,
// and in both the statement text sits at a shallow, near-fixed offset from
// the start of a write. That is the shared seam, and it is the whole reason
// one probe can cover both without a per-dialect program.
//
// POSTGRES (message-per-write, a tag byte then a big-endian length):
//
//   'Q' | int32 len | cstring sql                     simple query
//   'P' | int32 len | cstring name | cstring sql | …   Parse (prepare)
//   'B' | int32 len | cstring portal | cstring stmt | …  Bind (the VALUES)
//   'E' | int32 len | cstring portal | int32 max      Execute
//
//   `len` counts itself but not the tag, so a valid frame satisfies
//   len + 1 <= write_size. Replies come back tagged too: 'T' row
//   description, 'D' data row, 'C' command complete ("SELECT 42"), 'E'
//   error. Postgres pipelines several messages into ONE write, which is
//   why the parser below walks frames in a loop rather than assuming the
//   write is one message.
//
// MYSQL (one command per write, little-endian length, then a sequence byte):
//
//   int24 len | int8 seq | int8 cmd | payload…
//
//   cmd 0x03 = COM_QUERY, payload is raw SQL to the end of the packet.
//   cmd 0x16 = COM_STMT_PREPARE, same shape.
//   cmd 0x17 = COM_STMT_EXECUTE, payload is a statement id then the
//              binary-encoded parameter VALUES.
//
//   A valid frame satisfies len + 4 == write_size for a single-packet
//   command, which is a strong discriminator: it pins three length bytes
//   against the actual write size and rejects almost all non-MySQL traffic.
//
// THE KERNEL STAYS DUMB. It decides "is this a SQL frame, and where does
// the text start", then copies a raw window for userspace to parse. It does
// NOT tokenize SQL, normalize a statement, or decode a MySQL binary
// parameter — those are unbounded walks over variable-length data, exactly
// what the verifier rejects and exactly what JS does well. Everything past
// "here are the bytes" happens in lib/postgres.js and lib/mysql.js.
//
// PAIRING. Unlike MongoDB's wire protocol, SQL carries no request id, so
// there is nothing to correlate on but the socket. We key inflight state on
// (pid, sock*) and pair the next reply on that socket with the last
// statement sent on it. That is correct for the request/response cycle every
// SQL client actually uses, and it is wrong when a client pipelines several
// statements without waiting for replies — the same caveat redissnoop
// carries. The latency is labelled as socket-paired in the UI rather than
// presented as exact.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define SQL_LEN       256 // statement-text window handed to userspace
#define PARAM_LEN     192 // parameter-bytes window (PG Bind / MySQL EXECUTE)

// Which wire protocol produced an event.
#define DIALECT_PG    1
#define DIALECT_MYSQL 2

// How the bytes were observed. The plaintext socket path and the TLS path
// feed the same ring buffer and the same parser; only the tag differs, so
// the UI can show the split and an engineer can see that encrypted traffic
// is genuinely being read rather than assumed.
#define SRC_WIRE 0 // tcp_sendmsg/tcp_recvmsg — plaintext on the wire
#define SRC_TLS  1 // SSL_write/SSL_read — read INSIDE encrypted connections

// What kind of message this event carries. A statement and its parameters
// arrive in separate wire messages, so they arrive as separate events and
// userspace stitches them together.
#define KIND_QUERY   1 // statement text (PG 'Q'/'P', MySQL COM_QUERY/PREPARE)
#define KIND_PARAMS  2 // parameter values (PG 'B', MySQL COM_STMT_EXECUTE)
#define KIND_REPLY   3 // a reply landed — carries the latency and row count

// Slow-statement floor in microseconds, patched live from the UI. Default 0:
// emit everything until the user raises the bar. Kept in .data (volatile,
// referenced) so the bound section stays `<obj>.data`. Must match
// `minLatency`'s initial value in probes/sql.js.
volatile __u64 min_latency_us = 0;

// One observed SQL event.
struct sql_event {
	__u32 pid;
	__u32 tid;
	__u32 kind;               // KIND_QUERY | KIND_PARAMS | KIND_REPLY
	__u32 dialect;            // DIALECT_PG | DIALECT_MYSQL
	__u32 source;             // SRC_WIRE | SRC_TLS
	__u32 lat_us;             // KIND_REPLY only: statement -> reply
	__u32 bytes;              // size of the originating write/read
	__u32 sql_len;            // valid bytes in `sql`
	__u32 param_len;          // valid bytes in `params`
	__u32 rows;               // KIND_REPLY: rows, when the reply states it
	__u32 truncated;          // 1 if the statement was longer than the window
	__u32 is_prepare;         // 1 if this is a prepare, not a direct execute
	__u64 sock;               // socket identity, for correlation in the UI
	char comm[TASK_COMM_LEN]; // client process
	__u8 tag;                 // the raw protocol tag/command byte
	__u8 sql[SQL_LEN];        // statement text — parsed in JS, never here
	__u8 params[PARAM_LEN];   // raw parameter bytes — decoded in JS
};

// Force BTF emission so the daemon resolves btf_struct: "sql_event".
struct sql_event *_unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} sql_events SEC(".maps");

// Statements sent on one socket and still awaiting their replies.
//
// A RING, not a single slot, and that distinction is the difference between
// timing most statements and timing almost none. SQL clients do not wait for
// a reply before sending the next statement — psycopg3 in autocommit mode
// puts a whole burst on the wire back to back, and a prepare-once client
// sends nine Binds before the first reply lands. With one slot per socket
// each send overwrote the last, so eight of every nine replies found no
// timestamp to pair against and were dropped in the kernel: measured 135
// statements against 21 replies.
//
// Replies come back in the order the statements were sent (both protocols
// are strictly ordered per connection), so a FIFO of send timestamps pairs
// them correctly. `head` is where the next send writes, `tail` is the oldest
// send still unanswered, and the depth is how far ahead the client is
// running.
#define INFLIGHT_RING 16 // power of two — the index is masked, not bounds-checked

struct inflight {
	__u64 ts[INFLIGHT_RING]; // send timestamps, oldest at `tail`
	__u32 dialect[INFLIGHT_RING];
	__u32 head; // next write position
	__u32 tail; // oldest unanswered send
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); // pid_tgid ^ sock, folded — see ikey()
	__type(value, struct inflight);
} inflight SEC(".maps");

// A zeroed ring to initialise a socket's first entry with. `bpf_map_update_elem`
// needs a value to copy and the struct is too large for the BPF stack, so it
// lives in a per-CPU array like the other big ones.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct inflight);
} inflight_init SEC(".maps");

// Where a pending recvmsg will deposit its bytes, keyed by pid_tgid. The
// entry probe sees the buffer pointer but not the data; the return probe
// sees the length but no longer has the msghdr. One slot per thread,
// matching mongosnoop's deliberate choice: a missed pairing costs one
// statement and self-corrects, whereas a depth-counting stack drifts
// permanently once the kernel silently drops a return probe past maxactive.
struct recv_scratch {
	__u64 base; // user address the reply lands at
	__u64 sock; // which socket it belongs to
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64); // pid_tgid
	__type(value, struct recv_scratch);
} recv_scratch SEC(".maps");

// The SSL_read equivalent. Kept separate from the wire path's map so a
// process doing both plaintext and TLS on one thread can't have one path
// clobber the other's pending buffer.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64); // pid_tgid
	__type(value, struct recv_scratch);
} ssl_recv_scratch SEC(".maps");

// The event we're building, kept in a per-CPU array rather than on the
// stack: `struct sql_event` is far over the 512-byte BPF stack limit once
// both windows are in it, so it cannot be a local.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sql_event);
} event_scratch SEC(".maps");

// A raw copy of the head of a write, used to sniff the framing before we
// commit to believing anything about it. Also per-CPU for the stack reason.
#define SNIFF_LEN 512
struct sniff_buf {
	__u8 b[SNIFF_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sniff_buf);
} sniff_scratch SEC(".maps");

// Fold (pid, sock) into one u64 key. The high bits of a kernel pointer are
// effectively constant, so xor-ing the pid into them keeps two processes on
// coincidentally-similar socket addresses from colliding.
static __always_inline __u64 ikey(__u64 sock)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	return sock ^ ((__u64)pid << 48);
}

// Pull the user-buffer base out of a msghdr's iov_iter. Modern kernels store
// a single user buffer inline as ITER_UBUF (ptr in `ubuf`); a classic iovec
// array is ITER_IOVEC (ptr in `__iov->iov_base`). Client writes land as
// either depending on kernel version and how the client issues the write, so
// both are handled. This is the one fragile read here, and it is the same
// read mongosnoop and redissnoop make.
static __always_inline const void *iter_base(struct msghdr *msg)
{
	__u8 itype = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (itype == ITER_UBUF)
		return BPF_CORE_READ(msg, msg_iter.ubuf);
	if (itype == ITER_IOVEC) {
		const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
		if (iov)
			return BPF_CORE_READ(iov, iov_base);
	}
	return NULL;
}


// MySQL's 3-byte little-endian packet length.
static __always_inline __u32 le24(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) | ((__u32)p[2] << 16);
}

// Does this byte look like printable SQL? Used to confirm a candidate frame
// really carries a statement rather than coincidentally-shaped binary. A
// statement starts with a keyword letter, or a paren/comment in the
// wrapped-query case.
static __always_inline int sql_start_ok(__u8 c)
{
	if (c >= 'A' && c <= 'Z') return 1;
	if (c >= 'a' && c <= 'z') return 1;
	if (c == '(' || c == '-' || c == '/') return 1;
	return 0;
}

// Copy a fixed window out of the sniffed buffer, starting at `off`.
//
// This copies SQL_LEN bytes UNCONDITIONALLY — no early exit on the frame end
// and no NUL stop. That is deliberate and it is the third rewrite of this
// function, so the reasoning is worth recording:
//
// A loop whose exit depends on a runtime value (`if (i >= end) break`) is not
// something the verifier will generalize. It walks the loop iteration by
// iteration, and because `end` is an unknown scalar it cannot prove the same
// state repeats, so 256 iterations become 256 distinct verifier states per
// call site — half a megabyte of verifier log and a rejection. Masking the
// index (`i & (SNIFF_LEN - 1)`) makes each ACCESS safe but does nothing about
// the state explosion, because the mask is not what the verifier is stuck on.
//
// A constant-trip loop over a power-of-two window with a masked index has
// exactly one state to prove, so it verifies instantly. The cost is copying
// some bytes past the end of the frame; the benefit is a program that loads.
// Userspace already knows the real length (`sql_len` / `param_len` travel on
// the event) and trims there, which is where every other decision about
// these bytes is made anyway.
//
// Returns the number of bytes the caller should treat as valid — computed
// arithmetically, not by walking.
static __noinline __u32 copy_sql(struct sql_event *e, const __u8 *buf, __u32 off, __u32 end)
{
	if (end > SNIFF_LEN) end = SNIFF_LEN;

	for (int j = 0; j < SQL_LEN; j++)
		e->sql[j] = buf[(off + (__u32)j) & (SNIFF_LEN - 1)];

	// How much of that window is really this frame's text.
	__u32 avail = end > off ? end - off : 0;
	return avail < SQL_LEN ? avail : SQL_LEN;
}

// Same discipline for the raw parameter bytes. A binary parameter block
// legitimately contains zero bytes, so a NUL stop would be wrong here even
// if the verifier allowed it — userspace walks this window with the real
// format rules.
static __noinline __u32 copy_params(struct sql_event *e, const __u8 *buf, __u32 off, __u32 end)
{
	if (end > SNIFF_LEN) end = SNIFF_LEN;

	for (int j = 0; j < PARAM_LEN; j++)
		e->params[j] = buf[(off + (__u32)j) & (SNIFF_LEN - 1)];

	__u32 avail = end > off ? end - off : 0;
	return avail < PARAM_LEN ? avail : PARAM_LEN;
}

// Zero the two windows without memset-ing the whole struct twice. Kept
// explicit because the per-CPU scratch is reused across events and stale
// bytes from a previous, longer statement would otherwise trail into this
// one's window.
static __always_inline void clear_windows(struct sql_event *e)
{
	__builtin_memset(e->sql, 0, SQL_LEN);
	__builtin_memset(e->params, 0, PARAM_LEN);
}

// ─── Postgres ───────────────────────────────────────────────────────────────
//
// Walk the frames in one write. Postgres pipelines: a prepared-statement
// execution is typically Parse+Bind+Describe+Execute+Sync in a SINGLE write,
// so a parser that reads only the first frame sees the SQL and never the
// parameter values.
//
// STRUCTURE, and why it is this shape. The frame walk and the per-frame
// handling are separate functions, and `pos` is masked to the sniff window on
// every iteration. Both are verifier accommodations:
//
//   - Each frame advances `pos` by a length read off the wire, so after six
//     iterations the verifier is tracking six unknown-but-related offsets and
//     the state space multiplies out (half a megabyte of log, then a
//     rejection). Masking `pos` into [0, SNIFF_LEN) at the top of each
//     iteration collapses that: the verifier re-enters the loop body with a
//     bounded scalar it has already proven, so one state covers all six.
//
//   - The per-frame body is a separate noinline function so its (large,
//     copy_sql-containing) instruction block exists ONCE rather than being
//     inlined per iteration, which is what previously pushed the object past
//     BPF's branch range.
//
// Returns 1 if it emitted anything.

// One Postgres frame's bounds, already masked into the sniff window by the
// caller. Passed as a pointer because a BPF global function takes at most
// five register arguments and `pg_frame` needs six values — packing the three
// frame numbers into a struct is the standard way around that limit.
struct pg_frame_desc {
	__u32 body; // first byte of the frame payload
	__u32 end;  // one past the frame
	__u32 len;  // the frame's declared length
	__u8 tag;   // the frame's type byte
};

// Handle one Postgres frame.
static __noinline int pg_frame(struct sql_event *e, const __u8 *buf, const struct pg_frame_desc *d)
{
	__u8 tag = d->tag;
	__u32 body = d->body;
	__u32 end = d->end;
	__u32 len = d->len;

	if (tag == 'Q') {
		// Simple query: the body is the statement, NUL-terminated.
		if (!sql_start_ok(buf[body & (SNIFF_LEN - 1)]))
			return 0;
		clear_windows(e);
		e->kind = KIND_QUERY;
		e->tag = tag;
		e->is_prepare = 0;
		e->sql_len = copy_sql(e, buf, body, end);
		e->param_len = 0;
		// A statement longer than the window was cut; say so on the event.
		e->truncated = (len > SQL_LEN + 4) ? 1 : 0;
		if (e->sql_len == 0)
			return 0;
		bpf_ringbuf_output(&sql_events, e, sizeof(*e), 0);
		return 1;
	}

	if (tag == 'P') {
		// Parse: cstring statement name, THEN the SQL.
		//
		// The kernel does NOT find where the name ends. Scanning a
		// variable-length cstring is precisely the unbounded walk this
		// program refuses to do — a 64-iteration masked scan verified, but
		// it unrolled into ~1700 instructions of verifier state on its own
		// and pushed the whole object over the complexity limit.
		//
		// So the window is copied from the START of the frame body, name
		// included, and userspace splits on the first NUL. It has the bytes
		// and a real string API; this is the same division of labour as the
		// Bind window below. The cost is a few bytes of the window spent on
		// a name that is almost always empty (one NUL for an unnamed
		// prepare, which is what every pooled client sends).
		clear_windows(e);
		e->kind = KIND_QUERY;
		e->tag = tag;
		e->is_prepare = 1;
		e->sql_len = copy_sql(e, buf, body, end);
		e->param_len = 0;
		e->truncated = (len > SQL_LEN + 4) ? 1 : 0;
		if (e->sql_len == 0)
			return 0;
		bpf_ringbuf_output(&sql_events, e, sizeof(*e), 0);
		return 1;
	}

	if (tag == 'B') {
		// Bind: the parameter VALUES for the statement just parsed. Layout
		// is cstring portal, cstring statement, an int16 format-code count,
		// the codes, then the parameters. Every offset past the two
		// cstrings is variable, so the kernel copies a flat window from the
		// frame body and lib/params.js walks it with the real rules.
		clear_windows(e);
		e->kind = KIND_PARAMS;
		e->tag = tag;
		e->is_prepare = 0;
		e->sql_len = 0;
		e->param_len = copy_params(e, buf, body, end);
		e->truncated = 0;
		if (e->param_len == 0)
			return 0;
		bpf_ringbuf_output(&sql_events, e, sizeof(*e), 0);
		return 1;
	}

	// 'E' (Execute), 'D' (Describe), 'S' (Sync) carry no text or values we
	// need — they are walked over to reach later frames.
	return 0;
}

static __noinline int parse_pg(struct sql_event *e, const __u8 *buf, __u32 size, __u64 sock)
{
	__u32 pos = 0;
	int emitted = 0;

	// FOUR frames, and the number is a verifier budget rather than a protocol
	// limit. Each iteration inlines a `copy_sql`/`copy_params` call whose body
	// is a 256-byte constant-trip loop, so the frame count multiplies straight
	// into verifier complexity: at six frames `on_sendmsg` verified at 686,652
	// instructions, 69% of the 1,000,000 ceiling, and an older kernel's
	// verifier explores more states for the same code — which is how a program
	// that loads here gets rejected on a user's 6.1 box.
	//
	// Four still reaches the frames that matter. What the parser needs from a
	// pipelined write is the Parse (statement text) and the Bind (values);
	// Describe, Execute and Sync carry nothing it reads. A write whose fourth
	// frame is a Bind is covered, and a longer pipeline loses only its tail.
	for (int f = 0; f < 4; f++) {
		// Mask first: this is what keeps `pos` a bounded scalar across
		// iterations instead of an ever-widening unknown.
		pos &= SNIFF_LEN - 1;
		if (pos + 5 > size)
			break;

		// Read the header through masked indices: the verifier knows
		// `pos` is in range from the mask above, but `buf + pos + 1` as a
		// pointer expression re-widens it, so index instead of offset.
		__u8 tag = buf[pos];
		__u32 len = ((__u32)buf[(pos + 1) & (SNIFF_LEN - 1)] << 24) |
			    ((__u32)buf[(pos + 2) & (SNIFF_LEN - 1)] << 16) |
			    ((__u32)buf[(pos + 3) & (SNIFF_LEN - 1)] << 8) |
			     (__u32)buf[(pos + 4) & (SNIFF_LEN - 1)];

		// `len` counts itself but not the tag. Reject an implausible frame
		// rather than walking into garbage: 4 is the minimum (an empty
		// body) and a frame cannot exceed the write it arrived in.
		if (len < 4 || len > size)
			break;

		__u32 body = (pos + 5) & (SNIFF_LEN - 1);
		__u32 end = pos + 1 + len;
		if (end > SNIFF_LEN)
			end = SNIFF_LEN;
		if (end <= body)
			break;

		struct pg_frame_desc d = { .body = body, .end = end, .len = len, .tag = tag };
		if (pg_frame(e, buf, &d))
			emitted = 1;

		// Forward progress is guaranteed by len >= 4, so no spin check is
		// needed beyond the loop bound itself.
		pos = pos + 1 + len;
	}

	return emitted;
}

// ─── MySQL ──────────────────────────────────────────────────────────────────
//
// One command per write, so no frame loop. The discriminator is strong:
// three length bytes must agree with the actual write size.
static __noinline int parse_mysql(struct sql_event *e, const __u8 *buf, __u32 size, __u64 sock)
{
	if (size < 5)
		return 0;

	__u32 len = le24(buf);
	// len counts cmd + payload; the 4-byte header is on top. A single-packet
	// command matches the write exactly. (A statement over 16MB spans
	// packets and is not covered — stated as a limit.)
	if (len + 4 != size)
		return 0;

	__u8 cmd = buf[4];
	__u32 body = 5;
	__u32 end = size < SNIFF_LEN ? size : SNIFF_LEN;

	if (cmd == 0x03 || cmd == 0x16) { // COM_QUERY | COM_STMT_PREPARE
		if (body >= SNIFF_LEN || !sql_start_ok(buf[body]))
			return 0;
		clear_windows(e);
		e->kind = KIND_QUERY;
		e->tag = cmd;
		e->is_prepare = (cmd == 0x16) ? 1 : 0;
		e->sql_len = copy_sql(e, buf, body, end);
		e->param_len = 0;
		e->truncated = (len - 1 > SQL_LEN) ? 1 : 0;
		if (e->sql_len == 0)
			return 0;
		bpf_ringbuf_output(&sql_events, e, sizeof(*e), 0);
		return 1;
	}

	if (cmd == 0x17) { // COM_STMT_EXECUTE — statement id, then the values
		clear_windows(e);
		e->kind = KIND_PARAMS;
		e->tag = cmd;
		e->is_prepare = 0;
		e->sql_len = 0;
		e->param_len = copy_params(e, buf, body, end);
		e->truncated = 0;
		if (e->param_len == 0)
			return 0;
		bpf_ringbuf_output(&sql_events, e, sizeof(*e), 0);
		return 1;
	}

	return 0;
}

// Common send path, shared by the socket kprobe and the TLS uprobe. `base`
// is the user address of the outgoing bytes; everything else is identical
// between the two, which is the point — one parser, two seams.
static __noinline int on_send(const void *base, __u32 size, __u64 sock, __u32 source)
{
	if (size < 5)
		return 0;

	__u32 zero = 0;
	struct sniff_buf *sb = bpf_map_lookup_elem(&sniff_scratch, &zero);
	if (!sb)
		return 0;

	// Copy only what's there. bpf_probe_read_user of a fixed SNIFF_LEN past
	// the end of a short write fails outright on some kernels rather than
	// short-reading, which would silently drop every small statement.
	__u32 n = size < SNIFF_LEN ? size : SNIFF_LEN;
	if (bpf_probe_read_user(sb->b, SNIFF_LEN, base) != 0) {
		// Retry bounded to the write itself. The verifier needs a provable
		// bound, hence the explicit clamp before the call.
		if (n > SNIFF_LEN) n = SNIFF_LEN;
		if (bpf_probe_read_user(sb->b, n & (SNIFF_LEN - 1), base) != 0)
			return 0;
	}

	struct sql_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->bytes = size;
	e->source = source;
	e->sock = sock;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Try Postgres first: its tag+length framing is checked against the
	// write size, so a MySQL packet almost never satisfies it. MySQL's
	// len+4==size test is stricter still. Neither matching means this write
	// is not SQL we understand, and nothing is emitted — no guessing.
	int hit = 0;
	e->dialect = DIALECT_PG;
	hit = parse_pg(e, sb->b, n, sock);
	if (!hit) {
		e->dialect = DIALECT_MYSQL;
		hit = parse_mysql(e, sb->b, n, sock);
	}
	if (!hit)
		return 0;

	// Record the send so its reply can be paired and timed.
	//
	// BOTH a statement and a parameter block start a clock, because both are
	// things the server answers. A prepare-once/execute-many client sends
	// only a Bind per execution, so treating a Bind as "part of the previous
	// round trip" left every execution after the first untimed — which is
	// exactly the traffic an N+1 is made of.
	if (e->kind == KIND_QUERY || e->kind == KIND_PARAMS) {
		__u64 k = ikey(sock);
		struct inflight *fl = bpf_map_lookup_elem(&inflight, &k);
		if (!fl) {
			// First send on this socket: seed a zeroed ring.
			__u32 z = 0;
			struct inflight *init = bpf_map_lookup_elem(&inflight_init, &z);
			if (!init)
				return 0;
			__builtin_memset(init, 0, sizeof(*init));
			bpf_map_update_elem(&inflight, &k, init, BPF_ANY);
			fl = bpf_map_lookup_elem(&inflight, &k);
			if (!fl)
				return 0;
		}
		__u32 h = fl->head & (INFLIGHT_RING - 1);
		fl->ts[h] = bpf_ktime_get_ns();
		fl->dialect[h] = e->dialect;
		fl->head = fl->head + 1;
		// Overrun: the client is more than a ring ahead of its replies. Drop
		// the oldest rather than mispair, and let the tail catch up.
		if (fl->head - fl->tail > INFLIGHT_RING)
			fl->tail = fl->head - INFLIGHT_RING;
	}
	return 0;
}

// Common reply path. Reads the head of what landed, works out the row count
// where the protocol states it plainly, and emits the paired latency.
static __noinline int on_reply(const void *base, __u32 size, __u64 sock, __u32 source)
{
	__u64 k = ikey(sock);
	struct inflight *fl = bpf_map_lookup_elem(&inflight, &k);
	if (!fl)
		return 0; // a reply to a statement sent before we attached

	// Nothing outstanding: this reply follows one we already paired (a
	// multi-packet result set arriving in several reads, for instance).
	if (fl->head == fl->tail)
		return 0;

	// Pop the OLDEST outstanding send — replies are ordered per connection,
	// so the front of the ring owns this one.
	__u32 t = fl->tail & (INFLIGHT_RING - 1);
	__u64 sent_ts = fl->ts[t];
	__u32 dialect = fl->dialect[t];
	fl->tail = fl->tail + 1;

	if (sent_ts == 0)
		return 0;

	__u64 lat_us = (bpf_ktime_get_ns() - sent_ts) / 1000;
	if (lat_us < min_latency_us) // kernel-side slow-statement floor
		return 0;

	__u32 zero = 0;
	struct sniff_buf *sb = bpf_map_lookup_elem(&sniff_scratch, &zero);
	if (!sb)
		return 0;
	__u32 n = size < SNIFF_LEN ? size : SNIFF_LEN;
	if (bpf_probe_read_user(sb->b, SNIFF_LEN, base) != 0)
		return 0;

	struct sql_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->kind = KIND_REPLY;
	e->dialect = dialect;
	e->source = source;
	e->sock = sock;
	e->lat_us = (__u32)lat_us;
	e->bytes = size;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// The reply head is copied for userspace to interpret: Postgres states
	// its row count as ASCII text in the CommandComplete frame ("SELECT 42",
	// "UPDATE 3"), which is a string parse and therefore JS work. The tag is
	// lifted here only so the UI can tell an error reply from a data one
	// without parsing anything.
	if (n > 0 && dialect == DIALECT_PG) {
		e->tag = sb->b[0];
		clear_windows(e);
		e->param_len = copy_params(e, sb->b, 0, n);
	} else if (n > 4) {
		e->tag = sb->b[4]; // MySQL: first payload byte (0x00 OK, 0xff ERR)
		clear_windows(e);
		e->param_len = copy_params(e, sb->b, 0, n);
	}

	bpf_ringbuf_output(&sql_events, e, sizeof(*e), 0);
	return 0;
}

// ─── plaintext wire path ────────────────────────────────────────────────────

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(on_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	const void *base = iter_base(msg);
	if (!base)
		return 0;
	return on_send(base, (__u32)size, (__u64)sk, SRC_WIRE);
}

// Entry: remember where the reply will be written, and on which socket. The
// bytes aren't there yet, so there is nothing to parse until the return.
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(on_recvmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	const void *base = iter_base(msg);
	if (!base)
		return 0;

	struct recv_scratch rs = { .base = (__u64)base, .sock = (__u64)sk };
	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&recv_scratch, &key, &rs, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(on_recvmsg_ret, int ret)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct recv_scratch *rs = bpf_map_lookup_elem(&recv_scratch, &key);
	if (!rs)
		return 0;
	__u64 base = rs->base;
	__u64 sock = rs->sock;
	bpf_map_delete_elem(&recv_scratch, &key);

	if (ret <= 0)
		return 0;
	return on_reply((const void *)base, (__u32)ret, sock, SRC_WIRE);
}

// ─── TLS path ───────────────────────────────────────────────────────────────
//
// Everything above reads the socket, which means it sees nothing once the
// connection is encrypted — and both Postgres and MySQL negotiate TLS by
// default in most managed setups. These programs hook the TLS library
// instead, on the application's side of the encryption boundary: SSL_write is
// called with the plaintext the client wants to send, SSL_read returns the
// plaintext it just received. Same bytes, same parser.
//
// There is no `sk` here, so the SSL* pointer stands in as the connection
// identity. It is exactly as good for our purpose: one SSL object per
// connection, stable for its lifetime.
//
// Not covered, and stated as a limit rather than worked around: Go clients
// (crypto/tls is pure Go — no C symbol exists to hook) and Java (JSSE lives
// inside the JVM).

// int SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/SSL_write")
int BPF_UPROBE(on_ssl_write, void *ssl, const void *buf, int num)
{
	if (!buf || num < 5)
		return 0;
	return on_send(buf, (__u32)num, (__u64)ssl, SRC_TLS);
}

// int SSL_read(SSL *ssl, void *buf, int num) — the buffer is filled on
// RETURN, so the entry probe only records where it will land.
SEC("uprobe/SSL_read")
int BPF_UPROBE(on_ssl_read, void *ssl, void *buf, int num)
{
	struct recv_scratch rs = { .base = (__u64)buf, .sock = (__u64)ssl };
	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&ssl_recv_scratch, &key, &rs, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(on_ssl_read_ret, int ret)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct recv_scratch *rs = bpf_map_lookup_elem(&ssl_recv_scratch, &key);
	if (!rs)
		return 0;
	__u64 base = rs->base;
	__u64 sock = rs->sock;
	bpf_map_delete_elem(&ssl_recv_scratch, &key);

	if (ret <= 0)
		return 0;
	return on_reply((const void *)base, (__u32)ret, sock, SRC_TLS);
}
