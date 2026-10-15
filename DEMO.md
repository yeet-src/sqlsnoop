# Running the demo

sqlsnoop reads the kernel, so it runs on Linux. On a Mac that means the VM.

## Two terminals

**Terminal 1 — the dashboard**

```sh
limactl shell yeet.debian-13
cd ~/sqlsnoop
yeet run .
```

No `sudo`. The yeet daemon does the privileged BPF load.

**Terminal 2 — the traffic**

```sh
limactl shell yeet.debian-13
cd ~/sqlsnoop
demo/native.sh
```

That seeds a small shop schema into the Postgres already running in the VM
(500 customers, 5000 orders, 2000 inventory rows) and then loops a workload
containing a deliberate N+1.

Start the dashboard first. The probes only see traffic that happens while
they're attached.

## What to point at

Give it ten seconds of traffic, then:

**The feed** (the default view). Every statement as it completed, newest at
top. The line worth pausing on:

```
 python3/680498      81µs     —  SELECT id, status, total FROM orders WHERE customer_id = ? AND status = ?
   ⤷ ×112 identical, 22.2ms total, slowest 1.93ms   looks like an N+1
   ↳ $1=42  $2='pending'
```

Three things in one row. The query ran 112 times. No single run was slow (81µs)
but together they cost 22ms. And the values are real, read off the wire, so you
can see it's looping over different ids rather than repeating one lookup.

**`tab` — the aggregate.** The same traffic ranked by total time, which puts
that N+1 at the top as ~63% of everything the database did. This is the
pg_stat_statements view nobody had to enable.

**`enter` — the detail pane.** The full statement, its decoded parameters, and
an honest facts block: latency labelled as socket-paired, row counts marked
when the reply didn't state one.

**`n`** shows the session chatter (`BEGIN`, `COMMIT`, `SET`) that's hidden by
default. Worth one press to show it isn't cheating by dropping traffic.

## Keys

| key | does |
| --- | --- |
| `tab` | switch feed / aggregate |
| `↑` `↓` `j` `k` | select a row |
| `enter` | detail pane for the selected row |
| `n` | show/hide session chatter |
| `+` `-` | raise/lower the slow-statement floor (patched into the kernel live) |
| `q` | quit |

## MySQL instead

```sh
demo/mysql-run.sh      # starts a mysql:8 container, seeds it, drives traffic
```

The title bar's `pg` and `mysql` counters show which dialect is arriving, so
it's obvious the same run covers both.

## If the screen stays empty

**Traffic on a Unix socket.** The probes hook `tcp_sendmsg`, so a client
connected via `/var/run/postgresql/.s.PGSQL.5432` is invisible. Connect over
`127.0.0.1`, which is what the demo scripts do.

**The workload started first.** Restart it after the dashboard is up.

**Piping the output.** `yeet run . | tee log` cannot render a TUI and will tell
you so. To record, use `asciinema rec` or `script`, or run the probe module for
a line-at-a-time stream:

```sh
yeet run src/probes/sql.js
```

That last one is also the best way to show the raw capture: it prints each
statement, its parameter block, and its reply as separate events, which makes
the stitching visible.
