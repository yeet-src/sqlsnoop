#!/usr/bin/env python3
"""Generate realistic SQL traffic for the sqlsnoop TUI.

Shaped to look like an application, not a benchmark, because a demo whose
traffic is obviously synthetic undersells the tool. The first version of this
file ran the same five statements in the same order every 500ms, and the feed
showed a perfect `UPDATE SELECT UPDATE SELECT` metronome — which is not what
any real app looks like, and which made the whole screen read as fake.

What makes traffic look real, and what each one is here for:

  * SEVERAL CONNECTIONS, in threads, so statements from different "endpoints"
    interleave the way concurrent requests do. This is also the only way the
    feed's per-process and per-connection attribution has anything to show.
  * READS DOMINATE. Roughly fifteen reads per write, which is typical for a
    web app. A 1:1 mix is a tell.
  * IRREGULAR TIMING. Jittered think-time between requests, so nothing lands
    on a beat.
  * A WEIGHTED MIX OF ENDPOINTS, each touching different tables, so no single
    shape is the whole screen.
  * THE N+1 IS OCCASIONAL. It fires on one endpoint that runs maybe one
    request in six, so it stands out against normal traffic instead of being
    the baseline. An N+1 that is always on screen is wallpaper.

Uses psycopg3, which speaks the EXTENDED protocol (Parse/Bind/Execute, with
parameter values in their own wire message). That is deliberately the harder
case for a wire-level monitor to read, and the one worth demonstrating:
psycopg2 by contrast interpolates values into the SQL text client-side, so a
tool sees a finished statement and never has to reassemble anything.
"""
import os
import random
import sys
import threading
import time

try:
    import psycopg
except ImportError:
    sys.exit("needs psycopg3:  apt install python3-psycopg   (or pip install 'psycopg[binary]')")

DSN = os.environ.get("SQLSNOOP_DSN", "host=127.0.0.1 user=postgres password=snoop dbname=shop")
WORKERS = int(os.environ.get("SQLSNOOP_WORKERS", "4"))
ROUNDS = int(os.environ.get("SQLSNOOP_ROUNDS", "0")) or None  # None = forever

REGIONS = ("emea", "apac", "namer")
STATUSES = ("pending", "shipped", "cancelled")

stop = threading.Event()


# ── endpoints ───────────────────────────────────────────────────────────────
#
# Each function is one "request" a service might serve. They are picked by
# weight below, so the feed carries a mix in realistic proportions rather than
# a fixed cycle.


def ep_order_list(cur):
    """The N+1. The interesting one, and deliberately not the common one.

    A page of customers, then a per-customer lookup issued inside the loop
    that renders them. This is what an ORM does when a template touches a
    lazy association: no individual query is slow, and together they dominate.
    """
    region = random.choice(REGIONS)
    cur.execute("SELECT id, name FROM customers WHERE region = %s LIMIT %s", (region, random.randint(8, 20)))
    for cid, _name in cur.fetchall():
        cur.execute(
            "SELECT id, status, total FROM orders WHERE customer_id = %s AND status = %s",
            (cid, "pending"),
        )
        cur.fetchall()


def ep_order_list_fixed(cur):
    """The same page, written properly: one query instead of N+1.

    Present so the feed shows both shapes and the aggregate view can be used
    to compare them, which is the "verify your fix" story.
    """
    region = random.choice(REGIONS)
    cur.execute(
        "SELECT c.id, c.name, o.id, o.status, o.total "
        "FROM customers c LEFT JOIN orders o ON o.customer_id = c.id AND o.status = %s "
        "WHERE c.region = %s LIMIT %s",
        ("pending", region, random.randint(8, 20)),
    )
    cur.fetchall()


def ep_customer_detail(cur):
    """A single-row lookup by primary key. The most common shape in most apps."""
    cur.execute("SELECT id, name, region, email FROM customers WHERE id = %s", (random.randint(1, 500),))
    cur.fetchone()
    cur.execute("SELECT count(*) FROM orders WHERE customer_id = %s", (random.randint(1, 500),))
    cur.fetchone()


def ep_order_search(cur):
    """A filtered search with a sort and a limit. Well-behaved."""
    cur.execute(
        "SELECT id, customer_id, total FROM orders WHERE status = %s AND total > %s ORDER BY total DESC LIMIT %s",
        (random.choice(STATUSES), round(random.uniform(50, 300), 2), 25),
    )
    cur.fetchall()


def ep_dashboard(cur):
    """An expensive aggregate. Ranks high on average time, not on call count."""
    cur.execute(
        "SELECT o.status, count(*), avg(o.total) FROM orders o "
        "JOIN customers c ON c.id = o.customer_id GROUP BY o.status ORDER BY 2 DESC"
    )
    cur.fetchall()


def ep_inventory_adjust(cur):
    """A write. Small, frequent, indexed."""
    cur.execute(
        "UPDATE inventory SET qty = qty - %s WHERE sku = %s",
        (random.randint(1, 3), f"sku-{random.randint(1, 2000)}"),
    )


def ep_place_order(cur):
    """A write that inserts, so the feed has more than one write shape.

    Deletes an old cancelled order on the way, so a long demo run does not
    grow the table without bound and change the timings it is demonstrating.
    That also puts a DELETE shape in the feed, which is the verb the footgun
    checks care most about.
    """
    cur.execute(
        "INSERT INTO orders (customer_id, status, total) VALUES (%s, %s, %s)",
        (random.randint(1, 500), "pending", round(random.uniform(10, 400), 2)),
    )
    cur.execute(
        "DELETE FROM orders WHERE id IN (SELECT id FROM orders WHERE status = %s LIMIT 1)",
        ("cancelled",),
    )


def ep_admin_export(cur):
    """Two footguns on purpose, so the warning marks have something to mark.

    `SELECT *` with no predicate reads every column of every row; a
    leading-wildcard LIKE cannot use an index. Both are real mistakes that
    real code ships, which is why the tool flags them.
    """
    cur.execute("SELECT * FROM inventory LIMIT 100")
    cur.fetchall()
    cur.execute("SELECT name FROM customers WHERE name LIKE %s LIMIT 5", ("%cust 1%",))
    cur.fetchall()


# Weights, chosen so reads outnumber writes about 15:1 and the N+1 endpoint is
# uncommon enough to stand out when it fires.
ENDPOINTS = [
    (ep_customer_detail, 30),
    (ep_order_search, 22),
    (ep_order_list_fixed, 12),
    (ep_order_list, 7),  # the N+1 — roughly one request in fourteen
    (ep_dashboard, 5),
    (ep_inventory_adjust, 4),
    (ep_place_order, 2),
    (ep_admin_export, 3),
]
_FNS = [f for f, _ in ENDPOINTS]
_WEIGHTS = [w for _, w in ENDPOINTS]


def worker(name, transactional=False):
    """One connection, serving requests in a loop with irregular think time.

    `transactional` runs the connection WITHOUT autocommit, so psycopg wraps
    each request in `BEGIN` / `COMMIT` and the connection does the session
    setup a pooled client normally does. That traffic is what sqlsnoop calls
    session chatter, and it is hidden behind `n` in the UI.

    It matters that at least one worker does this. psycopg3 in autocommit mode
    sends no transaction control at all, so a demo where every connection is
    autocommit produces zero chatter and pressing `n` reveals nothing — the
    filter looks broken when it is simply working on an empty set. Most real
    applications use transactions, so this is the more honest default anyway;
    it is only a minority of workers because reads dominating without a
    transaction per read is also realistic.
    """
    try:
        with psycopg.connect(DSN, autocommit=not transactional) as conn, conn.cursor() as cur:
            if transactional:
                # The kind of connection setup a pool does once, on checkout.
                cur.execute("SET statement_timeout = 30000")
                cur.execute("SELECT 1")  # the canonical pool health check
                cur.fetchone()
                conn.commit()

            n = 0
            while not stop.is_set() and (ROUNDS is None or n < ROUNDS):
                fn = random.choices(_FNS, weights=_WEIGHTS, k=1)[0]
                try:
                    fn(cur)
                    if transactional:
                        conn.commit()  # ends the transaction psycopg opened
                except Exception as e:  # a demo should not die on one bad request
                    print(f"[{name}] {type(e).__name__}: {e}", file=sys.stderr)
                    if transactional:
                        conn.rollback()  # a real ROLLBACK, which chatter includes
                n += 1
                # Occasionally re-check the connection the way a pool does, so
                # the feed carries health checks rather than only transactions.
                if transactional and random.random() < 0.15:
                    cur.execute("SELECT 1")
                    cur.fetchone()
                    conn.commit()
                # Jittered think time. The spread matters more than the mean:
                # a constant delay is what produced the metronome.
                time.sleep(random.uniform(0.02, 0.35))
    except Exception as e:
        print(f"[{name}] connection failed: {e}", file=sys.stderr)


def main():
    # Roughly a third of the connections are transactional, so the feed
    # carries realistic session chatter without it dominating. That mix is
    # also what makes the `n` toggle worth pressing: hidden, the feed is your
    # application's queries; shown, you can see how much of the connection's
    # traffic is bookkeeping.
    txn_workers = max(1, WORKERS // 3)
    threads = [
        threading.Thread(target=worker, args=(f"w{i}", i < txn_workers), daemon=True)
        for i in range(WORKERS)
    ]
    for t in threads:
        t.start()
    try:
        # Stagger nothing on the way in; the jitter above desynchronises them
        # within a second or two on its own.
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.3)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
