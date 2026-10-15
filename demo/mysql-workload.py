#!/usr/bin/env python3
"""The MySQL half of the demo workload — same shape as workload.py.

Uses MySQLdb, which sends COM_QUERY with values already interpolated into the
statement text. That is the common MySQL client behaviour and it is the easier
case to read off the wire: the statement arrives complete, so nothing has to
be reassembled from a separate values message.

A driver configured for server-side prepared statements sends
COM_STMT_PREPARE then COM_STMT_EXECUTE instead, and sqlsnoop decodes those
binary parameters too — with the caveat that MySQL omits the type bytes on
repeat executions, which is reported on the row rather than guessed at.
"""
import os
import random
import sys
import time

try:
    import MySQLdb
except ImportError:
    sys.exit("needs MySQLdb:  apt install python3-mysqldb   (or pip install mysqlclient)")

ROUNDS = int(os.environ.get("SQLSNOOP_ROUNDS", "0")) or None


def one_round(cur):
    # The N+1.
    cur.execute("SELECT id FROM customers WHERE region = %s LIMIT 14", ("emea",))
    for (cid,) in cur.fetchall():
        cur.execute(
            "SELECT id, status, total FROM orders WHERE customer_id = %s AND status = %s",
            (cid, "pending"),
        )
        cur.fetchall()

    cur.execute(
        "SELECT o.status, count(*), avg(o.total) FROM orders o "
        "JOIN customers c ON c.id = o.customer_id GROUP BY o.status ORDER BY 2 DESC"
    )
    cur.fetchall()

    cur.execute("UPDATE inventory SET qty = qty - 1 WHERE sku = %s", (f"sku-{random.randint(1, 2000)}",))

    # Footguns.
    cur.execute("SELECT * FROM inventory LIMIT 50")
    cur.fetchall()
    cur.execute("SELECT name FROM customers WHERE name LIKE '%cust 1%' LIMIT 5")
    cur.fetchall()


def main():
    c = MySQLdb.connect(
        host=os.environ.get("SQLSNOOP_MYSQL_HOST", "127.0.0.1"),
        port=int(os.environ.get("SQLSNOOP_MYSQL_PORT", "3306")),
        user="root",
        passwd="snoop",
        db="shop",
        autocommit=True,
    )
    cur = c.cursor()
    n = 0
    while ROUNDS is None or n < ROUNDS:
        one_round(cur)
        n += 1
        time.sleep(0.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
