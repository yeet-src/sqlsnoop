#!/usr/bin/env bash
# Drive traffic at a Postgres already running on this host (no container).
#
#   terminal 1:  yeet run .
#   terminal 2:  demo/native.sh
#
# Use this when Postgres is installed on the box rather than in Docker, which
# is the common case in a dev VM. It seeds the shop schema if it's missing and
# then runs the same shaped workload as run.sh.
#
# Connects over TCP (127.0.0.1) rather than the Unix socket ON PURPOSE: the
# probes read tcp_sendmsg, so a client on a Unix socket is invisible. This is
# the single most common reason a first demo shows an empty screen.
set -eu

DB="${SQLSNOOP_DB:-shop}"
USER="${SQLSNOOP_USER:-postgres}"
PASS="${SQLSNOOP_PASS:-snoop}"
PORT="${SQLSNOOP_PORT:-5432}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# psql as the postgres role via sudo for the admin steps; the workload itself
# connects over TCP as a normal client.
as_admin() { sudo -u postgres psql -q "$@"; }

if ! as_admin -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw "$DB"; then
	echo "[demo] creating database $DB"
	as_admin -c "CREATE DATABASE $DB" >/dev/null
fi

if ! as_admin -d "$DB" -tc \
	"select 1 from information_schema.tables where table_name='orders'" 2>/dev/null | grep -q 1; then
	echo "[demo] seeding schema"
	as_admin -d "$DB" -f "$DIR/seed.sql" >/dev/null
fi

# The workload authenticates over TCP, so the role needs a password set. This
# is a throwaway demo credential on a local database.
echo "[demo] ensuring the $USER role has a demo password"
as_admin -c "ALTER USER $USER PASSWORD '$PASS'" >/dev/null

echo "[demo] generating traffic against 127.0.0.1:$PORT/$DB (ctrl-c to stop)"
export SQLSNOOP_DSN="host=127.0.0.1 port=$PORT user=$USER password=$PASS dbname=$DB"
exec python3 "$DIR/workload.py"
