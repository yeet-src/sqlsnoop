#!/usr/bin/env bash
# Spawn Postgres traffic for the sqlsnoop TUI.
#
#   terminal 1:  yeet run .        # the dashboard
#   terminal 2:  demo/run.sh       # this — starts Postgres and generates traffic
#
# Starts a throwaway Postgres container (if one isn't already up), seeds a
# small shop schema, and drives it with demo/workload.py. Nothing needs
# installing on the host beyond docker and psycopg3.
set -eu

NAME="${SQLSNOOP_DEMO_CONTAINER:-sqlsnoop-pg}"
IMAGE="${SQLSNOOP_DEMO_IMAGE:-postgres:16}"
PORT="${SQLSNOOP_DEMO_PORT:-5432}"
DIR="$(cd "$(dirname "$0")" && pwd)"

DOCKER="docker"
if ! docker info >/dev/null 2>&1; then DOCKER="sudo docker"; fi

if ! $DOCKER ps --format '{{.Names}}' | grep -qx "$NAME"; then
	echo "[demo] starting $IMAGE as $NAME on port $PORT"
	$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
	$DOCKER run -d --name "$NAME" -p "$PORT:5432" \
		-e POSTGRES_PASSWORD=snoop -e POSTGRES_DB=shop "$IMAGE" >/dev/null
	printf '[demo] waiting for postgres'
	for _ in $(seq 1 60); do
		if $DOCKER exec "$NAME" pg_isready -q 2>/dev/null; then
			echo " ready"
			break
		fi
		printf '.'
		sleep 1
	done
fi

# Seed idempotently: the workload needs the tables, and re-running the demo
# shouldn't duplicate the rows.
if ! $DOCKER exec "$NAME" psql -U postgres -d shop -tc \
	"select 1 from information_schema.tables where table_name='orders'" 2>/dev/null | grep -q 1; then
	echo "[demo] seeding schema"
	$DOCKER exec -i "$NAME" psql -q -U postgres -d shop <"$DIR/seed.sql"
fi

trap 'echo; echo "[demo] leaving $NAME running — remove it with: $DOCKER rm -f $NAME"' EXIT INT TERM

echo "[demo] generating traffic (ctrl-c to stop)"
export SQLSNOOP_DSN="host=127.0.0.1 port=$PORT user=postgres password=snoop dbname=shop"
exec python3 "$DIR/workload.py"
