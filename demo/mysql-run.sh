#!/usr/bin/env bash
# The MySQL half of the demo. Same idea as run.sh: a throwaway container, a
# small schema, and a shaped workload. Kept separate because the two servers
# want different ports and clients, and because watching them one at a time
# is how you'd actually use this.
#
#   terminal 1:  yeet run .
#   terminal 2:  demo/mysql-run.sh
set -eu

NAME="${SQLSNOOP_MYSQL_CONTAINER:-sqlsnoop-my}"
IMAGE="${SQLSNOOP_MYSQL_IMAGE:-mysql:8}"
PORT="${SQLSNOOP_MYSQL_PORT:-3306}"
DIR="$(cd "$(dirname "$0")" && pwd)"

DOCKER="docker"
if ! docker info >/dev/null 2>&1; then DOCKER="sudo docker"; fi

if ! $DOCKER ps --format '{{.Names}}' | grep -qx "$NAME"; then
	echo "[demo] starting $IMAGE as $NAME on port $PORT"
	$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
	$DOCKER run -d --name "$NAME" -p "$PORT:3306" \
		-e MYSQL_ROOT_PASSWORD=snoop -e MYSQL_DATABASE=shop "$IMAGE" >/dev/null
	printf '[demo] waiting for mysqld'
	for _ in $(seq 1 90); do
		if $DOCKER exec "$NAME" mysqladmin -psnoop ping >/dev/null 2>&1; then
			echo " ready"
			break
		fi
		printf '.'
		sleep 1
	done
fi

if ! $DOCKER exec "$NAME" mysql -uroot -psnoop -N -B shop \
	-e "select count(*) from information_schema.tables where table_name='orders'" 2>/dev/null | grep -q 1; then
	echo "[demo] seeding schema"
	$DOCKER exec -i "$NAME" mysql -uroot -psnoop shop <"$DIR/mysql-seed.sql" 2>/dev/null
fi

trap 'echo; echo "[demo] leaving $NAME running — remove it with: $DOCKER rm -f $NAME"' EXIT INT TERM

echo "[demo] generating traffic (ctrl-c to stop)"
exec python3 "$DIR/mysql-workload.py"
