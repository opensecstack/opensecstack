#!/bin/sh
# Generic dev migration runner for Go platforms that lack an auto-migrate-on-serve
# step. Applies the SQL files matched by $GLOB (sorted) from /migrations, but only
# when the target schema is empty — migrations here are not idempotent, so this
# guard keeps `docker compose up` safe to re-run.
set -e

CNT=$(psql -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
if [ "$CNT" != "0" ]; then
  echo "run-migrations: schema already has $CNT table(s); skipping"
  exit 0
fi

for f in $(ls /migrations/$GLOB 2>/dev/null | sort); do
  echo "run-migrations: applying $f"
  psql -v ON_ERROR_STOP=1 -f "$f"
done
echo "run-migrations: done"
