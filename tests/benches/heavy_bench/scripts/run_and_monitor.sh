#!/usr/bin/env bash
set -e

# Resolve paths
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPTS_DIR/../../../.." && pwd)"
BENCH_DIR="$ROOT_DIR/tests/benches/heavy_bench"

cd "$BENCH_DIR"
BSAN_ONLY_PASS=1 BSAN_ALLOCATOR=system cargo +bsan bsan run --release --bin ultimate_behemoth &
PID=$!
while kill -0 $PID 2>/dev/null; do
    ps -o pid,rss,vsz,comm -p $PID
    sleep 0.5
done
wait $PID
echo "Exit code: $?"
