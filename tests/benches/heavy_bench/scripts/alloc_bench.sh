#!/usr/bin/env bash
set -e

# Resolve paths
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPTS_DIR/../../../../" && pwd)"
BENCH_DIR="$ROOT_DIR/tests/benches/heavy_bench"
cd "$BENCH_DIR"

# Run hyperfine benchmark comparing allocator and GC configurations using precompiled binaries
hyperfine \
  --show-output \
  --warmup 0 \
  -r 5 \
  --export-markdown bench_results.md \
  -n "ultimate-behemoth-clearing" "BSAN_ONLY_PASS=1 BSAN_CLEAR_NODES=1 $BENCH_DIR/target_bsan_system/ultimate_behemoth" \
  -n "ultimate-behemoth-no-clearing" "BSAN_ONLY_PASS=1 BSAN_CLEAR_NODES=0 $BENCH_DIR/target_bsan_system/ultimate_behemoth"

cat bench_results.md

