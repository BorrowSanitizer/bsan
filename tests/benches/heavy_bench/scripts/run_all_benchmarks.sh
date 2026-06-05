#!/usr/bin/env bash
set -e

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "Starting performance profiling & compilation (profile_perf.sh)..."
echo "=========================================="
"$SCRIPTS_DIR/profile_perf.sh"

echo "=========================================="
echo "Starting memory profiling (profile_sizes.sh)..."
echo "=========================================="
"$SCRIPTS_DIR/profile_sizes.sh"

echo "=========================================="
echo "All benchmarking and profiling runs completed!"
echo "=========================================="
