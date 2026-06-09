#!/usr/bin/env bash
set -e

# Resolve paths
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPTS_DIR/../../../../" && pwd)"
BENCH_DIR="$ROOT_DIR/tests/benches/heavy_bench"

ALL_BINS=("alloc_bsan" "complex_ds" "mixed" "ultimate_behemoth" "rapid_cycling" "linked_list_frag" "btree_map_stress" "hash_map_stress" "vec_deque_stress" "deep_nesting_stress")

# All 10 programs are benchmarked. ultimate_behemoth uses node clearing (BSAN_CLEAR_NODES=1)
# to handle its heavier load; the other 9 don't call __bsan_clear_nodes at all.
BENCH_BINS=("alloc_bsan" "complex_ds" "mixed" "rapid_cycling" "linked_list_frag" "btree_map_stress" "hash_map_stress" "vec_deque_stress" "deep_nesting_stress")

CONFIGS=(
    "system:--no-default-features --features pic,alloc-system"
    "bsan_system:--no-default-features --features pic,alloc-bsan-metadata,alloc-system"
    "dlmalloc:--no-default-features --features pic,alloc-dlmalloc"
    "bsan_dlmalloc:--no-default-features --features pic,alloc-bsan-metadata,alloc-dlmalloc"
    "mimalloc:--no-default-features --features pic,alloc-mimalloc"
    "bsan_mimalloc:--no-default-features --features pic,alloc-bsan-metadata,alloc-mimalloc"
)

# 1. Compile all configurations upfront
echo "=== Compiling Allocator & Metadata Configurations ==="

for config in "${CONFIGS[@]}"; do
    name="${config%%:*}"
    features="${config#*:}"
    echo "Compiling configuration: $name..."
    mkdir -p "$BENCH_DIR/target_$name"

    cd "$ROOT_DIR"
    cargo clean --manifest-path=bsan-rt/Cargo.toml > /dev/null 2>&1
    "$ROOT_DIR/xb" install bsan-rt -- $features > /dev/null 2>&1
    cd "$BENCH_DIR"
    cargo +bsan bsan clean > /dev/null 2>&1
    cargo +bsan bsan build --release > /dev/null 2>&1

    for bin in "${ALL_BINS[@]}"; do
        cp -f "$BENCH_DIR/target/bsan/aarch64-unknown-linux-gnu/release/$bin" "$BENCH_DIR/target_$name/$bin"
    done
done

# Initialize performance results markdown
PERF_RESULTS="$BENCH_DIR/perf_results.md"
echo "# Hyperfine Allocator & Metadata Strategy Performance Comparison" > "$PERF_RESULTS"
echo "Comparing execution times across allocator backends and metadata allocation strategies." >> "$PERF_RESULTS"
echo "" >> "$PERF_RESULTS"

# 2. Benchmark all 9 programs across all configs (without node clearing)
for bin in "${BENCH_BINS[@]}"; do
    echo "=== Benchmarking Allocators for $bin using hyperfine ==="
    echo "## Allocator Benchmark: $bin" >> "$PERF_RESULTS"
    echo "" >> "$PERF_RESULTS"

    hyperfine -r 5 \
        --export-markdown "$BENCH_DIR/tmp_${bin}.md" \
        -n "system"        "BSAN_ONLY_PASS=1 $BENCH_DIR/target_system/$bin" \
        -n "bsan-system"   "BSAN_ONLY_PASS=1 $BENCH_DIR/target_bsan_system/$bin" \
        -n "dlmalloc"      "BSAN_ONLY_PASS=1 $BENCH_DIR/target_dlmalloc/$bin" \
        -n "bsan-dlmalloc" "BSAN_ONLY_PASS=1 $BENCH_DIR/target_bsan_dlmalloc/$bin" \
        -n "mimalloc"      "BSAN_ONLY_PASS=1 $BENCH_DIR/target_mimalloc/$bin" \
        -n "bsan-mimalloc" "BSAN_ONLY_PASS=1 $BENCH_DIR/target_bsan_mimalloc/$bin"

    cat "$BENCH_DIR/tmp_${bin}.md" >> "$PERF_RESULTS"
    rm "$BENCH_DIR/tmp_${bin}.md"
    echo "" >> "$PERF_RESULTS"
    echo "" >> "$PERF_RESULTS"
done

# 3. Benchmark ultimate_behemoth (Node Clearing Enabled vs Disabled)
echo "=== Benchmarking ultimate_behemoth (Node Clearing vs No Clearing) ==="
echo "## Node Clearing Performance: ultimate_behemoth" >> "$PERF_RESULTS"
echo "" >> "$PERF_RESULTS"

hyperfine -r 5 \
    --export-markdown "$BENCH_DIR/tmp_ultimate_behemoth.md" \
    -n "ultimate-behemoth-clearing" "BSAN_ONLY_PASS=1 BSAN_CLEAR_NODES=1 $BENCH_DIR/target_bsan_system/ultimate_behemoth" \
    -n "ultimate-behemoth-no-clearing" "BSAN_ONLY_PASS=1 BSAN_CLEAR_NODES=0 $BENCH_DIR/target_bsan_system/ultimate_behemoth"

cat "$BENCH_DIR/tmp_ultimate_behemoth.md" >> "$PERF_RESULTS"
rm "$BENCH_DIR/tmp_ultimate_behemoth.md"
echo "" >> "$PERF_RESULTS"
echo "" >> "$PERF_RESULTS"

# Reset build configuration back to default
cd "$ROOT_DIR"
"$ROOT_DIR/xb" install bsan-rt > /dev/null 2>&1

echo "=== Benchmarking Completed! ==="
cat "$PERF_RESULTS"
