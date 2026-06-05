#!/usr/bin/env bash
set -e

# Resolve paths
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPTS_DIR/../../../../" && pwd)"
BENCH_DIR="$ROOT_DIR/tests/benches/heavy_bench"

BENCH_BINS=("alloc_bsan" "complex_ds" "mixed" "rapid_cycling" "linked_list_frag" "btree_map_stress" "hash_map_stress" "vec_deque_stress" "deep_nesting_stress")

CONFIGS=("system" "bsan_system" "dlmalloc" "bsan_dlmalloc" "mimalloc" "bsan_mimalloc")

# Helper: return peak RSS in KB using /usr/bin/time -v (kernel-reported, accurate)
peak_rss_kb() {
    local bin_path=$1
    shift
    local time_output
    { time_output=$( { /usr/bin/time -v env "$@" "$bin_path" > /dev/null; } 2>&1 ); } || true
    echo "$time_output" | grep "Maximum resident set size" | awk '{print $NF}'
}

# Initialize results file
RESULTS_FILE="$BENCH_DIR/profile_results.md"
echo "# BSAN Peak Memory Usage (Peak RSS)" > "$RESULTS_FILE"
echo "Measured via \`/usr/bin/time -v\` (kernel-reported peak RSS at process exit)." >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

echo "## Peak RSS by Program and Allocator (KB)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "| Program | system | bsan-system | dlmalloc | bsan-dlmalloc | mimalloc | bsan-mimalloc |" >> "$RESULTS_FILE"
echo "|:---|---:|---:|---:|---:|---:|---:|" >> "$RESULTS_FILE"

for bin in "${BENCH_BINS[@]}"; do
    echo "  Profiling $bin..."
    row="| $bin"
    for name in "${CONFIGS[@]}"; do
        rss=$(peak_rss_kb "$BENCH_DIR/target_$name/$bin" BSAN_ONLY_PASS=1)
        row="$row | ${rss:-N/A}"
    done
    row="$row |"
    echo "$row"
    echo "$row" >> "$RESULTS_FILE"
done

# Profile ultimate_behemoth separately (Node Clearing Enabled vs Disabled)
echo "" >> "$RESULTS_FILE"
echo "## Node Clearing Memory Usage: ultimate_behemoth (KB)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "| Program | Node Clearing Enabled (BSAN_CLEAR_NODES=1) | Node Clearing Disabled (BSAN_CLEAR_NODES=0) |" >> "$RESULTS_FILE"
echo "|:---|---:|---:|" >> "$RESULTS_FILE"

echo "  Profiling ultimate_behemoth (with node clearing)..."
rss_clearing=$(peak_rss_kb "$BENCH_DIR/target_bsan_system/ultimate_behemoth" BSAN_ONLY_PASS=1 BSAN_CLEAR_NODES=1)
echo "  Profiling ultimate_behemoth (without node clearing)..."
rss_noclearing=$(peak_rss_kb "$BENCH_DIR/target_bsan_system/ultimate_behemoth" BSAN_ONLY_PASS=1 BSAN_CLEAR_NODES=0)

echo "| ultimate_behemoth | ${rss_clearing:-N/A} | ${rss_noclearing:-N/A} |" >> "$RESULTS_FILE"
echo "| ultimate_behemoth | ${rss_clearing:-N/A} | ${rss_noclearing:-N/A} |"

echo "" >> "$RESULTS_FILE"
echo "=== Profiling Completed! ==="
cat "$RESULTS_FILE"
