#!/bin/bash
set -e
##################### DOCUMENTATION #####################
# This script executes the bencher binary from https://bencher.dev/docs/tutorial/quick-start/
# The script requires a BENCHER_TOKEN and BENCHER_PROJECT as arguments to 
# authenticate with bencher.dev and associate the benchmark results with the correct project.
#
# IMPORTANT: For bencher.dev to recognize the project metadata (project name, branch, commit hash, etc.),
# ensure that this script is executed from the root directory of the repository. 
#########################################################

WORKDIR="$(pwd)"

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <BENCHER_PROJECT> <BENCHER_TOKEN> <BENCHER_BIN_PATH> [BENCHER_FLAGS...]"
    echo "If you run this script locally, supply \`--testbed <yourname-yourmachine>\` as BENCHER_FLAGS to identify your system in bencher.dev"
    exit 1
fi

BENCHER_PROJECT=$1
BENCHER_TOKEN=$2
BENCHER_BIN=$3
shift 3
BENCHER_FLAGS="$@"
RUN_BENCHER="$BENCHER_BIN run --project $BENCHER_PROJECT --token $BENCHER_TOKEN $BENCHER_FLAGS"  

RUNS=10
WARMUP=3

# Execute simple Rust programs
PROGRAMS_DIR="$WORKDIR/tests/benches/programs/"
for file_path in "$PROGRAMS_DIR"/*.rs; do
    echo "Processing file: $file_path"
    filename=$(basename "$file_path")
    program_name="${filename%.rs}"
    echo "compiling $program_name..."
    ./xb inst "$PROGRAMS_DIR/$filename"
    # the filename without .json is used by bencher.dev to identify the benchmark name
    echo "running $program_name with bencher and hyperfine..."
    $RUN_BENCHER --adapter shell_hyperfine --file "${program_name}.json" "hyperfine -i --runs $RUNS --warmup $WARMUP --shell=none --export-json '${program_name}.json' './${program_name}' --cleanup 'rm ${program_name}'"
    echo "cleaning ${program_name}.json"
    rm "${program_name}.json" # clean up the generated json file after bencher.dev has read it
done

# Exectute Rust test suites in crates
CRATES_DIR="$WORKDIR/tests/benches/crates"
for crate_path in "$CRATES_DIR"/*; do
    pushd "$crate_path"
    crate=$(basename "$crate_path")
    echo "Compiling $crate"
    cargo bsan clean
    cargo bsan test --no-run
    TEST_BINARY=$(cargo bsan test --no-run --message-format=json 2>&1 | \
    jq -r 'select(.executable != null) | .executable' | head -n1)
    echo "Compiled test binary: $TEST_BINARY"
    cp "$TEST_BINARY" ./$crate
    echo "Benchmarking $crate"
    $RUN_BENCHER --adapter shell_hyperfine --file "$crate.json" "hyperfine -i --runs $RUNS --warmup $WARMUP --shell=none --export-json '$crate.json' './$crate'"
    echo "cleaning $crate.json"
    rm "$crate.json" # clean up the generated json file after bencher.dev has read it
    popd
done

# Execute libtest benches in bsan-rt
echo "Running libtest benches in bsan-rt..."
pushd bsan-rt
$RUN_BENCHER "cargo bench"
popd
