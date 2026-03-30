#!/bin/bash
set -e

##################### DOCUMENTATION #####################
# This script executes the bencher binary from https://bencher.dev/docs/tutorial/quick-start/
# The script requires a BENCHER_TOKEN and BENCHER_PROJECT as arguments to 
# authenticate with bencher.dev and associate the benchmark results with the correct project.
# It runs benchmarks using using hyperfine on a set of Rust programs located in benches/programs/src/bin.

# IMPORTANT: For bencher.dev to recognize the project metadata (project name, branch, commit hash, etc.),
# ensure that this script is executed from the root directory of the repository. 
#########################################################

# set working directory to the script's directory (absolute path)
WORKDIR="$(cd "$(dirname "$0")" && pwd)"

# print Usage if no arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <BENCHER_PROJECT> <BENCHER_TOKEN> <BENCHER_BIN_PATH>"
    exit 1
fi

BENCHER_PROJECT=$1
BENCHER_TOKEN=$2
BENCHER_BIN=$3

#execute hyperfine tests
RUNS=20
WARMUP=5
PROGRAMS_DIR="$WORKDIR/benches/programs/src/bin"
for file_path in "$PROGRAMS_DIR"/*.rs; do
    echo "Processing file: $file_path"
    filename=$(basename "$file_path")
    program_name="${filename%.rs}"
    echo "compiling $program_name..."
    ./xb inst "$PROGRAMS_DIR/$filename"
    # the filename without .json is used by bencher.dev to identify the benchmark name
    echo "running $program_name with bencher and hyperfine..."
    $BENCHER_BIN run --project $BENCHER_PROJECT --adapter shell_hyperfine --file "${program_name}.json" --token $BENCHER_TOKEN "hyperfine -i --runs $RUNS --warmup $WARMUP --shell=none --export-json '${program_name}.json' './${program_name}' --cleanup 'rm ${program_name}'"
    echo "cleaning ${program_name}.json"
    rm "${program_name}.json" # clean up the generated json file after bencher.dev has read it
done




# execute libtest benches in bsan-rt
echo "Running libtest benches in bsan-rt..."
pushd bsan-rt
$BENCHER_BIN run --project $BENCHER_PROJECT --token $BENCHER_TOKEN "cargo bench"
popd
