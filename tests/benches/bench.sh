#!/bin/bash
set -eu

echo "Benchmarking..."

# Ensure hyperfine is installed

cargo install hyperfine --locked

# Ensure bsan is setup
./xb check

# # Compile the tests but don't run them 
# cargo test --no-run

# # Create a test directory
# mkdir -p benches

# # Compile miri tests such that the setup does not affect the bench runs
# cargo +nightly miri test --no-run --manifest-path=./hashbrown/Cargo.toml

# for test_binary in $(cargo test --manifest-path ./hashbrown/Cargo.toml --no-run --message-format=json | jq -r 'select(.profile.test == true and .filenames) | .filenames[]' | sort -u); do
#   test_names=$("$test_binary" --list | sed -n 's/ test$//p')

#   # Instrument the test binary with bsan

#   for test_name in $test_names; do
#     hyperfine --shell bash --show-output -i --warmup 3 --export-json ../results-hashbrown-$test_name.json

export MIRIFLAGS="-Zmiri-disable-stacked-borrows -Zmiri-ignore-leaks -Zmiri-disable-alignment-check -Zmiri-disable-data-race-detector -Zmiri-disable-validation -Zmiri-disable-weak-memory-emulation"


TARGET_DIR="./tests/benches/programs/src/bin"
for file_path in $TARGET_DIR/*.rs; do
  filename=$(basename "$file_path")
  program_name="${filename%.rs}"

  echo $file_path

  mkdir -p ./tests/benches/results/

  echo "=========================="
  echo "Benchmarking $program_name"
  echo "=========================="

  echo "Preparing..."

  ./xb inst $file_path

  cargo build -p programs --release --bin $program_name

  hyperfine \
  --warmup 5 \
  -i \
  --runs 50 \
  --prepare "./xb inst $file_path" \
  -N \
  --export-json ./tests/benches/results/$program_name-results.json \
  --cleanup "rm ./$program_name" \
  "./target/release/$program_name" "./$program_name" "cargo +nightly miri run -p programs --bin $program_name" 
  

  unset MIRIFLAGS
done;
