#!/bin/bash
set -eu
MIRIFLAGS="-Zmiri-tree-borrows -Zmiri-ignore-leaks -Zmiri-disable-alignment-check -Zmiri-disable-data-race-detector -Zmiri-disable-alignment-check -Zmiri-disable-validation -Zmiri-disable-weak-memory-emulation"

cargo +nightly miri run --manifest-path "$@"
