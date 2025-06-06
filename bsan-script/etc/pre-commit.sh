#!/usr/bin/bash

set -e

echo "Running BSAN pre-commit hook..."

GIT_ROOT=$(git rev-parse --show-toplevel)
cd "$GIT_ROOT"

echo "Running xb fmt..."
./xb fmt

echo "Finished running BSAN pre-commit hook"
