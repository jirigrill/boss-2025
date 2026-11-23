#!/bin/bash
set -e

# Define output directory and input file
OUTPUT_DIR="$(pwd)"
INPUT_FILE="test/input.json"

# Run Python code and save its debug output
echo "Running Python code..."
python3 main2.py "$OUTPUT_DIR" "$INPUT_FILE" > python_debug.log 2>&1

# Run Rust code (assuming the Rust binary is named rust_onion_packet)
echo "Running Rust code..."
(
  cd rust_onion_packet
  cargo run -- "$OUTPUT_DIR" "$INPUT_FILE"
) > rust_debug.log 2>&1


# Compare debug logs
echo "Comparing debug outputs..."
if diff python_debug.log rust_debug.log > /dev/null; then
    echo "Debug outputs match!"
else
    echo "Debug outputs differ!"
    diff python_debug.log rust_debug.log
fi