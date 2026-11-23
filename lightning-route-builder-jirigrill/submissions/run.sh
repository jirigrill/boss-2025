#!/bin/bash

# Check if three arguments are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <output_file_path> <input_file_path> <payment_request_hex> <current_block_height>"
    exit 1
fi

# Assign arguments to variables
output_file_path="$1"
input_file_path="$2"
payment_request_hex="$3"
current_block_height="$4"

# Please fill in the version of the programming language you used here to help us with debugging if we run into problems!
version="rust" # or python

# Check if the 'version' variable is not null
if [ -z "$version" ]; then
    echo "Please fill in the version of the programming language you used."
    exit 1
fi

# Your run command here:
if [ "$version" = "python" ]; then
    python3 submissions/routebuilder/src/main.py "$output_file_path" "$input_file_path" "$payment_request_hex" "$current_block_height"
elif [ "$version" = "rust" ]; then
    # Change to the Rust project directory and run
    cd submissions/routebuilder && \
    cargo run -- "$output_file_path" "$input_file_path" "$payment_request_hex" "$current_block_height"
else
    echo "Unsupported version: $version"
    exit 1
fi