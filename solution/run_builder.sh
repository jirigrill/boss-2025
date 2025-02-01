#!/bin/bash

# Get absolute paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Set PYTHONPATH
export PYTHONPATH="$SCRIPT_DIR/.."

# Run builder from its directory
cd python
python builder.py