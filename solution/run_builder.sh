#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Add the parent directory to PYTHONPATH so Python can find our modules
export PYTHONPATH="$SCRIPT_DIR/.."

# Run the builder script using the correct relative path
python "$SCRIPT_DIR/python/builder.py"
