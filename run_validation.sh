#!/bin/bash
# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <json_input_file> <cddl_file>"
    exit 1
fi

# Assign arguments to variables
JSON_INPUT_FILE=$1
CDDL_FILE=$2

# Run the commands
python3 "diag_genarator.py" "$JSON_INPUT_FILE"
diag2cbor.rb diag_auto_gen.diag > out.cbor

# Capture the output of the cddl validate command
VALIDATION_OUTPUT=$(cddl "$CDDL_FILE" validate "out.cbor")

# Check if there is any output
if [ -z "$VALIDATION_OUTPUT" ]; then
    echo "Validated successfully"
else
    echo "$VALIDATION_OUTPUT"
fi