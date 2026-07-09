#!/bin/bash

# Check if input file is provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 <memory_dump_file>"
  exit 1
fi

DUMP_FILE="$1"
OUTPUT_DIR="extracted_certs"
COUNTER=1

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Check if input file exists
if [ ! -f "$DUMP_FILE" ]; then
  echo "Error: File '$DUMP_FILE' not found"
  exit 1
fi

# Extract strings and process certificates
strings "$DUMP_FILE" | awk '
  /-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/ {
    if ($0 ~ /-----BEGIN CERTIFICATE-----/) {
      cert=""
      in_cert=1
    }
    if (in_cert) {
      cert=cert $0 "\n"
    }
    if ($0 ~ /-----END CERTIFICATE-----/) {
      print cert > sprintf("%s/cert_%03d.pem", "'"$OUTPUT_DIR"'", ++cert_count)
      in_cert=0
    }
  }
'

# Check if any certificates were extracted
if [ -n "$(ls -A "$OUTPUT_DIR")" ]; then
  echo "Certificates extracted to '$OUTPUT_DIR':"
  ls "$OUTPUT_DIR"
else
  echo "No certificates found in '$DUMP_FILE'"
fi