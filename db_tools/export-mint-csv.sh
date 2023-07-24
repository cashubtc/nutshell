#!/bin/bash

db_filename="../data/mint/mint.sqlite3"
csv_export_dir="../data/export"

# Get unique id values
ids=$(sqlite3 $db_filename "SELECT DISTINCT id FROM promises;")

# Loop over unique id values
for id in $ids; do
  # Replace special characters in id to make it safe for filename
  safe_id=$(echo $id | tr -dc '[:alnum:]\n\r' | tr '[:upper:]' '[:lower:]')

  # Export data for this id value
  sqlite3 -cmd ".mode csv" -cmd ".headers on" -cmd ".output '$csv_export_dir/mints_$safe_id.csv'" $db_filename "SELECT amount, B_b AS B_, C_b AS C_, id FROM promises WHERE id='$id';"
done