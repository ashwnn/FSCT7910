#!/usr/bin/env python3
import csv
import glob
import os

SRC_GLOB = 'data/raw/Timeline/*.csv'
OUTPUT_PATH = 'data/Timeline_2016_2025.csv'

def read_comment_lines(path):
    """Extract comment lines from the beginning of the file."""
    comments = []
    with open(path, newline='', encoding='utf-8') as f:
        for line in f:
            if line.startswith('#'):
                comments.append(line.rstrip('\n'))
            else:
                break
    return comments

def get_header(path):
    """Get the header row from a CSV file, skipping comment lines."""
    with open(path, newline='', encoding='utf-8') as f:
        for line in f:
            if not line.startswith('#'):
                return line.rstrip('\n')
    return None

def read_data_rows(path, fieldnames):
    """Read data rows from a CSV file, skipping comment lines and header."""
    rows = []
    with open(path, newline='', encoding='utf-8') as f:
        # Skip comment lines
        for line in f:
            if not line.startswith('#'):
                break
        
        # Use csv.DictReader for proper CSV parsing
        reader = csv.DictReader(f, fieldnames=fieldnames)
        for row in reader:
            # Skip empty rows and clean up None keys
            if row:
                # Remove any None keys that may appear from empty fields
                cleaned_row = {k: v for k, v in row.items() if k is not None}
                if any(cleaned_row.values()):
                    rows.append(cleaned_row)
    
    return rows

# Get all source files sorted by year
source_files = sorted(glob.glob(SRC_GLOB))

if not source_files:
    print(f"No files found matching pattern: {SRC_GLOB}")
    exit(1)

# Get header from first file
first_header = get_header(source_files[0])
if first_header is None:
    print("Error: Could not find header in first file.")
    exit(1)

fieldnames = [h.strip() for h in first_header.split(',')]

# Collect all data
all_rows = []
header = first_header
all_comments = read_comment_lines(source_files[0])

print(f"Processing {len(source_files)} Timeline files...")

for filepath in source_files:
    filename = os.path.basename(filepath)
    
    # Read data rows
    rows = read_data_rows(filepath, fieldnames)
    all_rows.extend(rows)
    print(f"  {filename}: {len(rows)} rows")

print(f"\nTotal rows collected: {len(all_rows)}")

# Write merged file
if all_rows and header:
    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_PATH) if os.path.dirname(OUTPUT_PATH) else '.', exist_ok=True)
    
    with open(OUTPUT_PATH, 'w', newline='', encoding='utf-8') as f:
        # Write comment lines
        for comment in all_comments:
            f.write(comment + '\n')
        
        # Write header
        f.write(header + '\n')
        
        # Write data rows
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        for row in all_rows:
            writer.writerow(row)
    
    print(f"\nMerged Timeline data written to: {OUTPUT_PATH}")
else:
    print("Error: No data or header found in source files.")
    exit(1)
