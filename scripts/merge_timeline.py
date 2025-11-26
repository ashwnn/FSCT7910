#!/usr/bin/env python3
"""
merge_timeline.py - Merge all timeline CSV files into one clean file.

This script:
1. Reads all timeline CSV files from data/raw/Timeline/
2. Skips header comment lines (lines starting with #) and empty lines
3. Validates each row to ensure it has the expected number of columns
4. Cleans up special characters (like _x000D_ carriage returns)
5. Removes corrupted rows (rows with wrong number of columns)
6. Outputs the merged data to data/Timeline_2016_2025.csv
"""
import csv
import glob
import os
import re
import io

SRC_GLOB = 'data/raw/Timeline/*.csv'
OUTPUT_PATH = 'data/Timeline_2016_2025.csv'

# Expected column names for timeline data
EXPECTED_COLUMNS = [
    'event_id', 'date', 'event_type', 'title', 'description',
    'affected_software_or_ecosystem', 'cve_ids', 'related_malware_families',
    'potential_impact_on_malware', 'metrics', 'source_ids', 'confidence_score', 'notes'
]


def clean_text(text):
    """Clean up special characters from text."""
    if text is None:
        return ''
    # Remove _x000D_ (Excel carriage return encoding)
    text = re.sub(r'_x000D_\s*', ' ', str(text))
    # Remove actual carriage returns but preserve data
    text = text.replace('\r\n', ' ').replace('\r', ' ')
    # Clean up multiple spaces
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def fix_row_with_extra_columns(row, expected_count):
    """
    Attempt to fix a row with extra columns by merging overflow into description field.
    
    The issue is that some source CSV files have unquoted commas in the description field.
    This causes the row to have more columns than expected.
    
    Row structure:
    0: event_id, 1: date, 2: event_type, 3: title, 4: description,
    5: affected_software_or_ecosystem, 6: cve_ids, 7: related_malware_families,
    8: potential_impact_on_malware, 9: metrics, 10: source_ids, 11: confidence_score, 12: notes
    
    Heuristics to identify the split:
    - confidence_score should be a number (0.0-1.0)
    - metrics should start with { (JSON)
    - source_ids should be a URL or list
    """
    if len(row) <= expected_count:
        return row
    
    extra_count = len(row) - expected_count
    
    # Try to find the pattern from the end
    # Look for confidence_score (should be last or second-to-last numeric value 0-1)
    fixed_row = row.copy()
    
    # The last field should be 'notes', second-to-last 'confidence_score' (0.x format)
    # Try to identify where the description field ends
    
    # Strategy: Find the first field after index 4 that looks like it could be 
    # 'affected_software_or_ecosystem' (often N/A or a software name/CPE)
    # Or find 'metrics' field (starts with {)
    
    for i in range(5, len(row) - 4):
        potential_metrics = row[i]
        # If this looks like metrics (JSON object)
        if potential_metrics.strip().startswith('{'):
            # Everything from index 4 to i-4 should be merged into description
            # The fields before metrics are: description (4), affected_software (5), 
            # cve_ids (6), related_malware (7), potential_impact (8)
            # So metrics is at index 9, meaning we have indices 4-8 before it (5 fields)
            
            # Calculate how many fields should be merged into description
            # If metrics is at index i, and it should be at index 9
            # Then indices 4 through (i-5) should be merged into description
            # Actually the structure before metrics is:
            # description, affected_software, cve_ids, related_malware, potential_impact
            # So there should be 5 fields before metrics
            
            merge_end = i - 4  # Fields after position 4 that should be in description
            if merge_end > 5:
                # Merge fields 4 through merge_end into description
                merged_description = ', '.join(row[4:merge_end])
                fixed_row = row[:4] + [merged_description] + row[merge_end:]
                if len(fixed_row) == expected_count:
                    return fixed_row
    
    # Alternative strategy: try different merge points and see if we get 13 columns
    for merge_count in range(1, extra_count + 1):
        # Try merging 'merge_count' extra fields into description (field 4)
        merged_description = ', '.join(row[4:4 + merge_count + 1])
        test_row = row[:4] + [merged_description] + row[4 + merge_count + 1:]
        if len(test_row) == expected_count:
            # Validate the result looks correct
            # Check if field at index 9 (metrics) looks like JSON
            if len(test_row) > 9 and test_row[9].strip().startswith('{'):
                return test_row
            # Check if field at index 11 (confidence_score) looks like a number
            if len(test_row) > 11:
                try:
                    score = float(test_row[11].strip())
                    if 0 <= score <= 1:
                        return test_row
                except (ValueError, TypeError):
                    pass
            # If no clear validation, still return this attempt
            return test_row
    
    return row  # Return original if we can't fix it


def read_and_clean_file(filepath):
    """
    Read a timeline CSV file, skip comments and empty lines,
    and return cleaned data rows.
    """
    cleaned_rows = []
    skipped_rows = []
    
    # Read raw file content in binary mode to handle line endings properly
    with open(filepath, 'rb') as f:
        raw_bytes = f.read()
    
    # Decode to string
    raw_content = raw_bytes.decode('utf-8')
    
    # First, clean up the _x000D_ patterns that cause multi-line issues
    # This pattern appears to be Excel's encoding for carriage returns within cells
    raw_content = re.sub(r'_x000D_[\r\n]*', ' ', raw_content)
    
    # Normalize line endings
    raw_content = raw_content.replace('\r\n', '\n').replace('\r', '\n')
    
    # Split into lines, handling the comment lines first
    all_lines = raw_content.split('\n')
    non_comment_lines = []
    for line in all_lines:
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        non_comment_lines.append(line)
    
    if not non_comment_lines:
        return [], []
    
    # Join back with proper line endings for CSV parsing
    csv_content = '\n'.join(non_comment_lines)
    
    # Parse with csv module - it will handle quoted fields properly
    reader = csv.reader(io.StringIO(csv_content))
    
    rows_list = list(reader)
    if not rows_list:
        return [], []
    
    # First row should be header
    header_row = rows_list[0]
    if header_row[0].lower() == 'event_id':
        # Skip header
        data_rows = rows_list[1:]
    else:
        data_rows = rows_list
    
    for row_num, row in enumerate(data_rows, start=1):
        # Try to fix rows with extra columns
        if len(row) > len(EXPECTED_COLUMNS):
            row = fix_row_with_extra_columns(row, len(EXPECTED_COLUMNS))
        
        # Validate row has expected number of columns
        if len(row) == len(EXPECTED_COLUMNS):
            # Clean each cell
            cleaned_row = {
                col: clean_text(val) 
                for col, val in zip(EXPECTED_COLUMNS, row)
            }
            # Check if the row has required data (at least event_id and date)
            if cleaned_row.get('event_id') and cleaned_row.get('date'):
                cleaned_rows.append(cleaned_row)
            else:
                skipped_rows.append((row_num, 'Missing required fields (event_id or date)', row))
        else:
            skipped_rows.append((row_num, f'Wrong column count: expected {len(EXPECTED_COLUMNS)}, got {len(row)}', row))
    
    return cleaned_rows, skipped_rows


def main():
    """Main function to merge all timeline files."""
    # Get all source files sorted by year
    source_files = sorted(glob.glob(SRC_GLOB))
    
    if not source_files:
        print(f"No files found matching pattern: {SRC_GLOB}")
        exit(1)
    
    print(f"Processing {len(source_files)} Timeline files...")
    print(f"Expected columns: {len(EXPECTED_COLUMNS)}")
    print()
    
    all_rows = []
    total_skipped = 0
    
    for filepath in source_files:
        filename = os.path.basename(filepath)
        
        rows, skipped = read_and_clean_file(filepath)
        all_rows.extend(rows)
        
        print(f"  {filename}: {len(rows)} valid rows", end='')
        if skipped:
            print(f", {len(skipped)} corrupted rows removed")
            total_skipped += len(skipped)
            # Optionally print details of skipped rows
            for row_num, reason, data in skipped[:3]:  # Show first 3
                print(f"    - Row {row_num}: {reason}")
            if len(skipped) > 3:
                print(f"    - ... and {len(skipped) - 3} more")
        else:
            print()
    
    print()
    print(f"Total valid rows collected: {len(all_rows)}")
    print(f"Total corrupted rows removed: {total_skipped}")
    
    # Write merged file
    if all_rows:
        # Ensure output directory exists
        output_dir = os.path.dirname(OUTPUT_PATH)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(OUTPUT_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=EXPECTED_COLUMNS)
            writer.writeheader()
            for row in all_rows:
                writer.writerow(row)
        
        print(f"\nMerged Timeline data written to: {OUTPUT_PATH}")
        print(f"Total records: {len(all_rows)}")
    else:
        print("Error: No valid data found in source files.")
        exit(1)


if __name__ == '__main__':
    main()
