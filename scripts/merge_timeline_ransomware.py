#!/usr/bin/env python3
"""
merge_timeline_ransomware.py - Merge Timeline data with Ransomware malware data.

This script simply concatenates the timeline events and ransomware malware entries
into a single dataset for unified analysis. Each row is tagged with its source.

Output: A merged dataset with all timeline events and ransomware entries.
"""
import pandas as pd
import os


# Input/Output paths
TIMELINE_PATH = 'data/Timeline_2016_2025.csv'
RANSOMWARE_PATH = 'data/Malware_Ransomware_2016_2025.csv'
OUTPUT_PATH = 'data/Timeline_Ransomware_Merged.csv'


def read_csv_skip_comments(filepath):
    """Read a CSV file, skipping comment lines."""
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return None
    
    # Read lines and skip comments
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = [line for line in f if not line.strip().startswith('#')]
    
    if not lines:
        return None
    
    # Parse with pandas
    from io import StringIO
    return pd.read_csv(StringIO(''.join(lines)))


def main():
    """Main function to merge timeline and ransomware data."""
    print("Reading input files...")
    
    # Read timeline data
    timeline_df = read_csv_skip_comments(TIMELINE_PATH)
    if timeline_df is None or timeline_df.empty:
        print(f"Error: No data found in {TIMELINE_PATH}")
        print("Please run merge_timeline.py first to create the merged timeline file.")
        return
    print(f"  Timeline: {len(timeline_df)} events")
    
    # Read ransomware data
    ransomware_df = read_csv_skip_comments(RANSOMWARE_PATH)
    if ransomware_df is None or ransomware_df.empty:
        print(f"Error: No data found in {RANSOMWARE_PATH}")
        return
    print(f"  Ransomware: {len(ransomware_df)} entries")
    
    # Add source column to identify data origin
    timeline_df['source'] = 'timeline'
    ransomware_df['source'] = 'ransomware'
    
    # Rename columns to create a unified schema
    # Timeline columns: event_id, date, event_type, title, description, ...
    # Ransomware columns: incident_id, malware_family, category, first_seen, last_seen, ...
    
    # Create mapping for common concepts
    timeline_df = timeline_df.rename(columns={
        'event_id': 'id',
        'date': 'date',
        'event_type': 'type',
        'title': 'name',
        'description': 'description'
    })
    
    ransomware_df = ransomware_df.rename(columns={
        'incident_id': 'id',
        'malware_family': 'name',
        'category': 'type',
        'first_seen': 'date'  # Use first_seen as the primary date
    })
    
    # Concatenate the dataframes
    merged_df = pd.concat([timeline_df, ransomware_df], ignore_index=True, sort=False)
    
    # Sort by date
    merged_df['date'] = pd.to_datetime(merged_df['date'], errors='coerce')
    merged_df = merged_df.sort_values('date').reset_index(drop=True)
    
    # Write output
    output_dir = os.path.dirname(OUTPUT_PATH)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    merged_df.to_csv(OUTPUT_PATH, index=False)
    
    print(f"\nMerged data written to: {OUTPUT_PATH}")
    print(f"  Timeline events: {len(timeline_df)}")
    print(f"  Ransomware entries: {len(ransomware_df)}")
    print(f"  Total records: {len(merged_df)}")


if __name__ == '__main__':
    main()
