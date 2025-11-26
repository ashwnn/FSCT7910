#!/usr/bin/env python3
"""
generate_paper_metrics.py - Generate metrics and analysis for the malware evolution paper.

This script analyzes the merged timeline and malware data to produce metrics for the paper:
"Malware Evasion and Defense: A 2016-2025 Timeline Analysis"

Metrics generated:
1. Event cadence - frequency of events per year
2. Patch-to-exploit lag - days between CVE publication and first malware exploitation
3. Active duration - lifespan of malware families
4. Technique breadth - unique MITRE ATT&CK techniques per family
5. Technique diversity - overall technique distribution
6. Double-extortion prevalence - percentage of ransomware using double extortion
7. Comparison between ransomware and botnets

Output: Console summary, CSV tables, and text report for paper inclusion.
"""
import pandas as pd
import numpy as np
import os
import re
import json
from datetime import datetime
from collections import Counter
from io import StringIO


# Input paths
TIMELINE_PATH = 'data/Timeline_2016_2025.csv'
BOTNET_PATH = 'data/Malware_Botnet_2016_2025.csv'
RANSOMWARE_PATH = 'data/Malware_Ransomware_2016_2025.csv'

# Output paths
OUTPUT_DIR = 'analysis'
METRICS_REPORT_PATH = os.path.join(OUTPUT_DIR, 'paper_metrics_report.txt')
EVENT_CADENCE_PATH = os.path.join(OUTPUT_DIR, 'event_cadence.csv')
MALWARE_DURATION_PATH = os.path.join(OUTPUT_DIR, 'malware_duration.csv')
TECHNIQUE_BREADTH_PATH = os.path.join(OUTPUT_DIR, 'technique_breadth.csv')
SUMMARY_STATS_PATH = os.path.join(OUTPUT_DIR, 'summary_statistics.csv')


def read_csv_skip_comments(filepath):
    """Read a CSV file, skipping comment lines."""
    if not os.path.exists(filepath):
        print(f"Warning: File not found: {filepath}")
        return None
    
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = [line for line in f if not line.strip().startswith('#')]
    
    if not lines:
        return None
    
    return pd.read_csv(StringIO(''.join(lines)))


def parse_list_field(value):
    """Parse a field that may contain a list in various formats."""
    if pd.isna(value) or str(value).strip().upper() in ('N/A', 'NA', '[]', ''):
        return []
    
    value = str(value).strip()
    
    # Try JSON format
    if value.startswith('['):
        try:
            items = json.loads(value.replace("'", '"'))
            return [str(item).strip() for item in items if item]
        except (json.JSONDecodeError, TypeError):
            value = value.strip('[]"\'')
    
    # Try semicolon-separated
    if ';' in value:
        items = value.split(';')
    elif ',' in value and not value.startswith('{'):
        items = value.split(',')
    else:
        items = [value]
    
    return [item.strip().strip('"\'') for item in items if item.strip()]


def extract_mitre_techniques(value):
    """Extract MITRE ATT&CK technique IDs from a field."""
    if pd.isna(value):
        return []
    
    value = str(value)
    # Match patterns like T1059, T1059.001, T1059.005
    pattern = r'T\d{4}(?:\.\d{3})?'
    matches = re.findall(pattern, value)
    return list(set(matches))


def parse_date(date_str):
    """Parse a date string in various formats."""
    if pd.isna(date_str) or str(date_str).strip().upper() in ('N/A', 'NA', 'ONGOING', ''):
        return None
    
    date_str = str(date_str).strip()
    
    formats = ['%Y-%m-%d', '%Y/%m/%d', '%d-%m-%Y', '%m/%d/%Y', '%Y-%m', '%Y']
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    return None


def calculate_event_cadence(timeline_df):
    """Calculate event frequency per year."""
    if timeline_df is None or timeline_df.empty:
        return pd.DataFrame()
    
    timeline_df['date'] = pd.to_datetime(timeline_df['date'], errors='coerce')
    timeline_df['year'] = timeline_df['date'].dt.year
    
    # Count by year and event type
    cadence = timeline_df.groupby(['year', 'event_type']).size().unstack(fill_value=0)
    cadence['total'] = cadence.sum(axis=1)
    
    return cadence


def calculate_active_duration(malware_df, category_name):
    """Calculate active duration for each malware family."""
    if malware_df is None or malware_df.empty:
        return pd.DataFrame()
    
    results = []
    
    for _, row in malware_df.iterrows():
        family = row.get('malware_family', 'Unknown')
        first_seen = parse_date(row.get('first_seen', ''))
        last_seen = parse_date(row.get('last_seen', ''))
        
        if first_seen:
            if last_seen:
                duration_days = (last_seen - first_seen).days
                status = 'ended'
            else:
                # Assume ongoing until today
                duration_days = (datetime.now() - first_seen).days
                status = 'ongoing'
            
            results.append({
                'malware_family': family,
                'category': category_name,
                'first_seen': first_seen.strftime('%Y-%m-%d') if first_seen else '',
                'last_seen': last_seen.strftime('%Y-%m-%d') if last_seen else 'ongoing',
                'duration_days': duration_days,
                'duration_years': round(duration_days / 365.25, 1),
                'status': status
            })
    
    return pd.DataFrame(results)


def calculate_technique_breadth(malware_df, category_name):
    """Calculate MITRE ATT&CK technique breadth per malware family."""
    if malware_df is None or malware_df.empty:
        return pd.DataFrame()
    
    results = []
    
    for _, row in malware_df.iterrows():
        family = row.get('malware_family', 'Unknown')
        
        # Extract techniques from multiple columns
        techniques = set()
        
        # From mitre_attack_ids column
        mitre_ids = row.get('mitre_attack_ids', '')
        techniques.update(extract_mitre_techniques(mitre_ids))
        
        # From tactics_techniques column
        tactics = row.get('tactics_techniques', '')
        techniques.update(extract_mitre_techniques(tactics))
        
        results.append({
            'malware_family': family,
            'category': category_name,
            'technique_count': len(techniques),
            'techniques': '; '.join(sorted(techniques))
        })
    
    return pd.DataFrame(results)


def calculate_double_extortion_prevalence(ransomware_df):
    """Calculate the prevalence of double extortion in ransomware."""
    if ransomware_df is None or ransomware_df.empty:
        return {'total': 0, 'double_extortion': 0, 'percentage': 0.0}
    
    total = len(ransomware_df)
    
    # Look for double extortion indicators in various columns
    double_extortion_count = 0
    
    for _, row in ransomware_df.iterrows():
        is_double = False
        
        # Check technical_traits for double_extortion
        traits = str(row.get('technical_traits', '')).lower()
        if 'double' in traits and 'extortion' in traits:
            is_double = True
        if '"double_extortion": true' in traits or '"double_extortion":true' in traits:
            is_double = True
        
        # Check tactics_techniques
        tactics = str(row.get('tactics_techniques', '')).lower()
        if 'double extortion' in tactics or 'data exfiltration' in tactics:
            is_double = True
        
        # Check notes
        notes = str(row.get('notes', '')).lower()
        if 'double extortion' in notes or 'double-extortion' in notes:
            is_double = True
        if 'data leak' in notes or 'leak site' in notes:
            is_double = True
        
        if is_double:
            double_extortion_count += 1
    
    return {
        'total': total,
        'double_extortion': double_extortion_count,
        'percentage': round(double_extortion_count / total * 100, 1) if total > 0 else 0.0
    }


def calculate_patch_to_exploit_lag(timeline_df, malware_df):
    """
    Calculate the lag between CVE patch dates and first exploitation.
    Uses timeline events with CVE information and malware first_seen dates.
    """
    if timeline_df is None or malware_df is None:
        return pd.DataFrame()
    
    results = []
    
    # Build a map of CVEs to their disclosure dates from timeline
    cve_dates = {}
    for _, row in timeline_df.iterrows():
        cve_ids = str(row.get('cve_ids', ''))
        event_date = parse_date(row.get('date', ''))
        
        if event_date:
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', cve_ids.upper())
            for cve in cves:
                if cve not in cve_dates:
                    cve_dates[cve] = event_date
    
    # Check malware entries for exploited CVEs
    for _, row in malware_df.iterrows():
        family = row.get('malware_family', 'Unknown')
        first_seen = parse_date(row.get('first_seen', ''))
        exploited_cves = str(row.get('exploited_cves', ''))
        
        if first_seen:
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', exploited_cves.upper())
            
            for cve in cves:
                if cve in cve_dates:
                    patch_date = cve_dates[cve]
                    lag_days = (first_seen - patch_date).days
                    
                    results.append({
                        'cve': cve,
                        'malware_family': family,
                        'patch_date': patch_date.strftime('%Y-%m-%d'),
                        'first_exploit_date': first_seen.strftime('%Y-%m-%d'),
                        'lag_days': lag_days
                    })
    
    return pd.DataFrame(results)


def generate_comparison_table(botnet_df, ransomware_df):
    """Generate a comparison table between botnets and ransomware."""
    
    botnet_techniques = calculate_technique_breadth(botnet_df, 'Botnet')
    ransomware_techniques = calculate_technique_breadth(ransomware_df, 'Ransomware')
    
    botnet_duration = calculate_active_duration(botnet_df, 'Botnet')
    ransomware_duration = calculate_active_duration(ransomware_df, 'Ransomware')
    
    comparison = {
        'Metric': [],
        'Botnets': [],
        'Ransomware': []
    }
    
    # Family count
    comparison['Metric'].append('Total Families')
    comparison['Botnets'].append(len(botnet_df) if botnet_df is not None else 0)
    comparison['Ransomware'].append(len(ransomware_df) if ransomware_df is not None else 0)
    
    # Technique breadth
    if not botnet_techniques.empty:
        comparison['Metric'].append('Mean Technique Count')
        comparison['Botnets'].append(round(botnet_techniques['technique_count'].mean(), 1))
        comparison['Ransomware'].append(round(ransomware_techniques['technique_count'].mean(), 1) if not ransomware_techniques.empty else 0)
        
        comparison['Metric'].append('Technique Count Range')
        comparison['Botnets'].append(f"{botnet_techniques['technique_count'].min()}-{botnet_techniques['technique_count'].max()}")
        comparison['Ransomware'].append(f"{ransomware_techniques['technique_count'].min()}-{ransomware_techniques['technique_count'].max()}" if not ransomware_techniques.empty else "N/A")
    
    # Duration
    if not botnet_duration.empty:
        comparison['Metric'].append('Mean Duration (years)')
        comparison['Botnets'].append(round(botnet_duration['duration_years'].mean(), 1))
        comparison['Ransomware'].append(round(ransomware_duration['duration_years'].mean(), 1) if not ransomware_duration.empty else 0)
        
        comparison['Metric'].append('Max Duration (years)')
        comparison['Botnets'].append(round(botnet_duration['duration_years'].max(), 1))
        comparison['Ransomware'].append(round(ransomware_duration['duration_years'].max(), 1) if not ransomware_duration.empty else 0)
        
        # Ongoing count
        comparison['Metric'].append('Ongoing Families')
        comparison['Botnets'].append(len(botnet_duration[botnet_duration['status'] == 'ongoing']))
        comparison['Ransomware'].append(len(ransomware_duration[ransomware_duration['status'] == 'ongoing']) if not ransomware_duration.empty else 0)
    
    return pd.DataFrame(comparison)


def main():
    """Main function to generate all metrics."""
    print("=" * 70)
    print("MALWARE EVOLUTION PAPER METRICS GENERATOR")
    print("=" * 70)
    print()
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Read data
    print("Reading data files...")
    timeline_df = read_csv_skip_comments(TIMELINE_PATH)
    botnet_df = read_csv_skip_comments(BOTNET_PATH)
    ransomware_df = read_csv_skip_comments(RANSOMWARE_PATH)
    
    print(f"  Timeline events: {len(timeline_df) if timeline_df is not None else 0}")
    print(f"  Botnet families: {len(botnet_df) if botnet_df is not None else 0}")
    print(f"  Ransomware families: {len(ransomware_df) if ransomware_df is not None else 0}")
    print()
    
    # Open report file
    report_lines = []
    
    def report(text):
        print(text)
        report_lines.append(text)
    
    # =========================================================================
    # 1. EVENT CADENCE
    # =========================================================================
    report("-" * 70)
    report("1. EVENT CADENCE (Timeline Events per Year)")
    report("-" * 70)
    
    event_cadence = calculate_event_cadence(timeline_df)
    if not event_cadence.empty:
        report(event_cadence.to_string())
        event_cadence.to_csv(EVENT_CADENCE_PATH)
        report(f"\nSaved to: {EVENT_CADENCE_PATH}")
    report("")
    
    # =========================================================================
    # 2. ACTIVE DURATION
    # =========================================================================
    report("-" * 70)
    report("2. MALWARE ACTIVE DURATION")
    report("-" * 70)
    
    botnet_duration = calculate_active_duration(botnet_df, 'Botnet')
    ransomware_duration = calculate_active_duration(ransomware_df, 'Ransomware')
    
    all_duration = pd.concat([botnet_duration, ransomware_duration], ignore_index=True)
    if not all_duration.empty:
        # Sort by duration
        all_duration = all_duration.sort_values('duration_years', ascending=False)
        report("\nTop 10 Longest-Running Malware:")
        report(all_duration[['malware_family', 'category', 'duration_years', 'status']].head(10).to_string(index=False))
        all_duration.to_csv(MALWARE_DURATION_PATH, index=False)
        report(f"\nSaved to: {MALWARE_DURATION_PATH}")
    report("")
    
    # =========================================================================
    # 3. TECHNIQUE BREADTH
    # =========================================================================
    report("-" * 70)
    report("3. MITRE ATT&CK TECHNIQUE BREADTH")
    report("-" * 70)
    
    botnet_techniques = calculate_technique_breadth(botnet_df, 'Botnet')
    ransomware_techniques = calculate_technique_breadth(ransomware_df, 'Ransomware')
    
    all_techniques = pd.concat([botnet_techniques, ransomware_techniques], ignore_index=True)
    if not all_techniques.empty:
        all_techniques = all_techniques.sort_values('technique_count', ascending=False)
        report("\nTechnique Count by Family:")
        report(all_techniques[['malware_family', 'category', 'technique_count']].to_string(index=False))
        all_techniques.to_csv(TECHNIQUE_BREADTH_PATH, index=False)
        report(f"\nSaved to: {TECHNIQUE_BREADTH_PATH}")
        
        report("\nSummary Statistics:")
        report(f"  Botnets - Mean: {botnet_techniques['technique_count'].mean():.1f}, "
               f"Range: {botnet_techniques['technique_count'].min()}-{botnet_techniques['technique_count'].max()}")
        report(f"  Ransomware - Mean: {ransomware_techniques['technique_count'].mean():.1f}, "
               f"Range: {ransomware_techniques['technique_count'].min()}-{ransomware_techniques['technique_count'].max()}")
    report("")
    
    # =========================================================================
    # 4. DOUBLE EXTORTION PREVALENCE
    # =========================================================================
    report("-" * 70)
    report("4. DOUBLE EXTORTION PREVALENCE (Ransomware)")
    report("-" * 70)
    
    double_extortion = calculate_double_extortion_prevalence(ransomware_df)
    report(f"  Total ransomware families: {double_extortion['total']}")
    report(f"  With double extortion: {double_extortion['double_extortion']}")
    report(f"  Prevalence: {double_extortion['percentage']}%")
    report("")
    
    # =========================================================================
    # 5. PATCH-TO-EXPLOIT LAG
    # =========================================================================
    report("-" * 70)
    report("5. PATCH-TO-EXPLOIT LAG (CVE to First Exploitation)")
    report("-" * 70)
    
    # Combine malware data for lag analysis
    all_malware = pd.concat([botnet_df, ransomware_df], ignore_index=True) if botnet_df is not None and ransomware_df is not None else (botnet_df if botnet_df is not None else ransomware_df)
    
    lag_data = calculate_patch_to_exploit_lag(timeline_df, all_malware)
    if not lag_data.empty:
        report("\nCVE Exploitation Lag:")
        report(lag_data.to_string(index=False))
        
        report(f"\nMean patch-to-exploit lag: {lag_data['lag_days'].mean():.1f} days")
        report(f"Median patch-to-exploit lag: {lag_data['lag_days'].median():.1f} days")
        report(f"Range: {lag_data['lag_days'].min()} to {lag_data['lag_days'].max()} days")
    else:
        report("  No matching CVE data found for lag analysis.")
    report("")
    
    # =========================================================================
    # 6. COMPARISON TABLE
    # =========================================================================
    report("-" * 70)
    report("6. BOTNET vs RANSOMWARE COMPARISON")
    report("-" * 70)
    
    comparison = generate_comparison_table(botnet_df, ransomware_df)
    report(comparison.to_string(index=False))
    report("")
    
    # =========================================================================
    # 7. SUMMARY STATISTICS FOR PAPER
    # =========================================================================
    report("-" * 70)
    report("7. SUMMARY STATISTICS FOR PAPER")
    report("-" * 70)
    
    summary_stats = []
    
    # Timeline stats
    if timeline_df is not None:
        summary_stats.append({'metric': 'Total Timeline Events', 'value': len(timeline_df)})
        summary_stats.append({'metric': 'Timeline Date Range', 
                             'value': f"{timeline_df['date'].min()} to {timeline_df['date'].max()}"})
    
    # Malware stats
    if botnet_df is not None:
        summary_stats.append({'metric': 'Botnet Families Analyzed', 'value': len(botnet_df)})
    if ransomware_df is not None:
        summary_stats.append({'metric': 'Ransomware Families Analyzed', 'value': len(ransomware_df)})
    
    # Technique stats
    if not botnet_techniques.empty:
        summary_stats.append({'metric': 'Botnet Technique Breadth (range)', 
                             'value': f"{botnet_techniques['technique_count'].min()}-{botnet_techniques['technique_count'].max()}"})
    if not ransomware_techniques.empty:
        summary_stats.append({'metric': 'Ransomware Technique Breadth (range)', 
                             'value': f"{ransomware_techniques['technique_count'].min()}-{ransomware_techniques['technique_count'].max()}"})
    
    # Double extortion
    summary_stats.append({'metric': 'Double Extortion Prevalence', 
                         'value': f"{double_extortion['percentage']}%"})
    
    # Lag stats
    if not lag_data.empty:
        summary_stats.append({'metric': 'Mean Patch-to-Exploit Lag (days)', 
                             'value': f"{lag_data['lag_days'].mean():.1f}"})
    
    # Duration stats
    if not all_duration.empty:
        longest = all_duration.iloc[0]
        summary_stats.append({'metric': 'Longest Active Malware', 
                             'value': f"{longest['malware_family']} ({longest['duration_years']} years)"})
    
    summary_df = pd.DataFrame(summary_stats)
    report(summary_df.to_string(index=False))
    summary_df.to_csv(SUMMARY_STATS_PATH, index=False)
    report(f"\nSaved to: {SUMMARY_STATS_PATH}")
    
    # Save full report
    with open(METRICS_REPORT_PATH, 'w') as f:
        f.write('\n'.join(report_lines))
    
    print()
    print("=" * 70)
    print(f"Full report saved to: {METRICS_REPORT_PATH}")
    print("=" * 70)


if __name__ == '__main__':
    main()
