#!/usr/bin/env python3
"""
generate_graphs.py - Generate visualizations for the malware evolution paper.

This script creates publication-ready graphs for the paper:
"Malware Evasion and Defense: A 2016-2025 Timeline Analysis"

Graphs generated:
1.  Timeline event cadence (stacked bar chart by year)
2.  Malware family active duration comparison (horizontal bar chart)
3.  MITRE ATT&CK technique breadth comparison (improved multi-panel visualization)
4.  Malware emergence timeline (scatter/timeline plot)
5.  Botnet vs Ransomware comparison (grouped bar chart)
6.  Event type distribution (pie chart)
7.  Top techniques heatmap
8.  Double extortion prevalence over time (line/area chart)
9.  Yearly malware emergence (stacked area chart)
10. Propagation vectors comparison (grouped bar chart)
11. Victim industry analysis (bar chart + pie chart)
12. Malware infection chains (flow diagram)
13. RaaS evolution (bar + stacked area chart)
14. CVE exploitation timeline (scatter plot)
15. Law enforcement impact (bar chart + timeline)
16. Persistence mechanisms comparison (grouped bar chart)

Output: PNG and PDF files in analysis/graphs/
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import Patch
import os
import re
import json
from datetime import datetime
from collections import Counter
from io import StringIO


# Configure matplotlib for publication quality
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({
    'font.size': 11,
    'axes.titlesize': 14,
    'axes.labelsize': 12,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 16,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1
})

# Color schemes
COLORS = {
    'botnet': '#3498db',      # Blue
    'ransomware': '#e74c3c',  # Red
    'timeline': '#2ecc71',    # Green
    'primary': '#9b59b6',     # Purple
    'secondary': '#f39c12',   # Orange
    'neutral': '#95a5a6'      # Gray
}

CATEGORY_COLORS = {
    'Botnet': COLORS['botnet'],
    'Ransomware': COLORS['ransomware']
}

# Paths
TIMELINE_PATH = 'data/Timeline_2016_2025.csv'
BOTNET_PATH = 'data/Malware_Botnet_2016_2025.csv'
RANSOMWARE_PATH = 'data/Malware_Ransomware_2016_2025.csv'
OUTPUT_DIR = 'analysis/graphs'


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


def extract_mitre_techniques(value):
    """Extract MITRE ATT&CK technique IDs from a field."""
    if pd.isna(value):
        return []
    value = str(value)
    pattern = r'T\d{4}(?:\.\d{3})?'
    matches = re.findall(pattern, value)
    return list(set(matches))


def save_figure(fig, name, formats=['png', 'pdf']):
    """Save figure in multiple formats."""
    for fmt in formats:
        filepath = os.path.join(OUTPUT_DIR, f'{name}.{fmt}')
        fig.savefig(filepath, format=fmt)
        print(f"  Saved: {filepath}")


# =============================================================================
# GRAPH 1: Event Cadence by Year (Stacked Bar Chart)
# =============================================================================
def plot_event_cadence(timeline_df):
    """Create stacked bar chart showing event types per year."""
    if timeline_df is None or timeline_df.empty:
        print("  Skipping: No timeline data")
        return
    
    timeline_df['date'] = pd.to_datetime(timeline_df['date'], errors='coerce')
    timeline_df['year'] = timeline_df['date'].dt.year
    
    # Get event type counts by year
    pivot = timeline_df.groupby(['year', 'event_type']).size().unstack(fill_value=0)
    
    # Select top event types for readability
    top_types = pivot.sum().nlargest(8).index.tolist()
    pivot_filtered = pivot[top_types]
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Color palette
    colors = plt.cm.Set3(np.linspace(0, 1, len(top_types)))
    
    pivot_filtered.plot(kind='bar', stacked=True, ax=ax, color=colors, edgecolor='white', linewidth=0.5)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of Events')
    ax.set_title('Timeline Event Cadence by Year (2016-2025)')
    ax.legend(title='Event Type', bbox_to_anchor=(1.02, 1), loc='upper left', fontsize=9)
    
    # Rotate x-axis labels
    plt.xticks(rotation=45, ha='right')
    
    # Add total counts on top of bars
    for i, year in enumerate(pivot_filtered.index):
        total = pivot_filtered.loc[year].sum()
        ax.annotate(f'{int(total)}', xy=(i, total), ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    save_figure(fig, 'event_cadence_by_year')
    plt.close()


# =============================================================================
# GRAPH 2: Malware Active Duration (Horizontal Bar Chart)
# =============================================================================
def plot_malware_duration(botnet_df, ransomware_df):
    """Create horizontal bar chart showing malware active duration."""
    
    def get_durations(df, category):
        if df is None or df.empty:
            return []
        results = []
        seen = set()
        for _, row in df.iterrows():
            family = row.get('malware_family', 'Unknown')
            if family in seen:
                continue
            seen.add(family)
            
            first_seen = parse_date(row.get('first_seen', ''))
            last_seen = parse_date(row.get('last_seen', ''))
            
            if first_seen:
                if last_seen:
                    duration_years = (last_seen - first_seen).days / 365.25
                    status = 'Ended'
                else:
                    duration_years = (datetime.now() - first_seen).days / 365.25
                    status = 'Ongoing'
                
                results.append({
                    'family': family,
                    'category': category,
                    'duration': duration_years,
                    'status': status,
                    'first_seen': first_seen
                })
        return results
    
    botnet_durations = get_durations(botnet_df, 'Botnet')
    ransomware_durations = get_durations(ransomware_df, 'Ransomware')
    
    all_durations = botnet_durations + ransomware_durations
    if not all_durations:
        print("  Skipping: No duration data")
        return
    
    # Sort by duration and take top 20
    df = pd.DataFrame(all_durations).sort_values('duration', ascending=True).tail(20)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    colors = [CATEGORY_COLORS[cat] for cat in df['category']]
    bars = ax.barh(df['family'], df['duration'], color=colors, edgecolor='white', linewidth=0.5)
    
    # Add category legend
    legend_elements = [
        Patch(facecolor=COLORS['botnet'], label='Botnet'),
        Patch(facecolor=COLORS['ransomware'], label='Ransomware')
    ]
    ax.legend(handles=legend_elements, loc='lower right')
    
    ax.set_xlabel('Active Duration (Years)')
    ax.set_ylabel('Malware Family')
    ax.set_title('Top 20 Longest-Running Malware Families')
    
    # Add duration values on bars
    for bar, duration in zip(bars, df['duration']):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                f'{duration:.1f}', va='center', fontsize=9)
    
    plt.tight_layout()
    save_figure(fig, 'malware_duration_comparison')
    plt.close()


# =============================================================================
# GRAPH 3: Technique Breadth Comparison (Improved Violin + Strip Plot)
# =============================================================================
def plot_technique_breadth(botnet_df, ransomware_df):
    """Create improved visualization comparing technique breadth between categories."""
    
    def get_technique_counts(df, category):
        if df is None or df.empty:
            return []
        results = []
        seen = set()
        for _, row in df.iterrows():
            family = row.get('malware_family', 'Unknown')
            if family in seen:
                continue
            seen.add(family)
            
            techniques = set()
            mitre_ids = row.get('mitre_attack_ids', '')
            techniques.update(extract_mitre_techniques(mitre_ids))
            tactics = row.get('tactics_techniques', '')
            techniques.update(extract_mitre_techniques(tactics))
            
            if len(techniques) > 0:  # Only include families with techniques
                results.append({
                    'family': family,
                    'category': category,
                    'count': len(techniques)
                })
        return results
    
    botnet_data = get_technique_counts(botnet_df, 'Botnet')
    ransomware_data = get_technique_counts(ransomware_df, 'Ransomware')
    
    if not botnet_data and not ransomware_data:
        print("  Skipping: No technique data")
        return
    
    df = pd.DataFrame(botnet_data + ransomware_data)
    
    fig, axes = plt.subplots(1, 3, figsize=(16, 6), gridspec_kw={'width_ratios': [1, 1.5, 1.5]})
    
    # Panel 1: Summary Statistics Bar Chart
    ax1 = axes[0]
    categories = ['Botnet', 'Ransomware']
    means = [df[df['category'] == cat]['count'].mean() for cat in categories]
    stds = [df[df['category'] == cat]['count'].std() for cat in categories]
    maxs = [df[df['category'] == cat]['count'].max() for cat in categories]
    
    x = np.arange(len(categories))
    width = 0.35
    
    bars = ax1.bar(x, means, width, yerr=stds, capsize=5, 
                   color=[COLORS['botnet'], COLORS['ransomware']], 
                   edgecolor='white', alpha=0.8)
    
    # Add max indicators
    for i, (m, mx) in enumerate(zip(means, maxs)):
        ax1.scatter(i, mx, marker='v', color='darkred', s=100, zorder=5)
        ax1.annotate(f'max={mx}', xy=(i, mx), xytext=(0, 5), 
                    textcoords='offset points', ha='center', fontsize=9, fontweight='bold')
    
    ax1.set_ylabel('MITRE ATT&CK Techniques')
    ax1.set_xlabel('')
    ax1.set_xticks(x)
    ax1.set_xticklabels(categories)
    ax1.set_title('Average Technique Count\n(± Std Dev)', fontsize=11)
    
    # Add mean values on bars
    for bar, mean in zip(bars, means):
        ax1.annotate(f'{mean:.1f}', xy=(bar.get_x() + bar.get_width()/2, mean/2),
                    ha='center', va='center', fontsize=14, fontweight='bold', color='white')
    
    # Panel 2: Distribution Strip Plot with Jitter
    ax2 = axes[1]
    
    for i, cat in enumerate(categories):
        cat_data = df[df['category'] == cat]
        jitter = np.random.uniform(-0.15, 0.15, len(cat_data))
        color = COLORS['botnet'] if cat == 'Botnet' else COLORS['ransomware']
        
        ax2.scatter(i + jitter, cat_data['count'], 
                   alpha=0.6, s=80, c=color, edgecolor='white', linewidth=0.5)
        
        # Add family labels for outliers (top 3 per category)
        top_families = cat_data.nlargest(3, 'count')
        for _, row in top_families.iterrows():
            idx = cat_data[cat_data['family'] == row['family']].index[0]
            jit_val = jitter[list(cat_data.index).index(idx)]
            ax2.annotate(row['family'], xy=(i + jit_val, row['count']),
                        xytext=(5, 0), textcoords='offset points',
                        fontsize=8, alpha=0.8, fontweight='bold')
    
    # Add mean line
    for i, cat in enumerate(categories):
        mean_val = df[df['category'] == cat]['count'].mean()
        ax2.hlines(mean_val, i - 0.3, i + 0.3, colors='black', linestyles='--', linewidth=2)
    
    ax2.set_xticks([0, 1])
    ax2.set_xticklabels(categories)
    ax2.set_ylabel('Number of MITRE ATT&CK Techniques')
    ax2.set_title('Technique Count Distribution\n(Each point = one malware family)', fontsize=11)
    ax2.set_xlim(-0.5, 1.5)
    
    # Panel 3: Histogram Comparison
    ax3 = axes[2]
    
    bins = range(0, max(df['count']) + 2)
    
    botnet_counts = df[df['category'] == 'Botnet']['count']
    ransomware_counts = df[df['category'] == 'Ransomware']['count']
    
    ax3.hist(botnet_counts, bins=bins, alpha=0.7, label='Botnet', 
             color=COLORS['botnet'], edgecolor='white', align='left')
    ax3.hist(ransomware_counts, bins=bins, alpha=0.7, label='Ransomware', 
             color=COLORS['ransomware'], edgecolor='white', align='left')
    
    ax3.set_xlabel('Number of MITRE ATT&CK Techniques')
    ax3.set_ylabel('Number of Malware Families')
    ax3.set_title('Technique Count Frequency\nDistribution', fontsize=11)
    ax3.legend(loc='upper right')
    ax3.set_xticks(range(0, max(df['count']) + 1))
    
    plt.suptitle('MITRE ATT&CK Technique Breadth: Botnet vs Ransomware Comparison', 
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    save_figure(fig, 'technique_breadth_comparison')
    plt.close()


# =============================================================================
# GRAPH 4: Malware Emergence Timeline
# =============================================================================
def plot_emergence_timeline(botnet_df, ransomware_df):
    """Create timeline scatter plot of malware emergence."""
    
    def get_emergence_data(df, category):
        if df is None or df.empty:
            return []
        results = []
        seen = set()
        for _, row in df.iterrows():
            family = row.get('malware_family', 'Unknown')
            if family in seen:
                continue
            seen.add(family)
            
            first_seen = parse_date(row.get('first_seen', ''))
            if first_seen and first_seen.year >= 2014:
                results.append({
                    'family': family,
                    'category': category,
                    'first_seen': first_seen
                })
        return results
    
    botnet_data = get_emergence_data(botnet_df, 'Botnet')
    ransomware_data = get_emergence_data(ransomware_df, 'Ransomware')
    
    df = pd.DataFrame(botnet_data + ransomware_data)
    if df.empty:
        print("  Skipping: No emergence data")
        return
    
    df['year'] = df['first_seen'].dt.year
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Plot by category with offset for visibility
    for i, (cat, group) in enumerate(df.groupby('category')):
        y_offset = i * 0.3
        ax.scatter(group['first_seen'], [y_offset] * len(group), 
                   c=CATEGORY_COLORS[cat], s=100, alpha=0.7, label=cat, edgecolor='white')
        
        # Add family labels for major ones
        for _, row in group.iterrows():
            ax.annotate(row['family'], 
                       xy=(row['first_seen'], y_offset),
                       xytext=(0, 10 + (i * 5)), 
                       textcoords='offset points',
                       fontsize=8, rotation=45, ha='left',
                       alpha=0.8)
    
    ax.set_xlabel('First Seen Date')
    ax.set_ylabel('')
    ax.set_title('Malware Family Emergence Timeline (2014-2025)')
    ax.legend(loc='upper left')
    
    # Format x-axis
    ax.xaxis.set_major_locator(mdates.YearLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y'))
    plt.xticks(rotation=45)
    
    # Remove y-axis ticks
    ax.set_yticks([])
    
    # Add vertical lines for years
    for year in range(2014, 2026):
        ax.axvline(datetime(year, 1, 1), color='gray', linestyle='--', alpha=0.3)
    
    plt.tight_layout()
    save_figure(fig, 'malware_emergence_timeline')
    plt.close()


# =============================================================================
# GRAPH 5: Botnet vs Ransomware Comparison (Grouped Bar Chart)
# =============================================================================
def plot_category_comparison(botnet_df, ransomware_df):
    """Create grouped bar chart comparing key metrics."""
    
    # Calculate metrics
    metrics = {
        'Total Families': [0, 0],
        'Mean Technique\nCount': [0, 0],
        'Ongoing\nFamilies (%)': [0, 0]
    }
    
    # Botnet metrics
    if botnet_df is not None and not botnet_df.empty:
        metrics['Total Families'][0] = len(botnet_df.drop_duplicates('malware_family'))
        
        technique_counts = []
        ongoing_count = 0
        seen = set()
        for _, row in botnet_df.iterrows():
            family = row.get('malware_family')
            if family in seen:
                continue
            seen.add(family)
            
            techniques = set()
            techniques.update(extract_mitre_techniques(row.get('mitre_attack_ids', '')))
            techniques.update(extract_mitre_techniques(row.get('tactics_techniques', '')))
            technique_counts.append(len(techniques))
            
            if str(row.get('last_seen', '')).strip().upper() in ('ONGOING', 'N/A', ''):
                ongoing_count += 1
        
        if technique_counts:
            metrics['Mean Technique\nCount'][0] = np.mean(technique_counts)
        metrics['Ongoing\nFamilies (%)'][0] = (ongoing_count / len(seen)) * 100 if seen else 0
    
    # Ransomware metrics
    if ransomware_df is not None and not ransomware_df.empty:
        metrics['Total Families'][1] = len(ransomware_df.drop_duplicates('malware_family'))
        
        technique_counts = []
        ongoing_count = 0
        seen = set()
        for _, row in ransomware_df.iterrows():
            family = row.get('malware_family')
            if family in seen:
                continue
            seen.add(family)
            
            techniques = set()
            techniques.update(extract_mitre_techniques(row.get('mitre_attack_ids', '')))
            techniques.update(extract_mitre_techniques(row.get('tactics_techniques', '')))
            technique_counts.append(len(techniques))
            
            if str(row.get('last_seen', '')).strip().upper() in ('ONGOING', 'N/A', ''):
                ongoing_count += 1
        
        if technique_counts:
            metrics['Mean Technique\nCount'][1] = np.mean(technique_counts)
        metrics['Ongoing\nFamilies (%)'][1] = (ongoing_count / len(seen)) * 100 if seen else 0
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(metrics))
    width = 0.35
    
    botnet_vals = [metrics[k][0] for k in metrics]
    ransomware_vals = [metrics[k][1] for k in metrics]
    
    bars1 = ax.bar(x - width/2, botnet_vals, width, label='Botnets', color=COLORS['botnet'], edgecolor='white')
    bars2 = ax.bar(x + width/2, ransomware_vals, width, label='Ransomware', color=COLORS['ransomware'], edgecolor='white')
    
    ax.set_ylabel('Value')
    ax.set_title('Botnet vs Ransomware: Key Metrics Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(list(metrics.keys()))
    ax.legend()
    
    # Add value labels on bars
    def add_labels(bars):
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.1f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    add_labels(bars1)
    add_labels(bars2)
    
    plt.tight_layout()
    save_figure(fig, 'botnet_vs_ransomware_comparison')
    plt.close()


# =============================================================================
# GRAPH 6: Event Type Distribution (Pie Chart)
# =============================================================================
def plot_event_distribution(timeline_df):
    """Create pie chart of event type distribution."""
    if timeline_df is None or timeline_df.empty:
        print("  Skipping: No timeline data")
        return
    
    event_counts = timeline_df['event_type'].value_counts()
    
    # Group small categories
    threshold = len(timeline_df) * 0.03
    major = event_counts[event_counts >= threshold]
    minor = event_counts[event_counts < threshold]
    
    if len(minor) > 0:
        major['Other'] = minor.sum()
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    colors = plt.cm.Set3(np.linspace(0, 1, len(major)))
    
    wedges, texts, autotexts = ax.pie(major, labels=major.index, autopct='%1.1f%%',
                                       colors=colors, pctdistance=0.75,
                                       wedgeprops=dict(width=0.5, edgecolor='white'))
    
    ax.set_title('Distribution of Timeline Event Types (2016-2025)')
    
    # Make percentage text bold
    for autotext in autotexts:
        autotext.set_fontsize(9)
        autotext.set_fontweight('bold')
    
    plt.tight_layout()
    save_figure(fig, 'event_type_distribution')
    plt.close()


# =============================================================================
# GRAPH 7: MITRE Technique Heatmap
# =============================================================================
def plot_technique_heatmap(botnet_df, ransomware_df):
    """Create heatmap of top MITRE techniques by category."""
    
    def collect_techniques(df, category):
        all_techniques = []
        if df is None:
            return all_techniques
        for _, row in df.iterrows():
            techniques = extract_mitre_techniques(row.get('mitre_attack_ids', ''))
            techniques.extend(extract_mitre_techniques(row.get('tactics_techniques', '')))
            all_techniques.extend(techniques)
        return all_techniques
    
    botnet_techniques = collect_techniques(botnet_df, 'Botnet')
    ransomware_techniques = collect_techniques(ransomware_df, 'Ransomware')
    
    # Get top techniques overall
    all_techniques = botnet_techniques + ransomware_techniques
    if not all_techniques:
        print("  Skipping: No technique data")
        return
    
    top_techniques = [t for t, _ in Counter(all_techniques).most_common(15)]
    
    # Count per category
    botnet_counts = Counter(botnet_techniques)
    ransomware_counts = Counter(ransomware_techniques)
    
    data = {
        'Botnet': [botnet_counts.get(t, 0) for t in top_techniques],
        'Ransomware': [ransomware_counts.get(t, 0) for t in top_techniques]
    }
    
    df = pd.DataFrame(data, index=top_techniques)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Create heatmap
    im = ax.imshow(df.values, cmap='YlOrRd', aspect='auto')
    
    # Add colorbar
    cbar = ax.figure.colorbar(im, ax=ax)
    cbar.ax.set_ylabel('Frequency', rotation=-90, va="bottom")
    
    # Set ticks
    ax.set_xticks(np.arange(len(df.columns)))
    ax.set_yticks(np.arange(len(df.index)))
    ax.set_xticklabels(df.columns)
    ax.set_yticklabels(df.index)
    
    # Rotate x labels
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center")
    
    # Add value annotations
    for i in range(len(df.index)):
        for j in range(len(df.columns)):
            text = ax.text(j, i, df.values[i, j],
                          ha="center", va="center", color="black" if df.values[i, j] < df.values.max()/2 else "white",
                          fontsize=11, fontweight='bold')
    
    ax.set_title('Top 15 MITRE ATT&CK Techniques by Category')
    
    plt.tight_layout()
    save_figure(fig, 'technique_heatmap')
    plt.close()


# =============================================================================
# GRAPH 8: Double Extortion Trend
# =============================================================================
def plot_double_extortion_trend(ransomware_df):
    """Create chart showing double extortion adoption over time."""
    if ransomware_df is None or ransomware_df.empty:
        print("  Skipping: No ransomware data")
        return
    
    results = []
    
    for _, row in ransomware_df.iterrows():
        first_seen = parse_date(row.get('first_seen', ''))
        if not first_seen:
            continue
        
        # Check for double extortion indicators
        is_double = False
        traits = str(row.get('technical_traits', '')).lower()
        if 'double' in traits and 'extortion' in traits:
            is_double = True
        if '"double_extortion": true' in traits or '"double_extortion":true' in traits:
            is_double = True
        
        tactics = str(row.get('tactics_techniques', '')).lower()
        if 'double extortion' in tactics or 'data exfiltration' in tactics:
            is_double = True
        
        notes = str(row.get('notes', '')).lower()
        if 'double extortion' in notes or 'double-extortion' in notes:
            is_double = True
        if 'data leak' in notes or 'leak site' in notes:
            is_double = True
        
        results.append({
            'year': first_seen.year,
            'family': row.get('malware_family'),
            'double_extortion': is_double
        })
    
    df = pd.DataFrame(results)
    if df.empty:
        print("  Skipping: No valid ransomware data")
        return
    
    # Group by year
    yearly = df.groupby('year').agg(
        total=('family', 'count'),
        double=('double_extortion', 'sum')
    ).reset_index()
    
    yearly['percentage'] = (yearly['double'] / yearly['total']) * 100
    
    # Filter to study period
    yearly = yearly[(yearly['year'] >= 2016) & (yearly['year'] <= 2025)]
    
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    # Bar chart for counts
    x = yearly['year']
    width = 0.35
    
    bars1 = ax1.bar(x - width/2, yearly['total'], width, label='Total Ransomware', 
                    color=COLORS['ransomware'], alpha=0.7, edgecolor='white')
    bars2 = ax1.bar(x + width/2, yearly['double'], width, label='With Double Extortion',
                    color=COLORS['primary'], alpha=0.7, edgecolor='white')
    
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Number of Families')
    ax1.legend(loc='upper left')
    
    # Add percentage line on secondary axis
    ax2 = ax1.twinx()
    line = ax2.plot(x, yearly['percentage'], 'o-', color=COLORS['secondary'], 
                    linewidth=2, markersize=8, label='Double Extortion %')
    ax2.set_ylabel('Double Extortion Prevalence (%)', color=COLORS['secondary'])
    ax2.tick_params(axis='y', labelcolor=COLORS['secondary'])
    ax2.set_ylim(0, 100)
    
    # Add percentage labels
    for xi, yi in zip(x, yearly['percentage']):
        ax2.annotate(f'{yi:.0f}%', xy=(xi, yi), xytext=(0, 8),
                    textcoords='offset points', ha='center', fontsize=9,
                    fontweight='bold', color=COLORS['secondary'])
    
    ax1.set_title('Double Extortion Adoption in Ransomware (2016-2025)')
    ax1.set_xticks(x)
    
    plt.tight_layout()
    save_figure(fig, 'double_extortion_trend')
    plt.close()


# =============================================================================
# GRAPH 9: Yearly Malware Count by Category
# =============================================================================
def plot_yearly_malware_count(botnet_df, ransomware_df):
    """Create stacked area chart of malware emergence by year."""
    
    def get_yearly_counts(df, category):
        if df is None or df.empty:
            return {}
        counts = {}
        seen = set()
        for _, row in df.iterrows():
            family = row.get('malware_family')
            if family in seen:
                continue
            seen.add(family)
            
            first_seen = parse_date(row.get('first_seen', ''))
            if first_seen and 2016 <= first_seen.year <= 2025:
                year = first_seen.year
                counts[year] = counts.get(year, 0) + 1
        return counts
    
    botnet_counts = get_yearly_counts(botnet_df, 'Botnet')
    ransomware_counts = get_yearly_counts(ransomware_df, 'Ransomware')
    
    years = list(range(2016, 2026))
    botnet_vals = [botnet_counts.get(y, 0) for y in years]
    ransomware_vals = [ransomware_counts.get(y, 0) for y in years]
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    ax.stackplot(years, botnet_vals, ransomware_vals, 
                 labels=['Botnets', 'Ransomware'],
                 colors=[COLORS['botnet'], COLORS['ransomware']],
                 alpha=0.8)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('New Malware Families')
    ax.set_title('New Malware Family Emergence by Year')
    ax.legend(loc='upper right')
    ax.set_xticks(years)
    
    # Add total line
    totals = [b + r for b, r in zip(botnet_vals, ransomware_vals)]
    ax.plot(years, totals, 'ko-', linewidth=2, markersize=6, label='Total')
    
    plt.tight_layout()
    save_figure(fig, 'yearly_malware_emergence')
    plt.close()


# =============================================================================
# GRAPH 10: Propagation Vectors Comparison
# =============================================================================
def plot_propagation_vectors(botnet_df, ransomware_df):
    """Create visualization comparing initial access/propagation methods."""
    
    def extract_vectors(df, category):
        if df is None or df.empty:
            return Counter()
        
        vector_counts = Counter()
        for _, row in df.iterrows():
            vectors = str(row.get('propagation_vectors', ''))
            
            # Normalize vector names
            vectors_lower = vectors.lower()
            
            if 'phishing' in vectors_lower or 'spam' in vectors_lower or 'malspam' in vectors_lower:
                vector_counts['Phishing/Spam'] += 1
            if 'rdp' in vectors_lower or 'brute' in vectors_lower:
                vector_counts['RDP Brute Force'] += 1
            if 'exploit' in vectors_lower or 'cve' in vectors_lower:
                vector_counts['Exploitation'] += 1
            if 'emotet' in vectors_lower or 'trickbot' in vectors_lower or 'dropped' in vectors_lower:
                vector_counts['Malware Dropper'] += 1
            if 'credential' in vectors_lower or 'compromised' in vectors_lower:
                vector_counts['Stolen Credentials'] += 1
            if 'telnet' in vectors_lower or 'ssh' in vectors_lower or 'default' in vectors_lower:
                vector_counts['Default Credentials'] += 1
            if 'drive-by' in vectors_lower or 'kit' in vectors_lower:
                vector_counts['Exploit Kit'] += 1
        
        return vector_counts
    
    botnet_vectors = extract_vectors(botnet_df, 'Botnet')
    ransomware_vectors = extract_vectors(ransomware_df, 'Ransomware')
    
    if not botnet_vectors and not ransomware_vectors:
        print("  Skipping: No propagation vector data")
        return
    
    # Get all unique vectors
    all_vectors = sorted(set(botnet_vectors.keys()) | set(ransomware_vectors.keys()),
                        key=lambda x: botnet_vectors.get(x, 0) + ransomware_vectors.get(x, 0),
                        reverse=True)
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    x = np.arange(len(all_vectors))
    width = 0.35
    
    botnet_vals = [botnet_vectors.get(v, 0) for v in all_vectors]
    ransomware_vals = [ransomware_vectors.get(v, 0) for v in all_vectors]
    
    bars1 = ax.bar(x - width/2, botnet_vals, width, label='Botnets', 
                   color=COLORS['botnet'], edgecolor='white')
    bars2 = ax.bar(x + width/2, ransomware_vals, width, label='Ransomware', 
                   color=COLORS['ransomware'], edgecolor='white')
    
    ax.set_ylabel('Number of Malware Families')
    ax.set_xlabel('Propagation Vector')
    ax.set_title('Initial Access & Propagation Vectors by Malware Category')
    ax.set_xticks(x)
    ax.set_xticklabels(all_vectors, rotation=30, ha='right')
    ax.legend()
    
    # Add value labels
    def add_labels(bars):
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.annotate(f'{int(height)}',
                           xy=(bar.get_x() + bar.get_width()/2, height),
                           xytext=(0, 3), textcoords="offset points",
                           ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    add_labels(bars1)
    add_labels(bars2)
    
    plt.tight_layout()
    save_figure(fig, 'propagation_vectors_comparison')
    plt.close()


# =============================================================================
# GRAPH 11: Victim Industry Analysis
# =============================================================================
def plot_victim_industries(botnet_df, ransomware_df):
    """Create visualization of targeted industries."""
    
    def extract_industries(df, category):
        if df is None or df.empty:
            return Counter()
        
        industry_counts = Counter()
        for _, row in df.iterrows():
            industries = str(row.get('victim_industries', ''))
            
            # Parse industries (may be comma-separated or JSON-like)
            industries_lower = industries.lower()
            
            industry_map = {
                'healthcare': 'Healthcare',
                'health': 'Healthcare',
                'financial': 'Financial',
                'banking': 'Financial',
                'government': 'Government',
                'education': 'Education',
                'manufacturing': 'Manufacturing',
                'industrial': 'Manufacturing',
                'energy': 'Energy/Utilities',
                'utilities': 'Energy/Utilities',
                'critical infrastructure': 'Critical Infrastructure',
                'infrastructure': 'Critical Infrastructure',
                'retail': 'Retail',
                'media': 'Media',
                'transportation': 'Transportation',
                'iot': 'IoT/Consumer',
                'consumer': 'IoT/Consumer',
                'all sectors': 'All Sectors',
                'various': 'All Sectors',
                'multiple': 'All Sectors',
                'smb': 'SMB',
                'small': 'SMB',
            }
            
            for key, value in industry_map.items():
                if key in industries_lower:
                    industry_counts[value] += 1
        
        return industry_counts
    
    botnet_industries = extract_industries(botnet_df, 'Botnet')
    ransomware_industries = extract_industries(ransomware_df, 'Ransomware')
    
    if not botnet_industries and not ransomware_industries:
        print("  Skipping: No industry data")
        return
    
    # Get top industries
    all_industries = set(botnet_industries.keys()) | set(ransomware_industries.keys())
    industry_totals = {ind: botnet_industries.get(ind, 0) + ransomware_industries.get(ind, 0) 
                      for ind in all_industries}
    top_industries = sorted(industry_totals.keys(), key=lambda x: industry_totals[x], reverse=True)[:10]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Left: Grouped bar chart
    x = np.arange(len(top_industries))
    width = 0.35
    
    botnet_vals = [botnet_industries.get(ind, 0) for ind in top_industries]
    ransomware_vals = [ransomware_industries.get(ind, 0) for ind in top_industries]
    
    ax1.barh(x - width/2, botnet_vals, width, label='Botnets', 
             color=COLORS['botnet'], edgecolor='white')
    ax1.barh(x + width/2, ransomware_vals, width, label='Ransomware', 
             color=COLORS['ransomware'], edgecolor='white')
    
    ax1.set_yticks(x)
    ax1.set_yticklabels(top_industries)
    ax1.set_xlabel('Number of Malware Families Targeting')
    ax1.set_title('Top Targeted Industries by Category')
    ax1.legend(loc='lower right')
    ax1.invert_yaxis()
    
    # Right: Pie chart for ransomware (primary concern)
    ransomware_top = {k: ransomware_industries.get(k, 0) for k in top_industries if ransomware_industries.get(k, 0) > 0}
    
    if ransomware_top:
        colors = plt.cm.Reds(np.linspace(0.3, 0.9, len(ransomware_top)))
        wedges, texts, autotexts = ax2.pie(ransomware_top.values(), labels=ransomware_top.keys(),
                                           autopct='%1.1f%%', colors=colors, pctdistance=0.7,
                                           wedgeprops=dict(width=0.6, edgecolor='white'))
        ax2.set_title('Ransomware Target Distribution')
        for autotext in autotexts:
            autotext.set_fontsize(9)
            autotext.set_fontweight('bold')
    
    plt.suptitle('Victim Industry Analysis (2016-2025)', fontsize=14, fontweight='bold')
    plt.tight_layout()
    save_figure(fig, 'victim_industry_analysis')
    plt.close()


# =============================================================================
# GRAPH 12: Malware Infection Chain Relationships
# =============================================================================
def plot_infection_chains(botnet_df, ransomware_df):
    """Visualize known malware delivery chains (e.g., Emotet -> TrickBot -> Ryuk)."""
    
    # Known infection chains from the data
    chains = [
        ('Emotet', 'TrickBot', 'Ryuk'),
        ('Emotet', 'TrickBot', 'Conti'),
        ('Necurs', 'Locky', None),
        ('Necurs', 'Dridex', None),
        ('Dridex', 'Locky', None),
        ('Dridex', 'BitPaymer', None),
        ('Dridex', 'DoppelPaymer', None),
        ('TrickBot', 'Conti', None),
        ('Qakbot', 'REvil', None),
        ('Qakbot', 'Egregor', None),
        ('IcedID', 'Egregor', None),
    ]
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Create a simplified flow diagram
    stages = ['Stage 1\n(Initial Access)', 'Stage 2\n(Loader/Dropper)', 'Stage 3\n(Ransomware)']
    
    # Position nodes
    stage1_malware = ['Emotet', 'Necurs', 'Dridex', 'Qakbot', 'IcedID']
    stage2_malware = ['TrickBot', 'Dridex']
    stage3_malware = ['Ryuk', 'Conti', 'Locky', 'REvil', 'Egregor', 'DoppelPaymer', 'BitPaymer']
    
    # Draw stage labels
    for i, stage in enumerate(stages):
        ax.text(i * 2, 6.5, stage, ha='center', va='center', fontsize=12, fontweight='bold',
               bbox=dict(boxstyle='round', facecolor='lightgray', edgecolor='gray'))
    
    # Draw nodes
    node_positions = {}
    
    # Stage 1 nodes (Botnets - blue)
    for j, malware in enumerate(stage1_malware):
        y = 5 - j * 1.2
        ax.scatter(0, y, s=1500, c=COLORS['botnet'], edgecolor='white', linewidth=2, zorder=3)
        ax.text(0, y, malware, ha='center', va='center', fontsize=9, fontweight='bold', color='white', zorder=4)
        node_positions[malware] = (0, y)
    
    # Stage 2 nodes (Mixed)
    stage2_y = {'TrickBot': 4, 'Dridex': 2}
    for malware, y in stage2_y.items():
        ax.scatter(2, y, s=1500, c=COLORS['primary'], edgecolor='white', linewidth=2, zorder=3)
        ax.text(2, y, malware, ha='center', va='center', fontsize=9, fontweight='bold', color='white', zorder=4)
        node_positions[f'{malware}_s2'] = (2, y)
    
    # Stage 3 nodes (Ransomware - red)
    for j, malware in enumerate(stage3_malware):
        y = 5.5 - j * 1.0
        ax.scatter(4, y, s=1500, c=COLORS['ransomware'], edgecolor='white', linewidth=2, zorder=3)
        ax.text(4, y, malware, ha='center', va='center', fontsize=9, fontweight='bold', color='white', zorder=4)
        node_positions[malware] = (4, y)
    
    # Draw connections
    connections = [
        ('Emotet', 'TrickBot_s2', COLORS['botnet']),
        ('TrickBot_s2', 'Ryuk', COLORS['primary']),
        ('TrickBot_s2', 'Conti', COLORS['primary']),
        ('Necurs', 'Locky', COLORS['botnet']),
        ('Dridex', 'Locky', COLORS['botnet']),
        ('Dridex', 'DoppelPaymer', COLORS['botnet']),
        ('Dridex', 'BitPaymer', COLORS['botnet']),
        ('Qakbot', 'REvil', COLORS['botnet']),
        ('Qakbot', 'Egregor', COLORS['botnet']),
        ('IcedID', 'Egregor', COLORS['botnet']),
    ]
    
    for start, end, color in connections:
        start_key = start if start in node_positions else f'{start}_s2'
        end_key = end if end in node_positions else f'{end}_s2'
        
        if start_key in node_positions and end_key in node_positions:
            x1, y1 = node_positions[start_key]
            x2, y2 = node_positions[end_key]
            ax.annotate('', xy=(x2 - 0.15, y2), xytext=(x1 + 0.15, y1),
                       arrowprops=dict(arrowstyle='->', color=color, lw=2, alpha=0.6))
    
    # Add legend
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor=COLORS['botnet'], 
               markersize=15, label='Botnet/Loader'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor=COLORS['primary'], 
               markersize=15, label='Intermediate'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor=COLORS['ransomware'], 
               markersize=15, label='Ransomware'),
    ]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=10)
    
    ax.set_xlim(-1, 5)
    ax.set_ylim(-0.5, 7.5)
    ax.axis('off')
    ax.set_title('Malware Infection Chains: From Initial Access to Ransomware\n(Common Delivery Relationships 2016-2025)', 
                fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    save_figure(fig, 'infection_chain_relationships')
    plt.close()


# =============================================================================
# GRAPH 13: RaaS (Ransomware-as-a-Service) Evolution
# =============================================================================
def plot_raas_evolution(ransomware_df):
    """Track the rise of Ransomware-as-a-Service model over time."""
    if ransomware_df is None or ransomware_df.empty:
        print("  Skipping: No ransomware data")
        return
    
    raas_families = []
    non_raas_families = []
    
    seen = set()
    for _, row in ransomware_df.iterrows():
        family = row.get('malware_family', 'Unknown')
        if family in seen:
            continue
        seen.add(family)
        
        first_seen = parse_date(row.get('first_seen', ''))
        if not first_seen:
            continue
        
        # Check for RaaS indicators
        is_raas = False
        traits = str(row.get('technical_traits', '')).lower()
        notes = str(row.get('notes', '')).lower()
        
        if 'raas' in traits or '"raas":true' in traits or '"raas": true' in traits:
            is_raas = True
        if 'raas' in notes or 'ransomware-as-a-service' in notes or 'affiliate' in notes:
            is_raas = True
        
        # Known RaaS families
        known_raas = ['gandcrab', 'revil', 'sodinokibi', 'lockbit', 'darkside', 'blackmatter',
                     'conti', 'hive', 'blackcat', 'alphv', 'cerber', 'dharma', 'phobos',
                     'maze', 'egregor', 'netwalker', 'ragnar', 'avaddon', 'babuk', 'play',
                     'black basta', 'royal', 'akira', 'bianlian', 'rhysida', 'ransomhub', 'clop']
        
        if any(r in family.lower() for r in known_raas):
            is_raas = True
        
        entry = {
            'family': family,
            'year': first_seen.year,
            'is_raas': is_raas
        }
        
        if is_raas:
            raas_families.append(entry)
        else:
            non_raas_families.append(entry)
    
    # Count by year
    years = list(range(2016, 2026))
    raas_counts = Counter(f['year'] for f in raas_families)
    non_raas_counts = Counter(f['year'] for f in non_raas_families)
    
    raas_vals = [raas_counts.get(y, 0) for y in years]
    non_raas_vals = [non_raas_counts.get(y, 0) for y in years]
    
    # Cumulative
    raas_cumulative = np.cumsum(raas_vals)
    non_raas_cumulative = np.cumsum(non_raas_vals)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Left: Yearly emergence
    width = 0.35
    x = np.arange(len(years))
    
    ax1.bar(x - width/2, non_raas_vals, width, label='Traditional Ransomware', 
            color=COLORS['neutral'], edgecolor='white')
    ax1.bar(x + width/2, raas_vals, width, label='Ransomware-as-a-Service (RaaS)', 
            color=COLORS['ransomware'], edgecolor='white')
    
    ax1.set_xlabel('Year')
    ax1.set_ylabel('New Ransomware Families')
    ax1.set_title('Annual Ransomware Emergence by Model')
    ax1.set_xticks(x)
    ax1.set_xticklabels(years, rotation=45)
    ax1.legend()
    
    # Right: Cumulative with percentage
    ax2.stackplot(years, non_raas_cumulative, raas_cumulative,
                  labels=['Traditional', 'RaaS'],
                  colors=[COLORS['neutral'], COLORS['ransomware']],
                  alpha=0.8)
    
    # Calculate and annotate RaaS percentage over time
    for i, year in enumerate(years):
        total = raas_cumulative[i] + non_raas_cumulative[i]
        if total > 0:
            pct = (raas_cumulative[i] / total) * 100
            if i == len(years) - 1 or (i > 0 and i % 2 == 0):
                ax2.annotate(f'{pct:.0f}%', xy=(year, raas_cumulative[i] + non_raas_cumulative[i]/2),
                            fontsize=9, fontweight='bold', ha='center')
    
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Cumulative Ransomware Families')
    ax2.set_title('Cumulative RaaS Adoption Over Time')
    ax2.legend(loc='upper left')
    
    plt.suptitle('The Rise of Ransomware-as-a-Service (2016-2025)', fontsize=14, fontweight='bold')
    plt.tight_layout()
    save_figure(fig, 'raas_evolution')
    plt.close()


# =============================================================================
# GRAPH 14: CVE Exploitation Timeline
# =============================================================================
def plot_cve_exploitation(timeline_df, botnet_df, ransomware_df):
    """Visualize CVE discoveries and their exploitation by malware."""
    
    # Collect CVEs from all sources
    cve_data = []
    
    # From timeline
    if timeline_df is not None:
        for _, row in timeline_df.iterrows():
            cve_ids = str(row.get('cve_ids', ''))
            if 'CVE-' in cve_ids:
                cves = re.findall(r'CVE-\d{4}-\d+', cve_ids)
                for cve in cves:
                    date = parse_date(row.get('date', ''))
                    cve_data.append({
                        'cve': cve,
                        'date': date,
                        'year': date.year if date else None,
                        'event_type': row.get('event_type', 'unknown'),
                        'title': row.get('title', ''),
                        'malware': str(row.get('related_malware_families', ''))
                    })
    
    # From malware data
    for df, category in [(botnet_df, 'Botnet'), (ransomware_df, 'Ransomware')]:
        if df is None:
            continue
        for _, row in df.iterrows():
            cve_ids = str(row.get('exploited_cves', ''))
            if 'CVE-' in cve_ids:
                cves = re.findall(r'CVE-\d{4}-\d+', cve_ids)
                first_seen = parse_date(row.get('first_seen', ''))
                for cve in cves:
                    cve_data.append({
                        'cve': cve,
                        'date': first_seen,
                        'year': first_seen.year if first_seen else None,
                        'event_type': 'malware_exploitation',
                        'title': f'{row.get("malware_family", "Unknown")} ({category})',
                        'malware': row.get('malware_family', '')
                    })
    
    if not cve_data:
        print("  Skipping: No CVE data")
        return
    
    df = pd.DataFrame(cve_data)
    df = df[df['year'].notna()]
    
    # Count CVEs by year and categorize
    years = list(range(2016, 2026))
    
    # High-impact CVEs (mentioned in multiple places or major incidents)
    high_impact_cves = ['CVE-2017-0144', 'CVE-2017-0145', 'CVE-2019-0708', 'CVE-2019-11510',
                       'CVE-2019-2725', 'CVE-2017-5638', 'CVE-2019-19781', 'CVE-2020-1472',
                       'CVE-2021-34527', 'CVE-2021-44228']
    
    fig, ax = plt.subplots(figsize=(14, 7))
    
    # Plot CVE events as scatter
    for _, row in df.iterrows():
        if row['date'] is None:
            continue
        
        color = COLORS['ransomware'] if 'ransomware' in str(row['title']).lower() else COLORS['botnet']
        size = 200 if row['cve'] in high_impact_cves else 80
        
        ax.scatter(row['date'], row['cve'], s=size, c=color, alpha=0.7, edgecolor='white')
    
    # Add labels for high-impact CVEs
    labeled_cves = set()
    for _, row in df.iterrows():
        if row['cve'] in high_impact_cves and row['cve'] not in labeled_cves:
            ax.annotate(row['cve'].replace('CVE-', ''), xy=(row['date'], row['cve']),
                       xytext=(5, 0), textcoords='offset points', fontsize=8, fontweight='bold')
            labeled_cves.add(row['cve'])
    
    ax.set_xlabel('Date')
    ax.set_ylabel('CVE Identifier')
    ax.set_title('CVE Exploitation Timeline (2016-2025)\n(Larger dots = High-impact vulnerabilities)')
    
    # Format x-axis
    ax.xaxis.set_major_locator(mdates.YearLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y'))
    plt.xticks(rotation=45)
    
    # Add legend
    legend_elements = [
        Patch(facecolor=COLORS['botnet'], label='Botnet-related'),
        Patch(facecolor=COLORS['ransomware'], label='Ransomware-related'),
    ]
    ax.legend(handles=legend_elements, loc='upper left')
    
    plt.tight_layout()
    save_figure(fig, 'cve_exploitation_timeline')
    plt.close()


# =============================================================================
# GRAPH 15: Law Enforcement Actions Impact
# =============================================================================
def plot_law_enforcement_impact(timeline_df):
    """Visualize law enforcement actions and their timing."""
    if timeline_df is None or timeline_df.empty:
        print("  Skipping: No timeline data")
        return
    
    # Filter for law enforcement events
    le_events = timeline_df[timeline_df['event_type'].str.contains('law_enforcement|takedown|arrest', 
                                                                    case=False, na=False)]
    
    if le_events.empty:
        print("  Skipping: No law enforcement data")
        return
    
    le_events = le_events.copy()
    le_events['date'] = pd.to_datetime(le_events['date'], errors='coerce')
    le_events['year'] = le_events['date'].dt.year
    
    # Count by year
    yearly_counts = le_events.groupby('year').size()
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Left: Bar chart by year
    years = list(range(2016, 2026))
    counts = [yearly_counts.get(y, 0) for y in years]
    
    colors = [COLORS['timeline'] if c > 0 else COLORS['neutral'] for c in counts]
    bars = ax1.bar(years, counts, color=colors, edgecolor='white')
    
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Number of Law Enforcement Actions')
    ax1.set_title('Law Enforcement Actions by Year')
    ax1.set_xticks(years)
    ax1.set_xticklabels(years, rotation=45)
    
    # Add value labels
    for bar, count in zip(bars, counts):
        if count > 0:
            ax1.annotate(f'{count}', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                        xytext=(0, 3), textcoords='offset points', ha='center', fontweight='bold')
    
    # Right: Notable takedowns timeline
    notable_events = le_events.dropna(subset=['date']).nlargest(15, 'date')
    
    for i, (_, row) in enumerate(notable_events.iterrows()):
        title = row['title'][:40] + '...' if len(str(row['title'])) > 40 else row['title']
        ax2.barh(i, 1, color=COLORS['timeline'], alpha=0.7, edgecolor='white')
        ax2.text(0.02, i, f"{row['date'].strftime('%Y-%m')}: {title}", 
                va='center', fontsize=9, fontweight='bold')
    
    ax2.set_xlim(0, 1)
    ax2.set_ylim(-0.5, len(notable_events) - 0.5)
    ax2.axis('off')
    ax2.set_title('Recent Notable Law Enforcement Actions')
    ax2.invert_yaxis()
    
    plt.suptitle('Law Enforcement Actions Against Malware Operations (2016-2025)', 
                fontsize=14, fontweight='bold')
    plt.tight_layout()
    save_figure(fig, 'law_enforcement_impact')
    plt.close()


# =============================================================================
# GRAPH 16: Persistence Mechanisms Comparison
# =============================================================================
def plot_persistence_mechanisms(botnet_df, ransomware_df):
    """Compare persistence mechanisms used by different malware categories."""
    
    def extract_persistence(df, category):
        if df is None or df.empty:
            return Counter()
        
        mechanism_counts = Counter()
        for _, row in df.iterrows():
            mechanisms = str(row.get('persistence_mechanisms', ''))
            mechanisms_lower = mechanisms.lower()
            
            if 'registry' in mechanisms_lower or 'run key' in mechanisms_lower:
                mechanism_counts['Registry Run Keys'] += 1
            if 'scheduled' in mechanisms_lower or 'task' in mechanisms_lower:
                mechanism_counts['Scheduled Tasks'] += 1
            if 'service' in mechanisms_lower:
                mechanism_counts['Windows Services'] += 1
            if 'boot' in mechanisms_lower or 'mbr' in mechanisms_lower or 'startup' in mechanisms_lower:
                mechanism_counts['Boot/Startup'] += 1
            if 'rootkit' in mechanisms_lower or 'kernel' in mechanisms_lower:
                mechanism_counts['Rootkit/Kernel'] += 1
            if 're-infection' in mechanisms_lower or 'weak' in mechanisms_lower:
                mechanism_counts['Re-infection (Weak)'] += 1
            if 'ssh' in mechanisms_lower or 'key' in mechanisms_lower:
                mechanism_counts['SSH Keys'] += 1
        
        return mechanism_counts
    
    botnet_persistence = extract_persistence(botnet_df, 'Botnet')
    ransomware_persistence = extract_persistence(ransomware_df, 'Ransomware')
    
    if not botnet_persistence and not ransomware_persistence:
        print("  Skipping: No persistence data")
        return
    
    all_mechanisms = sorted(set(botnet_persistence.keys()) | set(ransomware_persistence.keys()),
                           key=lambda x: botnet_persistence.get(x, 0) + ransomware_persistence.get(x, 0),
                           reverse=True)
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    x = np.arange(len(all_mechanisms))
    width = 0.35
    
    botnet_vals = [botnet_persistence.get(m, 0) for m in all_mechanisms]
    ransomware_vals = [ransomware_persistence.get(m, 0) for m in all_mechanisms]
    
    ax.bar(x - width/2, botnet_vals, width, label='Botnets', color=COLORS['botnet'], edgecolor='white')
    ax.bar(x + width/2, ransomware_vals, width, label='Ransomware', color=COLORS['ransomware'], edgecolor='white')
    
    ax.set_ylabel('Number of Malware Families')
    ax.set_xlabel('Persistence Mechanism')
    ax.set_title('Persistence Mechanisms by Malware Category')
    ax.set_xticks(x)
    ax.set_xticklabels(all_mechanisms, rotation=30, ha='right')
    ax.legend()
    
    plt.tight_layout()
    save_figure(fig, 'persistence_mechanisms')
    plt.close()


# =============================================================================
# MAIN
# =============================================================================
def main():
    """Generate all graphs."""
    print("=" * 70)
    print("MALWARE EVOLUTION PAPER - GRAPH GENERATOR")
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
    
    # Generate graphs
    print("Generating graphs...")
    print()
    
    print("1. Event Cadence by Year")
    plot_event_cadence(timeline_df)
    print()
    
    print("2. Malware Duration Comparison")
    plot_malware_duration(botnet_df, ransomware_df)
    print()
    
    print("3. Technique Breadth Comparison")
    plot_technique_breadth(botnet_df, ransomware_df)
    print()
    
    print("4. Malware Emergence Timeline")
    plot_emergence_timeline(botnet_df, ransomware_df)
    print()
    
    print("5. Botnet vs Ransomware Comparison")
    plot_category_comparison(botnet_df, ransomware_df)
    print()
    
    print("6. Event Type Distribution")
    plot_event_distribution(timeline_df)
    print()
    
    print("7. MITRE Technique Heatmap")
    plot_technique_heatmap(botnet_df, ransomware_df)
    print()
    
    print("8. Double Extortion Trend")
    plot_double_extortion_trend(ransomware_df)
    print()
    
    print("9. Yearly Malware Emergence")
    plot_yearly_malware_count(botnet_df, ransomware_df)
    print()
    
    print("10. Propagation Vectors Comparison")
    plot_propagation_vectors(botnet_df, ransomware_df)
    print()
    
    print("11. Victim Industry Analysis")
    plot_victim_industries(botnet_df, ransomware_df)
    print()
    
    print("12. Malware Infection Chains")
    plot_infection_chains(botnet_df, ransomware_df)
    print()
    
    print("13. RaaS Evolution")
    plot_raas_evolution(ransomware_df)
    print()
    
    print("14. CVE Exploitation Timeline")
    plot_cve_exploitation(timeline_df, botnet_df, ransomware_df)
    print()
    
    print("15. Law Enforcement Impact")
    plot_law_enforcement_impact(timeline_df)
    print()
    
    print("16. Persistence Mechanisms")
    plot_persistence_mechanisms(botnet_df, ransomware_df)
    print()
    
    print("=" * 70)
    print(f"All graphs saved to: {OUTPUT_DIR}/")
    print("=" * 70)


if __name__ == '__main__':
    main()
