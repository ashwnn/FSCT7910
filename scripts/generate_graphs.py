#!/usr/bin/env python3
"""
generate_graphs.py - Generate visualizations for the malware evolution paper.

This script creates publication-ready graphs for the paper:
"Malware Evasion and Defense: A 2016-2025 Timeline Analysis"

Graphs generated:
1. Timeline event cadence (stacked bar chart by year)
2. Malware family active duration comparison (horizontal bar chart)
3. MITRE ATT&CK technique breadth comparison (boxplot and bar chart)
4. Double extortion prevalence over time (line/area chart)
5. Botnet vs Ransomware comparison (grouped bar chart)
6. Malware emergence timeline (scatter/timeline plot)
7. Top techniques heatmap
8. Event type distribution (pie chart)

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
# GRAPH 3: Technique Breadth Comparison (Box Plot)
# =============================================================================
def plot_technique_breadth(botnet_df, ransomware_df):
    """Create box plot comparing technique breadth between categories."""
    
    def get_technique_counts(df, category):
        if df is None or df.empty:
            return []
        results = []
        for _, row in df.iterrows():
            techniques = set()
            mitre_ids = row.get('mitre_attack_ids', '')
            techniques.update(extract_mitre_techniques(mitre_ids))
            tactics = row.get('tactics_techniques', '')
            techniques.update(extract_mitre_techniques(tactics))
            
            results.append({
                'family': row.get('malware_family', 'Unknown'),
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
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Box plot
    categories = ['Botnet', 'Ransomware']
    data_by_category = [df[df['category'] == cat]['count'].values for cat in categories]
    
    bp = ax1.boxplot(data_by_category, tick_labels=categories, patch_artist=True)
    for patch, color in zip(bp['boxes'], [COLORS['botnet'], COLORS['ransomware']]):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    ax1.set_ylabel('Number of MITRE ATT&CK Techniques')
    ax1.set_title('Technique Breadth Distribution by Category')
    
    # Add mean markers
    for i, cat in enumerate(categories):
        mean_val = df[df['category'] == cat]['count'].mean()
        ax1.scatter(i + 1, mean_val, marker='D', color='white', edgecolor='black', s=50, zorder=3)
        ax1.annotate(f'μ={mean_val:.1f}', xy=(i + 1.15, mean_val), fontsize=10)
    
    # Bar chart of top families
    top_families = df.nlargest(15, 'count')
    colors = [CATEGORY_COLORS[cat] for cat in top_families['category']]
    
    ax2.barh(range(len(top_families)), top_families['count'], color=colors, edgecolor='white')
    ax2.set_yticks(range(len(top_families)))
    ax2.set_yticklabels(top_families['family'])
    ax2.set_xlabel('Number of MITRE ATT&CK Techniques')
    ax2.set_title('Top 15 Families by Technique Count')
    ax2.invert_yaxis()
    
    # Add legend
    legend_elements = [
        Patch(facecolor=COLORS['botnet'], label='Botnet'),
        Patch(facecolor=COLORS['ransomware'], label='Ransomware')
    ]
    ax2.legend(handles=legend_elements, loc='lower right')
    
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
    
    print("=" * 70)
    print(f"All graphs saved to: {OUTPUT_DIR}/")
    print("=" * 70)


if __name__ == '__main__':
    main()
