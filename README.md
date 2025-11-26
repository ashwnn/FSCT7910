# FSCT 7910: Mapping the Evolution of Malware Evasion Techniques

This repository contains the dataset, analysis artifacts, and scripts for the FSCT 7910 research project. The goal of this paper is to map and analyse major ransomware and botnet families across 2016–2025, document their tactics and technical traits, and analyze their trends overtime.

## Quick Links

- **[METRICS.md](./METRICS.md)** — Key findings, statistics, and analysis results from the research

## What this repo contains

- `data/` — CSV datasets and raw source files.
	- `data/raw/Malware/` — per-year and analysis CSVs used as source material (2016–2025).
	- `data/raw/Timeline/` — per-year and analysis CSVs for timeline events (2016–2025).
	- `data/Malware_Ransomware_2016_2025.csv` — aggregated ransomware incidents extracted from the raw sources.
	- `data/Malware_Botnet_2016_2025.csv` — aggregated botnet incidents extracted from the raw sources.
	- `data/Timeline_Ransomware_Merged.csv` — merged timeline events for ransomware.
	- `data/Timeline_Botnet_Merged.csv` — merged timeline events for botnets.
- `scripts/` — helper scripts for extracting and normalizing data.
	- `scripts/extract_malware.py` — parses `data/raw/Malware/*.csv`, skips comment lines, deduplicates by `incident_id`, and appends ransomware- and botnet-category rows into the two aggregated CSVs.
	- `scripts/merge_timeline.py` — merges timeline CSV files across years.
	- `scripts/generate_paper_metrics.py` — generates comprehensive analysis metrics and statistics.
	- `scripts/generate_graphs.py` — creates visualization graphs from analysis data.
- `analysis/` — computed metrics and analysis results.
	- `analysis/summary_statistics.csv` — key metrics from the research.
	- `analysis/event_cadence.csv` — timeline events aggregated by type and year.
	- `analysis/malware_duration.csv` — active duration for major malware families.
	- `analysis/technique_breadth.csv` — MITRE ATT&CK technique counts by family.
	- `analysis/graphs/` — visualizations of analysis results.
- `reports/` — deliverables and written reports.

## License

This project is provided under the MIT License — see the `LICENSE` file in the repository root for full text.