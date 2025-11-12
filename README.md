# FSCT 7910: Mapping the Evolution of Malware Evasion Techniques

This repository contains the dataset, analysis artifacts, and scripts for the FSCT 7910 research project. The goal of this paper is to map and analyse major ransomware and botnet families across 2016–2025, document their tactics and technical traits, and analyze their trends overtime 

**What this repo contains**
- `data/` — CSV datasets and raw source files.
	- `data/raw/Malware/` — per-year and analysis CSVs used as source material (2016–2025).
	- `data/Malware_Ransomware_2016_2025.csv` — aggregated ransomware incidents extracted from the raw sources.
	- `data/Malware_Botnet_2016_2025.csv` — aggregated botnet incidents extracted from the raw sources.
- `scripts/` — helper scripts for extracting and normalizing data.
	- `scripts/extract_malware.py` — parses `data/raw/Malware/*.csv`, skips comment lines, deduplicates by `incident_id`, and appends ransomware- and botnet-category rows into the two aggregated CSVs.
- `reports/` — deliverables and written reports.

**License**

This project is provided under the MIT License — see the `LICENSE` file in the repository root for full text.

