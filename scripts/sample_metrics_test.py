import os
import sys

import matplotlib.pyplot as plt
import pandas as pd

base_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
ransom_path = os.path.join(base_dir, "data", "Malware_Ransomware_2016_2025.csv")
botnet_path = os.path.join(base_dir, "data", "Malware_Botnet_2016_2025.csv")

def require_file(path: str) -> None:
    if not os.path.exists(path):
        print(f"ERROR: required data file not found: {path}")
        print("Make sure you've run the extraction script and the CSVs exist in `data/`.")
        sys.exit(2)

for p in (ransom_path, botnet_path):
    require_file(p)

ransom_df = pd.read_csv(ransom_path)
botnet_df = pd.read_csv(botnet_path)

# Parse dates and add "year" column
for df in (ransom_df, botnet_df):
    df["first_seen"] = pd.to_datetime(df.get("first_seen"), errors="coerce")
    df["year"] = df["first_seen"].dt.year

# Coerce numeric columns
for col in ("victim_count", "ransom_amount_usd", "botnet_size"):
    if col in ransom_df.columns:
        ransom_df[col] = pd.to_numeric(ransom_df[col], errors="coerce")
    if col in botnet_df.columns:
        botnet_df[col] = pd.to_numeric(botnet_df[col], errors="coerce")

# Ransomware metrics
ransom_incidents_by_year = (
    ransom_df.groupby("year")["incident_id"].nunique().dropna()
)
ransom_victims_by_year = (
    ransom_df.groupby("year")["victim_count"].sum(min_count=1).dropna()
)
ransom_amount_by_year = (
    ransom_df.groupby("year")["ransom_amount_usd"].sum(min_count=1).dropna()
)

print("Ransomware incidents by year:")
print(ransom_incidents_by_year)
print("\nTotal ransomware victim count by year:")
print(ransom_victims_by_year)
print("\nTotal ransom (USD) by year:")
print(ransom_amount_by_year)

# Botnet metrics
botnet_incidents_by_year = (
    botnet_df.groupby("year")["incident_id"].nunique().dropna()
)
botnet_avg_size_by_year = (
    botnet_df.groupby("year")["botnet_size"].mean().dropna()
)

print("\nBotnet incidents by year:")
print(botnet_incidents_by_year)
print("\nAverage botnet size by year:")
print(botnet_avg_size_by_year)

# Output directory for graphs
graphs_dir = os.path.join(base_dir, "analysis", "graphs")
os.makedirs(graphs_dir, exist_ok=True)


def save_current_plot(path: str) -> None:
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()
    print(f"Saved: {path}")


# Graph 1: Incidents per year (ransomware vs botnet)
combined_incidents = pd.DataFrame(
    {
        "Ransomware": ransom_incidents_by_year,
        "Botnet": botnet_incidents_by_year,
    }
)

plt.figure(figsize=(10, 5))
combined_incidents.plot(kind="bar")
plt.title("Incidents per Year (Ransomware vs Botnet)")
plt.xlabel("Year")
plt.ylabel("Number of incidents")
plt.xticks(rotation=45)
save_current_plot(os.path.join(graphs_dir, "incidents_per_year.png"))

# Graph 2: Total ransom amount per year
plt.figure(figsize=(10, 5))
ransom_amount_by_year.plot(marker="o")
plt.title("Total Ransom Amount per Year")
plt.xlabel("Year")
plt.ylabel("Total ransom (USD)")
plt.grid(True)
save_current_plot(os.path.join(graphs_dir, "ransom_amount_per_year.png"))

# Graph 3: Average botnet size per year
plt.figure(figsize=(10, 5))
botnet_avg_size_by_year.plot(marker="o")
plt.title("Average Botnet Size per Year")
plt.xlabel("Year")
plt.ylabel("Average botnet size")
plt.grid(True)
save_current_plot(os.path.join(graphs_dir, "botnet_avg_size_per_year.png"))
