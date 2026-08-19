"""
Fetches a fresh URLhaus snapshot and splits it into:
- ingest_blocklist.txt (70%) — served to the app as the blocklist source
- heldout_eval.txt (30%) — NEVER ingested, used only to test detection
  of genuinely unseen threats via the typosquat/heuristic layers.
"""

import random
import urllib.request

FEED_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
SPLIT_RATIO = 0.7
SEED = 42

print("Fetching fresh URLhaus snapshot...")
with urllib.request.urlopen(FEED_URL) as response:
    raw = response.read().decode("utf-8")

lines = [line.strip() for line in raw.split("\n")]
header_lines = [line for line in lines if line.startswith("#") or line == ""]
domain_lines = [line for line in lines if line and not line.startswith("#")]

random.seed(SEED)
random.shuffle(domain_lines)

split_index = int(len(domain_lines) * SPLIT_RATIO)
ingest_lines = domain_lines[:split_index]
heldout_lines = domain_lines[split_index:]

with open("ingest_blocklist.txt", "w") as f:
    f.write("\n".join(header_lines) + "\n")
    f.write("\n".join(ingest_lines) + "\n")

with open("heldout_eval.txt", "w") as f:
    f.write("\n".join(heldout_lines) + "\n")

print(f"Total domains: {len(domain_lines)}")
print(f"Ingest set (blocklist):  {len(ingest_lines)}")
print(f"Held-out set (eval only): {len(heldout_lines)}")
