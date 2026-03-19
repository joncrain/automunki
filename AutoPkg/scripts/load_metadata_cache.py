"""Download the metadata cache from the AutoMunki API into metadata_cache.json."""

import json
import os

response_file = "metadata_cache_response.json"
output_file = "metadata_cache.json"

if not os.path.exists(response_file):
    print("No API response file found, starting with empty cache")
    with open(output_file, "w") as f:
        json.dump({}, f)
    raise SystemExit(0)

with open(response_file) as f:
    resp = json.load(f)

cache = resp.get("cache_data", {})
with open(output_file, "w") as f:
    json.dump(cache, f, indent=4)
print(f"Loaded metadata cache with {len(cache)} entries")
