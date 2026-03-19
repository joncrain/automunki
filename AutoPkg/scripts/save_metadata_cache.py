"""Upload the local metadata_cache.json to the AutoMunki API."""

import json
import os
import urllib.request

api_base = os.environ["API_BASE_URL"] + "/api/v1/autopkg"

with open("metadata_cache.json") as f:
    cache = json.load(f)

payload = json.dumps({"cache_data": cache}).encode()
req = urllib.request.Request(
    f"{api_base}/metadata-cache",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="PUT",
)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(f"Saved metadata cache ({resp.status})")
except Exception as e:
    print(f"Failed to save metadata cache: {e}")
