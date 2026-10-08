import csv, requests

url = "https://bazaar.abuse.ch/export/csv/recent/"
valid_count = 0

with requests.get(url, stream=True, timeout=30) as resp:
    resp.raise_for_status()
    for line_bytes in resp.iter_lines():
        line = line_bytes.decode("utf-8", errors="ignore").strip()
        if not line or line.startswith("#"):
            continue
        row = next(csv.reader([line]))
        sha256 = row[0].strip()
        if len(sha256) == 64:
            valid_count += 1

print("Valid SHA256 in recent feed:", valid_count)
