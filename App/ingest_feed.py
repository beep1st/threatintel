from threatintel.env import get_env
import time
import requests
import re
import os
import subprocess
import json
from datetime import datetime, timedelta
from dateutil import parser
from django.utils import timezone
from django.core.management.base import BaseCommand
from .models import ThreatRecord

# ==============================================================
# CONFIGURATION
# ==============================================================
ABUSEIPDB_API_KEY = get_env('ABUSEIPDB_API_KEY')
MALWAREBAZAAR_AUTH_KEY = get_env('MALWAREBAZAAR_AUTH_KEY')

# CVE Configuration (Git sparse checkout)
REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
LOCAL_PATH = os.path.abspath("cvelistV5_cache")
YEARS_TO_TRACK = [str(y) for y in range(2025, datetime.now().year + 2)]  # 2025, 2026, 2027

# ==============================================================
# UTILITY FUNCTIONS
# ==============================================================
def validate_threat_score(score):
    if not isinstance(score, (int, float)):
        return 0
    return max(0, min(100, float(score)))

def is_legitimate_ip_range(ip):
    try:
        ip_parts = ip.split('.')
        ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
    except:
        return False

    legitimate_ranges = [
        ((103 << 24) + (21 << 16) + (244 << 8) + 0, (103 << 24) + (21 << 16) + (247 << 8) + 255),
        ((8 << 24) + (8 << 16) + (8 << 8) + 0, (8 << 24) + (8 << 16) + (8 << 8) + 255),
        ((64 << 24) + (233 << 16) + (160 << 8) + 0, (64 << 24) + (233 << 16) + (191 << 8) + 255),
        ((13 << 24) + (64 << 16), (13 << 24) + (111 << 16) + (255 << 8) + 255),
        ((52 << 24), (52 << 24) + (95 << 16) + (255 << 8) + 255),
        ((38 << 24) + (202 << 16) + (252 << 8), (38 << 24) + (202 << 16) + (255 << 8) + 255),
        ((159 << 24) + (203 << 16), (159 << 24) + (203 << 16) + (255 << 8) + 255),
        ((45 << 24) + (79 << 16), (45 << 24) + (79 << 16) + (255 << 8) + 255),
        ((146 << 24) + (59 << 16), (146 << 24) + (59 << 16) + (255 << 8) + 255),
        ((49 << 24) + (12 << 16), (49 << 24) + (12 << 16) + (255 << 8) + 255),
        ((10 << 24), (10 << 24) + (255 << 16) + (255 << 8) + 255),
        ((172 << 24) + (16 << 16), (172 << 24) + (31 << 16) + (255 << 8) + 255),
        ((192 << 24) + (168 << 16), (192 << 24) + (168 << 16) + (255 << 8) + 255),
    ]

    for start_ip, end_ip in legitimate_ranges:
        if start_ip <= ip_int <= end_ip:
            print(f"[IP Filter] Skipping {ip} - legitimate range")
            return True
    return False

def save_or_update_record(type_, value, score, reputation, source, category='', tags=None, first_seen=None, last_seen=None, description=''):
    if tags is None:
        tags = []
    if not isinstance(tags, list):
        tags = [str(tags)] if tags else []

    defaults = {
        'threat_score': validate_threat_score(score),
        'reputation': str(reputation).lower(),
        'source': source,
        'category': category or 'unknown',
        'tags': tags,
        'description': str(description)[:500],
    }
    if first_seen:
        try:
            defaults['first_seen'] = timezone.make_aware(parser.parse(first_seen))
        except:
            defaults['first_seen'] = timezone.now()
    if last_seen:
        try:
            defaults['last_seen'] = timezone.make_aware(parser.parse(last_seen))
        except:
            defaults['last_seen'] = timezone.now()

    obj, created = ThreatRecord.objects.update_or_create(
        type=type_,
        value=value.strip(),
        defaults=defaults
    )
    return created

def check_ip_reputation(ip, retries=3):
    for attempt in range(retries):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            r = requests.get(url, headers=headers, params=params, timeout=15)
            if r.status_code == 200:
                data = r.json()["data"]
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "score": validate_threat_score(score),
                    "reputation": "Malicious" if score >= 75 else "Suspicious" if score >= 40 else "Clean",
                    "reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "??"),
                }
        except Exception as e:
            print(f"API retry {attempt+1} for {ip}: {e}")
            if attempt < retries - 1:
                time.sleep(2)
    return {"score": 0, "reputation": "Unknown", "reports": 0, "country": "??"}

# ==============================================================
# GIT FUNCTIONS FOR CVE REPO
# ==============================================================
def run_git_command(args, cwd=None):
    cmd_str = "git " + " ".join(args)
    print(f"    > {cmd_str}")
    try:
        # For non-interactive commands, use subprocess.run with capture_output
        if args[0] == "remote":
            result = subprocess.run(["git"] + args, cwd=cwd, check=True, capture_output=True, text=True)
            return result.stdout.strip()
        
        # For reset/checkout commands that might fail, add retry logic
        result = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            print(f"    ! Git error: {error_msg}")
            
            # If it's a lock/reset error, try cleanup and retry
            if "lock" in error_msg or "unlink" in error_msg or "failed" in error_msg:
                print("    ! Git file conflict detected. Cleaning and retrying...")
                
                # 1. Try git clean first
                subprocess.run(["git", "clean", "-fd"], cwd=cwd, capture_output=True)
                
                # 2. Remove any lock files
                git_dir = os.path.join(cwd or os.getcwd(), ".git")
                lock_files = ["shallow.lock", "index.lock", "HEAD.lock", "config.lock"]
                for lock in lock_files:
                    lock_path = os.path.join(git_dir, lock)
                    if os.path.exists(lock_path):
                        try:
                            os.remove(lock_path)
                            print(f"      - Removed {lock}")
                        except:
                            pass
                
                # 3. Force reset with different approach if needed
                if args[0] == "reset":
                    print("    > Alternative: git checkout . && git fetch && git reset")
                    subprocess.run(["git", "checkout", "."], cwd=cwd)
                    subprocess.run(["git", "fetch", "origin", "main"], cwd=cwd)
                    subprocess.run(["git", "reset", "--hard", "origin/main"], cwd=cwd)
                    return ""
                
                # Retry original command
                print(f"    > {cmd_str} (RETRY)")
                result = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"    ! Retry failed: {result.stderr}")
                    return None
            
        return result.stdout.strip()
    except Exception as e:
        print(f"    ! Unexpected error: {e}")
        return None

def update_cve_repo():
    """Clone/pull CVE repo using sparse checkout (only recent years)."""
    os.makedirs(LOCAL_PATH, exist_ok=True)
    git_dir = os.path.join(LOCAL_PATH, ".git")

    if not os.path.exists(git_dir):
        print("[CVE] Initializing new repository...")
        run_git_command(["init"], cwd=LOCAL_PATH)
        run_git_command(["remote", "add", "origin", REPO_URL], cwd=LOCAL_PATH)
        run_git_command(["config", "core.sparseCheckout", "true"], cwd=LOCAL_PATH)
    else:
        print("[CVE] Updating existing repository...")

    # Write sparse-checkout paths
    sparse_file = os.path.join(git_dir, "info", "sparse-checkout")
    with open(sparse_file, "w") as f:
        for year in YEARS_TO_TRACK:
            f.write(f"cves/{year}/\n")

    print(f"[CVE] Sparse checkout configured for: {YEARS_TO_TRACK}")

    # Fetch and pull
    run_git_command(["fetch", "origin", "main"], cwd=LOCAL_PATH)
    run_git_command(["reset", "--hard", "origin/main"], cwd=LOCAL_PATH)

    run_git_command(["checkout", "main"], cwd=LOCAL_PATH)

    print("[CVE] Repository updated successfully")

# ==============================================================
# CVE INGESTION
# ==============================================================
def ingest_cves(max_cves=100):
    """Ingest latest real CVEs — All 2026 CVEs first, then newest 2025."""
    update_cve_repo()

    created = 0
    cve_files = []

    print(f"[CVE] Scanning for CVEs in years: {YEARS_TO_TRACK}...")

    base_dir = os.path.join(LOCAL_PATH, "cves")
    if not os.path.exists(base_dir):
        print("[CVE] No CVE data directory found after update")
        return 0

    # Collect files by year for debugging
    files_by_year = {}
    for year in YEARS_TO_TRACK:
        year_dir = os.path.join(base_dir, year)
        if not os.path.exists(year_dir):
            print(f"[CVE] Year {year} directory not found")
            continue

        year_files = []
        for root, _, files in os.walk(year_dir):
            for file in files:
                if file.endswith(".json") and file.startswith("CVE-"):
                    year_files.append(os.path.join(root, file))
        
        files_by_year[year] = year_files
        print(f"[CVE] Year {year}: {len(year_files)} files")
        cve_files.extend(year_files)

    print(f"[CVE] Total files found: {len(cve_files)}")

    if not cve_files:
        print("[CVE] No CVE files found!")
        return 0

    # === IMPROVED SORTING: 2026 first, then newest sequence within year ===
    def cve_sort_key(file_path):
        filename = os.path.basename(file_path)
        try:
            parts = filename.split('-')
            if len(parts) < 3:
                return (0, 0)  # fallback
            
            year = int(parts[1])
            
            # Extract sequence number: CVE-YYYY-XXXXX.json → XXXXX
            seq_str = parts[2].split('.')[0]
            
            # Extract only numeric part (some CVEs have letters)
            seq_num = ''
            for char in seq_str:
                if char.isdigit():
                    seq_num += char
                else:
                    break
            
            seq = int(seq_num) if seq_num else 0
            
        except (ValueError, IndexError) as e:
            print(f"[DEBUG] Error parsing {filename}: {e}")
            year = 0
            seq = 0
        
        # Primary: higher year first (2026 > 2025)
        # Secondary: higher sequence first (newest in year)
        return (-year, -seq)

    cve_files.sort(key=cve_sort_key)

    # === DEBUG: Show top 15 after sorting ===
    print("[CVE] Top 15 CVEs after sorting (2026 first, then newest 2025):")
    for i, fp in enumerate(cve_files[:15]):
        filename = os.path.basename(fp)
        # Extract year for verification
        try:
            year = filename.split('-')[1]
            seq = filename.split('-')[2].split('.')[0]
            print(f"  {i+1:2}. {filename} (Year: {year}, Seq: {seq})")
        except:
            print(f"  {i+1:2}. {filename}")

    # Process only up to max_cves
    for file_path in cve_files[:max_cves]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            cve_id = data.get("cveMetadata", {}).get("cveId", "")
            if not cve_id:
                continue

            # Extract description
            desc = ""
            containers = data.get("containers", {})
            cna = containers.get("cna", {})
            descriptions = cna.get("descriptions", [])
            if descriptions:
                desc = descriptions[0].get("value", "")[:500]

            # CVSS score
            cvss_score = 0.0
            cvss_severity = "Unknown"
            metrics = cna.get("metrics", [])
            for metric in metrics:
                for ver in ["cvssV3_1", "cvssV3_0"]:
                    if ver in metric:
                        cvss_data = metric[ver]
                        cvss_score = cvss_data.get("baseScore", 0)
                        cvss_severity = cvss_data.get("baseSeverity", "Unknown")
                        break
                if cvss_score > 0:
                    break

            # Fallback scoring if no CVSS
            if cvss_score == 0:
                desc_lower = desc.lower()
                if any(k in desc_lower for k in ["rce", "remote code execution", "privilege escalation", "critical"]):
                    cvss_score = 8.5
                    cvss_severity = "High"
                elif any(k in desc_lower for k in ["xss", "injection", "bypass", "dos"]):
                    cvss_score = 6.5
                    cvss_severity = "Medium"
                else:
                    cvss_score = 4.5
                    cvss_severity = "Low"

            db_score = int(cvss_score * 10)
            reputation = "critical" if cvss_score >= 9.0 else "malicious" if cvss_score >= 7.0 else "suspicious"

            # Tags
            tags = [f"severity:{cvss_severity.lower()}"]
            affected = cna.get("affected", [])
            if affected:
                vendors = {item.get("vendor") for item in affected[:3] if item.get("vendor")}
                tags.extend([v for v in vendors if v][:3])

            desc_full = f"{desc}"
            if cvss_score > 0:
                desc_full += f" | CVSS: {cvss_score:.1f} ({cvss_severity})"

            published = data.get("cveMetadata", {}).get("datePublished", "")
            updated = data.get("cveMetadata", {}).get("dateUpdated", "")

            save_or_update_record(
                type_='cve',
                value=cve_id,
                score=db_score,
                reputation=reputation,
                source=f"CVE Project ({cve_id.split('-')[1]})",
                category="vulnerability",
                tags=tags[:10],
                first_seen=published,
                last_seen=updated or published,
                description=desc_full
            )
            created += 1

            if created % 20 == 0:
                print(f"[CVE] Processed {created}/{min(max_cves, len(cve_files))} CVEs...")

        except Exception as e:
            print(f"[CVE] Error processing {file_path}: {e}")
            continue

    print(f"[CVE] Ingested {created} real CVEs — 2026 entries prioritized at the top!")
    
    # Show summary by year
    print(f"[CVE] Summary by year:")
    for year in sorted(YEARS_TO_TRACK, reverse=True):
        year_cves = [c for c in cve_files[:max_cves] if f"/cves/{year}/" in c]
        if year_cves:
            print(f"  - {year}: {len(year_cves)} CVEs")
    
    return created

# ==============================================================
# 1. MALICIOUS URLS - URLHAUS
# ==============================================================
def ingest_urls(max_urls=50):
    # (Same as your clean version — unchanged)
    created = 0
    seen = set()
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json,text/plain"}
    urls_data = []

    print(f"[URLhaus] Starting ingestion - MAX: {max_urls} URLs")

    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/json_recent/", headers=headers, timeout=15)
        if r.status_code == 200:
            urls_data.extend(r.json().get("urls", [])[:max_urls])
    except Exception as e:
        print(f"[URLhaus] Recent JSON failed: {e}")

    if len(urls_data) < max_urls:
        try:
            r = requests.get("https://urlhaus.abuse.ch/downloads/json_online/", headers=headers, timeout=15)
            if r.status_code == 200:
                urls_data.extend(r.json().get("urls", [])[:max_urls - len(urls_data)])
        except Exception as e:
            print(f"[URLhaus] Online JSON failed: {e}")

    if not urls_data:
        try:
            r = requests.get("https://urlhaus.abuse.ch/downloads/text/", headers=headers, timeout=20)
            if r.status_code == 200:
                lines = [l.strip() for l in r.text.split('\n') if l.strip() and not l.startswith('#')]
                for i, line in enumerate(lines[:max_urls]):
                    urls_data.append({"url": line, "status": "online", "threat": "malware_download"})
        except Exception as e:
            print(f"[URLhaus] Text feed failed: {e}")

    current_time = timezone.now()
    for i, item in enumerate(urls_data):
        if created >= max_urls:
            break
        url = item.get("url", "").strip()
        if not url or url in seen or len(url) > 500:
            continue
        if not url.startswith('http'):
            url = 'http://' + url
        seen.add(url)

        threat = str(item.get("threat", "")).lower()
        status = str(item.get("status", "")).lower()
        score = 90 if "online" in status else 75
        category = "ransomware" if "ransom" in threat else "phishing" if "phish" in threat else "malware_distribution"

        tags = item.get("tags", []) or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        tags = (tags)[:3]
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match and domain_match.group(1) not in tags:
            tags.append(f"domain:{domain_match.group(1)}")

        save_or_update_record(
            type_="url",
            value=url,
            score=score,
            reputation="malicious" if score >= 75 else "suspicious",
            source="URLhaus",
            category=category,
            tags=tags,
            first_seen=(current_time - timedelta(minutes=i)).isoformat(),
            last_seen=current_time.isoformat(),
            description=f"URL from URLhaus | Threat: {threat[:50]}" if threat else "Malicious URL"
        )
        created += 1

    print(f"[URLhaus] Ingested {created} URLs")
    return created

# ==============================================================
# 2. MALWARE SAMPLES - MALWAREBAZAAR
# ==============================================================
def ingest_malware(max_samples=100):
    created = 0
    try:
        print("[MalwareBazaar] Fetching latest samples...")
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={'Auth-Key': MALWAREBAZAAR_AUTH_KEY},
            data={'query': 'get_recent', 'selector': 'time', 'limit': str(max_samples)},
            timeout=30
        )

        if resp.status_code != 200:
            print(f"[MalwareBazaar] HTTP error: {resp.status_code}")
            return 0

        api_data = resp.json()
        if api_data.get('query_status') != 'ok':
            print(f"[MalwareBazaar] API error: {api_data.get('query_status')}")
            return 0

        data_list = api_data.get('data', [])
        print(f"[MalwareBazaar] Received {len(data_list)} samples")

        for item in data_list:
            sha256 = item.get('sha256_hash', '').strip()
            if not sha256 or len(sha256) != 64:
                continue

            tags = [str(t).strip() for t in item.get('tags', []) if t]
            filename = item.get('file_name') or 'unknown.exe'
            file_type = item.get('file_type') or 'unknown'

            # FIXED: Safe handling of signature (can be None or missing)
            signature = item.get('signature') or 'unknown'
            sig_lower = str(signature).lower()
            score = 95 if any(s in sig_lower for s in ['mirai', 'gafgyt', 'blacknet', 'gcleaner', 'ransom']) else 90

            save_or_update_record(
                type_='malware',
                value=sha256,
                score=score,
                reputation='malicious',
                source='MalwareBazaar API',
                category=str(signature),
                tags=tags,
                first_seen=item.get('first_seen'),
                description=f"{filename} ({file_type}) | Size: {item.get('file_size', 0)} bytes | Origin: {item.get('origin_country', '??')}"
            )
            created += 1

        print(f"[MalwareBazaar] Ingested {created} samples")
    except Exception as e:
        print(f"[MalwareBazaar] Failed: {e}")
    return created

# ==============================================================
# 3. MALICIOUS IPS - ABUSEIPDB
# ==============================================================
def ingest_ips(max_ips=150):
    # (Same as before — unchanged)
    created = 0
    print(f"[IPs] Fetching up to {max_ips} malicious IPs...")

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'text/plain'},
            params={'confidenceMinimum': 25, 'limit': max_ips * 1, 'plaintext': True},
            timeout=40
        )
        if response.status_code != 200:
            print(f"[IPs] Failed: {response.status_code}")
            return 0

        ips = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')]
        print(f"[IPs] Received {len(ips)} raw IPs")

        for ip in ips:
            if created >= max_ips:
                break
            data = check_ip_reputation(ip)
            if data["score"] < 10 or is_legitimate_ip_range(ip):
                continue

            reputation = "malicious" if data["score"] >= 60 else "suspicious"

            save_or_update_record(
                type_='ip',
                value=ip,
                score=data["score"],
                reputation=reputation,
                source='AbuseIPDB Blacklist',
                category='abuse',
                tags=['abuseipdb', 'blacklist', data["country"]],
                description=f"Reports: {data['reports']} | Confidence: {data['score']}% | {data['country']}"
            )
            created += 1

        print(f"[IPs] Ingested {created} IPs")
    except Exception as e:
        print(f"[IPs] Error: {e}")
    return created

# ==============================================================
# MANAGEMENT COMMAND
# ==============================================================
class Command(BaseCommand):
    help = 'Ingest URLs, malware, IPs, and latest CVEs (2025–2027) from official sources'

    def add_arguments(self, parser):
        parser.add_argument('--max-urls', type=int, default=50)
        parser.add_argument('--max-malware', type=int, default=100)
        parser.add_argument('--max-ips', type=int, default=150)
        parser.add_argument('--max-cves', type=int, default=100)

    def handle(self, *args, **options):
        print("Starting threat intelligence ingestion...")
        print("=" * 70)

        total = 0

        print("1. Ingesting Malicious URLs (URLhaus)")
        total += ingest_urls(options['max_urls'])

        print("\n2. Ingesting Malware Samples (MalwareBazaar)")
        total += ingest_malware(options['max_malware'])

        print("\n3. Ingesting Malicious IPs (AbuseIPDB)")
        total += ingest_ips(options['max_ips'])

        print("\n4. Ingesting Latest CVEs (2025–2027 via Git)")
        total += ingest_cves(options['max_cves'])

        print("\n" + "=" * 70)
        self.stdout.write(self.style.SUCCESS(
            f'INGESTION COMPLETE!\n'
            f'   • URLs:     {options["max_urls"]}\n'
            f'   • Malware:  {options["max_malware"]}\n'
            f'   • IPs:      {options["max_ips"]}\n'
            f'   • CVEs:     {options["max_cves"]}\n'
            f'   • TOTAL:    {total} records processed\n'
            f'   • CVE-2026 will appear automatically when published!'
        ))