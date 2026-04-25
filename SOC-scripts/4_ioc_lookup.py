"""
ioc_lookup.py
Takes a list of IPs or file hashes and checks them against VirusTotal's free API.
Returns a verdict for each IOC — clean, suspicious, or malicious.
Usage: python ioc_lookup.py --iocs ioc_list.txt --apikey YOUR_VT_API_KEY
Get free API key: https://www.virustotal.com/gui/join-us
Free tier: 500 lookups/day, 4 requests/minute
"""

import requests
import argparse
import time
import re
from datetime import datetime

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Thresholds for verdict
MALICIOUS_THRESHOLD = 5     # 5+ engines flagged = malicious
SUSPICIOUS_THRESHOLD = 1    # 1-4 engines flagged = suspicious

def detect_ioc_type(ioc):
    """Guess whether an IOC is an IP, domain, URL, or hash."""
    ioc = ioc.strip()
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")

    if ip_pattern.match(ioc):
        return "ip"
    elif hash_pattern.match(ioc):
        return "hash"
    elif ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    else:
        return "domain"

def lookup_ip(ioc, headers):
    url = f"{VT_BASE_URL}/ip_addresses/{ioc}"
    return requests.get(url, headers=headers)

def lookup_hash(ioc, headers):
    url = f"{VT_BASE_URL}/files/{ioc}"
    return requests.get(url, headers=headers)

def lookup_domain(ioc, headers):
    url = f"{VT_BASE_URL}/domains/{ioc}"
    return requests.get(url, headers=headers)

def lookup_url(ioc, headers):
    import base64
    url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    url = f"{VT_BASE_URL}/urls/{url_id}"
    return requests.get(url, headers=headers)

def get_verdict(malicious_count, suspicious_count):
    if malicious_count >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    elif malicious_count > 0 or suspicious_count >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    else:
        return "CLEAN"

def lookup_ioc(ioc, headers):
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)

    try:
        if ioc_type == "ip":
            response = lookup_ip(ioc, headers)
        elif ioc_type == "hash":
            response = lookup_hash(ioc, headers)
        elif ioc_type == "url":
            response = lookup_url(ioc, headers)
        else:
            response = lookup_domain(ioc, headers)

        if response.status_code == 404:
            return ioc, ioc_type, "NOT FOUND", 0, 0, "No data in VirusTotal"

        if response.status_code == 429:
            return ioc, ioc_type, "RATE LIMITED", 0, 0, "Too many requests — wait 60s"

        if response.status_code != 200:
            return ioc, ioc_type, "ERROR", 0, 0, f"HTTP {response.status_code}"

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        verdict = get_verdict(malicious, suspicious)
        detail = f"Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} | Undetected: {undetected}"

        return ioc, ioc_type, verdict, malicious, suspicious, detail

    except Exception as e:
        return ioc, ioc_type, "ERROR", 0, 0, str(e)

def main():
    parser = argparse.ArgumentParser(description="Bulk IOC lookup via VirusTotal API.")
    parser.add_argument("--iocs", required=True, help="Path to text file with one IOC per line")
    parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
    parser.add_argument("--output", help="Optional: save results to file")
    parser.add_argument("--delay", type=float, default=15.0,
                        help="Seconds between requests (default: 15 for free tier)")
    args = parser.parse_args()

    headers = {"x-apikey": args.apikey}

    with open(args.iocs, "r") as f:
        iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print("=" * 65)
    print("IOC LOOKUP REPORT — VirusTotal")
    print(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"IOCs      : {len(iocs)}")
    print("=" * 65)

    results = []
    for i, ioc in enumerate(iocs, 1):
        print(f"[{i}/{len(iocs)}] Checking: {ioc}")
        result = lookup_ioc(ioc, headers)
        results.append(result)

        ioc_val, ioc_type, verdict, mal, sus, detail = result
        print(f"  Type    : {ioc_type.upper()}")
        print(f"  Verdict : {verdict}")
        print(f"  Details : {detail}")
        print()

        # Respect free tier rate limit (4 req/min = 15s between calls)
        if i < len(iocs):
            time.sleep(args.delay)

    # Summary
    malicious_list = [r for r in results if r[2] == "MALICIOUS"]
    suspicious_list = [r for r in results if r[2] == "SUSPICIOUS"]

    print("=" * 65)
    print("SUMMARY")
    print(f"  Total checked  : {len(results)}")
    print(f"  MALICIOUS      : {len(malicious_list)}")
    print(f"  SUSPICIOUS     : {len(suspicious_list)}")
    print(f"  Clean/Unknown  : {len(results) - len(malicious_list) - len(suspicious_list)}")

    if malicious_list:
        print("\n  !!! MALICIOUS IOCs !!!")
        for r in malicious_list:
            print(f"    {r[0]} ({r[1].upper()}) — {r[3]} engines")

    if args.output:
        with open(args.output, "w") as f:
            for r in results:
                f.write(f"{r[0]},{r[1]},{r[2]},{r[3]},{r[4]},{r[5]}\n")
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
