"""
failed_login_counter.py
Counts failed login attempts per IP and username from a CSV log.
Flags any that exceed a defined threshold — mimics basic Sentinel alert logic.
Usage: python failed_login_counter.py --file logs.csv --threshold 5
"""

import csv
import argparse
from collections import defaultdict
from datetime import datetime

DEFAULT_THRESHOLD = 5

def count_failures(filepath, threshold):
    ip_counts = defaultdict(int)
    user_counts = defaultdict(int)
    flagged_ips = []
    flagged_users = []

    with open(filepath, newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            event_id = row.get("EventID", "").strip()

            if event_id == "4625":
                ip = row.get("IpAddress", "unknown").strip()
                user = row.get("TargetUserName", row.get("SubjectUserName", "unknown")).strip()

                ip_counts[ip] += 1
                user_counts[user] += 1

    # Flag anything over threshold
    for ip, count in ip_counts.items():
        if count >= threshold:
            flagged_ips.append((ip, count))

    for user, count in user_counts.items():
        if count >= threshold:
            flagged_users.append((user, count))

    return ip_counts, user_counts, flagged_ips, flagged_users

def print_report(ip_counts, user_counts, flagged_ips, flagged_users, threshold):
    print("=" * 60)
    print("FAILED LOGIN COUNTER REPORT")
    print(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Threshold : {threshold} attempts")
    print("=" * 60)

    total_failures = sum(ip_counts.values())
    print(f"Total Failed Login Events: {total_failures}")
    print(f"Unique Source IPs        : {len(ip_counts)}")
    print(f"Unique Usernames         : {len(user_counts)}")
    print()

    print("--- All IPs (sorted by attempts) ---")
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1]):
        flag = " <<< FLAGGED" if count >= threshold else ""
        print(f"  {ip:<20} {count} attempts{flag}")
    print()

    print("--- All Usernames (sorted by attempts) ---")
    for user, count in sorted(user_counts.items(), key=lambda x: -x[1]):
        flag = " <<< FLAGGED" if count >= threshold else ""
        print(f"  {user:<30} {count} attempts{flag}")
    print()

    if flagged_ips or flagged_users:
        print("=" * 60)
        print("!!! ALERT: THRESHOLD EXCEEDED !!!")
        print("=" * 60)
        if flagged_ips:
            print("Flagged IPs:")
            for ip, count in sorted(flagged_ips, key=lambda x: -x[1]):
                print(f"  [HIGH] {ip} — {count} failed attempts")
        if flagged_users:
            print("Flagged Usernames:")
            for user, count in sorted(flagged_users, key=lambda x: -x[1]):
                print(f"  [HIGH] {user} — {count} failed attempts")
    else:
        print("[OK] No IPs or users exceeded the threshold.")

def main():
    parser = argparse.ArgumentParser(description="Count and flag failed login attempts.")
    parser.add_argument("--file", required=True, help="Path to CSV log file")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"Alert threshold (default: {DEFAULT_THRESHOLD})")
    args = parser.parse_args()

    print(f"[*] Scanning: {args.file} | Threshold: {args.threshold}")
    ip_counts, user_counts, flagged_ips, flagged_users = count_failures(args.file, args.threshold)
    print_report(ip_counts, user_counts, flagged_ips, flagged_users, args.threshold)

if __name__ == "__main__":
    main()
