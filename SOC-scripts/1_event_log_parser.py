"""
event_log_parser.py
Parses Windows Event Log exports (.csv) and filters by Event ID.
Targets: 4625 (failed login), 4624 (successful login)
Usage: python event_log_parser.py --file logs.csv --output report.txt
"""

import csv
import argparse
from datetime import datetime
from collections import defaultdict

# Event IDs we care about
WATCHED_EVENTS = {
    "4624": "Successful Login",
    "4625": "Failed Login"
}

def parse_log(filepath):
    results = []

    with open(filepath, newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            event_id = row.get("EventID", "").strip()

            if event_id in WATCHED_EVENTS:
                results.append({
                    "timestamp": row.get("TimeCreated", "N/A"),
                    "event_id": event_id,
                    "event_type": WATCHED_EVENTS[event_id],
                    "username": row.get("SubjectUserName", row.get("TargetUserName", "N/A")),
                    "source_ip": row.get("IpAddress", "N/A"),
                    "workstation": row.get("WorkstationName", "N/A"),
                    "logon_type": row.get("LogonType", "N/A")
                })

    return results

def generate_summary(events):
    total = len(events)
    failed = [e for e in events if e["event_id"] == "4625"]
    success = [e for e in events if e["event_id"] == "4624"]

    # Count failures per user
    fail_by_user = defaultdict(int)
    for e in failed:
        fail_by_user[e["username"]] += 1

    # Count failures per IP
    fail_by_ip = defaultdict(int)
    for e in failed:
        fail_by_ip[e["source_ip"]] += 1

    lines = []
    lines.append("=" * 60)
    lines.append("WINDOWS EVENT LOG PARSE SUMMARY")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append(f"Total Events Matched : {total}")
    lines.append(f"Successful Logins    : {len(success)}")
    lines.append(f"Failed Logins        : {len(failed)}")
    lines.append("")

    if fail_by_user:
        lines.append("--- Failed Logins by Username ---")
        for user, count in sorted(fail_by_user.items(), key=lambda x: -x[1]):
            lines.append(f"  {user:<30} {count} attempts")
        lines.append("")

    if fail_by_ip:
        lines.append("--- Failed Logins by Source IP ---")
        for ip, count in sorted(fail_by_ip.items(), key=lambda x: -x[1]):
            lines.append(f"  {ip:<20} {count} attempts")
        lines.append("")

    lines.append("--- Raw Event Details ---")
    for e in events:
        lines.append(
            f"[{e['timestamp']}] {e['event_type']} | "
            f"User: {e['username']} | IP: {e['source_ip']} | "
            f"Logon Type: {e['logon_type']}"
        )

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Parse Windows Event Logs for login events.")
    parser.add_argument("--file", required=True, help="Path to CSV log file")
    parser.add_argument("--output", help="Optional: save report to file")
    args = parser.parse_args()

    print(f"[*] Parsing: {args.file}")
    events = parse_log(args.file)

    if not events:
        print("[!] No matching events found. Check your CSV column headers.")
        return

    summary = generate_summary(events)
    print(summary)

    if args.output:
        with open(args.output, "w") as f:
            f.write(summary)
        print(f"\n[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
