"""
log_anomaly_detector.py
Reads a CSV of login events, builds a baseline of normal login hours per user,
then flags any logins that fall outside that user's normal pattern.
This is simplified behavioral detection — the same logic used in UBA/UEBA tools.
Usage: python log_anomaly_detector.py --file logins.csv
Expected CSV columns: timestamp, username, source_ip, event_id
"""

import csv
import argparse
from collections import defaultdict
from datetime import datetime

# How many std deviations outside normal = anomaly
# Simpler version: just flag anything outside the user's min/max hour range
ALLOW_HOUR_BUFFER = 1  # +/- 1 hour buffer around known login window

def parse_logins(filepath):
    """Load login events from CSV."""
    logins = []

    with open(filepath, newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            event_id = row.get("EventID", row.get("event_id", "")).strip()

            # Only process successful logins (4624) for baseline
            # Include failed (4625) for anomaly flagging
            ts_raw = row.get("TimeCreated", row.get("timestamp", "")).strip()

            try:
                # Try common timestamp formats
                for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        ts = datetime.strptime(ts_raw, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    continue  # Skip rows with unparseable timestamps

                logins.append({
                    "timestamp": ts,
                    "hour": ts.hour,
                    "username": row.get("TargetUserName", row.get("username", "unknown")).strip(),
                    "source_ip": row.get("IpAddress", row.get("source_ip", "unknown")).strip(),
                    "event_id": event_id
                })

            except Exception:
                continue

    return logins

def build_baseline(logins):
    """Build normal login hour range per user from successful logins."""
    user_hours = defaultdict(list)

    for event in logins:
        if event["event_id"] == "4624":
            user_hours[event["username"]].append(event["hour"])

    baselines = {}
    for user, hours in user_hours.items():
        if hours:
            baselines[user] = {
                "min_hour": max(0, min(hours) - ALLOW_HOUR_BUFFER),
                "max_hour": min(23, max(hours) + ALLOW_HOUR_BUFFER),
                "typical_hours": sorted(set(hours)),
                "login_count": len(hours)
            }

    return baselines

def detect_anomalies(logins, baselines):
    """Flag logins outside each user's normal hour window."""
    anomalies = []

    for event in logins:
        user = event["username"]
        hour = event["hour"]

        if user not in baselines:
            # No baseline = first time seen user, flag it
            anomalies.append({
                **event,
                "reason": "No baseline — first time seen user"
            })
            continue

        baseline = baselines[user]
        if hour < baseline["min_hour"] or hour > baseline["max_hour"]:
            anomalies.append({
                **event,
                "reason": (
                    f"Login at {hour:02d}:00 is outside normal window "
                    f"({baseline['min_hour']:02d}:00 – {baseline['max_hour']:02d}:00)"
                )
            })

    return anomalies

def print_report(logins, baselines, anomalies):
    print("=" * 65)
    print("LOG ANOMALY DETECTION REPORT")
    print(f"Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Events: {len(logins)}")
    print(f"Users Baselined: {len(baselines)}")
    print("=" * 65)

    print("\n--- User Baselines (Normal Login Windows) ---")
    for user, b in sorted(baselines.items()):
        print(
            f"  {user:<30} Normal: {b['min_hour']:02d}:00 – {b['max_hour']:02d}:00 "
            f"| Logins in dataset: {b['login_count']}"
        )

    print(f"\n--- Anomalies Detected: {len(anomalies)} ---")
    if not anomalies:
        print("  [OK] No anomalies found.")
    else:
        for a in sorted(anomalies, key=lambda x: x["timestamp"]):
            print(
                f"\n  [!] ANOMALY"
                f"\n      Time     : {a['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                f"\n      User     : {a['username']}"
                f"\n      Source IP: {a['source_ip']}"
                f"\n      Event ID : {a['event_id']}"
                f"\n      Reason   : {a['reason']}"
            )

    print("\n" + "=" * 65)

def main():
    parser = argparse.ArgumentParser(description="Detect anomalous logins based on user behavior baseline.")
    parser.add_argument("--file", required=True, help="Path to CSV login log file")
    parser.add_argument("--output", help="Optional: save report to file")
    args = parser.parse_args()

    print(f"[*] Loading: {args.file}")
    logins = parse_logins(args.file)

    if not logins:
        print("[!] No parseable login events found. Check your CSV format.")
        return

    baselines = build_baseline(logins)
    anomalies = detect_anomalies(logins, baselines)
    print_report(logins, baselines, anomalies)

    if args.output:
        import io, sys
        buffer = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buffer
        print_report(logins, baselines, anomalies)
        sys.stdout = old_stdout
        with open(args.output, "w") as f:
            f.write(buffer.getvalue())
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
