"""
sentinel_alert_formatter.py
Takes a raw Microsoft Sentinel incident JSON export and formats it
into a clean, readable triage report for SOC L1 analysts.
Usage: python sentinel_alert_formatter.py --file incident.json
Export from Sentinel: Incidents blade > select incident > Export JSON
"""

import json
import argparse
from datetime import datetime

# Map Sentinel severity levels to triage priority
SEVERITY_MAP = {
    "High": "P1 - Respond immediately",
    "Medium": "P2 - Investigate within 1 hour",
    "Low": "P3 - Review within 4 hours",
    "Informational": "P4 - Log and monitor"
}

# Basic recommended actions per alert type keyword
ACTION_HINTS = {
    "brute force": "Isolate affected account. Check source IP against threat intel. Consider blocking IP at firewall.",
    "malware": "Isolate affected endpoint immediately. Capture memory dump if possible. Escalate to L2.",
    "phishing": "Quarantine email. Check if user clicked link or opened attachment. Reset credentials if compromised.",
    "lateral movement": "Map affected accounts and systems. Check for new admin accounts. Escalate to L2.",
    "data exfiltration": "Identify destination IPs. Block outbound traffic if active. Escalate to L2 immediately.",
    "privilege escalation": "Audit recent permission changes. Verify if change was authorized. Escalate if not.",
    "anomalous login": "Verify with user if login was legitimate. Check geolocation and device. Reset if suspicious.",
    "default": "Review all related events. Document findings. Escalate to L2 if scope is unclear."
}

def get_action_hint(title):
    title_lower = title.lower()
    for keyword, action in ACTION_HINTS.items():
        if keyword in title_lower:
            return action
    return ACTION_HINTS["default"]

def format_timestamp(ts):
    """Convert ISO timestamp to readable format."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts

def format_incident(incident):
    props = incident.get("properties", incident)  # handle both wrapped and flat JSON

    title = props.get("title", "N/A")
    severity = props.get("severity", "N/A")
    status = props.get("status", "N/A")
    created = format_timestamp(props.get("createdTimeUtc", props.get("createdTime", "N/A")))
    updated = format_timestamp(props.get("lastModifiedTimeUtc", props.get("lastModifiedTime", "N/A")))
    description = props.get("description", "No description provided.")
    incident_number = props.get("incidentNumber", props.get("incidentId", "N/A"))
    incident_url = props.get("incidentUrl", "N/A")

    # Entities (affected assets)
    entities = props.get("relatedAnalyticRuleIds", [])
    alerts = props.get("additionalData", {}).get("alertsCount", "N/A")
    bookmarks = props.get("additionalData", {}).get("bookmarksCount", "N/A")
    comments = props.get("additionalData", {}).get("commentsCount", "N/A")

    triage_priority = SEVERITY_MAP.get(severity, "Review manually")
    recommended_action = get_action_hint(title)

    lines = []
    lines.append("=" * 65)
    lines.append("SENTINEL INCIDENT TRIAGE REPORT")
    lines.append(f"Report Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 65)
    lines.append(f"Incident #       : {incident_number}")
    lines.append(f"Title            : {title}")
    lines.append(f"Severity         : {severity}")
    lines.append(f"Status           : {status}")
    lines.append(f"Triage Priority  : {triage_priority}")
    lines.append(f"Created          : {created}")
    lines.append(f"Last Updated     : {updated}")
    lines.append(f"Incident URL     : {incident_url}")
    lines.append("")
    lines.append("--- Description ---")
    lines.append(description)
    lines.append("")
    lines.append("--- Scope ---")
    lines.append(f"  Alerts    : {alerts}")
    lines.append(f"  Bookmarks : {bookmarks}")
    lines.append(f"  Comments  : {comments}")
    lines.append("")
    lines.append("--- Recommended Action ---")
    lines.append(f"  {recommended_action}")
    lines.append("")
    lines.append("--- Analyst Notes (fill in) ---")
    lines.append("  Investigated by : ___________________")
    lines.append("  Time started    : ___________________")
    lines.append("  Findings        : ___________________")
    lines.append("  Resolution      : ___________________")
    lines.append("=" * 65)

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Format Sentinel incident JSON into triage report.")
    parser.add_argument("--file", required=True, help="Path to Sentinel incident JSON file")
    parser.add_argument("--output", help="Optional: save report to .txt file")
    args = parser.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle single incident or array of incidents
    incidents = data if isinstance(data, list) else [data]

    all_reports = []
    for incident in incidents:
        report = format_incident(incident)
        all_reports.append(report)
        print(report)
        print()

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n\n".join(all_reports))
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
