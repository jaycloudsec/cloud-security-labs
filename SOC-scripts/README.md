# SOC Python Scripts

A collection of Python utilities for SOC L1 triage and investigation tasks.
Built as part of my security operations portfolio while transitioning into cybersecurity.

## Vendor Compatibility

Most scripts are vendor-agnostic and work with any SIEM or log source that exports CSV data.

| Script | Azure Sentinel | Splunk | CrowdStrike | Elastic | On-prem |
|--------|:--------------:|:------:|:-----------:|:-------:|:-------:|
| 1. Event Log Parser | ✅ | ✅ | ✅ | ✅ | ✅ |
| 2. Failed Login Counter | ✅ | ✅ | ✅ | ✅ | ✅ |
| 3. Sentinel Alert Formatter | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| 4. IOC Lookup (VirusTotal) | ✅ | ✅ | ✅ | ✅ | ✅ |
| 5. Log Anomaly Detector | ✅ | ✅ | ✅ | ✅ | ✅ |

⚠️ Script 3 is built around Sentinel's incident JSON structure. It can be adapted to other platforms by remapping the field names — the triage logic itself is not vendor-specific.

---

## Scripts

### 1. `event_log_parser.py` — Windows Event Log Parser
Parses exported Windows Event Log CSV files and filters for login events (4624/4625).
Outputs a clean summary grouped by user and source IP.

```bash
python event_log_parser.py --file logs.csv --output report.txt
```

---

### 2. `failed_login_counter.py` — Failed Login Counter
Counts failed login attempts (Event ID 4625) per IP and username.
Flags anything that exceeds a defined threshold — mirrors basic Sentinel alert logic.

```bash
python failed_login_counter.py --file logs.csv --threshold 5
```

---

### 3. `sentinel_alert_formatter.py` — Sentinel Alert Formatter
Takes a raw Microsoft Sentinel incident JSON export and formats it into a
readable triage report with recommended actions and analyst notes fields.
Field mappings are Sentinel-specific but the logic is portable to other platforms.

```bash
python sentinel_alert_formatter.py --file incident.json --output triage.txt
```

Export JSON from Sentinel: Incidents blade → select incident → Export

---

### 4. `ioc_lookup.py` — IOC Lookup (VirusTotal)
Bulk-checks IPs, domains, URLs, and file hashes against VirusTotal's API.
Supports free tier (500 lookups/day). Returns MALICIOUS / SUSPICIOUS / CLEAN verdict.

```bash
python ioc_lookup.py --iocs ioc_list.txt --apikey YOUR_VT_KEY
```

Get a free API key at: https://www.virustotal.com/gui/join-us

---

### 5. `log_anomaly_detector.py` — Log Anomaly Detector
Builds a per-user baseline of normal login hours from historical data,
then flags any logins that fall outside that window. Simplified UEBA logic.

```bash
python log_anomaly_detector.py --file logins.csv
```

---

## Sample Data

Each script works with CSV files exported from Windows Event Viewer or Azure Log Analytics.
Minimum expected columns: `TimeCreated`, `EventID`, `TargetUserName`, `IpAddress`

---

## Related Projects

- [Azure SOC Lab](https://github.com/jaycloudsec/cloud-security-labs) — Microsoft Sentinel deployment with KQL detection rules and brute force simulation
- [Portfolio](https://jaycloudsec.github.io)
