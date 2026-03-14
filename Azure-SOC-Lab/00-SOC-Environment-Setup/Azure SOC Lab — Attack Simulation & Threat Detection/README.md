# Azure SOC Lab — Attack Simulation & Threat Detection

## Project Overview

This phase of the Azure SOC Lab focuses on detecting suspicious authentication activity using Microsoft Sentinel within Microsoft Azure.

The objective of this project is to simulate attacker behavior, analyze failed login attempts, and create detection rules capable of identifying potential brute force attacks.

This project demonstrates a simplified Security Operations Center (SOC) workflow including threat hunting, detection engineering, and monitoring.

---

# Technologies Used

* Microsoft Azure
* Microsoft Sentinel
* Azure Log Analytics
* Kusto Query Language (KQL)

---

# Log Verification

Before performing threat analysis, security logs were verified in the workspace to ensure authentication events were being collected properly.

This confirms that the environment is receiving Windows security events that can be used for threat hunting and detection.

## KQL Query

```kql
SecurityEvent
| take 10
```

## Screenshot

![Log Ingestion Verification](screenshots/log-ingestion-verification.png)

---

# Failed Login Analysis

Windows **Event ID 4625** represents failed authentication attempts.

These logs were queried to identify patterns of repeated login failures originating from external IP addresses that may indicate brute force activity.

## KQL Query

```kql
SecurityEvent
| where EventID == 4625
| summarize AttemptCount = count() by IpAddress
| sort by AttemptCount desc
```

## Screenshot

![Failed Login Analysis](screenshots/failed-login-analysis.png)

---

# Attacker IP Analysis

The IP addresses responsible for repeated failed login attempts were investigated to identify suspicious sources targeting the system.

Analyzing these IP addresses allows analysts to determine potential attacker behavior and identify high-volume authentication attempts.

## Screenshot

![Attacker IP Analysis](screenshots/attacker-ip-analysis.png)

---

# Brute Force Detection Rule

A scheduled analytics rule was created in Microsoft Sentinel to automatically detect potential brute force attacks based on repeated failed authentication attempts.

The rule monitors authentication failures and generates alerts when the number of attempts exceeds a defined threshold.

## Screenshot

![Brute Force Detection Rule Summary](screenshots/sentinel-bruteforce-rule-summary.png)

---

# Active Detection Rule

Once configured, the detection rule continuously monitors incoming log data and triggers alerts when suspicious activity is identified.

This allows security analysts to be notified of potential brute force attacks in near real time.

## Screenshot

![Active Detection Rule](screenshots/sentinel-active-detection-rule.png)

---

# SOC Workflow Demonstrated

```
Log Verification
      ↓
Threat Hunting
      ↓
Failed Login Analysis
      ↓
Attacker Investigation
      ↓
Detection Rule Creation
      ↓
Security Monitoring
```

---

# Skills Demonstrated

* Security Log Analysis
* Threat Hunting using KQL
* Detection Engineering
* Brute Force Attack Identification
* SOC Monitoring Workflow

---

# MITRE ATT&CK Mapping

| Technique | Description                       |
| --------- | --------------------------------- |
| T1110     | Brute Force Authentication Attack |

---

# Cost Management

To prevent unnecessary Azure charges, the virtual machine used during the lab was stopped after completing the testing phase. The environment can be restarted later from the Azure portal if additional testing is required.

---

# References

* [Microsoft Sentinel Analytics Rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
* [KQL Tutorial](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/tutorial)
* [Scheduled Query Rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
* [MITRE ATT&CK: Brute Force](https://attack.mitre.org/techniques/T1110/)