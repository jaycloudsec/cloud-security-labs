# Azure SOC Lab — Attack Simulation & Threat Detection

## Overview

This project continues from the **Azure SOC Lab — SIEM Deployment & Log Ingestion** environment.
The goal of this phase is to simulate attacker behavior and detect malicious activity using Microsoft Sentinel.

The lab focuses on generating realistic security events and analyzing them using **Kusto Query Language (KQL)** within the Log Analytics Workspace.

This simulates a basic **Security Operations Center (SOC)** workflow including attack simulation, log analysis, detection, and investigation.

---

# Lab Architecture

Attack activity is generated against the monitored Azure virtual machine and ingested into Microsoft Sentinel.

Internet (Attacker Machine)
↓
Azure Virtual Network
↓
Windows Virtual Machine (Target)
↓
Azure Monitor Agent (AMA)
↓
Data Collection Rule (DCR)
↓
Log Analytics Workspace
↓
Microsoft Sentinel (SIEM)

---

# Attack Simulation

Several attack scenarios are performed against the Azure virtual machine to generate detectable security telemetry.

These activities are conducted in a controlled lab environment for educational purposes.

Simulated attack techniques:

* Network reconnaissance using Nmap
* Multiple failed authentication attempts
* Remote Desktop brute force attempts

These actions generate Windows Security Events that are collected by the **Azure Monitor Agent** and forwarded to the **Log Analytics Workspace**.

---

# Attack Scenario 1 — Port Scanning

Attackers commonly begin with reconnaissance to discover open services.

In this lab, a port scan is performed against the public IP address of the Azure virtual machine.

Example command:

```bash
nmap -sS <target-vm-public-ip>
```

This scan attempts to identify open ports and services exposed to the internet.

Port scanning activity can provide early indicators of attacker reconnaissance behavior.

---

# Attack Scenario 2 — Failed Login Attempts

Multiple failed login attempts are generated to simulate an attacker attempting to guess credentials.

Windows records these attempts as **Event ID 4625** in the Security log.

These logs are forwarded to Azure Log Analytics where they can be analyzed using KQL queries.

---

# Attack Scenario 3 — RDP Brute Force Simulation

Repeated authentication attempts are performed against the Remote Desktop service.

This produces multiple **Event ID 4625** entries in the Windows Security logs.

High volumes of these events often indicate brute force attempts against exposed RDP services.

---

# Log Analysis Using KQL

After attack simulation, security events can be queried in the Log Analytics Workspace.

Example query to identify failed login attempts:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress
| sort by FailedAttempts desc
```

This query helps identify accounts receiving the highest number of failed authentication attempts.

---

# Threat Hunting

Threat hunting queries can be used to proactively search for suspicious activity.

Example hunting query:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
```

This query identifies failed login attempts within the last hour.

Threat hunters often use similar queries to detect suspicious patterns before automated alerts are triggered.

---

# Sentinel Detection Rule

Microsoft Sentinel analytic rules can be configured to automatically detect suspicious login activity.

Example detection logic:

Trigger an alert when a large number of **Event ID 4625** entries occur within a short time window.

Detection indicators may include:

* Multiple failed logins
* Same target account
* Repeated attempts from the same IP address

When these conditions are met, **Microsoft Sentinel generates an incident** for investigation.

---

# Incident Investigation

When an alert is triggered, Microsoft Sentinel creates a security incident containing relevant log data.

SOC analysts investigate the incident by reviewing:

* Source IP address
* Target user account
* Authentication attempt count
* Event timestamps

This process helps determine whether the activity represents a legitimate user error or a malicious attack.

---

# Skills Demonstrated

Cloud Security

* Monitoring Azure infrastructure using Microsoft Sentinel
* Analyzing security telemetry using Log Analytics

Security Operations

* Simulating attacker behavior in a controlled environment
* Developing SIEM detection logic
* Threat hunting using Kusto Query Language

Incident Response

* Investigating authentication attack patterns
* Identifying brute force attempts

---

# Outcome

This lab demonstrates the ability to:

* Simulate attacker activity against a monitored system
* Analyze Windows security logs in a cloud SIEM
* Detect brute force authentication attempts
* Use KQL queries for threat hunting
* Investigate security incidents within Microsoft Sentinel

---

# Future Improvements

Possible enhancements to extend this lab include:

* Global attacker map visualization
* GeoIP enrichment of attacker IP addresses
* Automated response playbooks using Azure Logic Apps
* Additional threat hunting queries

These improvements would further simulate real-world SOC detection and response workflows.
