# Azure Honeypot + Attack Map

## Overview

This lab focuses on **deploying a honeypot virtual machine** in Azure to attract and monitor malicious traffic from the internet.

The objective is to expose a vulnerable Windows VM with intentionally weakened security configurations, collect authentication attempt logs from attackers worldwide, and **analyze attack patterns using geolocation data**.

This project demonstrates:

* Honeypot deployment strategy
* Attack surface exposure
* Geolocation-based threat analysis
* Real-world attacker behavior patterns
* Coordinated botnet identification

---

## Lab Architecture

### Honeypot Attack Map Architecture

```
Internet (Global Attackers)
      │
      ▼
Azure Public IP (No NSG Restrictions)
      │
      ▼
Honeypot Windows VM (RDP Exposed)
      │
      ▼
Windows Security Event Logs
      │
      ▼
Azure Monitor Agent (AMA)
      │
      ▼
Log Analytics Workspace
      │
      ▼
Microsoft Sentinel
      │
      ▼
Attack Analysis & Visualization
```

---

## Technologies Used

* Microsoft Azure
* Microsoft Sentinel
* Windows Virtual Machine (Honeypot)
* Azure Monitor Agent
* Log Analytics Workspace
* Kusto Query Language (KQL)
* IP Geolocation API (ip-api.com)
* LibreOffice Calc

---

## Honeypot Deployment Strategy

A honeypot is a deliberately vulnerable system designed to attract attackers and collect threat intelligence.

For this lab, the honeypot configuration includes:

* **Public-facing Windows VM** with RDP enabled
* **Network Security Group (NSG) with Allow All rules**
* **Windows Firewall disabled**
* **No authentication restrictions**
* **Security Event Log collection enabled**

This configuration intentionally exposes the system to internet-based attacks.

---

# Lab Walkthrough

## Step 1 — Deploy Honeypot Virtual Machine

Navigate to:

```
Azure Portal
→ Virtual Machines
→ Create
```

Configuration:

**VM Name**: `honeypot-vm`  
**Region**: Australia East  
**Operating System**: Windows 10 Enterprise, Version 22H2  
**VM Size**: Standard B2ts v2 (2 vCPU, 1 GB memory)  
**Authentication**: Username/Password  
**Public IP**: Enabled  
**Network Security Group**: Create new  
**Auto-shutdown**: Disabled

![Honeypot VM Deployment](screenshots/honeypot-vm-deployment.png)

---

## Step 2 — Configure Network Security Group (Allow All)

The Network Security Group (NSG) must be configured to **allow all inbound traffic** to expose the honeypot.

Navigate to:

```
Azure Portal
→ Network Security Groups
→ honeypot-vm-nsg
→ Inbound security rules
```

Create inbound rule:

**Priority**: 100  
**Name**: `DANGER-Allow-All-Inbound`  
**Source**: Any  
**Source port ranges**: *  
**Destination**: Any  
**Destination port ranges**: *  
**Protocol**: Any  
**Action**: Allow

⚠️ **Warning**: This configuration is intentionally insecure and should only be used in isolated lab environments.

Azure displays multiple security warnings for exposing:

* RDP (3389)
* SSH (22)
* SQL Server (1433)
* Oracle DB (1521)
* MySQL (3306)
* PostgreSQL (5432)

These warnings confirm the honeypot is properly exposed.

![NSG Allow All Rule](screenshots/nsg-allow-all-rule.png)

---

## Step 3 — Disable Windows Firewall

The Windows Firewall must be disabled to maximize attack surface exposure.

Since RDP was unavailable on Windows 11 Home, the **Run Command** feature was used instead of direct remote access.

Navigate to:

```
Azure Portal
→ Virtual Machines
→ honeypot-vm
→ Run command
→ RunPowerShellScript
```

Run PowerShell commands:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Get-NetFirewallProfile | Select-Object Name, Enabled
```

Expected output:

```
Name    Enabled
----    -------
Domain  False
Private False
Public  False
```

![Windows Firewall Disabled](screenshots/windows-firewall-disabled.png)

---

## Step 4 — Enable Security Event Logging

Ensure Windows Security Event Logs are being collected.

The existing **Data Collection Rule (DCR)** from previous SOC lab projects was reused.

Navigate to:

```
Azure Portal
→ Monitor
→ Data Collection Rules
→ windows-security-events-dcr
→ Resources
```

Add honeypot VM:

* Click **Add**
* Select **honeypot-vm**
* Click **Apply**

The Azure Monitor Agent automatically installs on the VM.

Data Collection Rule configuration:

**Data source type**: Windows Event Logs  
**Event logs**: Security (All Events)  
**Destination**: Log Analytics Workspace (soc-law)

![Data Collection Rule Configuration](screenshots/dcr-security-events.png)

---

## Step 5 — Verify Log Ingestion

Wait 10-15 minutes for logs to begin flowing into Log Analytics.

Navigate to:

```
Azure Portal
→ Log Analytics Workspaces
→ soc-law
→ Logs
```

Run query:

```kql
SecurityEvent
| where Computer == "honeypot-vm"
| take 10
```

This confirms security events are being collected from the honeypot.

Results show:

* Event IDs: 12544, 12292
* Computer: honeypot-vm
* Security channel events
* Real-time telemetry collection

![Log Verification](screenshots/honeypot-log-verification.png)

---

## Step 6 — Extract Failed RDP Attempts

Failed login attempts indicate attackers attempting to brute-force the honeypot.

Windows **Event ID 4625** represents failed authentication.

Query:

```kql
SecurityEvent
| where EventID == 4625
| where Computer == "honeypot-vm"
| project TimeGenerated, Account, IpAddress, LogonTypeName
| sort by TimeGenerated desc
```

This shows attacker IP addresses attempting authentication.

### Attack Volume Analysis

Query to identify top attackers:

```kql
SecurityEvent
| where EventID == 4625
| where Computer == "honeypot-vm"
| summarize FailedAttempts = count() by IpAddress
| sort by FailedAttempts desc
| take 20
```

**Results:**

| IP Address | Failed Attempts |
|------------|----------------|
| 185.156.73.169 | 11,489 |
| 92.63.197.9 | 10,697 |
| 92.63.197.69 | 10,693 |
| 185.156.73.24 | 10,655 |
| 185.156.73.59 | 10,641 |
| 185.156.73.173 | 10,585 |

**Total failed login attempts from top 6 IPs: 64,760**

### Targeted Username Analysis

Query:

```kql
SecurityEvent
| where EventID == 4625
| where Computer == "honeypot-vm"
| summarize AttemptCount = count() by Account
| sort by AttemptCount desc
| take 20
```

**Most targeted usernames:**

* administrator - 1,040 attempts
* user - 981 attempts
* admin - 926 attempts
* administrador - 303 attempts
* uuuuu - 251 attempts
* test - 222 attempts
* scanner - 190 attempts
* scan - 103 attempts
* user1 - 99 attempts
* testuser - 89 attempts

![Failed RDP Attempts](screenshots/failed-rdp-attempts.png)

---

## Step 7 — Enrich Logs with Geolocation Data

To visualize attack origins, IP addresses were enriched with geolocation data.

Attacker IPs were exported to CSV and analyzed using **ip-api.com** (free IP geolocation API).

### Geolocation Lookup Process

For each attacker IP, the following data was collected:

* Country
* City
* ISP/Organization
* Latitude/Longitude
* AS Number

**Example lookup for 185.156.73.169:**

```json
{
  "country": "The Netherlands",
  "city": "Amsterdam",
  "isp": "FOP Dmytro Nedilskyi",
  "org": "IP Kiktev Nikolay Vladimirovich",
  "as": "AS211736 FOP Dmytro Nedilskyi",
  "lat": 52.3676,
  "lon": 4.90414
}
```

### Critical Finding: Coordinated Botnet Attack

All 6 top attacker IPs shared identical geolocation data:

* **Country**: Netherlands
* **City**: Amsterdam
* **ISP**: FOP Dmytro Nedilskyi
* **AS Number**: AS211736
* **Latitude**: 52.3676
* **Longitude**: 4.90414

This indicates a **coordinated botnet attack** from the same infrastructure.

Enriched data was compiled into CSV format and visualized using LibreOffice Calc.

![Geolocation Enrichment](screenshots/geolocation-enrichment.png)

---

## Step 8 — Analyze Attack Patterns

Review collected data to identify attack trends.

### Attack Timeline Analysis

Query to visualize attack volume over time:

```kql
SecurityEvent
| where EventID == 4625
| where Computer == "honeypot-vm"
| summarize AttackCount = count() by bin(TimeGenerated, 1h)
| render timechart
```

**Key observations:**

* Attacks began within hours of honeypot deployment
* Peak attack volume: ~37,000 attempts per hour (around 2:00 PM UTC)
* Attack volume gradually decreased from 1:20 PM to 4:00 PM
* Total attack duration: Approximately 3 hours of sustained activity

This pattern indicates **automated botnet scanning** targeting newly exposed systems.

![Attack Pattern Analysis](screenshots/attack-pattern-analysis.png)

---

## Step 9 — Document Findings

### Attack Summary

**Total Statistics:**

* **Total Failed Login Attempts**: 64,760+
* **Unique Attacker IPs**: 6 (all from same botnet)
* **Time to First Attack**: Within hours of deployment
* **Attack Duration**: ~3 hours of peak sustained activity
* **Peak Attack Rate**: ~37,000 attempts per hour

**Attack Source:**

* **Country**: Netherlands 🇳🇱
* **City**: Amsterdam
* **Infrastructure**: FOP Dmytro Nedilskyi (AS211736)
* **Attack Type**: Coordinated automated brute force

**Targeted Credentials:**

* Primary targets: administrator, user, admin
* Secondary targets: administrador (Spanish), test, scanner
* Attack pattern: Dictionary-based username enumeration

### Key Observations

* **Immediate Exposure**: Attacks began almost immediately after the VM was exposed to the internet
* **Coordinated Attack**: All top attackers originated from a single botnet infrastructure
* **Automated Behavior**: Consistent attack patterns indicate automated scanning tools
* **Global Threat Landscape**: Demonstrates real-world threats facing internet-exposed systems
* **Common Credentials**: Attackers primarily target default and common administrative accounts

---

# Troubleshooting & Key Observations

### Windows 11 Home RDP Limitation

**Issue**: Windows 11 Home edition does not support Remote Desktop Protocol client connections.

**Solution**: Used Azure **Run Command** feature to execute PowerShell scripts remotely without requiring RDP access.

This method proved effective for:

* Disabling Windows Firewall
* Running administrative commands
* Verifying system configuration

### Log Ingestion Delay

**Observation**: Security event logs took 10-15 minutes to begin appearing in Log Analytics after VM deployment.

**Cause**: Azure Monitor Agent installation and initial log pipeline configuration.

**Solution**: Waited 15 minutes before verifying log ingestion.

### Coordinated Botnet Detection

**Observation**: All top 6 attacker IPs shared identical geolocation and ISP information.

**Analysis**: This indicates the attacks originated from a coordinated botnet infrastructure rather than distributed individual attackers.

**Significance**: Demonstrates how threat actors use multiple IPs from the same infrastructure to distribute attacks and evade simple IP-based blocking.

---

# Security Considerations

⚠️ **CRITICAL WARNINGS**

* This honeypot is **intentionally vulnerable**
* Do NOT use production credentials on honeypot systems
* Do NOT store sensitive data on honeypot VMs
* Monitor honeypot activity closely
* Shut down honeypot when not actively monitoring
* This configuration is for **educational purposes only**
* Never deploy this configuration in a production environment

---

# Skills Demonstrated

* Honeypot deployment and configuration
* Network security group configuration
* Security log analysis
* Geolocation-based threat intelligence
* Data visualization using spreadsheet tools
* Attack pattern analysis
* Threat hunting with KQL
* Botnet infrastructure identification

---

# MITRE ATT&CK Mapping

| Technique | Description |
| --------- | ----------- |
| T1110.001 | Brute Force: Password Guessing |
| T1110.003 | Brute Force: Password Spraying |
| T1078     | Valid Accounts |
| T1021.001 | Remote Services: Remote Desktop Protocol |

---

# Cost Management

To prevent excessive Azure costs:

* **Stop the honeypot VM** when not actively monitoring
* Use Azure Cost Management alerts
* B-series burstable VMs provide cost-effective performance
* Delete resources after lab completion
* Monitor daily spending in Azure Cost Management

**Total lab cost**: ~$10 for VM deployment over several hours of active monitoring.

---

# Conclusion

This lab successfully demonstrates how honeypots can be used to:

* Attract and monitor real-world attacker activity
* Collect threat intelligence from active attacks
* Analyze global attack patterns and sources
* Identify coordinated botnet infrastructure
* Understand common attack vectors and techniques

The data collected provides valuable insights into:

* Attacker behavior and targeting patterns
* Common credential attacks (administrator, admin, user)
* Botnet infrastructure and coordination
* Real-world threat landscape facing internet-exposed systems

Within hours of deployment, the honeypot attracted **over 64,760 failed login attempts** from a coordinated Netherlands-based botnet, demonstrating the constant threat environment facing publicly accessible systems.

---

# Next Phase

The next lab will focus on:

* Automated incident response
* Logic Apps playbooks
* Security orchestration automation
* Automated containment actions
