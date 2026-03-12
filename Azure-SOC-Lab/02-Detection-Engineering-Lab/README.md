# Detection Engineering Lab

## Overview

This lab focuses on **Detection Engineering using Microsoft Sentinel**.
The goal is to create a **custom analytics rule** that detects suspicious authentication behavior using Windows security logs collected from a monitored virtual machine.

In this scenario, a rule was created to detect **multiple failed login attempts**, which is a common indicator of **brute-force authentication attacks**.

The lab demonstrates how security analysts:

* Write detection logic using **KQL (Kusto Query Language)**
* Create **Scheduled Analytics Rules**
* Simulate attacker behavior
* Validate security telemetry inside the SIEM

---

## Technologies Used

* Microsoft Azure
* Microsoft Sentinel
* Log Analytics Workspace
* Windows Virtual Machine
* Azure Monitor Agent
* Kusto Query Language (KQL)

---

## Detection Scenario

Brute-force attacks attempt to guess credentials by repeatedly submitting incorrect login attempts.

Windows systems generate **Event ID 4625** whenever an authentication attempt fails.

By analyzing these events in Microsoft Sentinel, a detection rule can identify patterns indicating a possible brute-force attempt.

Detection logic used in this lab:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```

This query counts failed login attempts grouped by **Account** and **IP address** and triggers when attempts exceed the defined threshold.

---

## Lab Walkthrough

### Step 1 — Open Analytics Rules

Navigate to:

```
Azure Portal
→ Microsoft Sentinel
→ Analytics
```

This section is where detection rules are created and managed.

Screenshot:

```
analytics-rule-creation.png
```

---

### Step 2 — Create a Scheduled Query Rule

Create a new rule:

```
Create → Scheduled Query Rule
```

This rule type allows custom detection logic using KQL queries.

Screenshot:

```
analytics-rule-configuration.png
```

---

### Step 3 — Configure Rule Details

The rule was configured with the following settings:

**Rule Name**

```
Multiple Failed Login Detection
```

**Severity**

```
Medium
```

**MITRE ATT&CK Tactic**

```
Credential Access
```

Screenshot:

```
analytics-rule-details.png
```

---

### Step 4 — Define Detection Logic

Detection logic was written using KQL to identify multiple failed login attempts.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```

Rule configuration:

```
Run query every: 5 minutes
Lookup data from the last: 5 minutes
Alert threshold: results greater than 0
```

Screenshot:

```
analytics-rule-logic.png
```

---

### Step 5 — Configure Incident Settings

The rule was configured to automatically generate incidents when alerts are triggered.

Settings:

```
Create incidents from alerts triggered by this analytics rule: Enabled
Alert grouping: Disabled
```

Screenshot:

```
incident-settings.png
```

---

### Step 6 — Automated Response

Automation playbooks were not configured during this lab.

Playbooks are covered later in the **Automated SOC Response Lab**.

Screenshot:

```
automated-response.png
```

---

### Step 7 — Review and Create Rule

The rule configuration was reviewed and deployed.

Once created, the rule becomes active in Microsoft Sentinel and begins running according to its configured schedule.

Screenshot:

```
analytics-rule-review.png
```

---

### Step 8 — Simulate Failed Login Attempts

Failed authentication attempts were simulated on the monitored virtual machine.

Location:

```
Azure Portal
→ Virtual Machines
→ soc-target-vm
→ Run command
→ RunPowerShellScript
```

PowerShell script used:

```powershell
for ($i=0; $i -lt 10; $i++) {
net use \\127.0.0.1\IPC$ /user:administrator wrongpassword
}
```

This command generates multiple **Windows failed login events (EventID 4625)**.

Screenshot:

```
failed-login-simulation.png
```

---

## Troubleshooting & Key Observations

During testing, the detection rule was successfully created and telemetry was confirmed in the SIEM. However, alerts and incidents were not generated during the testing window.

Several observations were made during troubleshooting.

### Failed Login Events Were Generated

The simulated authentication failures produced the expected Windows security errors:

```
System error 1326 has occurred.
The user name or password is incorrect.
```

These events are logged as **EventID 4625** in the Windows Security log.

---

### Security Logs Were Successfully Ingested

Running KQL queries inside the Log Analytics workspace confirmed that failed login events were present.

Example validation query:

```kql
SecurityEvent
| where EventID == 4625
| sort by TimeGenerated desc
```

This verified that telemetry from the virtual machine was successfully reaching Microsoft Sentinel.

---

### Detection Rule Configuration Was Verified

The following rule configuration settings were validated:

* Rule Status: Enabled
* Query Schedule: 5 minutes
* Lookup Window: 5 minutes
* Incident Creation: Enabled
* Alert Threshold: Results greater than 0

The rule logic returned expected results when tested manually.

---

### Possible Causes for Missing Alerts

Several factors may explain why alerts were not generated during testing:

1. **Low telemetry volume** in a single VM lab environment.
2. **Scheduled analytics rules execute periodically**, not immediately.
3. Event timing may not have aligned with the rule's query window.
4. Microsoft Sentinel may delay rule run visibility in the **Rule Runs preview panel**.

This behavior is not uncommon when testing SIEM rules in small environments with limited event volume.

---

## Key Skills Demonstrated

This lab demonstrates practical **Detection Engineering** concepts used by SOC teams.

Skills practiced include:

* Writing detection logic using KQL
* Creating custom analytics rules in Microsoft Sentinel
* Simulating attacker authentication attempts
* Validating security telemetry in a SIEM
* Troubleshooting detection rule behavior

---

## Conclusion

This lab demonstrates the workflow used by SOC analysts to design and test detection rules in a SIEM environment.

Although alerts were not triggered during the testing window, the lab successfully demonstrated:

* Detection rule creation
* Security log analysis
* Threat simulation
* SIEM troubleshooting

These activities represent the foundational processes used when developing and validating detection logic in real-world security operations environments.
