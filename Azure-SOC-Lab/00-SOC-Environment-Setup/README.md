# Cloud Security Labs

This repository contains hands-on cloud security projects focused on
SIEM deployment, threat detection, and SOC operations.

---

## Projects

### Azure SOC Lab — SIEM Deployment & Log Ingestion

Build and configure a cloud SIEM environment in Microsoft Azure.

Skills demonstrated:

- Azure infrastructure deployment
- Log Analytics configuration
- Microsoft Sentinel setup
- Azure Monitor Agent deployment
- Data Collection Rules (DCR)
- Log ingestion troubleshooting
- KQL log analysis

📂 Project Folder  
`azure-soc-lab-siem-deployment`

---

### Azure SOC Lab — Attack Simulation & Threat Detection

Simulate attacker behavior and detect malicious activity using
Microsoft Sentinel.

Skills demonstrated:

- Port scanning detection
- Failed login monitoring
- Brute force detection
- KQL threat hunting
- Sentinel detection rules
- SOC investigation workflow

📂 Project Folder  
`azure-soc-lab-attack-detection`


# Azure SOC Lab — Quick Walkthrough

This quick walkthrough provides the exact steps used to complete the **Azure SOC Lab — SIEM Deployment & Attack Detection** project.

For full documentation, architecture, queries, and screenshots, see the project folders in this repository.

---

# Part 1 — SIEM Deployment & Log Ingestion

1. Log in to the Azure Portal.

2. Create a Resource Group.

* Go to **Resource Groups**
* Click **Create**
* Enter Resource Group name
* Select Region
* Click **Review + Create**
* Click **Create**

3. Deploy a Virtual Machine.

* Go to **Virtual Machines**
* Click **Create**
* Select the Resource Group
* Enter VM Name
* Select Region
* Choose **Windows Server**
* Select VM size
* Configure Administrator Username and Password
* Enable **Public IP**
* Click **Review + Create**
* Click **Create**

4. Create a Log Analytics Workspace.

* Go to **Log Analytics Workspaces**
* Click **Create**
* Select Resource Group
* Enter Workspace Name
* Select Region
* Click **Review + Create**
* Click **Create**

5. Enable Microsoft Sentinel.

* Open the **Log Analytics Workspace**
* Click **Microsoft Sentinel**
* Click **Create**
* Click **Add**

6. Install Azure Monitor Agent.

* Go to **Virtual Machines**
* Select the deployed VM
* Open **Extensions + Applications**
* Click **Add**
* Select **Azure Monitor Agent**
* Click **Install**

7. Create a Data Collection Rule.

* Go to **Monitor**
* Click **Data Collection Rules**
* Click **Create**
* Select Resource Group
* Enter Rule Name
* Select Region
* Click **Next**

8. Add Data Source.

* Select **Windows Event Logs**
* Add **Security**
* Continue

9. Add Destination.

* Select the **Log Analytics Workspace**
* Click **Create**

10. Associate the VM.

* Add the deployed Virtual Machine
* Save the Data Collection Rule

---

# Part 2 — Attack Simulation & Threat Detection

1. Open Microsoft Sentinel.

* Go to **Microsoft Sentinel**
* Open the connected **Log Analytics Workspace**

2. Verify Logs.

* Click **Logs**
* Run query:

```kql
SecurityEvent
| take 10
```

3. Analyze Failed Logins.

* In **Logs**, run query:

```kql
SecurityEvent
| where EventID == 4625
| summarize AttemptCount = count() by IpAddress
| sort by AttemptCount desc
```

4. Identify Attacker IP Addresses.

* Review results in query output
* Note IP addresses with highest failed attempts

5. Create Detection Rule.

* In **Microsoft Sentinel**
* Click **Analytics**
* Click **Create**
* Select **Scheduled query rule**

6. Configure Rule.

* Enter Rule Name
* Set Severity
* Paste detection query

7. Configure Query Settings.

* Query frequency: **5 minutes**
* Lookup period: **5 minutes**

8. Configure Alert Logic.

* Trigger alert when results exceed threshold

9. Review Rule.

* Click **Next**
* Review settings

10. Enable Rule.

* Click **Create**

11. Confirm Rule Status.

* Go to **Analytics**
* Verify rule is **Enabled**

---

# End of Walkthrough

Refer to the project documentation in this repository for:

* Screenshots
* Detection logic explanation
* Investigation workflow
* SOC analysis
