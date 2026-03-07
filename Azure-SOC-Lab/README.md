# Azure SOC Detection Lab

## Objective

Build a small cloud environment and use Microsoft Sentinel to detect
simulated cyber attacks.

## Technologies Used

-   Microsoft Azure
-   Microsoft Sentinel
-   Log Analytics
-   Windows Virtual Machine
-   Network Security Groups
-   Nmap (attack simulation)

## Lab Architecture

Internet \| Attacker Machine \| Azure Virtual Network \| Windows VM
(Target)

Logs collected by Log Analytics and monitored with Microsoft Sentinel.

------------------------------------------------------------------------

# Lab Environment Setup

A dedicated resource group was created to contain all SOC lab resources.

![Resource Groups](screenshots/resource-groups.png)

### Observation: Multiple Resource Groups

During this step, two Resource Groups appear in the Azure portal. This
behavior is normal in Microsoft Azure.

The **soc-lab-rg** Resource Group was manually created to store the main
resources for this SOC lab environment. This group contains the virtual
machine, networking components, and other resources used in the project.

The **NetworkWatcherRG** Resource Group was automatically created by
Azure. It contains resources used by Azure's network monitoring service,
which helps diagnose and monitor network traffic, connectivity, and
performance within the virtual network.

Azure automatically creates certain system-managed resource groups to
support infrastructure services without requiring manual configuration.
This allows users to focus on deploying and managing their own resources
while Azure handles background monitoring and diagnostic capabilities.

------------------------------------------------------------------------

## Windows Target Virtual Machine

A Windows 10 virtual machine was deployed in Microsoft Azure to simulate
a corporate endpoint within the SOC lab environment.

This machine acts as the target system where login attempts,
authentication failures, and other security events will be generated.
These events will later be collected and analyzed using Microsoft
Sentinel for security monitoring and threat detection.

Configuration:

VM Name: soc-target-vm\
Operating System: Windows 10 Enterprise 22H2\
Region: Australia East\
VM Size: Standard_B2ts_v2\
Access Method: Remote Desktop Protocol (RDP)

![Virtual Machine Deployment](screenshots/virtual-machine.png)

------------------------------------------------------------------------

## Virtual Machine Networking

The virtual machine was connected to an Azure Virtual Network and
assigned a public IP address to allow remote access.

A Network Security Group rule allowing **Remote Desktop Protocol (RDP)
on port 3389** was configured so the system can be accessed from the
internet.

This configuration allows the VM to simulate a corporate endpoint
capable of generating authentication events and security logs for
monitoring within the SOC lab.

![VM Networking](screenshots/vm-networking.png)

------------------------------------------------------------------------

## Log Analytics Workspace

A Log Analytics Workspace was deployed to collect and store security
logs generated within the SOC lab environment.

Log Analytics acts as the centralized logging platform for Microsoft
Sentinel, allowing telemetry data from the virtual machine and other
Azure resources to be collected and analyzed.

Configuration:

Workspace Name: soc-law\
Resource Group: soc-lab-rg\
Region: Australia East

This workspace will collect logs including:

-   Windows authentication events
-   Failed login attempts
-   System security events
-   Network activity

These logs will later be analyzed by Microsoft Sentinel to detect
suspicious activity.

![Log Analytics Workspace](screenshots/log-analytics.png)

------------------------------------------------------------------------

## Microsoft Sentinel Deployment

Microsoft Sentinel was enabled on the Log Analytics Workspace to provide
SIEM capabilities for the SOC lab environment.

Microsoft Sentinel is a cloud-native security information and event
management (SIEM) platform used to collect, analyze, and detect threats
across cloud infrastructure.

By connecting the Log Analytics Workspace to Sentinel, security events
generated from the Windows virtual machine can be monitored and analyzed
for suspicious activity.

The Microsoft Sentinel free trial was activated for this lab
environment, allowing up to 10 GB of log ingestion per day.

![Microsoft Sentinel Overview](screenshots/sentinel-overview.png)

------------------------------------------------------------------------

## Windows Security Events Connector

The Windows Security Events connector was installed from the Microsoft
Sentinel Content Hub to enable collection of authentication and security
logs from the Windows virtual machine.

This connector allows Microsoft Sentinel to ingest Windows event logs
such as:

-   Successful logins
-   Failed login attempts
-   Account lockouts
-   Security auditing events

The logs are collected using the Azure Monitor Agent and sent to the Log
Analytics Workspace for analysis.

Once connected, Microsoft Sentinel can detect suspicious authentication
behavior such as brute force login attempts and unauthorized access
activity.

------------------------------------------------------------------------

## Step 5 -- Connect Windows Security Events via AMA

1.  Navigate to **Microsoft Sentinel**.
2.  Open **Content Hub**.
3.  Install **Windows Security Events via AMA**.
4.  Create a **Data Collection Rule (DCR)**.
5.  Select the target VM `soc-target-vm`.
6.  Choose **All Events** for the lab.

------------------------------------------------------------------------

## Lab Troubleshooting and Observations

During the configuration of the Windows Security Events connector,
several issues were encountered while attempting to enable log ingestion
from the virtual machine.

Although the Microsoft documentation suggests the connector
automatically configures the environment, multiple components had to be
verified manually.

Troubleshooting steps included checking:

-   Virtual Machine extensions
-   Data Collection Rules
-   Data sources
-   Log Analytics ingestion
-   Sentinel query results

This process helped reveal how the telemetry pipeline works in Azure.

------------------------------------------------------------------------

### ⚠️ Lab Note -- VM Was Stopped During Setup

During the setup of the Windows Security Events connector, the Data
Collection Rule was created successfully but the extension installation
failed.

Error message:

Cannot modify extensions in the VM when the VM is not running.

The VM had previously been stopped (deallocated) to avoid Azure compute
charges. Because the VM was not running, Azure could not install the
**Azure Monitor Agent (AMA)** required for log ingestion.

Resolution:

1.  Navigate to **Virtual Machines** in Azure.
2.  Locate the VM `soc-target-vm`.
3.  Click **Start**.

After starting the VM, Azure successfully installed the monitoring
agent.

> Lesson learned: Azure cannot install monitoring agents when a VM is
> stopped.

------------------------------------------------------------------------

### ⚠️ Observation -- No Logs Appearing in Microsoft Sentinel

After configuring the connector, running queries in Microsoft Sentinel
returned no results.

Example queries:

    SecurityEvent
    | take 10

    search *
    | take 10

The query result returned:

    No results found from the last 24 hours

This indicated that log ingestion had not started yet.

------------------------------------------------------------------------

### ⚠️ Observation -- Monitoring Agent Not Visible in VM Extensions

While investigating the issue, the **Extensions + Applications** section
of the virtual machine was inspected.

No monitoring agents were visible initially. This raised concerns that
the Azure Monitor Agent had not been deployed correctly.

This required further verification of the Data Collection Rule
configuration.

------------------------------------------------------------------------

### ⚠️ Observation -- Data Collection Rule Attached but No Data Sources

The Data Collection Rule created earlier was confirmed to be attached to
the VM.

However, the **Data Sources section contained no configured log
sources**.

Because no Windows Event Logs were defined, the system had no telemetry
to forward to Log Analytics.

As a result, Microsoft Sentinel queries returned empty results.

------------------------------------------------------------------------

### ⚠️ Azure Portal Limitation Encountered

While attempting to modify the Data Collection Rule, the Azure portal
returned the following message:

    This data collection rule contains properties that are not currently supported in the portal.
    Please use Azure CLI or ARM template to edit the rule.

This appears to be a limitation or bug in the Azure portal interface
when working with Data Collection Rules.

To resolve this, the plan was to recreate the Data Collection Rule with
proper configuration.

------------------------------------------------------------------------

## Log Ingestion Pipeline

Security logs generated on the Windows virtual machine follow this
telemetry path:

Windows VM\
↓\
Azure Monitor Agent\
↓\
Data Collection Rule\
↓\
Log Analytics Workspace\
↓\
Microsoft Sentinel

Understanding this pipeline is critical when troubleshooting log
ingestion issues.

------------------------------------------------------------------------

## Attack Simulations

The following attack scenarios will be simulated against the target
virtual machine:

1.  Port scanning using **Nmap**
2.  Failed login attempts
3.  Brute force authentication attempts

These simulations generate logs that will be collected by Microsoft
Sentinel.

------------------------------------------------------------------------

## Detection

Security logs will be ingested into Microsoft Sentinel through Log
Analytics.

Detection rules will be configured to identify suspicious activity such
as:

-   Multiple failed login attempts
-   Network scanning behavior
-   Unauthorized access attempts

------------------------------------------------------------------------

## Outcome

This lab demonstrates the ability to:

-   Deploy cloud infrastructure in Microsoft Azure
-   Configure networking and remote access
-   Simulate cyber attacks in a controlled environment
-   Collect and analyze security logs using a SIEM platform

This project showcases practical SOC analyst skills including threat
detection, log analysis, and cloud security monitoring.
