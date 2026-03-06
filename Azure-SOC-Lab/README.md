# Azure SOC Detection Lab

## Objective
Build a small cloud environment and use Microsoft Sentinel to detect simulated cyber attacks.

## Technologies Used

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics
- Windows Virtual Machine
- Network Security Groups
- Nmap (attack simulation)

## Lab Architecture

Internet
 |
Attacker Machine
 |
Azure Virtual Network
 | 
Windows VM (Target)


Logs collected by Log Analytics and monitored with Microsoft Sentinel.

---

# Lab Environment Setup

A dedicated resource group was created to contain all SOC lab resources.

![Resource Groups](screenshots/resource-groups.png)

### Observation: Multiple Resource Groups

During this step, two Resource Groups appear in the Azure portal. This behavior is normal in Microsoft Azure.

The **soc-lab-rg** Resource Group was manually created to store the main resources for this SOC lab environment. This group contains the virtual machine, networking components, and other resources used in the project.

The **NetworkWatcherRG** Resource Group was automatically created by Azure. It contains resources used by Azure's network monitoring service, which helps diagnose and monitor network traffic, connectivity, and performance within the virtual network.

Azure automatically creates certain system-managed resource groups to support infrastructure services without requiring manual configuration. This allows users to focus on deploying and managing their own resources while Azure handles background monitoring and diagnostic capabilities.

---

## Windows Target Virtual Machine

A Windows 10 virtual machine was deployed in Microsoft Azure to simulate a corporate endpoint within the SOC lab environment.

This machine acts as the target system where login attempts, authentication failures, and other security events will be generated. These events will later be collected and analyzed using Microsoft Sentinel for security monitoring and threat detection.

Configuration:

VM Name: soc-target-vm  
Operating System: Windows 10 Enterprise 22H2  
Region: Australia East  
VM Size: Standard_B2ts_v2  
Access Method: Remote Desktop Protocol (RDP)

![Virtual Machine Deployment](screenshots/virtual-machine.png)

---

## Virtual Machine Networking

The virtual machine was connected to an Azure Virtual Network and assigned a public IP address to allow remote access.

A Network Security Group rule allowing **Remote Desktop Protocol (RDP) on port 3389** was configured so the system can be accessed from the internet.

This configuration allows the VM to simulate a corporate endpoint capable of generating authentication events and security logs for monitoring within the SOC lab.

![VM Networking](screenshots/vm-networking.png)

---

## Attack Simulations

The following attack scenarios will be simulated against the target virtual machine:

1. Port scanning using **Nmap**
2. Failed login attempts
3. Brute force authentication attempts

These simulations generate logs that will be collected by Microsoft Sentinel.

---

## Detection

Security logs will be ingested into Microsoft Sentinel through Log Analytics.

Detection rules will be configured to identify suspicious activity such as:

- Multiple failed login attempts
- Network scanning behavior
- Unauthorized access attempts

---

## Outcome

This lab demonstrates the ability to:

- Deploy cloud infrastructure in Microsoft Azure
- Configure networking and remote access
- Simulate cyber attacks in a controlled environment
- Collect and analyze security logs using a SIEM platform

This project showcases practical SOC analyst skills including threat detection, log analysis, and cloud security monitoring.
