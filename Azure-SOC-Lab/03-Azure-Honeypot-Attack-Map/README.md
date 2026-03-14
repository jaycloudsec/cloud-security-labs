# Azure Honeypot + Attack Map

## Overview

This lab demonstrates the deployment and analysis of a **honeypot virtual machine** in Azure to attract and monitor malicious traffic from the internet.

The project is split into two parts:

---

## 📂 Project Structure

### **[Part 1: Honeypot Deployment & Data Collection](README-1.md)**

Deploy a deliberately vulnerable Windows VM and collect real-world attack data.

**Topics covered:**
* Honeypot VM deployment with maximum exposure
* Network Security Group configuration (Allow All)
* Windows Firewall disabled
* Security event log collection
* Attack data extraction

**Attack data collected**: 64,760+ failed login attempts

---

### **[Part 2: Attack Analysis & Visualization](README-2.md)**

Analyze collected attack data, enrich with geolocation, and identify threat patterns.

**Topics covered:**
* IP geolocation enrichment
* Coordinated botnet identification
* Attack pattern analysis
* Timeline visualization
* Threat intelligence insights

**Key finding**: All attacks originated from Netherlands-based botnet (AS211736)

---

## Quick Stats

* **Total attacks**: 64,760+ failed login attempts
* **Attack sources**: 6 IPs from same botnet infrastructure
* **Peak attack rate**: ~37,000 attempts/hour
* **Time to first attack**: Within hours of deployment
* **Attack duration**: ~3 hours sustained activity

---

## Technologies Used

* Microsoft Azure
* Microsoft Sentinel
* Windows Virtual Machine (Honeypot)
* Azure Monitor Agent
* Log Analytics Workspace
* KQL (Kusto Query Language)
* IP Geolocation API (ip-api.com)
* LibreOffice Calc

---

## MITRE ATT&CK Mapping

| Technique | Description |
| --------- | ----------- |
| T1110.001 | Brute Force: Password Guessing |
| T1110.003 | Brute Force: Password Spraying |
| T1078     | Valid Accounts |
| T1021.001 | Remote Services: RDP |

---

## Learning Outcomes

* Deploy and configure honeypot infrastructure
* Collect real-world threat intelligence
* Analyze global attack patterns
* Identify botnet infrastructure
* Enrich security data with geolocation
* Visualize attack data

---

## ⚠️ Security Warning

This honeypot is **intentionally vulnerable**. Do NOT:
* Use production credentials
* Store sensitive data on honeypot VMs
* Deploy in production environments

**Educational purposes only.**

---

## Getting Started

**[Start with Part 1: Honeypot Deployment →](README-1.md)**
