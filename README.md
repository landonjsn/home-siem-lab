# Home SIEM Lab: Credential Theft Detection with Splunk

## Overview
I built this lab to get hands-on experience detecting a real attacker technique using actual attack data. Using Splunk Enterprise, I ingested 915 Windows Security and Sysmon events from the OTRF Security Datasets project, which captures a simulated attacker using esentutl.exe to steal local password hashes from the Windows SAM database. The goal was simple: understand what this attack looks like in logs, then build something that catches it.

## Tools Used
- Splunk Enterprise (free license)
- Windows Security Event Logs
- Sysmon (System Monitor)
- OTRF Security Datasets
- MITRE ATT&CK Framework

## The Attack
**Technique:** OS Credential Dumping via SAM (MITRE ATT&CK T1003.002)

The SAM database stores hashed passwords for every local Windows account on a machine. Attackers use tools like esentutl.exe, a legitimate Windows database utility, to quietly make a copy of it. Once they have the copy, they can crack the hashes offline or use them in pass-the-hash attacks without ever needing the actual password. It's a real technique used and subtle enough to blend in with normal Windows activity if you're not watching the right events.

## What I Did

### Ingesting the Data
I loaded 915 events from an OTRF atomic dataset into a dedicated Splunk index. The dataset captures the full attack chain: process creation, file access, and process memory access events logged by both Windows Security auditing and Sysmon.

### Event IDs I Focused On
| Event ID | Source | What It Shows |
|----------|--------|---------------|
| 4688 | Windows Security | esentutl.exe spawned as a new process |
| 4663 | Windows Security | Direct read access to the SAM database file |
| 10 | Sysmon | lsass.exe repeatedly opening esentutl.exe memory |
| 4799 | Windows Security | Local security group enumeration |
| 1102 | Windows Security | Audit log cleared after the attack |

### What the Logs Actually Showed
The most interesting finding was in the Sysmon EventID 10 data: lsass.exe, the Windows process responsible for managing credentials, was opening esentutl.exe's memory multiple times within a single second. That's not normal. Combined with EventID 4663 confirming a direct read of the SAM file, the full picture was clear.

EventID 1102 showing up at the end was also worth noting. The attacker cleared the audit log after the theft, which is a defensive evasion move in its own right and a secondary detection opportunity.

### Detection Rule
index=otrf EventID=4663 ObjectName="SAM"

Configured as a Splunk alert:
- Triggers when events > 0
- Severity: High
- Action: Add to Triggered Alerts

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access (TA0006)
- **Technique:** OS Credential Dumping: Security Account Manager (T1003.002)
- **Defense Evasion:** Indicator Removal: Clear Windows Event Logs (T1070.001)

## Screenshots

### Event ID Breakdown (915 events ingested)
![Event ID Breakdown](page-000.png)

### esentutl.exe Process Creation (EventID 4688)
![Process Creation](page-001.png)

### SAM Database File Access (EventID 4663)
![SAM File Access](page-002.png)

### lsass.exe Accessing esentutl.exe Memory (Sysmon EventID 10)
![Process Memory Access](page-003.png)

### Detection Alert Configuration
![Alert Configuration](page-004.png)

## What I Took Away
The biggest takeaway was how much cross-source correlation matters. Relying on one log source isn’t enough. Without Sysmon, the lsass/esentutl connection disappears entirely. I also came away thinking differently about log clearing: EventID 1102 showing up after a credential theft sequence isn’t just noise, it’s a signal in itself.
