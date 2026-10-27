Home SIEM Lab: Credential Theft Detection with Splunk
Overview

I built this lab to get hands-on experience detecting a real attacker technique using actual attack data. Using Splunk Enterprise, I ingested 915 Windows Security, System, and Sysmon events from the OTRF Security Datasets project, which captures a simulated attacker using esentutl.exe to copy the Windows SAM database. The goal was simple: understand what this attack looks like in logs, separate it from normal Windows noise, then build something that catches it.

Tools Used
Splunk Enterprise (free license)
Windows Security and System Event Logs
Sysmon (System Monitor)
OTRF Security Datasets
MITRE ATT&CK Framework
The Attack

Technique: OS Credential Dumping: Security Account Manager (MITRE ATT&CK T1003.002)

The SAM database stores hashed passwords for every local Windows account on a machine. Windows keeps the live file locked, so attackers use tricks to copy it. Here, the attacker used esentutl.exe, a legitimate Windows database utility, with the /vss option to copy SAM out of a Volume Shadow Copy. With the copy, an attacker can crack the hashes offline or reuse them in pass-the-hash attacks. Because it uses a built-in Windows tool, it blends in easily if you're not watching the right events.

What I Did
Ingesting the Data

I loaded the OTRF atomic dataset into a dedicated Splunk index. It covers about 36 seconds of activity on one workstation, logged by Windows auditing and Sysmon.

Event IDs I Focused On
Event ID	Source	What It Shows
4688	Windows Security	esentutl.exe launched from cmd.exe, with the full command line
1	Sysmon	The same process creation, seen by a second log source
11	Sysmon	The copied SAM file created at C:\ProgramData\SAM
4663	Windows Security	esentutl.exe reading the Lsa registry key (supporting context)
10	Sysmon	Process access events, mostly routine noise (see below)
1102 / 104	Security / System	Event logs cleared shortly before the attack
What the Logs Actually Showed

The clearest evidence was the command line in EventID 4688 and Sysmon EventID 1:

esentutl.exe /y /vss C:\windows/system32/config/SAM /d C:\ProgramData\SAM

Five seconds later, Sysmon EventID 11 showed esentutl.exe creating C:\ProgramData\SAM, confirming the copy worked. Seeing the same action from two independent sources (the Security log and Sysmon) is what made the finding solid.

A big part of the work was ruling out noise:

Sysmon EventID 10: 188 events showed lsass.exe opening esentutl.exe and vssvc.exe. At first this looked suspicious, but lsass.exe was the source, not the target, and it only had low-level 0x1000 access. That's routine. Credential dumping from memory looks like the reverse: another process opening lsass.exe with read access.
EventID 4799: 186 group membership checks turned out to be a side effect of the shadow copy, not separate discovery activity.
EventID 4663: this was a read of the Lsa registry key, not the SAM file itself.
EventID 1102: the logs were cleared 7 seconds before the attack started. In OTRF datasets this is typically done to get a clean capture, so I didn't treat it as attacker activity here. In a real environment I would still escalate it.
Detection Rule

My first alert searched for EventID 4663 on the SAM file. When I tested it against the data, it matched zero events, because the only 4663 was a registry read. I rewrote it to match the behavior from two sources: the command line and the file it creates.

index=otrf
    ( (EventID=4688 OR EventID=1)
      (CommandLine="*esentutl*" OR CommandLine="*reg*save*")
      (CommandLine="*config*SAM*" OR CommandLine="*config*SYSTEM*" OR CommandLine="*config*SECURITY*"
       OR CommandLine="*HKLM*SAM*" OR CommandLine="*HKLM*SYSTEM*" OR CommandLine="*HKLM*SECURITY*") )
    OR
    ( EventID=11
      (TargetFilename="*\\SAM" OR TargetFilename="*\\SYSTEM" OR TargetFilename="*\\SECURITY")
      NOT TargetFilename="*System32*config*" )
| eval Process=coalesce(Image, NewProcessName)
| table _time Hostname EventID Process CommandLine TargetFilename
| sort _time

It returns exactly the 3 attack events with no false positives. The wildcards around config matter because the attacker's path mixed forward and back slashes.

Configured as a Splunk alert:

Triggers when events > 0
Severity: High
Action: Add to Triggered Alerts
MITRE ATT&CK Mapping
Tactic: Credential Access (TA0006)
Technique: OS Credential Dumping: Security Account Manager (T1003.002)
Execution: Command and Scripting Interpreter: Windows Command Shell (T1059.003)
Screenshots
Event ID Breakdown (915 events ingested)

Event ID Breakdown

esentutl.exe Copying the SAM Hive (EventID 4688)

Process Creation

Supporting Context: Lsa Registry Read (EventID 4663)

Registry Access

Ruling Out Noise: Routine lsass.exe Process Access (Sysmon EventID 10)

Process Access Noise

Detection Alert Configuration

Alert Configuration

What I Took Away

The biggest takeaway was how much cross-source correlation matters. Relying on one log source isn't enough: the Security log showed the command, and Sysmon showed the file it created. The second lesson was to test detections against real data. My first alert looked right on paper and matched nothing. Checking actual field values, and the direction of events like process access, changed my conclusions.

I later turned this triage process into a reusable Claude skill: soc-triage-skill.
