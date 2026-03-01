# SIEM Log Monitoring & Threat Detection Lab
## Table of Contents

- [Project Overview](#project-overview)
- [Lab Architecture](#lab-architecture)
- [Detections Developed](#detections-developed)
- [Attack Simulation](#attack-simulation)
- [Incident Timeline](#incident-timeline)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Detection Logic (SPL Queries)](#detection-logic-spl-queries)
- [Lessons Learned](#lessons-learned)
- [Executive Incident Summary](#executive-incident-summary)

---

## Project Overview
This project was built to simulate realistic attack activity in a controlled lab environment and develop practical detection logic using Splunk and Sysmon telemetry.

The objective was to move beyond simple log ingestion and instead focus on multi-stage detection, event correlation, and investigation workflow. I configured a Windows 10 Enterprise host with Sysmon and centralized logs into Splunk Enterprise. A separate Linux VM was used to simulate external attack activity.

This lab includes multiple custom detections, attack simulations (brute force, PowerShell execution, suspicious outbound network activity, and LSASS credential access), and an end-to-end incident investigation with documented findings.

The focus of this project was detection engineering and log analysis, generating alerts, understanding the underlying telemetry, validating signal quality, and mapping activity to MITRE ATT&CK techniques. 

---

## Lab Architecture
The lab environment was designed to simulate internal log collection and external attack activity across separate hosts.

**Environment Components:**

- **Windows 10 Enterprise VM**
  - Sysmon installed and configured for enhanced telemetry
  - Windows Security logs enabled
  - Target system for attack simulation
  - Log forwarder sending data to Splunk

- **Linux Slingshot VM**
  - Used to simulate external attack activity
  - Performed authentication attempts and network-based attacks against the Windows host

- **Splunk Enterprise**
  - Centralized log ingestion and analysis platform
  - Ingested:
    - Windows Security Event Logs
    - Sysmon Operational Logs
  - Used for detection development, correlation searches, and investigation

**Network Configuration:**
Both virtual machines operated within a NAT network to simulate segmented hosts while maintaining internet access. The Linux VM acted as an external threat source interacting with the Windows system over SMB, RDP, and other network services.

This architecture allowed for realistic multi-event attack simulation and end-to-end detection validation within Splunk.

---

## Detections Developed
The following detections were developed and validated using simulated attack activity within the lab environment.

Each detection was tested against controlled attack scenarios to ensure signal accuracy and reduce false positives.

---

### 1. Failed SMB Authentication Brute Force (Event ID 4625)

Identifies multiple failed authentication attempts from a single source IP within a defined time window.

- Data Source: Windows Security Logs
- Event ID: 4625
- Detection Logic: Threshold-based aggregation on Source IP
- Objective: Detect password brute force attempts over SMB

---

### 2. Brute Force → Successful Login Correlation (Event ID 4625 → 4624)

Correlates repeated failed login attempts followed by a successful authentication from the same source.

- Data Source: Windows Security Logs
- Event IDs: 4625 (failure), 4624 (success)
- Detection Logic: Multi-event correlation within time window
- Objective: Identify potential credential compromise following brute force activity

---

### 3. Suspicious PowerShell Execution

Detects potentially malicious or unusual PowerShell execution patterns.

- Data Source: Windows Security Logs / Sysmon
- Event ID: 4688 (Process Creation) / Sysmon Event ID 1
- Detection Logic: Command-line monitoring for suspicious flags and encoded commands
- Objective: Detect execution abuse and post-authentication activity

---

### 4. Suspicious Outbound Network Activity (Sysmon Event ID 3)

Monitors outbound network connections initiated from the Windows host to external systems.

- Data Source: Sysmon Operational Logs
- Event ID: 3
- Detection Logic: Filtering for uncommon or unexpected external connections
- Objective: Detect potential command-and-control or data exfiltration behavior

---

### 5. LSASS Credential Access Attempt (Sysmon Event ID 10)

Detects process access attempts targeting `lsass.exe`, commonly associated with credential dumping.

- Data Source: Sysmon Operational Logs
- Event ID: 10 (Process Access)
- Detection Logic: Monitoring access to LSASS memory by non-system processes
- Objective: Identify potential credential dumping attempts

---

### 6. Multi-Event Attack Timeline Correlation

Combines authentication failures, successful login, process execution, network activity, and credential access events into a structured timeline.

- Data Source: Windows Security + Sysmon
- Detection Logic: Event sequencing and timestamp correlation
- Objective: Reconstruct full attack lifecycle and improve investigation context
---
## Attack Simulation
Attack activity was intentionally simulated from the Linux Slingshot VM to validate detection logic and test end-to-end visibility within Splunk.

The objective was to replicate common adversary behaviors across multiple stages of the attack lifecycle.

---

### 1. SMB / RDP Brute Force Attempts

Multiple authentication attempts were generated against the Windows host to trigger failed login events (Event ID 4625). This activity was used to validate threshold-based brute force detection logic.

---

### 2. Successful Authentication After Failed Attempts

Following repeated failures, a valid login was performed to simulate credential compromise. This generated Event ID 4624 and enabled correlation testing between failed and successful authentication events.

---

### 3. Post-Authentication PowerShell Execution

PowerShell was executed on the Windows host to simulate post-exploitation activity. Command-line logging and process creation telemetry were validated against detection logic monitoring suspicious execution patterns.

---

### 4. Suspicious Outbound Network Connection

A manual outbound network connection was initiated from the Windows host to simulate potential command-and-control communication. Sysmon Event ID 3 was used to validate external connection visibility.

---

### 5. Credential Dump Simulation (LSASS Access)

Credential access behavior was simulated by initiating a process attempting to access `lsass.exe` memory. Sysmon Event ID 10 confirmed visibility into process access activity commonly associated with credential dumping tools.

---

Each simulated action was verified within Splunk to confirm telemetry ingestion, detection trigger accuracy, and investigation workflow integrity.

---

## Incident Timeline
The following timeline reconstructs the simulated attack sequence based on correlated Security and Sysmon telemetry within Splunk.

This timeline demonstrates how individual detections can be combined to provide full attack context.

---

### T0 — Initial Authentication Failures

Multiple failed login attempts (Event ID 4625) were observed from a single external source IP within a short time window. This activity matched brute force detection thresholds.

---

### T1 — Successful Authentication

A successful login (Event ID 4624) occurred from the same source IP following repeated failed attempts. Correlation logic flagged this sequence as potential credential compromise.

---

### T2 — Suspicious Process Execution

Shortly after successful authentication, PowerShell execution events were logged (Event ID 4688 / Sysmon Event ID 1). Command-line telemetry confirmed execution activity on the host.

---

### T3 — Outbound Network Connection

Sysmon Event ID 3 recorded an outbound network connection initiated from the compromised host. This validated visibility into potential command-and-control or external communication behavior.

---

### T4 — LSASS Process Access Attempt

Sysmon Event ID 10 captured a process attempting to access `lsass.exe`, indicating potential credential dumping behavior.

---

By correlating these events chronologically, the full attack lifecycle — from initial access to credential access — was reconstructed within Splunk, demonstrating multi-stage detection capability.

---

## MITRE ATT&CK Mapping
The simulated attack behaviors and corresponding detections were mapped to the MITRE ATT&CK framework to align activity with standardized adversary tactics and techniques.

---

| Attack Stage | Technique | MITRE ID |
|--------------|-----------|----------|
| Brute Force Authentication Attempts | Brute Force | T1110 |
| Successful Login After Brute Force | Valid Accounts | T1078 |
| PowerShell Execution | Command and Scripting Interpreter | T1059.001 |
| Suspicious Outbound Network Connection | Application Layer Protocol | T1071 |
| LSASS Credential Access | OS Credential Dumping | T1003 |

---

This mapping demonstrates coverage across multiple ATT&CK tactics, including:

- Initial Access
- Execution
- Persistence / Privilege Escalation (contextual)
- Credential Access
- Command and Control

Aligning detections to ATT&CK ensures standardized reporting, improved detection engineering practices, and clearer communication of defensive coverage.

---

## Detection Logic (SPL Queries)

This section documents the investigative process performed in Splunk, including the SPL used to identify and correlate malicious behavior.

The goal was not just to generate logs, but to detect, analyze, and validate attacker activity across multiple stages of the intrusion lifecycle.

---

### 1. Brute Force Authentication Attempts (Windows Security Event ID 4625)

**Objective:** Identify repeated failed login attempts indicative of password guessing.

```spl
index=windows source="XmlWinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
| sort -count
```

### 2. Brute Force → Successful Login Correlation (4625 → 4624)

**Objective:** Detect successful authentication immediately following multiple failures. 

```spl
index=windows source="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| stats 
    count(eval(EventCode=4625)) as failed_attempts 
    count(eval(EventCode=4624)) as successful_logins 
    by Account_Name, Source_Network_Address
| where failed_attempts > 5 AND successful_logins > 0
```

### 3. PowerShell Execution Detection (Event ID 4688)

**Objective:** Identify suspicious PowerShell execution.

```spl
index=windows source="XmlWinEventLog:Security" EventCode=4688
| where New_Process_Name="*powershell.exe"
| table _time, Account_Name, New_Process_Name, Process_Command_Line, Parent_Process_Name
```


### 4. Suspicious Outbound Network Activity (Sysmon Event ID 3)

**Objective:** Identify outbound connections from suspicious processes.

```spl
index=sysmon EventCode=3
| table _time, Image, DestinationIp, DestinationPort, Initiated, User
```

### 5. LSASS Access / Credential Dumping Detection

**Objective:** Detect credential access attempts targeting LSASS.

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| table _time, SourceImage, TargetImage, GrantedAccess, User
```
---

## Lessons Learned

This lab moved beyond log generation and query syntax, exposing the operational realities of detection engineering.

### 1. Telemetry is the Foundation

Early in the build, several detections failed. Not due to incorrect SPL logic, but due to logging gaps.

Issues Encountered: Missing process creation flags, disabled firewall services, and misconfigured Universal Forwarders.

Key Takeaway: Detection engineering is only as effective as the underlying telemetry. Visibility is not a default state; it must be engineered.

### 2. Distinguishing Signal from Noise

The lab demonstrated that "suspicious" does not always mean "malicious." PowerShell execution and failed logins are common in administrative workflows.

Insight: Moving from single-event alerts to behavioral correlation (e.g., correlating a surge in 4625s with a subsequent 4624) is the only way to reduce false positives and maintain analyst trust.

### 3. The Value of Adversary Emulation

Active simulation (e.g., using Hydra to simulate RDP brute-force) provided a "ground truth" that passive log review cannot.

Validation: By "breaking" the environment, I was able to validate field extractions and ensure the detection logic fired precisely when the threshold was crossed. By simulating the attack, you can better validate the detection.

### 4. Shifting to an Engineering Mindset

The primary takeaway was a shift in perspective. Tools like Splunk and Sysmon are merely vehicles for a broader strategy. True detection engineering requires mapping activity to frameworks like MITRE ATT&CK® and understanding the mechanics of an exploit rather than just searching for a specific string.

### 5. Operational Impact in the SOC

In a production environment, an un-tuned detection is a liability. This lab reinforced that:
	- Over-alerting degrades SOC morale and efficiency.
	- Missing telemetry creates a false sense of security.
	- Continuous validation is required to account for evolving attacker techniques.

---

## Executive Incident Summary

This project involved the design and execution of a controlled **Adversary Emulation** exercise within a virtualized SOC environment. The primary objective was to validate detection efficacy and telemetry reliability across the Windows attack lifecycle, moving from initial access to credential dumping.

### Scope of Simulation

Using a Linux-based attacker framework, the following behaviors were simulated against a hardened Windows 10 Enterprise host:

**T1110 (Brute Force):** RDP authentication attacks via Hydra.
**T1059.001 (PowerShell):** Execution of obfuscated commands and post-compromise scripts.
**T1071 (Application Layer Protocol):** Outbound C2 simulation via Sysmon Event ID 3.
**T1003.001 (LSASS Memory):** Credential dumping simulation targeting the Local Security Authority Subsystem Service.

---

## Detection Strategy & Validation

| Threat Category | Data Source | Event ID | Logic / Validation Outcome |
| :--- | :--- | :--- | :--- |
| **Brute Force** | Windows Security | 4625 | **Success:** Threshold-based aggregation (>10 attempts/min). |
| **Compromise** | Windows Security | 4625 → 4624 | **Success:** Correlated failed logons followed by success from the same IP. |
| **Execution** | Sysmon / Security | 1 / 4688 | **Success:** Identified suspicious process trees and flags (e.g., `-enc`, `-nop`). |
| **Network C2** | Sysmon | 3 | **Success:** Captured outbound socket creation from non-browser processes. |
| **Cred. Access**| Sysmon | 10 | **Success:** Detected unauthorized memory access to `lsass.exe`. |

---

## Lessons Learned

### 1. Telemetry is the Foundation
Early in the build, several detections failed—not due to incorrect SPL logic, but due to **logging gaps**.
* **Issues Encountered:** Missing process creation flags, disabled firewall services, and misconfigured Universal Forwarders.
* > **Key Takeaway:** Detection engineering is only as effective as the underlying telemetry. Visibility is not a default state; it must be engineered.

### 2. Distinguishing Signal from Noise
The lab demonstrated that "suspicious" does not always mean "malicious." PowerShell execution and failed logins are common in administrative workflows.
* **Insight:** Moving from single-event alerts to **behavioral correlation** is the only way to reduce false positives and maintain analyst trust.

### 3. The Value of Adversary Emulation
Active simulation provided a "ground truth" that passive study cannot. 
* **Validation:** By "breaking" the environment, I validated field extractions and ensured the logic fired precisely when thresholds were crossed. If you haven't simulated the attack, you haven't validated the detection.

---

### Operational Impact

The lab provided a platform for iterative **Detection Tuning**, moving beyond "out of the box" alerts to high-fidelity logic:

* **Telemetry Resilience:** Identified and remediated logging gaps by enabling Advanced Audit Policies to ensure 100% ingestion of critical event IDs.
* **False Positive Mitigation:** Refined SPL queries to filter authorized administrative activity, significantly increasing the **Signal-to-Noise Ratio**.
* **End-to-End Workflow:** Validated the complete pipeline from **Attack Trigger → Log Generation → Splunk Ingestion → Alert Logic.**

---

### Conclusion

This project reflects hands-on experience with the **Detection Engineering Lifecycle**. By intentionally breaking and rebuilding the environment, the resulting detection suite is not only accurate but resilient. The focus remains on engineering alerts that provide **actionable intelligence** and reduce the Mean Time to Detect (MTTD) during real-world incidents.

---
