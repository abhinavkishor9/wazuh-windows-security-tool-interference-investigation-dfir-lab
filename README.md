# Windows Security Tool Interference Investigation with Wazuh (DFIR Lab 52)

## Overview

Security tool interference occurs when endpoint security configurations are changed in a way that can reduce protection or visibility. Such changes can be legitimate administrative actions or may indicate unauthorized defense-evasion activity.

In this lab, a controlled and reversible Microsoft Defender configuration change was performed by adding the investigation directory `C:\SecurityToolLab` as a Defender exclusion. The change was then investigated using PowerShell, Windows Defender Operational logs, Windows Security process-creation telemetry, Sysmon, and Wazuh Discover.

The exclusion was removed after the investigation to restore the endpoint to its original security state.

---

# Lab Objectives

- Understand security-tool interference from a DFIR perspective.
- Establish the endpoint's security configuration baseline.
- Identify a Defender configuration change.
- Determine which process performed the change.
- Correlate the configuration change with Windows telemetry.
- Investigate Microsoft Defender Event ID 5007.
- Review Windows process creation telemetry.
- Correlate the activity in Wazuh Discover.
- Distinguish controlled administrative activity from potential defense evasion.
- Restore the original Defender configuration after the investigation.

---

# Lab Environment

| Component          | Value                                      |
| ------------------ | ------------------------------------------ |
| Host OS            | Windows 11 Pro                             |
| SIEM               | Wazuh 4.12                                 |
| Endpoint Agent     | Wazuh Agent                                |
| Endpoint Name      | DESKTOP-9MMM37V                            |
| Agent ID           | 001                                        |
| Security Tool      | Microsoft Defender Antivirus               |
| Investigation Type | Security Tool Interference Investigation   |
| Lab Directory      | C:\SecurityToolLab                         |
| Primary Event      | Defender Event ID 5007                      |
| Tools Used         | PowerShell, Event Viewer, Sysmon, Wazuh    |

---

# Tools Used

- PowerShell
- Microsoft Defender Antivirus
- `Get-MpComputerStatus`
- `Get-MpPreference`
- `Add-MpPreference`
- `Remove-MpPreference`
- Windows Event Viewer
- Windows Security Event ID 4688
- Microsoft Defender Event ID 5007
- Sysmon Event ID 1
- PowerShell Event ID 4104, where available
- Wazuh Discover
- Wazuh Agent

---

# Investigation Scenario

A SOC analyst receives an alert indicating that Microsoft Defender configuration may have changed on a Windows endpoint.

The analyst must determine:

- What Defender setting changed?
- Which account and process made the change?
- Was the change expected?
- Was the affected path or setting legitimate?
- Did additional suspicious activity occur after the change?
- Was the change visible in Wazuh?

For the controlled lab, only the investigation directory `C:\SecurityToolLab` was added as a Defender exclusion. Defender protection itself was not disabled.

---

# Investigation Workflow

```text
Defender Baseline
        ↓
Controlled Configuration Change
        ↓
Defender Event ID 5007
        ↓
PowerShell Process Evidence
        ↓
Security / Sysmon Telemetry
        ↓
Wazuh Correlation
        ↓
Context Assessment
        ↓
Restore Original Configuration
        ↓
Final DFIR Assessment
```

---

# Investigation Steps

### Step 1 – Verify Wazuh Agent

On the Wazuh server:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Verify:

- Agent ID
- Agent name
- Status
- Operating system

---

### Step 2 – Create Investigation Workspace

```powershell
New-Item -Path "C:\SecurityToolLab" -ItemType Directory -Force
```

This directory was used as the controlled investigation target.

---

### Step 3 – Establish Microsoft Defender Baseline

```powershell
Get-MpComputerStatus |
Select-Object `
AMServiceEnabled,
AntivirusEnabled,
RealTimeProtectionEnabled,
BehaviorMonitorEnabled,
IoavProtectionEnabled,
AntispywareEnabled
```

Record the Defender protection state before making any changes.

---

### Step 4 – Record Existing Exclusions

```powershell
Get-MpPreference |
Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension
```

Save the baseline:

```powershell
Get-MpPreference |
Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension |
Out-File "C:\SecurityToolLab\defender-baseline.txt"
```

This provides an initial `before` state.

---

### Step 5 – Identify User Context

```powershell
whoami
```

```powershell
whoami /user
```

Record the account that performs the configuration change.

---

### Step 6 – Perform Controlled Defender Configuration Change

Add only the lab directory as an exclusion:

```powershell
Add-MpPreference -ExclusionPath "C:\SecurityToolLab"
```

This does not disable Defender or real-time protection.

It creates a controlled configuration change that can be investigated.

---

### Step 7 – Verify the Configuration Change

```powershell
Get-MpPreference |
Select-Object ExclusionPath
```

Verify that:

```text
C:\SecurityToolLab
```

is present.

---

### Step 8 – Investigate Microsoft Defender Event ID 5007

Open:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows Defender
→ Operational
```

Review events around the time of the configuration change.

The primary event of interest is:

```text
Event ID 5007
```

Event ID 5007 represents a Microsoft Defender configuration change.

Record:

- Timestamp
- Event ID
- Change details
- Provider
- Available user/context information

---

### Step 9 – Investigate PowerShell Process Creation

Review Sysmon:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

Review:

```text
Event ID 1 – Process Creation
```

Look for PowerShell activity around the configuration-change timestamp.

Record:

- Image
- Process ID
- ParentImage
- ParentProcessId
- CommandLine
- User
- Timestamp

---

### Step 10 – Investigate Windows Security Event 4688

Open:

```text
Event Viewer
→ Windows Logs
→ Security
```

Search:

```text
Event ID 4688
```

Correlate the PowerShell process with the Defender configuration change.

---

### Step 11 – Check PowerShell Event ID 4104

If PowerShell Script Block Logging is enabled, review:

```text
Applications and Services Logs
→ Microsoft
→ Windows
→ PowerShell
→ Operational
```

Search for:

```text
Event ID 4104
```

Look for the `Add-MpPreference` command or related script activity.

If Event ID 4104 is unavailable, document that as a telemetry limitation.

---

### Step 12 – Investigate Wazuh Discover

Start with:

```text
agent.name: DESKTOP-9MMM37V
```

Search for Defender activity:

```text
agent.name: DESKTOP-9MMM37V AND 5007
```

Search for PowerShell:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

Where command-line fields are available:

```text
agent.name: DESKTOP-9MMM37V AND Add-MpPreference
```

Use the fields actually present in the indexed Wazuh event.

---

### Step 13 – Correlate the Evidence

The expected evidence chain is:

```text
Known User
    ↓
PowerShell
    ↓
Add-MpPreference
    ↓
Defender Configuration Change
    ↓
Event ID 5007
    ↓
Sysmon / Security Process Creation
    ↓
Wazuh Correlation
```

Use actual timestamps, process IDs, and usernames from the endpoint evidence.

---

### Step 14 – Assess the Context

The lab change was:

```text
Setting:
Defender Exclusion

Path:
C:\SecurityToolLab

Purpose:
Controlled DFIR exercise
```

The activity should therefore be assessed as:

```text
Benign Controlled Configuration Change
```

rather than unauthorized security-tool interference.

---

### Step 15 – Restore the Original Configuration

Remove the lab exclusion:

```powershell
Remove-MpPreference -ExclusionPath "C:\SecurityToolLab"
```

Verify:

```powershell
Get-MpPreference |
Select-Object ExclusionPath
```

Confirm the temporary exclusion is no longer present.

---

### Step 16 – Verify Defender State

```powershell
Get-MpComputerStatus |
Select-Object `
AMServiceEnabled,
AntivirusEnabled,
RealTimeProtectionEnabled,
BehaviorMonitorEnabled,
IoavProtectionEnabled,
AntispywareEnabled
```

Compare the result with the initial baseline.

---

### Step 17 – Remove Lab Artifacts

After evidence collection:

```powershell
Remove-Item "C:\SecurityToolLab" -Recurse -Force
```

Verify:

```powershell
Test-Path "C:\SecurityToolLab"
```

Expected result:

```text
False
```

---

# Key Findings

- Wazuh Agent `001` was active.
- A Defender baseline was established before modification.
- The investigation directory `C:\SecurityToolLab` was added as a temporary Defender exclusion.
- The change was intentionally performed using `Add-MpPreference`.
- Microsoft Defender Event ID 5007 was the primary configuration-change event of interest.
- PowerShell process telemetry was used to establish the execution context.
- Windows Security Event ID 4688 and Sysmon Event ID 1 were used as supporting process evidence.
- PowerShell Event ID 4104 was considered where available.
- Wazuh Discover was used to correlate endpoint telemetry.
- The temporary exclusion was removed after the investigation.
- Defender configuration was restored to the original intended state.

---

# Evidence Correlation

| Evidence | Source | Observation | DFIR Value |
|---|---|---|---|
| Defender Status | PowerShell | Protection baseline collected | Establishes `before` state |
| Defender Preferences | PowerShell | Existing exclusions recorded | Configuration baseline |
| User Identity | `whoami` | Change actor identified | User attribution |
| Configuration Change | Defender Event 5007 | Defender configuration changed | Primary security-tool evidence |
| Process Creation | Sysmon Event 1 | PowerShell execution reviewed | Process attribution |
| Process Creation | Security 4688 | Windows process evidence | Independent validation |
| Script Activity | PowerShell 4104 | Command context where available | Command attribution |
| Endpoint Telemetry | Wazuh Discover | Endpoint activity correlated | SIEM visibility |
| Restoration | PowerShell | Temporary exclusion removed | Post-investigation validation |

---

# DFIR Value

Security configuration changes can be legitimate administrative actions or indicators of defense evasion.

The investigator must determine:

- Who made the change?
- What changed?
- Why was it changed?
- What path or setting was affected?
- Was the change authorized?
- Did suspicious activity follow?
- Was the original state restored?

Correlating Defender events with process telemetry and Wazuh provides stronger evidence than relying on a Defender configuration event alone.

---

# Skills Practiced

- Security Tool Interference Analysis
- Microsoft Defender Investigation
- Defender Configuration Analysis
- Event ID 5007
- Windows Event ID 4688
- Sysmon Event ID 1
- PowerShell Analysis
- PowerShell Event ID 4104
- Wazuh Discover
- Process Attribution
- Configuration Baseline Analysis
- Evidence Correlation
- DFIR Timeline Reconstruction

---

# MITRE ATT&CK Context

Security-tool interference can be relevant to defense-evasion activity.

Potential ATT&CK context includes:

- **T1562 – Impair Defenses**
- **T1562.001 – Impair Defenses: Disable or Modify Tools**

The controlled exclusion used in this lab was legitimate lab activity and was not itself malicious behavior.

---

# Outcome

Successfully established a Microsoft Defender configuration baseline, performed a controlled reversible configuration change, investigated Defender Event ID 5007, correlated the change with process telemetry and Wazuh, and restored the original configuration.

The lab demonstrated how analysts can investigate security-tool modifications while distinguishing legitimate administrative changes from potentially unauthorized defense-evasion activity.
