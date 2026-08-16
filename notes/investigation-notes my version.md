# Investigation Notes

## Lab Summary

This investigation examined a controlled change to Microsoft Defender configuration on a Windows endpoint.

---

## Analyst Methodology

1. Verify Wazuh endpoint status.
2. Create the investigation workspace.
3. Capture the Defender protection baseline.
4. Record existing Defender exclusions.
5. Establish user context.
6. Perform the controlled configuration change.
7. Verify the changed Defender state.
8. Investigate Defender Event ID 5007.
9. Review Sysmon process creation telemetry.
10. Review Windows Security Event ID 4688.
11. Review PowerShell Event ID 4104 where available.
12. Correlate the activity in Wazuh Discover.
13. Assess whether the configuration change was expected.
14. Restore the Defender configuration.
15. Remove investigation artifacts.

---

## Investigation Scenario

A SOC analyst receives a high-priority Wazuh alert indicating that an endpoint's security configuration may have been changed.

The analyst needs to determine whether the change was:

Expected Administration
        OR
Unauthorized Security Tool Interference

The investigation will examine the change, the responsible account/process, surrounding endpoint activity, and Wazuh telemetry.


---

## Evidence Collected

### Evidence 1 – Wazuh Agent

Collected:

- Agent ID
- Agent name
- Agent status
- Windows operating system

Finding:

Confirmed that the endpoint was actively reporting to Wazuh.

---

### Evidence 2 – Investigation Workspace

Created:

`C:\SecurityToolLab`

Finding:

Established a controlled directory for the lab and for the temporary Defender exclusion.

---

### Evidence 3 – Defender Baseline

Command Used:

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

Finding:

Captured Defender protection state before making any configuration change.

---

### Evidence 4 – Defender Exclusion Baseline

Command Used:

```powershell
Get-MpPreference |
Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension
```

Finding:

Recorded the Defender exclusion state before the controlled modification.

---

### Evidence 5 – User Context

Commands Used:

```powershell
whoami
```

```powershell
whoami /user
```

Finding:

Established the user account responsible for the lab activity.

---

### Evidence 6 – Controlled Defender Change

Command Used:

```powershell
Add-MpPreference -ExclusionPath "C:\SecurityToolLab"
```

Finding:

A temporary Defender exclusion was added for the controlled investigation directory.

Defender protection itself was not disabled.

---

### Evidence 7 – Configuration Verification

Command Used:

```powershell
Get-MpPreference |
Select-Object ExclusionPath
```

Finding:

Confirmed that `C:\SecurityToolLab` appeared in the Defender exclusion configuration after the controlled change.

---

### Evidence 8 – Microsoft Defender Event 5007

Source:

`Microsoft-Windows-Windows Defender/Operational`

Event:

`5007`

Finding:

Event ID 5007 was investigated as the primary indicator of Defender configuration change.

---

### Evidence 9 – Sysmon Event ID 1

Source:

`Microsoft-Windows-Sysmon/Operational`

Event:

`1 – Process Create`

Finding:

Reviewed PowerShell process creation around the time of the Defender configuration change.

Relevant context included:

- Image
- CommandLine
- User
- ProcessId
- ParentImage
- ParentProcessId
- Timestamp

---

### Evidence 10 – Windows Security Event 4688

Source:

`Windows Security`

Event:

`4688 – Process Creation`

Finding:

Reviewed Windows process creation telemetry as an independent source for the PowerShell activity.

---

### Evidence 11 – PowerShell Event 4104

Source:

`Microsoft-Windows-PowerShell/Operational`

Event:

`4104 – Script Block Logging`

Finding:

Where available, PowerShell script-block telemetry was reviewed for the configuration-change command.

---

### Evidence 12 – Wazuh Correlation

Wazuh Discover searches included:

```text
agent.name: DESKTOP-9MMM37V
```

```text
agent.name: DESKTOP-9MMM37V AND 5007
```

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

```text
agent.name: DESKTOP-9MMM37V AND Add-MpPreference
```

Finding:

Wazuh was used to correlate Defender and PowerShell activity with endpoint telemetry.

---

## Evidence Correlation

| Evidence | Observation | Relevance |
|---|---|---|
| Defender baseline | Protection state recorded | Establishes initial state |
| Exclusion baseline | Existing exclusions recorded | Establishes configuration state |
| User identity | Account recorded | Supports attribution |
| PowerShell | Configuration command executed | Change mechanism |
| Event 5007 | Defender configuration changed | Primary change evidence |
| Sysmon 1 | Process creation telemetry | Process attribution |
| Security 4688 | Process creation telemetry | Independent validation |
| PowerShell 4104 | Script content where available | Command attribution |
| Wazuh | Endpoint correlation | Centralized investigation |
| Restoration | Exclusion removed | Confirms cleanup |

---

