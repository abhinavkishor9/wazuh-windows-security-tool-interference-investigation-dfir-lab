# Investigation Notes

## Lab Summary

This investigation examined a controlled change to Microsoft Defender configuration on a Windows endpoint.

A dedicated DFIR workspace was created and recorded as a baseline. A temporary Defender exclusion for `C:\SecurityToolLab` was then added using PowerShell. The resulting configuration change was investigated through Microsoft Defender Operational logs, Windows process telemetry, and Wazuh.

The temporary configuration was removed after evidence collection to restore the endpoint to its original state.

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

A SOC analyst receives an alert indicating that Microsoft Defender configuration may have been modified.

The analyst must determine whether the change was:

- Authorized administration
- Endpoint troubleshooting
- A security-control modification
- Potential defense-evasion activity

The investigation establishes the original state first and then follows the configuration change through Windows and Wazuh telemetry.

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

## DFIR Analysis

The investigation demonstrated how a security-control change should be investigated as a sequence of related events rather than as an isolated Defender event.

The initial Defender state was recorded before modification. The temporary exclusion was then added through PowerShell, allowing the analyst to trace the change to a specific administrative action.

Event ID 5007 provided the security-tool configuration-change evidence, while process telemetry provided context around the process responsible for the modification.

Wazuh supplied centralized visibility and allowed the individual Windows events to be correlated within the endpoint investigation.

---

## Analyst Observations

- Microsoft Defender configuration should be baselined before investigating changes.
- Defender Event ID 5007 is useful for identifying configuration modifications.
- Process telemetry helps attribute the action to an account and process.
- PowerShell command-line or script-block evidence provides additional context.
- A Defender configuration change does not automatically indicate malicious activity.
- The affected path or setting must be considered.
- User context and business purpose are important.
- Temporary lab changes should always be reversed after the investigation.
- Wazuh provides useful centralized correlation for endpoint events.

---

## Investigation Assessment

The observed Defender configuration change was intentionally generated as part of the lab.

The change affected only:

`C:\SecurityToolLab`

and did not disable Defender or its primary protection features.

The activity was therefore assessed as:

**Benign Controlled Security Configuration Change**

---

## Conclusion

The investigation demonstrated how Microsoft Defender configuration changes can be traced from the configuration layer to the responsible PowerShell process and then correlated through Windows telemetry and Wazuh.

The lab reinforced that a security-tool modification should be judged using context, attribution, affected settings, and surrounding activity rather than automatically being treated as malicious defense evasion.
