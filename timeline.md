# Investigation Timeline

## Lab 52 – Security Tool Interference Investigation

| Sequence | Activity | Evidence |
|---|---|---|
| T1 | Verified Wazuh Agent | Wazuh Manager |
| T2 | Created investigation workspace | PowerShell |
| T3 | Collected Defender security baseline | PowerShell |
| T4 | Collected existing Defender exclusions | PowerShell |
| T5 | Identified current user | PowerShell |
| T6 | Added temporary Defender exclusion | `Add-MpPreference` |
| T7 | Verified changed Defender configuration | `Get-MpPreference` |
| T8 | Reviewed Defender Event ID 5007 | Event Viewer |
| T9 | Reviewed Sysmon Event ID 1 | Event Viewer |
| T10 | Reviewed Security Event ID 4688 | Event Viewer |
| T11 | Reviewed PowerShell Event ID 4104 where available | PowerShell Operational |
| T12 | Searched Wazuh Discover | Wazuh |
| T13 | Correlated configuration change with process activity | Analyst |
| T14 | Removed temporary Defender exclusion | `Remove-MpPreference` |
| T15 | Verified Defender state | PowerShell |
| T16 | Removed investigation artifacts | PowerShell |
| T17 | Completed final assessment | Analyst |

---

# Investigation Flow

```text
Verify Wazuh Agent
        ↓
Capture Defender Baseline
        ↓
Capture Existing Exclusions
        ↓
Identify User
        ↓
Add Controlled Exclusion
        ↓
Verify Configuration Change
        ↓
Review Defender Event 5007
        ↓
Review PowerShell / Sysmon / Security Events
        ↓
Correlate in Wazuh
        ↓
Assess Context
        ↓
Remove Exclusion
        ↓
Verify Original State
        ↓
Clean Up Lab
```

---

# Configuration Timeline

| Stage | Defender State |
|---|---|
| Before Lab | Baseline captured |
| Change | `C:\SecurityToolLab` added as temporary exclusion |
| After Change | Exclusion verified |
| Investigation | Defender and process telemetry reviewed |
| Restoration | Temporary exclusion removed |
| Final State | Defender configuration returned to intended state |

---

# Evidence Timeline

## Stage 1 – Baseline

The initial Defender state and existing exclusions were recorded before any modification.

This established the comparison point for the investigation.

---

## Stage 2 – Controlled Change

The lab directory:

`C:\SecurityToolLab`

was added as a Defender exclusion using:

`Add-MpPreference`

This created the controlled configuration-change event.

---

## Stage 3 – Security Telemetry

The resulting Defender configuration change was investigated through:

- Defender Event ID 5007
- Sysmon Event ID 1
- Security Event ID 4688
- PowerShell Event ID 4104 where available

---

## Stage 4 – Wazuh Correlation

The endpoint:

`DESKTOP-9MMM37V`

was investigated in Wazuh Discover.

The objective was to correlate the Defender configuration change with the PowerShell process responsible for the action.

---

## Stage 5 – Restoration

The temporary exclusion was removed:

`Remove-MpPreference -ExclusionPath "C:\SecurityToolLab"`

The Defender configuration was then checked again against the initial baseline.

---

# Analyst Assessment

The timeline represents a controlled and reversible security configuration change.

The evidence chain is:

```text
Defender Baseline
        ↓
PowerShell Configuration Change
        ↓
Defender Event 5007
        ↓
Process Creation Telemetry
        ↓
Wazuh Correlation
        ↓
Configuration Restored
```

---

# Final Timeline Conclusion

The investigation demonstrated how a Microsoft Defender configuration modification can be traced from the initial security baseline through the configuration-change event, process telemetry, and Wazuh correlation.

Because the change was intentionally created for the lab and limited to `C:\SecurityToolLab`, the activity was classified as a benign controlled configuration change rather than unauthorized security-tool interference.

The temporary exclusion was removed and the investigation artifacts were cleaned up after evidence collection.
```
