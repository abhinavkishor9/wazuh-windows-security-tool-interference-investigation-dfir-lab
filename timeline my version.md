# Investigation Timeline

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
