# Benchmark — Accuracy on Public ATT&CK-Labelled Telemetry

_Generated 2026-10-20T11:54:11.900790+00:00 · model `deepseek-chat` · 20 hypotheses, one hunt each, temperature 0_

## Dataset provenance (OTRF Security-Datasets / Mordor)

| Index | ATT&CK | Technique | Ground-truth action |
|---|---|---|---|
| `mordor_adduser` | T1136.001 | Create Account: Local Account | A local user 'backdoor' is created via `WMIC ... net user /add` (Security 4720). |
| `mordor_schtask` | T1053.005 | Scheduled Task | `schtasks /Create /TN MordorSchtask` registers a persistence task. |
| `mordor_vbs_exec` | T1059.005 | Command and Scripting Interpreter: Visual Basic | WScript runs launcher.vbs which spawns an obfuscated PowerShell Empire stager. |
| `mordor_lsass_dump` | T1003.001 | OS Credential Dumping: LSASS Memory | Outflank-Dumpert opens a handle to lsass.exe to dump credentials (Sysmon 10). |
| `mordor_logtamper` | T1562.002 | Impair Defenses: Disable Windows Event Logging | The EventLog service Start value is set to 4 (disabled) in the registry. |
| `mordor_localgroup_disc` | T1069.001 | Permission Groups Discovery: Local Groups | `net localgroup Administrators` enumerates the local admins group. |
| `mordor_localuser_disc` | T1087.001 | Account Discovery: Local Account | `net user` enumerates local user accounts. |
| `mordor_sam_dump` | T1003.002 | OS Credential Dumping: Security Account Manager | `esentutl /y /vss ... config\SAM` copies the SAM hive via volume shadow. |
| `mordor_lsa_secrets` | T1003.004 | OS Credential Dumping: LSA Secrets | PsExec runs `reg save HKLM\security\policy\secrets` to dump LSA secrets. |
| `mordor_uac_bypass` | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | fodhelper.exe is abused to launch an elevated process (UAC bypass). |
| `mordor_svc_mod` | T1543.003 | Create or Modify System Process: Windows Service | `sc config Fax binPath=... powershell` repurposes the Fax service to run code. |
| `mordor_fw_disable` | T1562.004 | Impair Defenses: Disable or Modify System Firewall | `netsh advfirewall firewall add rule ... action=allow` opens an inbound port. |
| `mordor_mshta_exec` | T1218.005 | System Binary Proxy Execution: Mshta | mshta runs inline VBScript that launches PowerShell (signed-binary proxy). |
| `mordor_remote_svc` | T1021.002 | Remote Services: SMB/Windows Admin Shares | A Windows service is created remotely over SMB/svcctl (Security 4697 / System 7045). |
| `scn_benign` | — | (clean baseline) | A normal working day: no attack. |

## Per-hypothesis results

| Case | Scope | Ground truth | RAW (LLM) | HARNESS | Claims | Rejected | Correct (harness) |
|---|---|---|---|---|---|---|---|
| adduser.create | mordor_adduser | confirmed | confirmed | confirmed | 5 | 0 | ✅ |
| schtask.persist | mordor_schtask | confirmed | confirmed | confirmed | 6 | 0 | ✅ |
| vbs.exec | mordor_vbs_exec | confirmed | confirmed | confirmed | 6 | 0 | ✅ |
| lsass.dump | mordor_lsass_dump | confirmed | confirmed | confirmed | 6 | 0 | ✅ |
| logtamper.disable | mordor_logtamper | confirmed | confirmed | confirmed | 7 | 0 | ✅ |
| localgroup.disc | mordor_localgroup_disc | confirmed | confirmed | confirmed | 4 | 0 | ✅ |
| localuser.disc | mordor_localuser_disc | confirmed | confirmed | confirmed | 5 | 0 | ✅ |
| sam.dump | mordor_sam_dump | confirmed | confirmed | confirmed | 7 | 1 | ✅ |
| lsa.secrets | mordor_lsa_secrets | confirmed | confirmed | confirmed | 5 | 0 | ✅ |
| uac.bypass | mordor_uac_bypass | confirmed | confirmed | confirmed | 5 | 0 | ✅ |
| svc.mod | mordor_svc_mod | confirmed | confirmed | confirmed | 6 | 0 | ✅ |
| fw.disable | mordor_fw_disable | confirmed | confirmed | confirmed | 5 | 1 | ✅ |
| mshta.exec | mordor_mshta_exec | confirmed | confirmed | confirmed | 6 | 2 | ✅ |
| remote.svc | mordor_remote_svc | confirmed | confirmed | confirmed | 7 | 0 | ✅ |
| adduser.noweb | mordor_adduser | refuted | refuted | refuted | 9 | 0 | ✅ |
| schtask.nobrute | mordor_schtask | refuted | refuted | refuted | 5 | 1 | ✅ |
| vbs.noaccount | mordor_vbs_exec | refuted | refuted | refuted | 5 | 1 | ✅ |
| lsass.noschtask | mordor_lsass_dump | refuted | refuted | refuted | 9 | 1 | ✅ |
| mshta.nobrute | mordor_mshta_exec | refuted | refuted | refuted | 7 | 0 | ✅ |
| sam.noschtask | mordor_sam_dump | refuted | refuted | refuted | 8 | 0 | ✅ |

## Scores (positive class = attack confirmed)

### HARNESS — verdict re-derived from verified evidence

- Confusion: TP=14 FP=0 FN=0 TN=6
- Precision **100%** · Recall **100%** · F1 **100%**
- Accuracy **100%** · exact-verdict accuracy 100%
- **False-positive rate 0%**

### RAW — trust the LLM's self-reported verdict

- Confusion: TP=14 FP=0 FN=0 TN=6
- Precision **100%** · Recall **100%** · F1 **100%**
- Accuracy **100%** · exact-verdict accuracy 100%
- **False-positive rate 0%**

## Anti-hallucination

- Claims the LLM asserted across all hunts: **123**
- Claims the harness rejected as unsupported: **7** (**6%**)

_Each rejected claim cited a query that did not exist, was a context (non-query) tool, failed, or whose hit-count contradicted the claim's direction._
