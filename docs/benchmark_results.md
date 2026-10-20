# Benchmark — Accuracy on Public ATT&CK-Labelled Telemetry

_Generated 2026-10-20T06:05:12.127962+00:00 · 11 hypotheses, one hunt each, temperature 0_

## Dataset provenance (OTRF Security-Datasets / Mordor)

| Index | ATT&CK | Technique | Ground-truth action |
|---|---|---|---|
| `mordor_adduser` | T1136.001 | Create Account: Local Account | A local user 'backdoor' is created via `WMIC ... net user /add` (Security 4720). |
| `mordor_schtask` | T1053.005 | Scheduled Task | `schtasks /Create /TN MordorSchtask` registers a persistence task. |
| `mordor_vbs_exec` | T1059.005 | Command and Scripting Interpreter: Visual Basic | WScript runs launcher.vbs which spawns an obfuscated PowerShell Empire stager. |
| `mordor_lsass_dump` | T1003.001 | OS Credential Dumping: LSASS Memory | Outflank-Dumpert opens a handle to lsass.exe to dump credentials (Sysmon 10). |
| `mordor_logtamper` | T1562.002 | Impair Defenses: Disable Windows Event Logging | The EventLog service Start value is set to 4 (disabled) in the registry. |
| `scn_benign` | — | (clean baseline) | A normal working day: no attack. |

## Per-hypothesis results

| Case | Scope | Ground truth | RAW (LLM) | HARNESS | Claims | Rejected | Correct (harness) |
|---|---|---|---|---|---|---|---|
| adduser.create | mordor_adduser | confirmed | confirmed | confirmed | 6 | 0 | ✅ |
| schtask.persist | mordor_schtask | confirmed | confirmed | confirmed | 5 | 0 | ✅ |
| vbs.exec | mordor_vbs_exec | confirmed | confirmed | confirmed | 6 | 0 | ✅ |
| lsass.dump | mordor_lsass_dump | confirmed | confirmed | confirmed | 5 | 0 | ✅ |
| logtamper.disable | mordor_logtamper | confirmed | confirmed | confirmed | 5 | 0 | ✅ |
| adduser.noweb | mordor_adduser | refuted | refuted | refuted | 7 | 0 | ✅ |
| schtask.nobrute | mordor_schtask | refuted | refuted | refuted | 8 | 1 | ✅ |
| vbs.noaccount | mordor_vbs_exec | refuted | refuted | refuted | 7 | 1 | ✅ |
| lsass.noschtask | mordor_lsass_dump | refuted | refuted | refuted | 8 | 1 | ✅ |
| benign.nobrute | scn_benign | refuted | refuted | refuted | 6 | 1 | ✅ |
| benign.noaccount | scn_benign | refuted | refuted | refuted | 7 | 2 | ✅ |

## Scores (positive class = attack confirmed)

### HARNESS — verdict re-derived from verified evidence

- Confusion: TP=5 FP=0 FN=0 TN=6
- Precision **100%** · Recall **100%** · F1 **100%**
- Accuracy **100%** · exact-verdict accuracy 100%
- **False-positive rate 0%**

### RAW — trust the LLM's self-reported verdict

- Confusion: TP=5 FP=0 FN=0 TN=6
- Precision **100%** · Recall **100%** · F1 **100%**
- Accuracy **100%** · exact-verdict accuracy 100%
- **False-positive rate 0%**

## Anti-hallucination

- Claims the LLM asserted across all hunts: **70**
- Claims the harness rejected as unsupported: **6** (**9%**)

_Each rejected claim cited a query that did not exist, was a context (non-query) tool, failed, or whose hit-count contradicted the claim's direction._
