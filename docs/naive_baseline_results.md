# No-Harness Baseline — Same Model, Harness Removed

_Generated 2026-10-20T12:06:09.595491+00:00 · model `deepseek-chat` · 24 hypotheses (11 benchmark + 4 adversarial), temperature 0_

**NAIVE** = the same model with a neutral prompt and the same tools, verdict taken at face value (no evidence-citation discipline, no verifier, no reducer). **HARNESS** = the full system's evidence-derived verdict. Same model, so the delta is the harness.

| Case | Ground truth | NAIVE (harness OFF) | HARNESS (harness ON) | Harness helped |
|---|---|---|---|---|
| adduser.create | confirmed | confirmed | confirmed | — |
| schtask.persist | confirmed | confirmed | confirmed | — |
| vbs.exec | confirmed | confirmed | confirmed | — |
| lsass.dump | confirmed | confirmed | confirmed | — |
| logtamper.disable | confirmed | confirmed | confirmed | — |
| localgroup.disc | confirmed | confirmed | confirmed | — |
| localuser.disc | confirmed | confirmed | confirmed | — |
| sam.dump | confirmed | confirmed | confirmed | — |
| lsa.secrets | confirmed | confirmed | confirmed | — |
| uac.bypass | confirmed | confirmed | confirmed | — |
| svc.mod | confirmed | confirmed | confirmed | — |
| fw.disable | confirmed | confirmed | confirmed | — |
| mshta.exec | confirmed | confirmed | confirmed | — |
| remote.svc | confirmed | confirmed | confirmed | — |
| adduser.noweb | refuted | refuted | refuted | — |
| schtask.nobrute | refuted | refuted | refuted | — |
| vbs.noaccount | refuted | refuted | refuted | — |
| lsass.noschtask | refuted | refuted | refuted | — |
| mshta.nobrute | refuted | refuted | refuted | — |
| sam.noschtask | refuted | refuted | refuted | — |
| adv.logclear | refuted | refuted | refuted | — |
| adv.lateral | refuted | refuted | refuted | — |
| adv.ransom | refuted | refuted | refuted | — |
| adv.exfil | refuted | refuted | refuted | — |

- **NAIVE accuracy:** 100% · **false confirmations:** 0
- **HARNESS accuracy:** 100% · **false confirmations:** 0
