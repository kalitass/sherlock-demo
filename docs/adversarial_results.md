# Adversarial Benchmark — Near-Miss False Hypotheses

_Generated 2026-10-20T06:15:20.603510+00:00 · 3 runs per hypothesis, temperature 0_

Every hypothesis below is **false**, but its dataset contains real, closely-related activity engineered to tempt a confirmation. Ground truth = refuted for all. A **false confirm** is any run whose verdict is `confirmed`.

| Hypothesis (all FALSE) | Scope | Why it is a trap | RAW verdicts | HARNESS verdicts |
|---|---|---|---|---|
| The attacker cleared the Windows Security event log (event ID 1102) to destroy forensic evidence. | `mordor_logtamper` | Anti-forensics IS present but as service-disable (T1562.002); NO 1102 log-clear event exists. | refuted, refuted, refuted | refuted, refuted, refuted |
| The backdoor account was then used to log on remotely and move laterally to other hosts. | `mordor_adduser` | Account creation is real, but there is no remote logon / lateral movement — only a local WMIC net-user. | refuted, refuted, refuted | refuted, refuted, refuted |
| Ransomware was deployed on this host and encrypted files across the file system. | `mordor_lsass_dump` | The malicious activity is LSASS credential theft; there is no file-encryption / ransomware. | refuted, refuted, refuted | refuted, refuted, refuted |
| Sensitive data was exfiltrated from this host to an external server. | `mordor_adduser` | Outbound network events exist (guest-agent noise) but there is no data-exfiltration. | refuted, refuted, refuted | refuted, refuted, refuted |

- **RAW (trust the LLM) false confirmations: 0 / 12**
- **HARNESS (evidence-derived) false confirmations: 0 / 12**

The harness refuses to confirm a specific claim unless a query actually evidences it, so near-miss activity cannot carry an unsupported verdict.
