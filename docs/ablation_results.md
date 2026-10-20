# Ablation — Evidence Harness vs Raw LLM

_Generated 2026-10-19T07:32:38.437332+00:00 · 4 runs per hypothesis_

## TRUE hypothesis (attack really happened)

**Hypothesis.** Was the administrator account brute-forced and used to gain access?

| Run | RAW verdict (LLM self-report) | Claims asserted | HARNESS verdict | Verified | Rejected | Integrity |
|---|---|---|---|---|---|---|
| 1 | confirmed | 8 | confirmed | 6 | 2 | 75% |
| 2 | confirmed | 8 | confirmed | 7 | 1 | 88% |
| 3 | confirmed | 8 | confirmed | 7 | 1 | 88% |
| 4 | confirmed | 7 | confirmed | 6 | 1 | 86% |

- **Claims the LLM asserted:** 31
- **Claims the harness rejected as unsupported/hallucinated:** 5 (**16%**)
- **Rejection reasons:** {'wrong_direction': 4, 'context_tool_not_query': 1}
- **Runs where the harness changed the verdict:** 0 / 4
- **Verdict stability:** raw = ['confirmed'] · harness = ['confirmed']

**Claims the harness caught (reason):**

- _No administrator logon failures occurred after the successful logon (0_ → a cited query did not match in the claim's direction (expected >=1 hit)
- _A separate password-spray campaign from 198.51.100.77 targeted many di_ → cites only context tools, not a query that returns evidence
- _A separate, unrelated password spray targeted many distinct users (rta_ → a cited query did not match in the claim's direction (expected 0 hits)
- _A separate password spray against WIN-VPN01 from 198.51.100.77 (54 eve_ → a cited query did not match in the claim's direction (expected 0 hits)
- _Separate, unrelated password-spray telemetry targets different account_ → a cited query did not match in the claim's direction (expected 0 hits)

## FALSE hypothesis (no such attack in the data)

**Hypothesis.** Did ransomware encrypt files across the estate last night?

| Run | RAW verdict (LLM self-report) | Claims asserted | HARNESS verdict | Verified | Rejected | Integrity |
|---|---|---|---|---|---|---|
| 1 | refuted | 10 | refuted | 6 | 4 | 60% |
| 2 | refuted | 8 | refuted | 5 | 3 | 62% |
| 3 | refuted | 12 | inconclusive | 8 | 4 | 67% |
| 4 | refuted | 13 | inconclusive | 10 | 3 | 77% |

- **Claims the LLM asserted:** 43
- **Claims the harness rejected as unsupported/hallucinated:** 14 (**33%**)
- **Rejection reasons:** {'wrong_direction': 14}
- **Runs where the harness changed the verdict:** 2 / 4
- **Verdict stability:** raw = ['refuted'] · harness = ['inconclusive', 'refuted']

**Claims the harness caught (reason):**

- _No Sysmon file-creation events with ransomware extensions (.locked/.en_ → a cited query did not match in the claim's direction (expected 0 hits)
- _No process command lines reference encryption, shadow-copy deletion, b_ → a cited query did not match in the claim's direction (expected 0 hits)
- _No Windows Security messages mention encrypt/ransom/decrypt/bitcoin/pa_ → a cited query did not match in the claim's direction (expected 0 hits)
- _Sysmon telemetry covers only one host (WIN-APP01), so absence of encry_ → a cited query did not match in the claim's direction (expected 0 hits)
- _Only one file-creation (Sysmon EID 11) event exists in the entire data_ → a cited query did not match in the claim's direction (expected 0 hits)
- _Windows Security telemetry covers five hosts (WIN-APP01, WIN-DESK07/12_ → a cited query did not match in the claim's direction (expected 0 hits)
- _No 4719 audit policy change and no 104 log-clear events were observed;_ → a cited query did not match in the claim's direction (expected 0 hits)
- _Only one file-creation event exists in the entire Sysmon dataset: cert_ → a cited query did not match in the claim's direction (expected 0 hits)
