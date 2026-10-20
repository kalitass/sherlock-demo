# Experiment — Repeatability (same hypothesis, run twice)

_Generated 2026-10-20T11:59:07.010362+00:00 · temperature 0 · evidence-derived verdict_

Dataset manifest hash `d6aa1f8bc1b1`, **unchanged across all runs: True** — so any difference is agent variance, not data drift.

| Hypothesis | Verdict run 1 | Verdict run 2 | Match | Finding Jaccard | Query-plan Jaccard |
|---|---|---|---|---|---|
| adduser.create | confirmed | confirmed | ✅ | 0.8 | 0.072 |
| lsass.dump | confirmed | confirmed | ✅ | 0.75 | 0.222 |
| mshta.nobrute | refuted | refuted | ✅ | 0.2 | 0.111 |
| adv.logclear | refuted | refuted | ✅ | 0.429 | 0.057 |

- **Verified-verdict agreement:** 4/4
- **Mean finding-set Jaccard** (verified MITRE techniques): 0.545
- **Mean query-plan Jaccard** (index+DSL digests): 0.115

Convergence is engineered, not assumed: (1) **temperature 0** for near-deterministic decoding; (2) a **coverage-first system contract** that fixes the order of investigation (enumerate sources → quantify → pull records); (3) a **forced final answer** so a run that exhausts its tool budget still emits a verdict from the evidence gathered instead of defaulting to inconclusive; and (4) the **evidence gate**, which discards any claim not tied to a real query — so even when the free-text narrative differs slightly between runs, the *verified* findings and the verdict converge.
