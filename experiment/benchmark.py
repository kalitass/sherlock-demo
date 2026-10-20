"""Accuracy benchmark on REAL, ATT&CK-labelled public attack telemetry.

The assignment allows public datasets; this turns that into a score. We import
five single-technique Windows/Sysmon captures from OTRF Security-Datasets (see
`datasets/mordor_import.py`) plus Sherlock's own clean `benign` day, then pose a
fixed set of natural-language hypotheses whose ground-truth answer is known:

  * a POSITIVE hypothesis names the technique that capture actually contains
    -> the system should reach `confirmed`;
  * a NEGATIVE hypothesis names a technique ABSENT from that capture (or asks an
    attack question of the benign day) -> the system should NOT confirm.

Every hunt is scoped to exactly ONE index via `SHERLOCK_LOG_SCOPE`, so a case is
answered only from its own data. For each hunt we record BOTH verdicts the system
produces: the model's self-reported `candidate_verdict` (RAW, i.e. trust the LLM)
and the harness-derived `verdict` (re-computed from verified evidence). Scoring
both shows how much the evidence harness improves correctness and, in particular,
how it suppresses false confirmations.

Metrics (positive class = "attack confirmed"):
  precision, recall, F1, accuracy, and false-positive rate on the negatives.
Output: docs/benchmark_results.md + experiment/benchmark_results.json.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.settings import REPO_ROOT
from datasets.mordor_import import MANIFEST
from hunt_engine.hunt import run_hunt


@dataclass(frozen=True)
class Case:
    cid: str
    scope: str          # log_type (index = sherlock-logs-<scope>)
    hypothesis: str
    truth: str          # "confirmed" (attack present) | "refuted" (absent)
    rationale: str      # why this is the ground truth


CASES: list[Case] = [
    # ---- POSITIVES: ask each capture about the technique it actually contains ----
    Case("adduser.create", "mordor_adduser",
         "A new local user account was created on this host, consistent with an attacker planting a backdoor account.",
         "confirmed", "T1136.001 — Security 4720 creates user 'backdoor' + `net user /add`."),
    Case("schtask.persist", "mordor_schtask",
         "A scheduled task was created on this host to maintain persistence.",
         "confirmed", "T1053.005 — `schtasks /Create /TN MordorSchtask`."),
    Case("vbs.exec", "mordor_vbs_exec",
         "A Windows script host (WScript/VBScript) was used to launch a PowerShell payload on this host.",
         "confirmed", "T1059.005 — WScript runs launcher.vbs spawning PowerShell Empire."),
    Case("lsass.dump", "mordor_lsass_dump",
         "A process accessed the memory of the LSASS process in order to steal credentials.",
         "confirmed", "T1003.001 — Outflank-Dumpert opens a handle to lsass.exe (Sysmon 10)."),
    Case("logtamper.disable", "mordor_logtamper",
         "An attacker attempted to disable the Windows Event Log service to evade detection.",
         "confirmed", "T1562.002 — EventLog service Start set to 4 (disabled) via registry."),
    Case("localgroup.disc", "mordor_localgroup_disc",
         "An attacker enumerated the members of the local Administrators group on this host.",
         "confirmed", "T1069.001 — `net localgroup Administrators`."),
    Case("localuser.disc", "mordor_localuser_disc",
         "An attacker enumerated the local user accounts on this host.",
         "confirmed", "T1087.001 — `net user`."),
    Case("sam.dump", "mordor_sam_dump",
         "The SAM registry hive was copied in order to steal local password hashes.",
         "confirmed", "T1003.002 — `esentutl /y /vss ... config\\SAM`."),
    Case("lsa.secrets", "mordor_lsa_secrets",
         "LSA secrets were dumped from the registry to harvest stored credentials.",
         "confirmed", "T1003.004 — PsExec `reg save HKLM\\security\\policy\\secrets`."),
    Case("uac.bypass", "mordor_uac_bypass",
         "User Account Control was bypassed to launch a process with elevated privileges.",
         "confirmed", "T1548.002 — fodhelper.exe elevation."),
    Case("svc.mod", "mordor_svc_mod",
         "An existing Windows service was reconfigured to execute an attacker-controlled command.",
         "confirmed", "T1543.003 — `sc config Fax binPath=... powershell`."),
    Case("fw.disable", "mordor_fw_disable",
         "The host firewall was modified to permit an inbound network connection.",
         "confirmed", "T1562.004 — `netsh advfirewall firewall add rule action=allow`."),
    Case("mshta.exec", "mordor_mshta_exec",
         "The signed binary mshta.exe was used to proxy-execute a script that launched PowerShell.",
         "confirmed", "T1218.005 — `mshta vbscript:Execute(... powershell ...)`."),
    Case("remote.svc", "mordor_remote_svc",
         "A Windows service was created on this host to execute attacker code.",
         "confirmed", "T1021.002 — service creation over SMB/svcctl (4697 / 7045)."),

    # ---- NEGATIVES: ask a capture about a technique it does NOT contain ----
    Case("adduser.noweb", "mordor_adduser",
         "A web shell was uploaded to and executed on a web server on this host.",
         "refuted", "No web-server logs in this Windows/Sysmon capture."),
    Case("schtask.nobrute", "mordor_schtask",
         "The administrator account was brute-forced with many failed logon attempts.",
         "refuted", "No failed-logon (4625) bursts present."),
    Case("vbs.noaccount", "mordor_vbs_exec",
         "A new administrative user account was created on this host.",
         "refuted", "No account-creation (4720) events present."),
    Case("lsass.noschtask", "mordor_lsass_dump",
         "A scheduled task was created to establish persistence on this host.",
         "refuted", "No scheduled-task creation present."),

    # ---- NEGATIVES: cross-dataset (ask a capture about a technique it lacks) ----
    Case("mshta.nobrute", "mordor_mshta_exec",
         "The administrator account was brute-forced with many failed logon attempts.",
         "refuted", "mshta-execution capture — no 4625 failed-logon bursts present."),
    Case("sam.noschtask", "mordor_sam_dump",
         "A scheduled task was created to establish persistence on this host.",
         "refuted", "SAM-theft capture — no scheduled-task creation present."),
]


# Adversarial "near-miss" hypotheses: each is FALSE, but the capture contains real,
# strongly-related activity that tempts an unguarded LLM to over-confirm. Ground
# truth is refuted for all; the question is whether the harness refuses to confirm
# the SPECIFIC claimed act when no query actually evidences it.
ADVERSARIAL: list[Case] = [
    Case("adv.logclear", "mordor_logtamper",
         "The attacker cleared the Windows Security event log (event ID 1102) to destroy forensic evidence.",
         "refuted", "Anti-forensics IS present but as service-disable (T1562.002); NO 1102 log-clear event exists."),
    Case("adv.lateral", "mordor_adduser",
         "The backdoor account was then used to log on remotely and move laterally to other hosts.",
         "refuted", "Account creation is real, but there is no remote logon / lateral movement — only a local WMIC net-user."),
    Case("adv.ransom", "mordor_lsass_dump",
         "Ransomware was deployed on this host and encrypted files across the file system.",
         "refuted", "The malicious activity is LSASS credential theft; there is no file-encryption / ransomware."),
    Case("adv.exfil", "mordor_adduser",
         "Sensitive data was exfiltrated from this host to an external server.",
         "refuted", "Outbound network events exist (guest-agent noise) but there is no data-exfiltration."),
]


def _run_case(c: Case, run_label: str) -> dict[str, Any]:
    os.environ["SHERLOCK_LOG_SCOPE"] = c.scope
    try:
        b = run_hunt(c.hypothesis, run_label=run_label, use_llm=True, persist=False,
                     mcp_backend="direct")
    finally:
        os.environ.pop("SHERLOCK_LOG_SCOPE", None)
    r, v = b["result"], b["verification"]
    return {
        "cid": c.cid, "scope": c.scope, "truth": c.truth,
        "raw_verdict": r.get("candidate_verdict"),     # trust-the-LLM baseline
        "harness_verdict": r.get("verdict"),            # evidence-derived
        "claims": v["n_total"], "verified": v["n_verified"], "rejected": v["n_rejected"],
        "integrity": v["verification_rate"],
    }


def _confusion(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    """Positive class = attack confirmed. predicted-positive iff verdict=='confirmed'."""
    tp = fp = fn = tn = 0
    exact = 0
    for r in rows:
        actual_pos = r["truth"] == "confirmed"
        pred_pos = r[key] == "confirmed"
        if actual_pos and pred_pos: tp += 1
        elif actual_pos and not pred_pos: fn += 1
        elif not actual_pos and pred_pos: fp += 1
        else: tn += 1
        # exact: a refuted-truth case is only "exactly right" if verdict is 'refuted'
        if (actual_pos and pred_pos) or (not actual_pos and r[key] == "refuted"):
            exact += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    n = len(rows)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1,
            "fp_rate": fpr, "accuracy": (tp + tn) / n if n else 0.0,
            "exact_accuracy": exact / n if n else 0.0}


def run_benchmark(run_label: str = "bench") -> dict[str, Any]:
    from common.llm import LLMClient
    tag = os.environ.get("SHERLOCK_BENCH_TAG", "").strip()
    suffix = f"_{tag}" if tag else ""
    rows = [_run_case(c, run_label) for c in CASES]
    raw = _confusion(rows, "raw_verdict")
    harness = _confusion(rows, "harness_verdict")
    total_claims = sum(r["claims"] for r in rows)
    total_rejected = sum(r["rejected"] for r in rows)
    result = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "model": LLMClient().model, "tag": tag or "default",
        "n_cases": len(rows), "rows": rows,
        "raw": raw, "harness": harness,
        "claims_asserted": total_claims, "claims_rejected": total_rejected,
        "reject_rate": (total_rejected / total_claims) if total_claims else 0.0,
    }
    (REPO_ROOT / "experiment" / f"benchmark_results{suffix}.json").write_text(json.dumps(result, indent=2))
    _write_md(result, suffix)
    _print(result)
    return result


def _pct(x: float) -> str:
    return f"{x:.0%}"


def _write_md(res: dict[str, Any], suffix: str = "") -> None:
    rows = res["rows"]
    md: list[str] = [
        "# Benchmark — Accuracy on Public ATT&CK-Labelled Telemetry", "",
        f"_Generated {res['generated']} · model `{res.get('model','?')}` · "
        f"{res['n_cases']} hypotheses, one hunt each, temperature 0_", "",
        "## Dataset provenance (OTRF Security-Datasets / Mordor)", "",
        "| Index | ATT&CK | Technique | Ground-truth action |",
        "|---|---|---|---|",
    ]
    for m in MANIFEST:
        md.append(f"| `mordor_{m.label}` | {m.technique} | {m.technique_name} | {m.ground_truth} |")
    md += [""]

    md += ["## Per-hypothesis results", "",
           "| Case | Scope | Ground truth | RAW (LLM) | HARNESS | Claims | Rejected | Correct (harness) |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        correct = "✅" if ((r["truth"] == "confirmed" and r["harness_verdict"] == "confirmed")
                           or (r["truth"] == "refuted" and r["harness_verdict"] == "refuted")) else "❌"
        md.append(f"| {r['cid']} | {r['scope']} | {r['truth']} | {r['raw_verdict']} | "
                  f"{r['harness_verdict']} | {r['claims']} | {r['rejected']} | {correct} |")
    md.append("")

    def block(title: str, m: dict[str, Any]) -> list[str]:
        return [f"### {title}", "",
                f"- Confusion: TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}",
                f"- Precision **{_pct(m['precision'])}** · Recall **{_pct(m['recall'])}** · "
                f"F1 **{_pct(m['f1'])}**",
                f"- Accuracy **{_pct(m['accuracy'])}** · exact-verdict accuracy {_pct(m['exact_accuracy'])}",
                f"- **False-positive rate {_pct(m['fp_rate'])}**", ""]

    md += ["## Scores (positive class = attack confirmed)", ""]
    md += block("HARNESS — verdict re-derived from verified evidence", res["harness"])
    md += block("RAW — trust the LLM's self-reported verdict", res["raw"])
    md += [
        "## Anti-hallucination", "",
        f"- Claims the LLM asserted across all hunts: **{res['claims_asserted']}**",
        f"- Claims the harness rejected as unsupported: **{res['claims_rejected']}** "
        f"(**{_pct(res['reject_rate'])}**)", "",
        "_Each rejected claim cited a query that did not exist, was a context (non-query) tool, "
        "failed, or whose hit-count contradicted the claim's direction._", "",
    ]
    (REPO_ROOT / "docs" / f"benchmark_results{suffix}.md").write_text("\n".join(md))


def _print(res: dict[str, Any]) -> None:
    print("\n==== BENCHMARK ====")
    for r in res["rows"]:
        ok = "OK " if ((r["truth"] == "confirmed") == (r["harness_verdict"] == "confirmed")
                       and (r["truth"] != "refuted" or r["harness_verdict"] == "refuted")) else "XX "
        print(f"  {ok}{r['cid']:20} truth={r['truth']:9} raw={str(r['raw_verdict']):12} "
              f"harness={str(r['harness_verdict']):12} claims={r['claims']} rej={r['rejected']}")
    h, raw = res["harness"], res["raw"]
    print(f"\n  HARNESS  acc={_pct(h['accuracy'])}  P={_pct(h['precision'])} R={_pct(h['recall'])} "
          f"F1={_pct(h['f1'])}  FPR={_pct(h['fp_rate'])}")
    print(f"  RAW      acc={_pct(raw['accuracy'])}  P={_pct(raw['precision'])} R={_pct(raw['recall'])} "
          f"F1={_pct(raw['f1'])}  FPR={_pct(raw['fp_rate'])}")
    print(f"  claims={res['claims_asserted']} rejected={res['claims_rejected']} "
          f"({_pct(res['reject_rate'])})")


def run_adversarial(runs: int = 3) -> dict[str, Any]:
    """Each adversarial hypothesis is FALSE. Trusting the raw LLM confirms some of
    them from near-miss activity; the harness should confirm none (no verified
    evidence for the specific claimed act). Run several times to catch stochastic
    over-confirmation. A 'false confirm' = verdict == 'confirmed' on a refuted truth."""
    detail = []
    raw_fc = harness_fc = trials = 0
    for c in ADVERSARIAL:
        per = []
        for i in range(runs):
            r = _run_case(c, f"adv-{i+1}")
            per.append(r)
            trials += 1
            raw_fc += r["raw_verdict"] == "confirmed"
            harness_fc += r["harness_verdict"] == "confirmed"
        detail.append({"case": c, "runs": per})
        rawv = [p["raw_verdict"] for p in per]
        harv = [p["harness_verdict"] for p in per]
        print(f"  {c.cid:14} raw={rawv}  harness={harv}")
    res = {"runs": runs, "trials": trials, "raw_false_confirms": raw_fc,
           "harness_false_confirms": harness_fc, "detail": detail}
    print(f"\n  RAW false-confirms:     {raw_fc}/{trials}")
    print(f"  HARNESS false-confirms: {harness_fc}/{trials}")
    _write_adv_md(res)
    return res


def _write_adv_md(res: dict[str, Any]) -> None:
    md = ["# Adversarial Benchmark — Near-Miss False Hypotheses", "",
          f"_Generated {datetime.now(timezone.utc).isoformat()} · {res['runs']} runs per hypothesis, "
          "temperature 0_", "",
          "Every hypothesis below is **false**, but its dataset contains real, closely-related "
          "activity engineered to tempt a confirmation. Ground truth = refuted for all. A "
          "**false confirm** is any run whose verdict is `confirmed`.", "",
          "| Hypothesis (all FALSE) | Scope | Why it is a trap | RAW verdicts | HARNESS verdicts |",
          "|---|---|---|---|---|"]
    for d in res["detail"]:
        c = d["case"]
        rawv = ", ".join(p["raw_verdict"] or "?" for p in d["runs"])
        harv = ", ".join(p["harness_verdict"] or "?" for p in d["runs"])
        md.append(f"| {c.hypothesis} | `{c.scope}` | {c.rationale} | {rawv} | {harv} |")
    md += ["",
           f"- **RAW (trust the LLM) false confirmations: {res['raw_false_confirms']} / {res['trials']}**",
           f"- **HARNESS (evidence-derived) false confirmations: {res['harness_false_confirms']} / "
           f"{res['trials']}**", "",
           "The harness refuses to confirm a specific claim unless a query actually evidences it, "
           "so near-miss activity cannot carry an unsupported verdict.", ""]
    (REPO_ROOT / "docs" / "adversarial_results.md").write_text("\n".join(md))


if __name__ == "__main__":
    import sys
    if "--adversarial" in sys.argv:
        run_adversarial()
    else:
        run_benchmark()
