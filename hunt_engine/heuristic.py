"""Deterministic (no-LLM) hunt engine -- a SCANNER over the public OTRF corpus.

A no-LLM engine cannot understand natural language, so it does NOT interpret the
hypothesis and never keyword-matches it (interpreting a free-text hypothesis is the
LLM engine's job). Instead it sweeps the data for every known attack pattern and
reports what it finds -- a repeatable, audit-grade detection pass you could run on a
schedule.

It runs against the real, ATT&CK-labelled OTRF Security-Datasets ingested under
`sherlock-logs-mordor_*` (see datasets/mordor_import.py), querying the raw
Windows/Sysmon/PowerShell fields those captures carry (EventID, CommandLine, Image,
TargetObject, ...). Each probe is one atomic SOC detection tagged to a MITRE ATT&CK
technique, run through the same MCP tools + evidence ledger as the LLM path, so its
hits are verifiable. `ok` is False if a probe's query failed, so a query error is
never read as "no attack". ALL probes run and report.

The candidate verdict is about the SCAN: `confirmed` when attack activity is detected,
`refuted` when it ran clean, `inconclusive` when it could not run. The final verdict
is still re-derived by reduce_verdict from verified evidence.
"""
from __future__ import annotations

from typing import Any, Callable

from hunt_engine.evidence_ledger import EvidenceLedger
from hunt_engine.mcp_client import MCPClient

# The scanner sweeps the whole public corpus. Run it UNSCOPED (no SHERLOCK_LOG_SCOPE);
# a single-index scoped hunt is the LLM engine's job.
CORPUS = "sherlock-logs-mordor_*"

ProbeResult = tuple[dict[str, Any] | None, bool, dict[str, Any] | None]


class Probe:
    def __init__(self, pid, name, mitre, technique, severity,
                 run: Callable[[MCPClient, EvidenceLedger], ProbeResult]):
        self.pid, self.name, self.mitre, self.technique = pid, name, mitre, technique
        self.severity, self.run = severity, run


def _finding(claim, evidence_ids, mitre, technique, severity):
    return {"claim": claim, "evidence_ids": evidence_ids, "mitre": mitre, "technique": technique,
            "severity": severity, "detail": "", "role": "positive"}


def _absence(claim, evidence_ids, mitre, technique):
    return {"claim": claim, "evidence_ids": evidence_ids, "mitre": mitre, "technique": technique,
            "severity": "low", "detail": "", "role": "negative"}


def _ok(r: Any) -> bool:
    return isinstance(r, dict) and r.get("ok") is True


def _matched(r: dict) -> int:
    m = r.get("matched_documents", r.get("count"))
    return m if isinstance(m, int) and m >= 0 else 0


def _clean_zero(r: dict) -> bool:
    return _ok(r) and isinstance(r.get("matched_documents", r.get("count")), int) and _matched(r) == 0


# A probe spec: (id, query_string over the raw OTRF fields, mitre, technique, severity,
# claim-when-hit, claim-when-absent). Each becomes a count_logs probe over the corpus.
_SPECS = [
    ("account_creation", "EventID:4720", "T1136.001", "Create Account: Local Account", "high",
     "Local user account creation observed (Security 4720)",
     "No local-account-creation events were found."),
    ("scheduled_task", 'CommandLine:*schtasks* AND CommandLine:*Create*', "T1053.005", "Scheduled Task", "high",
     "Scheduled-task creation via schtasks observed",
     "No scheduled-task creation was found."),
    ("script_exec", "Image:*wscript.exe* OR Image:*cscript.exe*", "T1059.005",
     "Command and Scripting Interpreter: Visual Basic", "high",
     "Windows Script Host (wscript/cscript) execution observed",
     "No Windows Script Host execution was found."),
    ("encoded_powershell", "CommandLine:*-enc* OR CommandLine:*FromBase64String* OR CommandLine:*-EncodedCommand*",
     "T1059.001", "PowerShell", "high",
     "Encoded/obfuscated PowerShell execution observed",
     "No encoded PowerShell execution was found."),
    ("lsass_access", "EventID:10 AND TargetImage:*lsass.exe*", "T1003.001",
     "OS Credential Dumping: LSASS Memory", "critical",
     "A process opened a handle to LSASS memory (Sysmon 10)",
     "No LSASS process-access events were found."),
    ("sam_dump", "CommandLine:*esentutl* OR CommandLine:*\\\\SAM*", "T1003.002",
     "OS Credential Dumping: Security Account Manager", "critical",
     "SAM hive copy observed (esentutl / shadow copy)",
     "No SAM-hive copy was found."),
    ("lsa_secrets", "CommandLine:*reg* AND CommandLine:*secrets*", "T1003.004",
     "OS Credential Dumping: LSA Secrets", "critical",
     "LSA secrets dump via reg save observed",
     "No LSA-secrets dump was found."),
    ("disable_eventlog", "TargetObject:*Services*EventLog* OR TargetObject:*EventLog*Start*", "T1562.002",
     "Impair Defenses: Disable Windows Event Logging", "high",
     "Registry tampering with the Windows EventLog service observed",
     "No EventLog-service tampering was found."),
    ("disable_firewall", "CommandLine:*netsh* AND CommandLine:*firewall*", "T1562.004",
     "Impair Defenses: Disable or Modify System Firewall", "high",
     "Firewall modification via netsh observed",
     "No firewall modification was found."),
    ("log_cleared", "EventID:1102 OR EventID:104", "T1070.001",
     "Indicator Removal: Clear Windows Event Logs", "high",
     "Windows event log was cleared (1102/104)",
     "No event-log clearing was found."),
    ("group_discovery", "CommandLine:*localgroup*", "T1069.001",
     "Permission Groups Discovery: Local Groups", "medium",
     "Local-group enumeration (net localgroup) observed",
     "No local-group enumeration was found."),
    ("uac_bypass", "Image:*fodhelper.exe* OR CommandLine:*fodhelper*", "T1548.002",
     "Abuse Elevation Control Mechanism: Bypass UAC", "high",
     "UAC-bypass via fodhelper observed",
     "No UAC-bypass via fodhelper was found."),
    ("service_mod", "CommandLine:*sc* AND CommandLine:*config* AND CommandLine:*binPath*", "T1543.003",
     "Create or Modify System Process: Windows Service", "high",
     "Windows service reconfiguration (sc config binPath) observed",
     "No service reconfiguration was found."),
    ("proxy_mshta", "Image:*mshta.exe* OR CommandLine:*mshta*", "T1218.005",
     "System Binary Proxy Execution: Mshta", "high",
     "Signed-binary proxy execution via mshta observed",
     "No mshta proxy execution was found."),
    ("remote_service", "EventID:7045 OR EventID:4697", "T1021.002",
     "Remote Services: SMB/Windows Admin Shares", "high",
     "Windows service installation observed (7045/4697)",
     "No service-installation events were found."),
]


def _make(spec):
    pid, qs, mitre, technique, severity, hit, absent = spec

    def run(c: MCPClient, led: EvidenceLedger) -> ProbeResult:
        r = c.call("count_logs", {"index": CORPUS, "query_string": qs})
        ev = led.record("count_logs", {"probe": pid}, r)
        if not _ok(r):
            return None, False, None
        n = _matched(r)
        if n > 0:
            return _finding(f"{hit}: {n} event(s).", [ev.evidence_id], mitre, technique, severity), True, None
        if _clean_zero(r):
            return None, True, _absence(absent, [ev.evidence_id], mitre, technique)
        return None, True, None
    return Probe(pid, hit, mitre, technique, severity, run)


PROBES: list[Probe] = [_make(s) for s in _SPECS]
PROBE_BY_ID: dict[str, Probe] = {p.pid: p for p in PROBES}


def run_heuristic_hunt(hypothesis: str, client: MCPClient, ledger: EvidenceLedger,
                       on_event=lambda e: None) -> dict[str, Any]:
    """Deterministic SCAN of the public OTRF corpus. The hypothesis is NOT interpreted
    here (a no-LLM engine cannot read language and we never keyword-match it): the
    scanner runs every probe and reports what it finds. Matching a free-text hypothesis
    is the LLM engine's job."""
    lt = client.call("list_log_types", {})
    led_ev = ledger.record("list_log_types", {}, lt)
    on_event({"type": "tool_result", "tool": "list_log_types", "result": led_ev.result_summary})
    sources = lt.get("log_types", [])

    findings: list[dict[str, Any]] = []
    detected_techniques: list[str] = []
    probes_ok = probe_errors = positives = negatives = 0

    for probe in PROBES:
        on_event({"type": "probe", "name": probe.name, "mitre": probe.mitre})
        finding, ok, absence = probe.run(client, ledger)
        if ok:
            probes_ok += 1
        else:
            probe_errors += 1
        emit = finding or absence
        if emit:
            emit["probe"] = probe.pid
            findings.append(emit)
            if finding:
                positives += 1
                detected_techniques.append(probe.technique)
            else:
                negatives += 1
            on_event({"type": "finding", "finding": emit})

    scanned = probes_ok > 0
    if not scanned:
        candidate = "inconclusive"
    elif positives:
        candidate = "confirmed"
    elif not probe_errors:
        candidate = "refuted"
    else:
        candidate = "inconclusive"

    coverage = {
        "mode": "scan",
        "corpus": CORPUS,
        "techniques_probed": sorted({p.technique for p in PROBES}),
        "techniques_detected": sorted(set(detected_techniques)),
        "probes_run": len(PROBES),
        "probes_ok": probes_ok,
        "probe_errors": probe_errors,
        "time_window": {"earliest": min((s["earliest"] for s in sources), default=None),
                        "latest": max((s["latest"] for s in sources), default=None)},
    }
    return {"verdict": candidate, "confidence": 0.6, "findings": findings, "coverage": coverage,
            "summary": "", "engine": "heuristic", "hypothesis_covered": scanned}
