"""Import real, ATT&CK-labelled public attack telemetry (OTRF Security-Datasets,
a.k.a. Mordor) into Sherlock through the SAME agentic ingestion path used for any
other source.

Why this exists
---------------
Sherlock's primary corpus is a seeded synthetic estate (Operation Nightjar). To
show the system works on telemetry it has never seen, we pull a handful of
single-technique Windows/Sysmon/PowerShell captures published by the Open Threat
Research Forum. Each capture is a real adversary action recorded on a lab host and
mapped to a MITRE ATT&CK technique -- so it doubles as ground truth for the
accuracy benchmark in `experiment/benchmark.py`.

What it demonstrates
--------------------
The datasets are raw Windows event JSON (PascalCase fields, nested per event type)
in a schema Sherlock has no template for. They go through `ingest_records` with
`use_llm=False`, i.e. the deterministic auto-schema path: the schema is
fingerprinted, registered and validated on a sample, then the whole batch is
indexed -- no code change, no restart. The agent later adapts to the raw fields
via `get_field_mapping`. Each dataset lands in its own index
(`sherlock-logs-mordor_<label>`) so a hunt can be scoped to exactly one case.

Source: https://github.com/OTRF/Security-Datasets (MIT). Datasets are downloaded
on demand and cached locally; nothing large is committed to the repo.
"""
from __future__ import annotations

import io
import os
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.settings import REPO_ROOT
from ingestion.ingest_core import ingest_records

_RAW_BASE = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
             "datasets/atomic/windows")
CACHE_DIR = Path(os.environ.get("SHERLOCK_MORDOR_CACHE", str(REPO_ROOT / "datasets" / "mordor_cache")))


@dataclass(frozen=True)
class MordorSet:
    label: str          # -> log_type "mordor_<label>" -> index "sherlock-logs-mordor_<label>"
    zip_path: str       # path under _RAW_BASE
    technique: str      # MITRE ATT&CK id
    technique_name: str
    ground_truth: str   # the adversary action actually present (benchmark positive)


# The five captures used by the benchmark. Each is a DISTINCT technique so a hunt
# against one is a clean negative for the others.
MANIFEST: list[MordorSet] = [
    MordorSet("adduser", "defense_evasion/host/empire_wmic_add_user_backdoor.zip",
              "T1136.001", "Create Account: Local Account",
              "A local user 'backdoor' is created via `WMIC ... net user /add` (Security 4720)."),
    MordorSet("schtask", "persistence/host/empire_schtasks_creation_standard_user.zip",
              "T1053.005", "Scheduled Task",
              "`schtasks /Create /TN MordorSchtask` registers a persistence task."),
    MordorSet("vbs_exec", "execution/host/empire_launcher_vbs.zip",
              "T1059.005", "Command and Scripting Interpreter: Visual Basic",
              "WScript runs launcher.vbs which spawns an obfuscated PowerShell Empire stager."),
    MordorSet("lsass_dump", "credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip",
              "T1003.001", "OS Credential Dumping: LSASS Memory",
              "Outflank-Dumpert opens a handle to lsass.exe to dump credentials (Sysmon 10)."),
    MordorSet("logtamper", "defense_evasion/host/psh_disable_eventlog_service_startuptype_modification.zip",
              "T1562.002", "Impair Defenses: Disable Windows Event Logging",
              "The EventLog service Start value is set to 4 (disabled) in the registry."),
    # --- expansion: broaden ATT&CK tactic coverage (all OTRF Security-Datasets) ---
    MordorSet("localgroup_disc", "discovery/host/empire_shell_net_localgroup_administrators.zip",
              "T1069.001", "Permission Groups Discovery: Local Groups",
              "`net localgroup Administrators` enumerates the local admins group."),
    MordorSet("localuser_disc", "discovery/host/empire_shell_net_local_users.zip",
              "T1087.001", "Account Discovery: Local Account",
              "`net user` enumerates local user accounts."),
    MordorSet("sam_dump", "credential_access/host/cmd_sam_copy_esentutl.zip",
              "T1003.002", "OS Credential Dumping: Security Account Manager",
              "`esentutl /y /vss ... config\\SAM` copies the SAM hive via volume shadow."),
    MordorSet("lsa_secrets", "credential_access/host/cmd_psexec_lsa_secrets_dump.zip",
              "T1003.004", "OS Credential Dumping: LSA Secrets",
              "PsExec runs `reg save HKLM\\security\\policy\\secrets` to dump LSA secrets."),
    MordorSet("uac_bypass", "privilege_escalation/host/empire_uac_shellapi_fodhelper.zip",
              "T1548.002", "Abuse Elevation Control Mechanism: Bypass UAC",
              "fodhelper.exe is abused to launch an elevated process (UAC bypass)."),
    MordorSet("svc_mod", "privilege_escalation/host/cmd_service_mod_fax.zip",
              "T1543.003", "Create or Modify System Process: Windows Service",
              "`sc config Fax binPath=... powershell` repurposes the Fax service to run code."),
    MordorSet("fw_disable", "defense_evasion/host/cmd_netsh_fw_mod_open_ports.zip",
              "T1562.004", "Impair Defenses: Disable or Modify System Firewall",
              "`netsh advfirewall firewall add rule ... action=allow` opens an inbound port."),
    MordorSet("mshta_exec", "defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip",
              "T1218.005", "System Binary Proxy Execution: Mshta",
              "mshta runs inline VBScript that launches PowerShell (signed-binary proxy)."),
    MordorSet("remote_svc", "lateral_movement/host/covenant_sharpsc_create_dcerpc_smb_svcctl.zip",
              "T1021.002", "Remote Services: SMB/Windows Admin Shares",
              "A Windows service is created remotely over SMB/svcctl (Security 4697 / System 7045)."),
]

BY_LABEL = {m.label: m for m in MANIFEST}


def _fetch(m: MordorSet) -> list[dict[str, Any]]:
    """Download (and cache) a dataset, returning its records as a list of dicts.
    Handles both the `.zip`-of-JSON and bare `.json` layouts OTRF publishes."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    name = m.zip_path.rsplit("/", 1)[-1]
    cached = CACHE_DIR / name
    if not cached.exists():
        url = f"{_RAW_BASE}/{m.zip_path}"
        with urllib.request.urlopen(url, timeout=120) as r:      # noqa: S310 (trusted host)
            cached.write_bytes(r.read())
    data = cached.read_bytes()
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            member = next(n for n in zf.namelist() if n.endswith(".json"))
            text = zf.read(member).decode(errors="replace")
    else:
        text = data.decode(errors="replace")
    import json
    return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


def import_one(m: MordorSet, refresh: bool = True) -> dict[str, Any]:
    records = _fetch(m)
    summary = ingest_records(
        log_type=f"mordor_{m.label}", raw_records=records,
        source=f"OTRF/Security-Datasets:{m.zip_path}", mode="pull",
        refresh=refresh, use_llm=False,
    )
    summary["technique"] = m.technique
    summary["ground_truth"] = m.ground_truth
    return summary


def import_all(labels: list[str] | None = None) -> list[dict[str, Any]]:
    sets = [BY_LABEL[l] for l in labels] if labels else MANIFEST
    out = []
    for m in sets:
        s = import_one(m)
        out.append(s)
        print(f"[{m.label:11}] {m.technique:10} indexed={s.get('count_indexed'):>6}  "
              f"schema={s.get('schema_name')}  ok={s.get('ok')}")
    return out


if __name__ == "__main__":
    import sys
    import_all(sys.argv[1:] or None)
