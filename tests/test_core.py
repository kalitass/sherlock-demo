"""Self-contained tests for the pure logic (no live ES needed).

Run:  uv run python -m tests.test_core
"""
from __future__ import annotations

from ingestion.parsing import parse_record, normalise_ts
from ingestion import schema_registry as reg
from hunt_engine.evidence_ledger import EvidenceLedger
from hunt_engine.verifier import verify_findings
from hunt_engine.reduce import reduce_verdict
from common import providers as prov
from common import schemas as sch
from ingestion.schema_drift import observed_fields, check_drift


# --- parsing ---------------------------------------------------------------
def test_parse_json():
    schema = {"parser": {"kind": "json"}, "ts_field": "@timestamp", "ts_format": "auto", "log_type": "windows"}
    doc = parse_record(schema, {"@timestamp": "2026-09-15T02:11:00.000Z", "event_id": 4625})
    assert doc and doc["log_type"] == "windows" and doc["event_id"] == 4625 and doc["@timestamp"].endswith("Z")
    print("ok  test_parse_json")


def test_parse_clf():
    from ingestion.auto_schema import CLF_PATTERN
    schema = {"parser": {"kind": "regex", "pattern": CLF_PATTERN}, "ts_field": "timestamp",
              "ts_format": "clf", "log_type": "web"}
    line = '203.0.113.66 - - [15/Sep/2026:02:14:03 +0000] "POST /uploads/x.php HTTP/1.1" 200 512 "-" "curl"'
    doc = parse_record(schema, line)
    assert doc and doc["client_ip"] == "203.0.113.66" and doc["method"] == "POST" and doc["status"] == 200
    print("ok  test_parse_clf")


def test_parse_clf_rejects_partial_line():
    # A regex that only matches a prefix must NOT be accepted (fullmatch).
    from ingestion.auto_schema import CLF_PATTERN
    schema = {"parser": {"kind": "regex", "pattern": CLF_PATTERN}, "ts_field": "timestamp",
              "ts_format": "clf", "log_type": "web"}
    assert parse_record(schema, "garbage that is not a clf line") is None
    print("ok  test_parse_clf_rejects_partial_line")


def test_clf_timestamp():
    ts = normalise_ts("15/Sep/2026:02:14:03 +0000", "clf")
    assert ts and ts.startswith("2026-09-15T02:14:03")
    print("ok  test_clf_timestamp")


def test_epoch_timestamp():
    assert (normalise_ts(1757900000, "epoch") or "").startswith("2025-")
    assert (normalise_ts(1757900000000, "epoch_ms") or "").startswith("2025-")
    print("ok  test_epoch_timestamp")


def test_fingerprint_reuse():
    a = reg.fingerprint([{"a": 1, "b": 2}], "win")
    b = reg.fingerprint([{"b": 9, "a": 8}], "win")           # same keys+types+log_type
    c = reg.fingerprint([{"a": 1, "c": 3}], "win")           # different keys
    d = reg.fingerprint([{"a": 1, "b": 2}], "web")           # different log_type
    assert a == b and a != c and a != d
    print("ok  test_fingerprint_reuse")


# --- evidence ledger + verifier -------------------------------------------
def _led():
    return EvidenceLedger("t", persist=False)


def _q(matched):  # a query-tool success envelope
    return {"ok": True, "tool": "count_logs", "matched_documents": matched, "count": matched,
            "es_request": {"index": "sherlock-logs-windows", "body": {}}}


def _q_unknown():  # ok, but no match count (e.g. malformed/transport-recovered)
    return {"ok": True, "tool": "count_logs", "es_request": {"index": "sherlock-logs-windows", "body": {}}}


def _q_failed():
    return {"ok": False, "tool": "count_logs", "error": "boom"}


def test_ledger_metrics():
    led = _led()
    e_ctx = led.record("list_log_types", {}, {"ok": True, "tool": "list_log_types",
                                              "log_types": [{"log_type": "win", "count": 0}]})
    e_q = led.record("count_logs", {}, _q(7))
    e_stats = led.record("aggregate", {}, {"ok": True, "tool": "aggregate", "agg_type": "stats",
                                           "matched_documents": 7, "metric_value": 7, "result": {"count": 7}})
    assert e_ctx.is_query_tool is False           # context tool cannot support a claim
    assert e_q.is_query_tool and e_q.matched_documents == 7
    assert e_stats.matched_documents == 7         # stats no longer collapses to 0
    print("ok  test_ledger_metrics")


def test_verifier_contract():
    led = _led()
    led.record("count_logs", {}, _q(5))                                  # E1 supported
    led.record("count_logs", {}, _q(0))                                  # E2 zero matches
    led.record("list_log_types", {}, {"ok": True, "tool": "list_log_types",
                                      "log_types": [{"log_type": "win", "count": 3}]})  # E3 context
    led.record("count_logs", {}, _q_failed())                            # E4 failed
    findings = [
        {"claim": "supported", "evidence_ids": ["E1"]},                  # keep
        {"claim": "empty", "evidence_ids": ["E2"]},                      # reject: wrong direction
        {"claim": "context only", "evidence_ids": ["E3"]},              # reject: not a query tool
        {"claim": "failed query", "evidence_ids": ["E4"]},             # reject: query failed
        {"claim": "hallucinated", "evidence_ids": ["E99"]},            # reject: no such id
        {"claim": "uncited", "evidence_ids": []},                      # reject: no evidence
        {"claim": "no C2 was present", "evidence_ids": ["E2"], "role": "negative"},  # negative + zero -> keep
    ]
    out = verify_findings(findings, led)
    kept = {f["claim"] for f in out["verified_findings"]}
    assert kept == {"supported", "no C2 was present"}, kept
    reasons = " ".join(f["reject_reason"] for f in out["rejected_findings"])
    assert all(w in reasons for w in ("hallucinated", "direction", "context", "failed")), reasons
    print("ok  test_verifier_contract")


def test_verifier_multistage_requires_all_citations():
    led = _led()
    led.record("count_logs", {}, _q(1))          # E1 ok, matched
    led.record("count_logs", {}, _q_failed())    # E2 failed
    out = verify_findings([{"claim": "created AND added", "evidence_ids": ["E1", "E2"]}], led)
    assert out["n_verified"] == 0, "a multi-stage claim must fail if any cited query failed"
    print("ok  test_verifier_multistage_requires_all_citations")


def test_verifier_unknown_match_is_not_zero():
    led = _led()
    led.record("count_logs", {}, _q_unknown())   # E1 ok but match count unknown
    out = verify_findings([{"claim": "no activity present", "evidence_ids": ["E1"]}], led)  # negative
    assert out["n_verified"] == 0, "unknown match count must not be treated as a zero-match absence"
    print("ok  test_verifier_unknown_match_is_not_zero")


# --- verdict reducer -------------------------------------------------------
def test_reduce_all_rejected_is_not_confirmed():
    led = _led()
    led.record("count_logs", {}, _q(0))
    ver = verify_findings([{"claim": "x", "evidence_ids": ["E1"]}], led)   # rejected (zero)
    cov = {"complete": True, "sources_searched": ["windows"]}
    out = reduce_verdict("confirmed", "confirmed", ver, cov, led)
    assert out["verdict"] != "confirmed", out
    print("ok  test_reduce_all_rejected_is_not_confirmed")


def test_reduce_tool_error_is_inconclusive():
    led = _led()
    led.record("count_logs", {}, {"ok": False, "tool": "count_logs", "error": "mapping"})
    ver = verify_findings([], led)
    cov = {"complete": False, "sources_searched": []}
    out = reduce_verdict("refuted", "refuted", ver, cov, led)
    assert out["verdict"] == "inconclusive", out          # a failed query must not refute
    print("ok  test_reduce_tool_error_is_inconclusive")


def test_reduce_direction_from_supports():
    # The verdict follows `supports_hypothesis` -- the enumerable field the LLM sets
    # after reading the hypothesis -- NOT the claim's grammar (`role`) and NOT a
    # keyword flip. Same verified positive-role evidence, opposite argued direction.
    led = _led()
    led.record("count_logs", {}, _q(10))
    cov = {"complete": True, "sources_searched": ["web"]}
    for_hyp = verify_findings([{"claim": "web shell present", "evidence_ids": ["E1"],
                                "role": "positive", "supports_hypothesis": True}], led)
    against_hyp = verify_findings([{"claim": "web shell present", "evidence_ids": ["E1"],
                                    "role": "positive", "supports_hypothesis": False}], led)
    confirmed = reduce_verdict("a web shell was used", "confirmed", for_hyp, cov, led)
    assert confirmed["verdict"] == "confirmed", confirmed
    # A verified finding that argues AGAINST the stated hypothesis refutes it.
    refuted = reduce_verdict("there was no web shell", "confirmed", against_hyp, cov, led)
    assert refuted["verdict"] == "refuted", refuted
    print("ok  test_reduce_direction_from_supports")


def test_reduce_uncovered_is_inconclusive():
    led = _led()
    ver = verify_findings([], led)
    cov = {"complete": True, "sources_searched": ["windows", "web", "sysmon"]}
    out = reduce_verdict("ransomware last night", "inconclusive", ver, cov, led, hypothesis_covered=False)
    assert out["verdict"] == "inconclusive", out
    print("ok  test_reduce_uncovered_is_inconclusive")


def test_reduce_no_findings_is_not_refuted():
    # No verified findings must NOT be read as proof of absence.
    led = _led()
    led.record("count_logs", {}, _q(5))                 # a query ran, but nothing cited it
    ver = verify_findings([], led)
    cov = {"complete": True, "sources_searched": ["windows", "web", "sysmon"]}
    out = reduce_verdict("a web shell was used", "refuted", ver, cov, led)
    assert out["verdict"] == "inconclusive", out
    print("ok  test_reduce_no_findings_is_not_refuted")


def test_reduce_verified_absence_refutes():
    led = _led()
    led.record("count_logs", {}, _q(0))                 # E1 ran, zero matches
    ver = verify_findings([{"claim": "no web shell present", "evidence_ids": ["E1"], "role": "negative"}], led)
    assert ver["n_verified"] == 1
    cov = {"complete": True, "sources_searched": ["web"]}
    out = reduce_verdict("a web shell was used", "refuted", ver, cov, led)
    assert out["verdict"] == "refuted", out             # backed by a real zero-match query
    print("ok  test_reduce_verified_absence_refutes")


# --- provider compatibility layer -----------------------------------------
def _clear_llm_env(monkeypatch=None):
    import os
    for k in list(os.environ):
        if k.endswith("_API_KEY") or k.startswith("SHERLOCK_LLM") or k in ("OPENAI_BASE_URL",):
            os.environ.pop(k, None)


def test_provider_resolves_known_aliases():
    _clear_llm_env()
    import os
    # groq -> openai family, its endpoint + default model, reads GROQ_API_KEY
    os.environ["SHERLOCK_LLM_PROVIDER"] = "groq"
    os.environ["GROQ_API_KEY"] = "gsk_test"
    r = prov.resolve_provider()
    assert r.family == "openai" and "groq.com" in r.base_url and r.available
    assert r.model == "llama-3.3-70b-versatile"            # preset default
    # explicit model + base_url override the preset
    os.environ["SHERLOCK_LLM_MODEL"] = "mixtral"
    os.environ["SHERLOCK_LLM_BASE_URL"] = "http://proxy/v1"
    r2 = prov.resolve_provider()
    assert r2.model == "mixtral" and r2.base_url == "http://proxy/v1"
    _clear_llm_env()
    print("ok  test_provider_resolves_known_aliases")


def test_litellm_route_and_engine_selection():
    _clear_llm_env()
    import os
    os.environ["SHERLOCK_LLM_PROVIDER"] = "groq"
    os.environ["GROQ_API_KEY"] = "gsk_test"
    # force the LiteLLM engine: route is provider-qualified, adapter is LiteLLM
    os.environ["SHERLOCK_LLM_ENGINE"] = "litellm"
    r = prov.resolve_provider()
    assert r.engine == "litellm" and r.route == "groq/llama-3.3-70b-versatile"
    assert isinstance(r.adapter, prov.LiteLLMAdapter)
    # force native: hand-rolled adapter, no route, uses base_url
    os.environ["SHERLOCK_LLM_ENGINE"] = "native"
    r2 = prov.resolve_provider()
    assert r2.engine == "native" and r2.route == "" and isinstance(r2.adapter, prov.OpenAIAdapter)
    _clear_llm_env()
    print("ok  test_litellm_route_and_engine_selection")


def test_provider_local_is_keyless():
    _clear_llm_env()
    import os
    os.environ["SHERLOCK_LLM_PROVIDER"] = "ollama"
    r = prov.resolve_provider()
    assert r.family == "openai" and "11434" in r.base_url and r.available  # no key needed
    _clear_llm_env()
    print("ok  test_provider_local_is_keyless")


def test_provider_unknown_falls_back_openai():
    _clear_llm_env()
    import os
    os.environ["SHERLOCK_LLM_PROVIDER"] = "some-new-vendor"
    r = prov.resolve_provider()
    assert r.family == "openai" and not r.available and "unknown provider" in r.note
    _clear_llm_env()
    print("ok  test_provider_unknown_falls_back_openai")


def test_provider_registry_is_extensible():
    # Registering a brand-new family needs no change to the engine. A custom family
    # is served by its own adapter via the native engine (LiteLLM can't route it).
    _clear_llm_env()

    @prov.register
    class _DummyAdapter(prov.ProviderAdapter):
        family = "dummy-test"

        def complete(self, model, system, user, temperature, max_tokens):
            return "ok"

        def tool_loop(self, model, system, user, tools, max_turns, temperature,
                      max_tokens, on_event, dispatch):
            return "ok"

    prov.PRESETS["dummy-test"] = prov.Preset("dummy-test", ("DUMMY_API_KEY",),
                                             default_model="d1", local_key="x")
    r = prov.resolve_provider("dummy-test")
    assert r.family == "dummy-test" and r.engine == "native"
    assert isinstance(r.adapter, _DummyAdapter) and r.available
    del prov.PRESETS["dummy-test"]
    print("ok  test_provider_registry_is_extensible")


def test_hunt_falls_back_to_deterministic_on_llm_error(monkeypatch=None):
    # If the LLM engine raises mid-hunt, run_hunt must degrade to the deterministic
    # engine and label it — never crash. We stub the pieces so no ES/network is used.
    import hunt_engine.hunt as H

    class _FakeLedger:
        persist_errors = 0

        def __init__(self, *a, **k):
            pass

        def as_list(self):
            return []

    class _FakeClient:
        backend_name = "direct"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def list_tools(self):
            return []

    calls = {"heur": 0}

    def _boom(*a, **k):
        raise RuntimeError("provider down")

    def _heur(hypothesis, client, ledger, on_event):
        calls["heur"] += 1
        return {"verdict": "inconclusive", "confidence": 0.0, "summary": "s",
                "findings": [], "coverage": {}, "engine": "heuristic"}

    saved = (H.run_llm_hunt, H.run_heuristic_hunt, H.EvidenceLedger, H.MCPClient,
             H.ensure_state_indices, H.verify_findings, H.compute_coverage,
             H.reduce_verdict, H.build_report, H._persist_hunt, H._write_report)
    try:
        H.run_llm_hunt = _boom
        H.run_heuristic_hunt = _heur
        H.EvidenceLedger = _FakeLedger
        H.MCPClient = lambda *a, **k: _FakeClient()
        H.ensure_state_indices = lambda: None
        H.verify_findings = lambda f, l: {"verified_findings": [], "rejected_findings": [],
                                          "verification_rate": 1.0, "n_verified": 0}
        H.compute_coverage = lambda l, c: {"complete": True, "sources_searched": []}
        H.reduce_verdict = lambda *a, **k: {"verdict": "inconclusive", "confidence": 0.0,
                                            "summary": "s", "hypothesis_polarity": "affirmative"}
        H.build_report = lambda *a, **k: "report"
        H._persist_hunt = lambda b: None
        H._write_report = lambda *a, **k: None
        out = H.run_hunt("any hypothesis", use_llm=True, persist=False)
    finally:
        (H.run_llm_hunt, H.run_heuristic_hunt, H.EvidenceLedger, H.MCPClient,
         H.ensure_state_indices, H.verify_findings, H.compute_coverage,
         H.reduce_verdict, H.build_report, H._persist_hunt, H._write_report) = saved

    assert calls["heur"] == 1, "deterministic engine must run as fallback"
    assert out["meta"]["engine_fallback"] and "provider down" in out["meta"]["engine_fallback"]
    print("ok  test_hunt_falls_back_to_deterministic_on_llm_error")


# --- SIEM schema compatibility + normalisation (Week 2) --------------------
def test_cef_leef_parse():
    from ingestion.parsing import _parse_cef, _parse_leef, parse_record
    cef = _parse_cef("CEF:0|Vend|Prod|1.0|4625|An account failed to log on|7|"
                     "rt=2026-09-15T02:11:00Z dvchost=WIN-APP01 duser=administrator "
                     "src=203.0.113.66 outcome=Failure msg=bad password supplied")
    assert cef and cef["cef_sig_id"] == "4625" and cef["duser"] == "administrator"
    assert cef["outcome"] == "Failure" and cef["name"] == "An account failed to log on"
    assert cef["msg"] == "bad password supplied"            # spaces in an extension value survive
    # syslog prefix is tolerated
    assert _parse_cef("<13>Sep 15 host CEF:0|V|P|1|100|n|3|src=1.1.1.1")["src"] == "1.1.1.1"
    # LEEF 2.0 with an explicit tab delimiter header (x09)
    leef = _parse_leef("LEEF:2.0|Vend|Prod|1.0|4625|x09|devTime=2026-09-15T02:11:00Z\t"
                       "resource=WIN-APP01\tusrName=administrator\tsrc=203.0.113.66\tcat=Failed")
    assert leef and leef["EventID"] == "4625" and leef["usrName"] == "administrator" and leef["cat"] == "Failed"
    # CEF with only `rt` (no `start`) still parses via the ts_fallback
    spec = {"parser": {"kind": "cef"}, "ts_field": "start", "ts_fallback": "rt",
            "ts_format": "auto", "log_type": "cef"}
    doc = parse_record(spec, "CEF:0|V|P|1|4625|login|7|rt=1789437600000 src=1.2.3.4")
    assert doc and doc["@timestamp"].startswith("20") and doc["src"] == "1.2.3.4"
    print("ok  test_cef_leef_parse")


def test_schema_detection():
    assert sch.detect_schema("CEF:0|a|b|c|d|e|1|src=1.1.1.1") == "cef"
    assert sch.detect_schema("LEEF:2.0|a|b|c|100|x09|src=1.1.1.1") == "leef"
    assert sch.detect_schema({"@timestamp": "t", "event.code": "4625", "source.ip": "1.1.1.1"}) == "ecs"
    assert sch.detect_schema({"metadata.event_code": "4625", "src_endpoint.ip": "1.1.1.1", "class_uid": 3002}) == "ocsf"
    assert sch.detect_schema({"metadata.event_timestamp": "t", "principal.ip": "1.1.1.1", "target.user.userid": "x"}) == "udm"
    assert sch.detect_schema({"TimeGenerated": "t", "SrcIpAddr": "1.1.1.1", "TargetUsername": "x"}) == "asim"
    assert sch.detect_schema({"_time": "t", "signature_id": "4625", "action": "failure"}) == "cim"
    assert sch.detect_schema({"totally": "unknown"}) is None
    print("ok  test_schema_detection")


def test_norm_action_exact_match():
    # EXACT match only — a substring match would misread these (codex finding).
    assert sch._norm_action("Failed") == "failure" and sch._norm_action("FAILURE") == "failure"
    assert sch._norm_action("Success") == "success" and sch._norm_action("ALLOW") == "success"
    assert sch._norm_action("not allowed") == "not allowed"      # NOT success
    assert sch._norm_action("passcode required") == "passcode required"   # NOT success
    print("ok  test_norm_action_exact_match")


def test_normalise_all_seven_agree():
    # One logon-failure event, rendered in each schema with its REAL field names,
    # must normalise to the SAME canonical fields -> one detection fires across all
    # seven. @timestamp is present (parse_record sets it), so n_time must survive too.
    recs = {
        "cef": {"@timestamp": "T", "cef_sig_id": "4625", "dvchost": "H", "duser": "administrator",
                "src": "203.0.113.66", "outcome": "Failure"},
        "leef": {"@timestamp": "T", "EventID": "4625", "resource": "H", "usrName": "administrator",
                 "src": "203.0.113.66", "cat": "Failed"},
        "cim": {"@timestamp": "T", "signature_id": "4625", "dest": "H", "user": "administrator",
                "src": "203.0.113.66", "action": "failure"},
        "ecs": {"@timestamp": "T", "event.code": "4625", "host.name": "H", "user.name": "administrator",
                "source.ip": "203.0.113.66", "event.outcome": "failure"},
        "ocsf": {"@timestamp": "T", "metadata.event_code": "4625", "dst_endpoint.hostname": "H",
                 "user.name": "administrator", "src_endpoint.ip": "203.0.113.66", "status": "Failure"},
        "asim": {"@timestamp": "T", "EventOriginalType": "4625", "TargetHostname": "H",
                 "TargetUsername": "administrator", "SrcIpAddr": "203.0.113.66", "EventResult": "Failure"},
        "udm": {"@timestamp": "T", "metadata.product_event_type": "4625", "target.hostname": "H",
                "target.user.userid": "administrator", "principal.ip": "203.0.113.66",
                "extensions.auth.outcome": "FAILURE"},
    }
    want = {"n_event_id": "4625", "n_user": "administrator", "n_src_ip": "203.0.113.66",
            "n_action": "failure", "n_time": "T", "n_host": "H"}
    for schema, rec in recs.items():
        out = sch.normalise(rec, schema)
        for k, v in want.items():
            assert out.get(k) == v, f"{schema}: {k}={out.get(k)} != {v}"
        assert out["n_schema"] == schema
    print("ok  test_normalise_all_seven_agree")


def test_normalise_nested_json_and_severity():
    # get_path handles truly-nested JSON (not just flat dotted keys), and severity
    # is normalised per-schema to one vocabulary.
    nested = {"@timestamp": "T", "event": {"code": "4625", "outcome": "failure", "severity": 7},
              "source": {"ip": "1.2.3.4"}, "user": {"name": "admin"}, "host": {"name": "H"}}
    out = sch.normalise(nested, "ecs")
    assert out["n_event_id"] == "4625" and out["n_src_ip"] == "1.2.3.4" and out["n_user"] == "admin"
    assert out["n_action"] == "failure" and out["n_severity"] == "high"       # 7 -> high (0-10 band)
    assert sch._norm_severity(3, "ocsf") == "medium" and sch._norm_severity("High", "asim") == "high"
    print("ok  test_normalise_nested_json_and_severity")


def test_schema_drift_detection():
    base = [{"duser": "x", "src": "1.1.1.1", "act": "failure"}]
    assert observed_fields(base) == {"duser": "str", "src": "str", "act": "str"}
    # a drifted batch (duser renamed to suser, act dropped) vs a stored contract
    import ingestion.schema_drift as sd
    saved_get, saved_put = sd._get, sd._put
    store = {"log_type": "t", "contract": {"duser": "str", "src": "str", "act": "str"}}
    try:
        sd._get = lambda lt: dict(store)
        sd._put = lambda doc: None
        out = sd.check_drift("t", [{"suser": "x", "src": "1.1.1.1"}])
        assert out["status"] == "drift"
        assert "duser" in out["missing"] and "act" in out["missing"] and "suser" in out["added"]
    finally:
        sd._get, sd._put = saved_get, saved_put
    print("ok  test_schema_drift_detection")


def main():
    for fn in [test_parse_json, test_parse_clf, test_parse_clf_rejects_partial_line, test_clf_timestamp,
               test_epoch_timestamp, test_fingerprint_reuse, test_ledger_metrics, test_verifier_contract,
               test_verifier_multistage_requires_all_citations, test_verifier_unknown_match_is_not_zero,
               test_reduce_all_rejected_is_not_confirmed, test_reduce_tool_error_is_inconclusive,
               test_reduce_direction_from_supports, test_reduce_uncovered_is_inconclusive,
               test_reduce_no_findings_is_not_refuted, test_reduce_verified_absence_refutes,
               test_provider_resolves_known_aliases, test_litellm_route_and_engine_selection,
               test_provider_local_is_keyless, test_provider_unknown_falls_back_openai,
               test_provider_registry_is_extensible,
               test_hunt_falls_back_to_deterministic_on_llm_error,
               test_cef_leef_parse, test_schema_detection, test_norm_action_exact_match,
               test_normalise_all_seven_agree, test_normalise_nested_json_and_severity,
               test_schema_drift_detection]:
        fn()
    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
