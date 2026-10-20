"""Sigma-rule migration unit tests -- pure logic, no live ES needed.

Run:  uv run python -m tests.test_sigma
"""
from __future__ import annotations

from detections.sigma_import import migrate

_EVENTID = """
title: Failed Logons
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium
tags: [attack.credential_access, attack.t1110]
"""

_CONTAINS = """
title: Encoded PowerShell
logsource: {product: windows, category: process_creation}
detection:
  selection:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection
level: high
tags: [attack.execution, attack.t1059.001]
"""

_AND_NOT = """
title: Admin logon excluding SYSTEM
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4624
  filter:
    TargetUserName: SYSTEM
  condition: selection and not filter
level: medium
tags: [attack.t1078]
"""

_UNMAPPED = """
title: Weird field
logsource: {product: windows}
detection:
  selection:
    SomeWeirdField: foo
  condition: selection
level: low
"""

_AGG = """
title: Threshold rule
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection | count() > 20
level: high
tags: [attack.t1110]
"""


def test_eventid_rule_maps_and_translates():
    r = migrate(_EVENTID, use_llm=False)
    assert r.status == "migrated", r.notes
    assert r.field_map.get("eventid") == "n_event_id"
    assert "n_event_id:4625" in r.query_string
    assert "T1110" in r.mitre and r.severity == "medium"
    print("ok  test_eventid_rule_maps_and_translates")


def test_contains_list_becomes_wildcard_or():
    r = migrate(_CONTAINS, use_llm=False)
    assert r.status == "migrated", r.notes
    assert "n_cmdline:*" in r.query_string and "enc" in r.query_string
    assert " OR " in r.query_string          # the value list is OR-ed
    assert r.severity == "high" and "T1059.001" in r.mitre
    print("ok  test_contains_list_becomes_wildcard_or")


def test_and_not_condition():
    r = migrate(_AND_NOT, use_llm=False)
    assert r.status == "migrated", r.notes
    assert "AND NOT" in r.query_string
    assert "n_event_id:4624" in r.query_string and 'n_user:"SYSTEM"' in r.query_string
    print("ok  test_and_not_condition")


def test_unmapped_field_is_needs_review():
    r = migrate(_UNMAPPED, use_llm=False)
    assert r.status == "needs_review"
    assert "SomeWeirdField" in r.unmapped
    assert r.query_string is None
    print("ok  test_unmapped_field_is_needs_review")


def test_aggregation_is_needs_review():
    r = migrate(_AGG, use_llm=False)
    assert r.status == "needs_review"
    assert r.query_string is None
    assert any("aggregation" in n for n in r.notes)
    print("ok  test_aggregation_is_needs_review")


def main():
    for fn in [test_eventid_rule_maps_and_translates, test_contains_list_becomes_wildcard_or,
               test_and_not_condition, test_unmapped_field_is_needs_review,
               test_aggregation_is_needs_review]:
        fn()
    print("\nAll Sigma tests passed.")


if __name__ == "__main__":
    main()
