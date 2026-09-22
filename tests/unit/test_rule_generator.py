import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parents[2] / "services" / "rule-generator"
sys.path.insert(0, str(SERVICE_DIR))

from main import _validate_sigma_rule


def test_validate_sigma_rule_accepts_standard_structure():
    rule = """---
title: Successful Login During Non-Business Hours
status: experimental
description: Detects successful logins during non-business hours.
logsource:
  category: authentication
  product: linux
  service: sshd
detection:
  selection:
    event_type: login
    user: kali
  condition: selection
falsepositives:
  - Expected administrative activity
level: high
tags:
  - attack.t1078
"""
    valid, error = _validate_sigma_rule(rule)
    assert valid, error


def test_validate_sigma_rule_rejects_pseudo_sigma():
    rule = """---
title: Invalid Login Rule
status: experimental
description: Invalid detection syntax.
logsource:
  category: login
  product: network
  service: authentication
detection:
  selection:
    - user == "kali"
    - event_type == "login"
  condition: any
falsepositives:
  - None
level: high
tags:
  - T1078
"""
    valid, error = _validate_sigma_rule(rule)
    assert not valid
    assert "tag" in error.lower() or "selection" in error.lower() or "condition" in error.lower()


def test_validate_sigma_rule_rejects_undefined_condition_selection():
    rule = """---
title: Undefined Selection Rule
status: experimental
description: Condition references a selection that does not exist.
logsource:
  category: authentication
  product: linux
  service: sshd
detection:
  selection:
    event_type: login
    user: kali
  condition: selection and filter
falsepositives:
  - Expected administrative activity
level: high
tags:
  - attack.t1078
"""
    valid, error = _validate_sigma_rule(rule)
    assert not valid
    assert "undefined detection selection" in error.lower()


def test_ensure_sigma_condition_adds_condition_for_single_selection():
    from main import _ensure_sigma_condition

    rule = """---
title: Single Selection
status: experimental
logsource:
  category: authentication
detection:
  selection:
    user: kali
level: high
tags:
  - attack.t1078
"""
    normalized = _ensure_sigma_condition(rule)
    valid, error = _validate_sigma_rule(normalized)
    assert valid, error
    assert "condition: selection" in normalized


def test_normalize_generated_sigma_removes_unsupported_temporal_evidence_and_tags():
    from main import RuleGenerationRequest, _normalize_generated_sigma

    request = RuleGenerationRequest(
        alert_id="test-alert",
        alert_description="Successful login during non-business hours.",
        raw_log="Successful login from 192.168.100.140 using user kali during non-business hours",
        source_ip="192.168.100.140",
        mitre_techniques=["T1078"],
        severity="high",
    )
    rule = """---
title: Test Rule
status: experimental
logsource:
  category: authentication
detection:
  selection:
    user: kali
    hours: 20-23
  condition: selection
evidence: invented
level: high
tags:
  - attack.T1078
  - attack.T1210
"""
    normalized = _normalize_generated_sigma(rule, request)
    assert "hours:" not in normalized
    assert "evidence:" not in normalized
    assert "condition: selection" in normalized
    assert "attack.t1078" in normalized
    assert "attack.T1210" not in normalized
    assert "condition:" not in normalized.split("detection:", 1)[0]


def test_normalize_generated_sigma_repairs_scalar_falsepositives_and_invalid_temporal_yaml():
    from main import RuleGenerationRequest, _normalize_generated_sigma, _validate_sigma_rule

    request = RuleGenerationRequest(
        alert_id="test-alert-2",
        alert_description="Login anomaly.",
        raw_log="Successful login from 192.168.100.140 using user kali",
        source_ip="192.168.100.140",
        mitre_techniques=["T1078"],
        severity="high",
    )
    rule = """---
title: Test Rule
status: experimental
logsource:
  category: authentication
detection:
  selection:
    user: kali
    hour: !date-now %H
    event_type: login
  condition: selection
falsepositives: Known admin activity
level: high
tags:
  - attack.T1078
"""
    normalized = _normalize_generated_sigma(rule, request)
    valid, error = _validate_sigma_rule(normalized)
    assert valid, error
    assert "hour:" not in normalized
    assert "falsepositives:" in normalized
