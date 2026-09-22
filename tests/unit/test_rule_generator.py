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
