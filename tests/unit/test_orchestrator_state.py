import sys
from pathlib import Path

import pytest


ORCHESTRATOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "response-orchestrator"
)
sys.path.insert(0, str(ORCHESTRATOR_DIR))

from models import ActionStatus, PlannedAction  # noqa: E402
from orchestrator import _all_actions_resolved  # noqa: E402


def make_action(status: ActionStatus) -> PlannedAction:
    return PlannedAction.model_construct(status=status)


def test_empty_action_list_is_not_resolved():
    assert not _all_actions_resolved([])


def test_pending_action_keeps_plan_non_terminal():
    assert not _all_actions_resolved([make_action(ActionStatus.PENDING)])


@pytest.mark.parametrize(
    "status",
    [
        ActionStatus.COMPLETED,
        ActionStatus.FAILED,
        ActionStatus.SKIPPED,
        ActionStatus.VETOED,
        ActionStatus.ROLLED_BACK,
    ],
)
def test_terminal_action_status_is_resolved(status):
    assert _all_actions_resolved([make_action(status)])


def test_mixed_terminal_actions_are_resolved():
    actions = [
        make_action(ActionStatus.COMPLETED),
        make_action(ActionStatus.FAILED),
        make_action(ActionStatus.VETOED),
    ]
    assert _all_actions_resolved(actions)
