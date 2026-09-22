import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

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



@pytest.mark.asyncio
async def test_rollback_persists_each_action_immediately():
    from config import Settings
    from models import ActionType, AdapterType, BlastRadius, DefensePlan, PlanStatus
    from adapters.base import AdapterResult
    from orchestrator import ResponseOrchestrator

    orch = ResponseOrchestrator(Settings(dry_run_mode=False))
    rollback_adapter = AsyncMock()
    rollback_adapter.rollback.side_effect = [
        AdapterResult(True, "block_ip", "203.0.113.2", "wazuh", "rolled back"),
        AdapterResult(True, "block_ip", "203.0.113.1", "wazuh", "rolled back"),
    ]
    orch._adapters["wazuh"] = rollback_adapter

    actions = [
        PlannedAction(
            action_id="ACT-ROLL-1",
            action_type=ActionType.BLOCK_IP,
            target="203.0.113.1",
            adapter=AdapterType.WAZUH,
            confidence=0.9,
            impact_score=0.8,
            safety_score=0.9,
            composite_score=0.85,
            blast_radius=BlastRadius.LOW,
            approval_tier=2,
            requires_approval=False,
            status=ActionStatus.COMPLETED,
        ),
        PlannedAction(
            action_id="ACT-ROLL-2",
            action_type=ActionType.BLOCK_IP,
            target="203.0.113.2",
            adapter=AdapterType.WAZUH,
            confidence=0.9,
            impact_score=0.8,
            safety_score=0.9,
            composite_score=0.85,
            blast_radius=BlastRadius.LOW,
            approval_tier=2,
            requires_approval=False,
            status=ActionStatus.COMPLETED,
        ),
    ]
    plan = DefensePlan(
        plan_id="PLAN-ROLLBACK-PERSIST",
        incident_id="INC-ROLLBACK-PERSIST",
        status=PlanStatus.VERIFYING,
        actions=actions,
        total_actions=2,
        dry_run=False,
    )

    with patch.object(orch, "_persist_action", new_callable=AsyncMock) as persist:
        result = await orch._rollback_plan(plan)

    assert result is True
    assert [a.status for a in actions] == [ActionStatus.ROLLED_BACK, ActionStatus.ROLLED_BACK]
    assert persist.await_count == 2
    assert persist.await_args_list[0].args[0] is actions[1]
    assert persist.await_args_list[1].args[0] is actions[0]


@pytest.mark.asyncio
async def test_rollback_failure_is_persisted_without_marking_action_rolled_back():
    from config import Settings
    from models import ActionType, AdapterType, BlastRadius, DefensePlan, PlanStatus
    from adapters.base import AdapterResult
    from orchestrator import ResponseOrchestrator

    orch = ResponseOrchestrator(Settings(dry_run_mode=False))
    rollback_adapter = AsyncMock()
    rollback_adapter.rollback.return_value = AdapterResult(
        False, "block_ip", "203.0.113.10", "wazuh",
        "rollback rejected", error="force delete unsupported",
    )
    orch._adapters["wazuh"] = rollback_adapter

    action = PlannedAction(
        action_id="ACT-ROLL-FAIL",
        action_type=ActionType.BLOCK_IP,
        target="203.0.113.10",
        adapter=AdapterType.WAZUH,
        confidence=0.9,
        impact_score=0.8,
        safety_score=0.9,
        composite_score=0.85,
        blast_radius=BlastRadius.LOW,
        approval_tier=2,
        requires_approval=False,
        status=ActionStatus.COMPLETED,
    )
    plan = DefensePlan(
        plan_id="PLAN-ROLLBACK-FAIL-PERSIST",
        incident_id="INC-ROLLBACK-FAIL-PERSIST",
        status=PlanStatus.VERIFYING,
        actions=[action],
        total_actions=1,
        dry_run=False,
    )

    with patch.object(orch, "_persist_action", new_callable=AsyncMock) as persist:
        result = await orch._rollback_plan(plan)

    assert result is False
    assert action.status == ActionStatus.COMPLETED
    assert action.error_message == "Rollback failed: force delete unsupported"
    persist.assert_awaited_once_with(action)
