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
    assert not _all_actions_resolved(
        [make_action(ActionStatus.PENDING)]
    )


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
async def test_verification_failure_without_rollback_marks_plan_failed():
    from config import Settings
    from models import DefensePlan, PlanStatus, VerificationResult
    from orchestrator import ResponseOrchestrator

    settings = Settings(auto_rollback_on_verification_failure=False)
    orch = ResponseOrchestrator(settings)

    now = datetime.utcnow()
    plan = DefensePlan(
        plan_id="PLAN-VERIFY-NO-ROLLBACK",
        incident_id="INC-VERIFY-NO-ROLLBACK",
        status=PlanStatus.VERIFYING,
        created_at=now,
        updated_at=now,
        pre_defense_risk=0.8,
    )
    verification = VerificationResult(
        plan_id=plan.plan_id,
        pre_attack_success_rate=0.8,
        post_attack_success_rate=0.8,
        risk_reduction_pct=0.0,
        verification_passed=False,
        verdict_reason="Re-simulation was unavailable; result not treated as evidence.",
    )

    with patch.object(
        orch.verifier, "verify_plan", new_callable=AsyncMock, return_value=verification
    ), patch.object(
        orch, "_record_outcome", new_callable=AsyncMock
    ) as mock_record, patch.object(
        orch, "_persist_plan", new_callable=AsyncMock
    ) as mock_persist, patch.object(
        orch, "_rollback_plan", new_callable=AsyncMock
    ) as mock_rollback:
        await orch._verify_and_complete(plan)

    assert plan.verification is verification
    assert plan.status == PlanStatus.FAILED
    assert plan.completed_at is not None
    mock_rollback.assert_not_awaited()
    mock_record.assert_awaited_once_with(plan)
    mock_persist.assert_awaited_once_with(plan)


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


@pytest.mark.asyncio
async def test_persist_plan_reraises_production_database_errors():
    from config import Settings
    from models import DefensePlan
    from orchestrator import ResponseOrchestrator

    orch = ResponseOrchestrator(Settings())
    plan = DefensePlan(
        plan_id="PLAN-PERSIST-FAIL",
        incident_id="INC-PERSIST-FAIL",
    )

    class FailingDbSession:
        async def __aenter__(self):
            raise RuntimeError("database connection lost")

        async def __aexit__(self, exc_type, exc, tb):
            return False

    with patch("orchestrator.db_session", return_value=FailingDbSession()):
        with pytest.raises(RuntimeError, match="database connection lost"):
            await orch._persist_plan(plan)


@pytest.mark.asyncio
async def test_persist_plan_keeps_uninitialized_pool_test_fallback():
    from config import Settings
    from models import DefensePlan
    from orchestrator import ResponseOrchestrator

    orch = ResponseOrchestrator(Settings())
    plan = DefensePlan(
        plan_id="PLAN-PERSIST-NO-POOL",
        incident_id="INC-PERSIST-NO-POOL",
    )

    class UninitializedDbSession:
        async def __aenter__(self):
            raise RuntimeError("Database pool has not been initialised")

        async def __aexit__(self, exc_type, exc, tb):
            return False

    with patch("orchestrator.db_session", return_value=UninitializedDbSession()):
        await orch._persist_plan(plan)


@pytest.mark.asyncio
async def test_verification_tracks_run_concurrently():
    import asyncio
    from models import DefensePlan
    from verification import VerificationEngine

    engine = VerificationEngine(monitoring_duration_seconds=0)
    plan = DefensePlan(plan_id="PLAN-CONCURRENT", incident_id="INC-CONCURRENT")
    both_started = asyncio.Event()
    started = 0

    async def fake_resimulation(*args, **kwargs):
        nonlocal started
        started += 1
        if started == 2:
            both_started.set()
        await asyncio.wait_for(both_started.wait(), timeout=0.5)
        return {"simulation_id": "SIM-CONCURRENT", "pre_success_rate": 0.8, "post_success_rate": 0.4}

    async def fake_monitoring(*args, **kwargs):
        nonlocal started
        started += 1
        if started == 2:
            both_started.set()
        await asyncio.wait_for(both_started.wait(), timeout=0.5)
        return {"continued_indicators": False, "new_alerts": 0, "duration": 0}

    with (
        patch.object(engine, "_track_resimulation", side_effect=fake_resimulation),
        patch.object(engine, "_track_monitoring", side_effect=fake_monitoring),
    ):
        result = await engine.verify_plan(plan)

    assert result.verification_passed is True


@pytest.mark.asyncio
async def test_resimulation_uses_configured_timeout():
    from models import DefensePlan
    from verification import VerificationEngine

    engine = VerificationEngine(simulation_timeout_seconds=7)
    plan = DefensePlan(
        plan_id="PLAN-TIMEOUT-CONFIG",
        incident_id="INC-TIMEOUT-CONFIG",
        pre_defense_risk=0.8,
    )

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "simulation_id": "SIM-TIMEOUT-CONFIG",
                "results_summary": {"success_rate": 0.4},
            }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            assert kwargs["timeout"] == 7
            return FakeResponse()

    with patch("verification.httpx.AsyncClient", return_value=FakeClient()):
        result = await engine._track_resimulation(plan, None)

    assert result["simulation_id"] == "SIM-TIMEOUT-CONFIG"
    assert result["post_success_rate"] == 0.4
