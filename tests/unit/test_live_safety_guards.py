import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


ORCHESTRATOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "response-orchestrator"
)
sys.path.insert(0, str(ORCHESTRATOR_DIR))


@pytest.mark.asyncio
async def test_health_probe_uses_configured_wazuh_tls_setting():
    import main

    main.settings.wazuh_api_verify_ssl = False
    main.orchestrator = MagicMock()

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    response = MagicMock(status_code=401)
    client.get = AsyncMock(return_value=response)

    with (
        patch.object(main, "check_db_health", new=AsyncMock(return_value=True)),
        patch.object(main.httpx, "AsyncClient", return_value=client) as mock_async_client,
        patch.object(main.orchestrator, "get_all_plans", new=AsyncMock(return_value=[])),
    ):
        result = await main.health_check()

    assert result.wazuh_reachable is True
    assert result.status == "healthy"
    mock_async_client.assert_called_once_with(verify=False)


@pytest.mark.asyncio
async def test_health_probe_marks_wazuh_healthy_on_unauthorized_response():
    import main

    main.settings.wazuh_api_verify_ssl = False
    main.orchestrator = MagicMock()

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    responses = {
        f"{main.settings.correlation_engine_url}/health": MagicMock(status_code=200),
        f"{main.settings.ollama_host}/api/tags": MagicMock(status_code=200),
        f"{main.settings.wazuh_api_url}/": MagicMock(status_code=401),
    }

    async def fake_get(url, **kwargs):
        return responses[url]

    client.get = fake_get

    with patch.object(main, "check_db_health", new=AsyncMock(return_value=True)),          patch.object(main.httpx, "AsyncClient", return_value=client),          patch.object(main.orchestrator, "get_all_plans", new=AsyncMock(return_value=[])):

        result = await main.health_check()

    assert result.wazuh_reachable is True


@pytest.mark.asyncio
async def test_trigger_defense_marks_zero_action_plan_failed():
    from config import Settings
    from models import DefensePlan, PlanStatus
    from orchestrator import ResponseOrchestrator

    orch = ResponseOrchestrator(Settings())
    empty_plan = DefensePlan(
        plan_id="PLAN-NO-ACTIONS",
        incident_id="INC-NO-ACTIONS",
        actions=[],
        total_actions=0,
    )

    with patch.object(
        orch,
        "_count_active_plans",
        new=AsyncMock(return_value=0),
    ), patch.object(
        orch,
        "_fetch_incident",
        new=AsyncMock(
            return_value={
                "incident_id": "INC-NO-ACTIONS",
                "mitre_techniques": ["T1110"],
                "kill_chain_stage": "credential_access",
                "source_ips": ["203.0.113.42"],
                "dest_ips": ["10.0.0.10"],
                "summary": "No-action planner test",
            }
        ),
    ), patch.object(
        orch.planner,
        "generate_plan",
        new=AsyncMock(return_value=empty_plan),
    ), patch.object(
        orch,
        "_persist_plan",
        new=AsyncMock(),
    ) as persist:

        result = await orch.trigger_defense(
            incident_id="INC-NO-ACTIONS",
            dry_run=True,
            skip_simulation=True,
        )

    assert result.status == PlanStatus.FAILED
    assert result.completed_at is not None
    persist.assert_awaited()
