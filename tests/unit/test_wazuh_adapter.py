import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest


ORCHESTRATOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "response-orchestrator"
)
sys.path.insert(0, str(ORCHESTRATOR_DIR))

from adapters.wazuh import WazuhAdapter  # noqa: E402


def make_adapter() -> WazuhAdapter:
    return WazuhAdapter(
        api_url="https://wazuh.test:55000",
        username="test",
        password="test",
    )


@pytest.mark.asyncio
async def test_block_ip_rejects_wazuh_business_failure():
    adapter = make_adapter()
    adapter._api_call = AsyncMock(
        return_value={
            "error": 0,
            "data": {
                "total_failed_items": 1,
                "affected_items": [],
                "failed_items": [{"id": "001"}],
            },
        }
    )

    result = await adapter.execute("block_ip", "203.0.113.10")

    assert not result.success
    assert "rejected or did not execute" in result.detail


@pytest.mark.asyncio
async def test_isolate_host_rejects_wazuh_business_failure():
    adapter = make_adapter()
    adapter._api_call = AsyncMock(
        side_effect=[
            {"data": {"affected_items": [{"id": "001"}]}},
            {
                "error": 0,
                "data": {
                    "total_failed_items": 1,
                    "affected_items": [],
                    "failed_items": [{"id": "001"}],
                },
            },
        ]
    )

    result = await adapter.execute("isolate_host", "10.0.0.10")

    assert not result.success


@pytest.mark.asyncio
async def test_kill_process_rejects_wazuh_business_failure():
    adapter = make_adapter()
    adapter._api_call = AsyncMock(
        return_value={
            "error": 0,
            "data": {
                "total_failed_items": 1,
                "affected_items": [],
                "failed_items": [{"id": "001"}],
            },
        }
    )

    result = await adapter.execute(
        "kill_process",
        "10.0.0.10",
        {"agent_id": "001", "process_name": "bad.exe"},
    )

    assert not result.success


@pytest.mark.asyncio
async def test_block_ip_verification_rejects_empty_active_response():
    adapter = make_adapter()
    adapter._api_call = AsyncMock(
        return_value={"error": 0, "data": {"affected_items": []}}
    )

    result = await adapter.verify("block_ip", "203.0.113.10")

    assert not result.success
    assert "no active response entry" in result.detail


@pytest.mark.asyncio
async def test_unsupported_execution_actions_fail_closed():
    adapter = make_adapter()

    for action in ("add_monitoring", "deploy_sigma_rule", "patch_vulnerability"):
        result = await adapter.execute(action, "10.0.0.10")
        assert not result.success
        assert result.error == "Action not implemented"


@pytest.mark.asyncio
async def test_unsupported_verification_fails_closed():
    adapter = make_adapter()

    result = await adapter.verify("isolate_host", "10.0.0.10")

    assert not result.success
    assert result.error == "Verification not implemented"
