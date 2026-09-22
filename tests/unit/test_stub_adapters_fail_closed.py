import sys
from pathlib import Path

import pytest


ORCHESTRATOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "response-orchestrator"
)
sys.path.insert(0, str(ORCHESTRATOR_DIR))

from adapters.edr import EDRAdapter  # noqa: E402
from adapters.firewall import FirewallAdapter  # noqa: E402
from adapters.identity import IdentityAdapter  # noqa: E402


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter", "action", "target"),
    [
        (FirewallAdapter(), "block_ip", "203.0.113.42"),
        (FirewallAdapter(), "network_segment", "segment-b"),
        (FirewallAdapter(), "sinkhole_domain", "bad.example"),
        (EDRAdapter(), "deploy_edr", "10.0.0.10"),
        (EDRAdapter(), "isolate_host", "10.0.0.10"),
        (EDRAdapter(), "kill_process", "10.0.0.10"),
        (IdentityAdapter(), "revoke_credentials", "alice"),
        (IdentityAdapter(), "disable_account", "alice"),
        (IdentityAdapter(), "enable_mfa", "alice"),
    ],
)
async def test_stub_adapter_execution_fails_closed(adapter, action, target):
    result = await adapter.execute(action, target)
    assert not result.success
    assert result.error == "Action not implemented"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter", "action"),
    [
        (FirewallAdapter(), "block_ip"),
        (EDRAdapter(), "isolate_host"),
        (IdentityAdapter(), "disable_account"),
    ],
)
async def test_stub_adapter_verification_fails_closed(adapter, action):
    result = await adapter.verify(action, "10.0.0.10")
    assert not result.success
    assert result.error == "Action not implemented"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter", "action"),
    [
        (FirewallAdapter(), "block_ip"),
        (EDRAdapter(), "isolate_host"),
        (IdentityAdapter(), "disable_account"),
    ],
)
async def test_stub_adapter_rollback_fails_closed(adapter, action):
    result = await adapter.rollback(action, "10.0.0.10")
    assert not result.success
    assert result.error == "Action not implemented"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter",
    [FirewallAdapter(), EDRAdapter(), IdentityAdapter()],
)
async def test_stub_adapter_health_is_not_healthy(adapter):
    assert await adapter.health_check() is False
