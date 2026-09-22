import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

ORCHESTRATOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "response-orchestrator"
)
sys.path.insert(0, str(ORCHESTRATOR_DIR))

from orchestrator import ResponseOrchestrator, SimulationUnavailableError  # noqa: E402


def make_orchestrator():
    from config import Settings
    return ResponseOrchestrator(
        Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            correlation_engine_url="http://fake-correlation:8000",
            simulation_url="http://fake-simulation:8000",
            ollama_host="http://fake-ollama:11434",
            wazuh_api_url="https://fake-wazuh:55000",
            wazuh_api_password="test",
        )
    )


@pytest.mark.asyncio
async def test_required_simulation_rejects_busy_service():
    orchestrator = make_orchestrator()
    response = MagicMock(status_code=409)
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=response)

    with patch("orchestrator.httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(SimulationUnavailableError, match="HTTP 409"):
            await orchestrator._run_simulation({}, None)


@pytest.mark.asyncio
async def test_required_simulation_rejects_timeout_or_connection_error():
    orchestrator = make_orchestrator()
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(
        side_effect=httpx.ConnectTimeout("simulation unavailable")
    )

    with patch("orchestrator.httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(
            SimulationUnavailableError,
            match="Required simulation could not be completed",
        ):
            await orchestrator._run_simulation({}, None)


@pytest.mark.asyncio
async def test_successful_required_simulation_returns_payload():
    orchestrator = make_orchestrator()
    response = MagicMock(status_code=200)
    response.json.return_value = {"simulation_id": "SIM-TEST"}
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=response)

    with patch("orchestrator.httpx.AsyncClient", return_value=mock_client):
        result = await orchestrator._run_simulation({}, None)

    assert result == {"simulation_id": "SIM-TEST"}
