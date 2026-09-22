import sys
from pathlib import Path

import pytest


CORRELATION_DIR = Path(__file__).resolve().parents[2] / "services" / "correlation-engine"
sys.path.insert(0, str(CORRELATION_DIR))

from simulation_control import SimulationCoordinator  # noqa: E402


@pytest.mark.asyncio
async def test_first_job_acquires_slot_and_second_job_is_rejected():
    coordinator = SimulationCoordinator()

    assert await coordinator.try_acquire() is True
    assert coordinator.busy is True
    assert await coordinator.try_acquire() is False

    coordinator.release()
    assert coordinator.busy is False


@pytest.mark.asyncio
async def test_slot_can_be_reacquired_after_release():
    coordinator = SimulationCoordinator()

    assert await coordinator.try_acquire() is True
    coordinator.release()

    assert await coordinator.try_acquire() is True
    coordinator.release()


@pytest.mark.asyncio
async def test_release_without_active_slot_raises():
    coordinator = SimulationCoordinator()

    with pytest.raises(RuntimeError, match="not currently held"):
        coordinator.release()
