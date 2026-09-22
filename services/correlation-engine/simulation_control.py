"""Concurrency guard for long-running simulation jobs."""

import asyncio


class SimulationCoordinator:
    """Allow at most one simulation job per service process."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    async def try_acquire(self) -> bool:
        """Acquire the simulation slot without waiting for an existing job."""
        if self._lock.locked():
            return False
        await self._lock.acquire()
        return True

    def release(self) -> None:
        """Release the simulation slot."""
        if not self._lock.locked():
            raise RuntimeError("Simulation slot is not currently held")
        self._lock.release()
