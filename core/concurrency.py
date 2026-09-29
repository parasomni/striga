import asyncio

# Process-wide cap on how many enumeration/scan coroutines (each of which launches
# an external subprocess) run at once. Without this, striga fans every task out
# with an unbounded asyncio.gather -- under --auto-all that's N targets x M ports x
# ~10 tools launching hundreds of processes simultaneously, which thrashes CPU/NIC/
# RAM and *increases* wall-clock time (and trips target-side rate limiting/IDS).
# One shared semaphore, created lazily on the running loop (single asyncio.run in
# this framework), bounds the whole run rather than each gather independently.

_SEMAPHORE = None


def _get_semaphore():
    global _SEMAPHORE
    if _SEMAPHORE is None:
        from core import config
        limit = config.get_config_value("max_concurrency", "performance") or 20
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 20
        _SEMAPHORE = asyncio.Semaphore(max(1, limit))
    return _SEMAPHORE


async def _run_capped(coro):
    async with _get_semaphore():
        return await coro


async def bounded_gather(coros):
    """Drop-in replacement for `asyncio.gather(*coros)` that never lets more than
    `performance.max_concurrency` of them run concurrently. Accepts an iterable of
    coroutines; preserves result ordering and the return_exceptions=False default."""
    return await asyncio.gather(*(_run_capped(c) for c in coros))
